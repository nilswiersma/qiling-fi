# Generic imports
import sys, os, time, random
import sqlite3
import signal

from collections import namedtuple
TqdmIt = namedtuple('TqdmIt', ['tqdm', 'it'])
from itertools import product

# Installed together with qiling
import unicorn
import capstone

# Other installed packages
# from tqdm.contrib.itertools import product as tproduct
from tqdm import tqdm, trange
# from tqdm.auto import tqdm as tqdm_auto
# from tqdm.contrib.concurrent import process_map
from concurrent.futures import as_completed, ProcessPoolExecutor


# Custom imports
from QilingFi import QilingFi
from helpers import StringBuffer, MyDB
# from helpers import tproduct, tproduct_builder
from fault_models import flip_single_bit, random_word, set_word

console = False
terminal_logging = False

MAIN_START = 0x102ec
TRACE_END  = 0x10308
NRUNS=10000

def main_random(*args):
    _, addr = args

    exception = ''
    data = b''

    # arguments for fi_model
    fi_args = {
        'addr': addr,
    }

    ql2 = QilingFi(
        # Qiling args
        ["ifelse/ifelse"], ".", 
        console=console, stdin=StringBuffer(), stdout=StringBuffer(),

        # QilingFi args
        trace_start=MAIN_START, trace_end=TRACE_END,
        fi_model=random_word, fi_args=fi_args,
        md=md
        )

    try:
        ql2.restore(ql.snapshot)
        ql2.tracing = ql.tracing
        ql2.ins_counter = ql.ins_counter
        ql2.run(begin=addr, timeout=1000000)
    except Exception as e:
        # print('exception')
        exception = str(e)
        ql2.emu_stop()

    # read out data from the emulation
    data = ql2.stdout.read_all()

    return {
        'data' : data,
        'exception': exception,
        'addr' : f'{addr:x}',
        'ins' : ql2.fi_args['ins'][::-1].hex(),
        'addr_i' : addr,
        'ins_i' : int.from_bytes(ql2.fi_args['ins'],'big'),
        'trace' : '\n'.join(ql.trace)
    }

def pause_or_quit(signum, frame):
    # https://stackoverflow.com/questions/18114560/python-catch-ctrl-c-command-prompt-really-want-to-quit-y-n-resume-executi
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, original_sigint)

    try:
        input('Script paused, jobs are still running\nHit CTRL-C again to quit, Enter to continue > ')
    except KeyboardInterrupt:
        print('Killing script and jobs..')
        res = [job.cancel() for job in jobs]
        print(f'Killed {sum(res)} pending job(s)')
        print(f'Failed to kill {len(res)-sum(res)} pending job')
        print('Final db commit')
        db.con.commit()
        sys.exit(1)

    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, pause_or_quit)

if __name__ == "__main__":
    fm = 'random'
    DBNAME = f'{os.path.splitext(__file__)[0]}-{fm}.sqlite'
    # TABLE = f'log_{int(time.time()*1000)}'
    TABLE = f'log_combined'
    CREATE = "id integer PRIMARY KEY AUTOINCREMENT, data text, category int, addr text, ins text, addr_i int, ins_i int, disasm text, exception text, trace text"
    ARCH = capstone.CS_ARCH_ARM
    MODE = capstone.CS_MODE_ARM

    NO_BEER = 0
    FREE_BEER = 0
    EXCEPTION = 0

    db = MyDB(DBNAME, TABLE, CREATE)
    md = capstone.Cs(ARCH, MODE)

    snap_addr = 0x102f4#f4

    addrs = [
        # 102ec
        # 102f0
        # 102f4
        0x102f8,
        0x102fc,
        0x10300,#:  e51b3008    ldr r3, [fp, #-8]
        0x10304,#:  e3530000    cmp r3, #0
        0x10308,#:  1a000002    bne 10318 <main+0x2c>
    ]

    ## will stop AFTER snap_addr, get snapshot through ql.snapshot
    ql = QilingFi(
        # Qiling args
        ["ifelse/ifelse"], ".", 
        console=console, stdin=StringBuffer(), stdout=StringBuffer(),

        # QilingFi args
        trace_start=MAIN_START, trace_end=TRACE_END,
        snapshot_addr=snap_addr,
        md=md
        )
    ql.run()

    main = main_random

    print('iterating once to count')
    iterables = [range(NRUNS), addrs]
    total = None
    try:
        lens = list(map(len, iterables))
    except TypeError:
        total = None
    else:
        total = 1
        for i in lens:
            total *= i
    print(f' {total} iterations')


    ## https://stackoverflow.com/questions/35700273
    # Replace signal handler of parent process, so child processes will ignore terminate signals
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

    executor = ProcessPoolExecutor()

    print('spawning jobs')
    jobs = []
    for it in tqdm(product(*iterables), total=total):
        jobs.append(executor.submit(main_random, *it))

    results = []
    print('all spawned, waiting for completion')

    # Restore original handler, so the parent process can handle terminate signals
    signal.signal(signal.SIGINT, original_sigint_handler)
    # Set up ctrl-c to pause or quit
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, pause_or_quit)

    tqdm_it = tqdm(as_completed(jobs), total=total)
    for job in tqdm_it:
        res = job.result()

        category = 0

        # disassemble using capstone
        disasm = ''
        for i in md.disasm(bytes.fromhex(res['ins']), res['addr_i']):
            disasm += ql.trace_fstring.format(i.address, res['ins'], i.mnemonic, i.op_str)

        if b'FREE BEER' in res['data'] and b'NO BEER' not in res['data']:
            FREE_BEER += 1
            category = 1
        elif res['data'] == b'NO BEER' or res['data'] == b'NO BEER\n':
            NO_BEER += 1
            category = 2
        else:
            pass

        if res['exception'] != '':
            EXCEPTION += 1
            category = 3

        tqdm_it.set_description(f'FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}')
        res['category'] = category
        res['disasm'] = disasm
        db.add_row(res)
        # db.add_row(res['data'], category, res['ins'], res['addr'], disasm, res['exception'], res['trace'])

        if terminal_logging:
            tqdm_it.write(f"{res['addr']:x} | {res['ins'].hex()} | {disasm} | {res['data']} | {res['exception']}")

        results.append(res)

    # Commit one last time in case anything was lingering
    db.con.commit()


