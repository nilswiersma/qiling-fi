# Generic imports
import sys, os, time, random
import sqlite3
import signal

from collections import namedtuple
TqdmIt = namedtuple('TqdmIt', ['tqdm', 'it'])

# Installed together with qiling
import unicorn
import capstone

# Other installed packages
from tqdm.contrib.itertools import product as tproduct
from tqdm import tqdm, trange
from tqdm.auto import tqdm as tqdm_auto

# Custom imports
from QilingFi import QilingFi
from helpers import StringBuffer, MyDB
from helpers import tproduct, tproduct_builder
from fault_models import flip_single_bit, random_word, set_word

console = False
terminal_logging = True

MAIN_START = 0x10524
TRACE_END  = 0x1056c

def main_singlebit():
    NO_BEER = 0
    FREE_BEER = 0
    EXCEPTION = 0
    COUNTER = -1

    for addr, bitidx in tqdm_it.it:
        COUNTER += 1    
        exception = ''
        data = b''

        # arguments for fi_model
        fi_args = {
            'addr': addr,
            'bitidx': bitidx
        }

        ql = QilingFi(
            # Qiling args
            ["ifelse/ifelse"], ".", 
            console=console, stdin=StringBuffer(), stdout=StringBuffer(),

            # QilingFi args
            trace_start=MAIN_START, trace_end=TRACE_END,
            fi_model=flip_single_bit, fi_args=fi_args,
            md=md
            )

        try:
            # provide a timeout as some faults will trigger some deadlock, not sure how the scale works here
            ql.run(timeout=1000000)
        except Exception as e:
            # print('exception')
            exception = str(e)
            ql.emu_stop()
            EXCEPTION += 1

        # read out data from the emulation
        data = ql._os.stdout.read_all()

        # read out faulted instruction
        ins = ql.fi_args['ins']

        # disassemble using capstone
        disasm = ''
        for i in md.disasm(ins, addr):
            disasm += ql.trace_fstring.format(i.address, ins[::-1].hex(), i.mnemonic, i.op_str)

        category = 0
        if b'FREE BEER' in data and b'NO BEER' not in data:
            FREE_BEER += 1
            category = 1
        elif data == b'NO BEER' or data == b'NO BEER\n':
            NO_BEER += 1
            category = 2
        else:
            pass

        db.add_row(data, category, ins[::-1].hex(), disasm, exception, '\n'.join(ql.trace))

        # print(f'[{COUNTER}] FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}', end='\n' if console else '\r')
        if terminal_logging:
            tqdm_it.tqdm.write(f'{addr:x} | {ins[::-1].hex()} | {disasm} | {data} | {exception}')
            tqdm_it.tqdm.set_description(f'FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}')

def main_nop():
    NO_BEER = 0
    FREE_BEER = 0
    EXCEPTION = 0
    COUNTER = -1

    for addr in tqdm_it.it:
        addr = addr[0]
        COUNTER += 1    
        exception = ''
        data = b''

        # arguments for fi_model
        fi_args = {
            'addr': addr,
            'ins': b'\x00'*4
        }

        ql = QilingFi(
            # Qiling args
            ["ifelse/ifelse"], ".", 
            console=console, stdin=StringBuffer(), stdout=StringBuffer(),

            # QilingFi args
            trace_start=MAIN_START, trace_end=TRACE_END,
            fi_model=set_word, fi_args=fi_args,
            md=md
            )

        try:
            # provide a timeout as some faults will trigger some deadlock, not sure how the scale works here
            ql.run(timeout=1000000)
        except Exception as e:
            # print('exception')
            exception = str(e)
            ql.emu_stop()
            EXCEPTION += 1

        # read out data from the emulation
        data = ql._os.stdout.read_all()

        # read out faulted instruction
        ins = ql.fi_args['ins']

        # disassemble using capstone
        disasm = ''
        for i in md.disasm(ins, addr):
            disasm += ql.trace_fstring.format(i.address, ins[::-1].hex(), i.mnemonic, i.op_str)

        category = 0
        if b'FREE BEER' in data and b'NO BEER' not in data:
            FREE_BEER += 1
            category = 1
        elif data == b'NO BEER' or data == b'NO BEER\n':
            NO_BEER += 1
            category = 2
        else:
            pass

        db.add_row(data, category, ins[::-1].hex(), disasm, exception, '\n'.join(ql.trace))

        # print(f'[{COUNTER}] FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}', end='\n' if console else '\r')
        if terminal_logging:
            tqdm_it.tqdm.write(f'{addr:x} | {ins[::-1].hex()} | {disasm} | {data} | {exception}')
            tqdm_it.tqdm.set_description(f'FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}')

def main_random():
    NO_BEER = 0
    FREE_BEER = 0
    EXCEPTION = 0
    COUNTER = -1

    for _, addr in tqdm_it.it:
        COUNTER += 1    
        exception = ''
        data = b''

        # arguments for fi_model
        fi_args = {
            'addr': addr,
        }

        ql = QilingFi(
            # Qiling args
            ["ifelse/ifelse"], ".", 
            console=console, stdin=StringBuffer(), stdout=StringBuffer(),

            # QilingFi args
            trace_start=MAIN_START, trace_end=TRACE_END,
            fi_model=random_word, fi_args=fi_args,
            md=md
            )

        try:
            # provide a timeout as some faults will trigger some deadlock, not sure how the scale works here
            ql.run(timeout=1000000)
        except Exception as e:
            # print('exception')
            exception = str(e)
            ql.emu_stop()
            EXCEPTION += 1

        # read out data from the emulation
        data = ql._os.stdout.read_all()

        # read out faulted instruction
        ins = ql.fi_args['ins']

        # disassemble using capstone
        disasm = ''
        for i in md.disasm(ins, addr):
            disasm += ql.trace_fstring.format(i.address, ins[::-1].hex(), i.mnemonic, i.op_str)

        category = 0
        if b'FREE BEER' in data and b'NO BEER' not in data:
            FREE_BEER += 1
            category = 1
        elif data == b'NO BEER' or data == b'NO BEER\n':
            NO_BEER += 1
            category = 2
        else:
            pass

        db.add_row(data, category, ins[::-1].hex(), disasm, exception, '\n'.join(ql.trace))

        # print(f'[{COUNTER}] FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}', end='\n' if console else '\r')
        if terminal_logging:
            tqdm_it.tqdm.write(f'{addr:x} | {ins[::-1].hex()} | {disasm} | {data} | {exception}')
            tqdm_it.tqdm.set_description(f'FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}')

def pause_or_quit(signum, frame):
    # https://stackoverflow.com/questions/18114560/python-catch-ctrl-c-command-prompt-really-want-to-quit-y-n-resume-executi
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, original_sigint)

    try:
        input('Script paused, hit CTRL-C again to quit, Enter to continue > ')
    except KeyboardInterrupt:
        print('Killing script')
        sys.exit(1)

    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, pause_or_quit)

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['random', 'singlebit', 'nop']: 
        print(f'Usage: python3 {sys.argv[0]} [random|singlebit|nop]')
        sys.exit(1)

    DBNAME = f'{os.path.splitext(__file__)[0]}-{sys.argv[1]}.sqlite'
    TABLE = f'log_{int(time.time()*1000)}'
    CREATE = "id integer PRIMARY KEY AUTOINCREMENT, data text, category int, ins text, disasm text, exception text, trace text"
    INSERT = "data, category, ins, disasm, exception, trace"
    ARCH = capstone.CS_ARCH_ARM
    MODE = capstone.CS_MODE_ARM

    db = MyDB(DBNAME, TABLE, CREATE, INSERT)
    md = capstone.Cs(ARCH, MODE)

    if sys.argv[1] == 'random':
        addrs = [
            0x10300,#:  e51b3008    ldr r3, [fp, #-8]
            0x10304,#:  e3530000    cmp r3, #0
            0x10308,#:  1a000002    bne 10318 <main+0x2c>
        ]
        # test each address 100 times
        iterables = [range(100), addrs]

        main = main_random

    if sys.argv[1] == 'nop':
        # all addresses of main execution trace
        main_addrs = [0x10524, 0x10528, 0x1052c, 0x10530, 0x10534, 0x10538, 0x1053c, 0x10540, 0x10544, 0x10548, 0x1054c, 0x10550, 0x10554, 0x10558, 0x1055c, 0x10560, 0x10564, 0x10568, 0x1056c]
        iterables = [main_addrs]

        main = main_nop

    if sys.argv[1] == 'singlebit':
        # all addresses of main block
        main_addrs = [0x10524, 0x10528, 0x1052c, 0x10530, 0x10534, 0x10538, 0x1053c, 0x10540, 0x10544, 0x10548, 0x1054c, 0x10550, 0x10554, 0x10558, 0x1055c, 0x10560, 0x10564, 0x10568, 0x1056c]
        # iterate all bits of each address
        iterables = [main_addrs, range(32)]

        main = main_singlebit

    # tproduct_builder maps len onto its arguments, might not be desirable
    t = tproduct_builder(*iterables)
    it = tproduct(t, *iterables)
    tqdm_it = TqdmIt(t, it)

    ## set up ctrl-c to pause or quit
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, pause_or_quit)

    main()

    # Commit one last time in case anything was lingering
    db.con.commit()
