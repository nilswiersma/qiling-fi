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

MAIN_START = 0x102ec
TRACE_END  = 0x10308

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
        data = ql.stdout.read_all()

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
        data = ql.stdout.read_all()

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
        data = ql.stdout.read_all()

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
        main_addrs = [0x102ec, 0x102f0, 0x102f4, 0x102f8, 0x102fc, 0x10300, 0x10304, 0x10308, 0x10318, 0x1031c, 0x179cc, 0x179d0, 0x179d4, 0x25dd0, 0x25dd4, 0x25dd8, 0x25ddc, 0x25de0, 0x25df8, 0x25dfc, 0x25e00, 0x25e04, 0x25e08, 0x25e0c, 0x25e10, 0x25df8, 0x25dfc, 0x25e00, 0x25e04, 0x25e08, 0x25e0c, 0x25e10, 0x25df8, 0x25dfc, 0x25e00, 0x25e04, 0x25e08, 0x25e0c, 0x25e10, 0x25e14, 0x25e18, 0x25e1c, 0x25e20, 0x25e24, 0x25e28, 0x25e2c, 0x179d8, 0x179dc, 0x179e0, 0x179e4, 0x179e8, 0x179ec, 0x179f0, 0x10b40, 0x10b44, 0xffff0fe0, 0xffff0fe4, 0xffff0fe8, 0x179f4, 0x179f8, 0x179fc, 0x17a00, 0x17a04, 0x17a08, 0x17a0c, 0x17a10, 0x17a14, 0x17a18, 0x17a1c, 0x17a20, 0x17a24, 0x17a28, 0xffff0fc0, 0xffff0fc4, 0xffff0fc8, 0xffff0fcc, 0xffff0fd0, 0xffff0fd4, 0xffff0fd8, 0xffff0fdc, 0xffff0fe0, 0xffff0fe4, 0xffff0fe8, 0x17a2c, 0x17a30, 0x17a34, 0x17a38, 0x17a3c, 0x17a40, 0x17a44, 0x17a48, 0x17a4c, 0x17a50, 0x17a54, 0x17a5c, 0x17a60, 0x17a64, 0x17a68, 0x17a6c, 0x17a78, 0x17a7c, 0x17a80, 0x17a84, 0x17a88, 0x17a8c, 0x17a90, 0x17a94, 0x17a98, 0x17a9c, 0x17aa0, 0x1b608, 0x1b60c, 0x1b610, 0x1b614, 0x1b618, 0x1b61c, 0x1b620, 0x1b624, 0x1b628, 0x1b62c, 0x1b630, 0x1b634, 0x1b638, 0x1b63c, 0x1b640, 0x1b644, 0x1b648, 0x1b64c, 0x1b650, 0x1b654, 0x1b658, 0x1b65c, 0x1b660, 0x1b664, 0x1b668, 0x1b66c, 0x1c0f8, 0x1c0fc, 0x1c100, 0x1c104, 0x1c108, 0x1c10c, 0x1c110, 0x1c114, 0x1c118, 0x1c174, 0x1c178, 0x1c280, 0x1c284, 0x1d160, 0x1d164, 0x1d168, 0x1d16c, 0x1d170, 0x1d174, 0x1d178, 0x1d17c, 0x1d1a8, 0x1d1ac, 0x1d1b0, 0x1d1b4, 0x1d1b8, 0x1d1bc, 0x1d1c0, 0x1d1c4, 0x1d1c8, 0x1d1cc, 0x47118, 0x4711c, 0x47120, 0x47124, 0x47128, 0x4712c, 0x47130, 0x47134, 0x47138, 0x4713c, 0x47140, 0x47144, 0x47148, 0x4714c, 0x47150, 0x47154, 0x47158, 0x4715c, 0x47160, 0x47164, 0x1afdc, 0x1afe0, 0x1afe4, 0x1afe8, 0x28508, 0x2850c, 0x28510, 0x28514, 0x28518, 0x2851c, 0x28520, 0x28524, 0x28528, 0x2852c, 0x47168, 0x4716c, 0x47170, 0x47174, 0x47178, 0x4717c, 0x47180, 0x47184, 0x47188, 0x4718c, 0x47190, 0x471d0, 0x471d4, 0x471d8, 0x240ac, 0x240b0, 0x240b4, 0x240b8, 0x240bc, 0x240c0, 0x240c4, 0x240c8, 0x240cc, 0x240d0, 0x2417c, 0x24180, 0x24184, 0x24188, 0x2418c, 0x240d4, 0x240d8, 0x240dc, 0x10b40, 0x10b44, 0xffff0fe0, 0xffff0fe4, 0xffff0fe8, 0x240e0, 0x240e4, 0x240e8, 0x240ec, 0x240f0, 0x240f4, 0x240f8, 0x240fc, 0x24100, 0x24104, 0x24108, 0x2410c, 0x24110, 0x24114, 0x24118, 0x2411c, 0x24120, 0x24124, 0x24128, 0x2412c, 0x24130, 0x2207c, 0x22080, 0x22084, 0x22088, 0x2208c, 0x22090, 0x22094, 0x22098, 0x2209c, 0x220a0, 0x220a4, 0x220a8, 0x220ac, 0x220b0, 0x220b4, 0x220b8, 0x220bc, 0x220c0, 0x220c4, 0x220c8, 0x220cc, 0x220d0, 0x220d4, 0x220d8, 0x221fc, 0x22200, 0x22204, 0x22208, 0x2220c, 0x22210, 0x22214, 0x22218, 0x2221c, 0x22220, 0x22224, 0x22228, 0x2222c, 0x22230, 0x22234, 0x22238, 0x2223c, 0x22240, 0x22244, 0x22248, 0x2224c, 0x22250, 0x22254, 0x22258, 0x2225c, 0x2261c, 0x22620, 0x228bc, 0x228c0, 0x228c4, 0x22268, 0x2226c, 0x22270, 0x22274, 0x10b40, 0x10b44, 0xffff0fe0, 0xffff0fe4, 0xffff0fe8, 0x22278, 0x2227c, 0x22280, 0x22284, 0x22288, 0x2228c, 0x22290, 0x22294, 0x22298, 0x2229c, 0x222a0, 0x222a4, 0x222a8, 0x222ac, 0x222b0, 0x222b4, 0x222b8, 0x222bc, 0x222c0, 0x222c4, 0x222c8, 0x222cc, 0x222d0, 0x222d4, 0x222d8, 0x222dc, 0x222e0, 0x222e4, 0x222e8, 0x222ec, 0x222f0, 0x222f4, 0x222f8, 0x222fc, 0x22300, 0x22304, 0x223d4, 0x223d8, 0x223dc, 0x223e0, 0x223e4, 0x223e8, 0x223ec, 0x223f0, 0x223f4, 0x223f8, 0x223fc, 0x22400, 0x22404, 0x22414, 0x22418, 0x2241c, 0x22420, 0x22424, 0x22428, 0x2242c, 0x22430, 0x22434, 0x22438, 0x2243c, 0x22440, 0x22444, 0x22448, 0x2244c, 0x22450, 0x22454, 0x229c0, 0x229c4, 0x229c8, 0x229d8, 0x229dc, 0x229e0, 0x229e4, 0x229e8, 0x229ec, 0x229f0, 0x229f4, 0x229f8, 0x22cfc, 0x22d00, 0x22d04, 0x22d08, 0x22d0c, 0x22d10, 0x22d14, 0x22d18, 0x22d1c, 0x22d20, 0x22d24, 0x22d28, 0x22d2c, 0x22d30, 0x22d34, 0x22d38, 0x22d3c, 0x224e8, 0x224ec, 0x224f0, 0x24134, 0x24138, 0x2413c, 0x24140, 0x24144, 0x24148, 0x2414c, 0x241e8, 0x241ec, 0x471dc, 0x471e0, 0x471a4, 0x471a8, 0x471ac, 0x471b0, 0x1d10c, 0x1d110, 0x1d114, 0x1d118, 0x1d11c, 0x1d120, 0x1d124, 0x1d128, 0x1d12c, 0x1d138, 0x1d13c, 0x1d140, 0x1d144, 0x1d148, 0x1d14c, 0x1d150, 0x471b4, 0x471b8, 0x471bc, 0x471c0, 0x471c4, 0x471c8, 0x471cc, 0x1d1d0, 0x1d1d4, 0x1c288, 0x1c28c, 0x1c290, 0x1c294, 0x1c298, 0x1c29c, 0x1c180, 0x1c184, 0x1c188, 0x1c18c, 0x1c190, 0x1c194, 0x1c198, 0x1c19c, 0x1c1a0, 0x1c1a4, 0x1c1a8, 0x1c1ac, 0x1c1b0, 0x1c1b4, 0x1c1b8, 0x1c1bc, 0x1c1c0, 0x1c1c4, 0x1c1c8, 0x1c1cc, 0x1c1d0, 0x1c1d4, 0x1c1d8, 0x1c1dc, 0x1c1e0, 0x1c1e4, 0x1c1e8, 0x1c1ec, 0x1ba50, 0x1ba54, 0x1ba58, 0x1ba5c, 0x1b670, 0x1b674, 0x1b678, 0x1b67c, 0x1b680, 0x1b684, 0x1b688, 0x1b68c, 0x1b690, 0x1b694, 0x5dda8, 0x5ddac, 0x5ddb0, 0x5ddb4, 0x5dbbc, 0x5dbc0, 0x5dbc4, 0x5dbc8, 0x5dbcc, 0x5dd80, 0x5dd84, 0x5dd88, 0x5ddb8, 0x5ddbc, 0x5ddc0, 0x5ddc4, 0x1b698, 0x1b69c, 0x1b6a0, 0x1b6a4, 0x1b6a8, 0x1b768, 0x1b76c, 0x1b770, 0x1b774, 0x1d274, 0x1d278, 0x1d27c, 0x1d280, 0x1d284, 0x1d288, 0x1d28c, 0x1d290, 0x1d294, 0x1d298, 0x1d2e0, 0x1d2e4, 0x1d2e8, 0x1d2ec, 0x1d2f0, 0x1d2f4, 0x1d2f8, 0x1d2fc, 0x1d300, 0x1d304, 0x1d29c, 0x1d2a0, 0x1d32c, 0x1d330, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d334, 0x1d338, 0x1d33c, 0x1d340, 0x1d344, 0x1d348, 0x1d34c, 0x1d2a4, 0x1d2a8, 0x1d2ac, 0x1d324, 0x1d328, 0x1b778, 0x1b77c, 0x1b780, 0x17aa4, 0x17aa8, 0x17aac, 0x17ab0, 0x17ab4, 0x17ab8, 0x17abc, 0x17ac0, 0x17ac4, 0x17ac8, 0x17acc, 0x17ad0, 0x17ad4, 0x17ad8, 0x17adc, 0x17ae0, 0x17ae4, 0x17ae8, 0x17aec, 0x17af0, 0x17af4, 0x17af8, 0x17afc, 0x17b00, 0x17b04, 0x17b08, 0x17b0c, 0x17b10, 0x17b14, 0x17b18, 0x17b1c, 0x17b20, 0x17b24, 0x17b28, 0xffff0fc0, 0xffff0fc4, 0xffff0fc8, 0xffff0fcc, 0xffff0fd0, 0xffff0fd4, 0xffff0fd8, 0xffff0fdc, 0xffff0fe0, 0xffff0fe4, 0xffff0fe8, 0x17b2c, 0x17b30, 0x17b34, 0x17b38, 0x17b3c, 0x17b40, 0x17b44, 0x17b48, 0x10320, 0x10324, 0x10328, 0x1032c, ]
        iterables = [main_addrs]

        main = main_nop

    if sys.argv[1] == 'singlebit':
        # all addresses of main block
        main_addrs = [0x102ec, 0x102f0, 0x102f4, 0x102f8, 0x102fc, 0x10300, 0x10304, 0x10308, 0x1030c, 0x10310, 0x10314, 0x10318, 0x1031c, 0x10320, 0x10324, 0x10328, 0x1032c]
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
