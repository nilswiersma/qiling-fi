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
from tqdm.contrib.concurrent import process_map

# Custom imports
from QilingFi import QilingFi
from helpers import StringBuffer, MyDB
from helpers import tproduct, tproduct_builder
from fault_models import flip_single_bit, random_word, set_word

console = False
terminal_logging = False

MAIN_START = 0x102ec
TRACE_END  = 0x10308

def main_random(*args):
    exception = ''
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
        if sys.argv[1] == 'simple':
            # provide a timeout as some faults will trigger some deadlock, not sure how the scale works here
            ql2.run(timeout=1000000)
        else:
            ql2.restore(ql.snapshot)
            # continue tracing (or not) depending on snapshot
            ql2.tracing = ql.tracing
            # restore instruction counter state
            ql2.ins_counter = ql.ins_counter
            # create snapshot after addr-4 execution, continue from addr
            ql2.run(begin=addr, timeout=1000000)
    except Exception as e:
        # print('exception')
        exception = str(e)
        ql2.emu_stop()

    # read out data from the emulation
    data = ql2.stdout.read_all()

    if sys.argv[1] == 'snapshotmulti':
        return (ql2.fi_args['ins'], data, exception)
    else:
        tqdm.write(str((data, exception)))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['simple', 'snapshot', 'snapshotmulti']: 
        print(f'Usage: python3 {sys.argv[0]} [simple|snapshot|snapshotmulti]')
        sys.exit(1)

    ARCH = capstone.CS_ARCH_ARM
    MODE = capstone.CS_MODE_ARM

    NRUNS = 1000

    md = capstone.Cs(ARCH, MODE)

    addr = 0x102f8#4#ec#0x102f8

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
        snapshot_addr=addr-4, #snapshot_file='.snapshot.bin',
        md=md
        )

    ql.run()

    if sys.argv[1] == 'snapshotmulti':
        ret = process_map(main_random, range(NRUNS))
        for x in ret:
            print(x)
    else:
        for _ in trange(NRUNS):
            main_random()
