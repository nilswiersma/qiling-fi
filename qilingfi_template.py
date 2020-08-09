
# Generic imports
import sys, os, time, random
import sqlite3
import signal
from collections import namedtuple

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
from fault_models import flip_single_bit

TqdmIt = namedtuple('TqdmIt', ['tqdm', 'it'])

console = False
terminal_logging = True

def main(db, md, tqdm_it):
	COUNTER = -1
	EXCEPTION = 0

    for addr, it1, it2, ... in tqdm_it.it:
        COUNTER += 1
        exception = ''
        data = b''

        # arguments for fi_model
        fi_args = {
            'addr': addr,
            TODO
        }

        ql = QilingFi(
            # Qiling args
            [TODO], TODO, 
            console=console, stdin=StringBuffer(), stdout=StringBuffer(),

            # QilingFi args
            trace_start=MAIN_ADDRS[0], trace_end=MAIN_ADDRS[-1],
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

        ## Do more stuff here

        db.add_row(COUNTER, data, category, ins[::-1].hex(), disasm, exception, '\n'.join(ql.trace))

        # print(f'[{COUNTER}] FREE_BEER: {FREE_BEER} | NO_BEER: {NO_BEER} | EXCEPTION: {EXCEPTION}', end='\n' if console else '\r')
        if terminal_logging:
            tqdm_it.tqdm.write(f'Rolling message, forexample containing: {data} and {exception}')
            tqdm_it.tqdm.set_description(f'Progress bar message, for example containing {EXCEPTION}')

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

    ## Setup before running

    DBNAME = f'{os.path.splitext(__file__)[0]}.sqlite'
    TABLE = f'log_{int(time.time()*1000)}'
    CREATE = "id integer PRIMARY KEY, data text, category int, ..."
    INSERT = "id, data, category, ..."
    ARCH = capstone.CS_ARCH_ARM
    MODE = capstone.CS_MODE_ARM

    db = MyDB(DBNAME, TABLE, CREATE, INSERT)
    md = capstone.Cs(ARCH, MODE)

    iterables = [TODO, TODO]
    # tproduct_builder maps len onto its arguments, might not be desirable
    t = tproduct_builder(*iterables)
    it = tproduct(t, *iterables)
    tqdm_it = TqdmIt(t, it)

    ## set up ctrl-c to pause or quit
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, pause_or_quit)

    ## Main loop
    main(db, md, tqdm_it)

    # Commit one last time in case anything was lingering
    db.con.commit()
