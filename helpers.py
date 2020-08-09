###
## Stringbuffer for hijacking stdin/stdout
## https://docs.qiling.io/en/latest/hijack/
###

class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def read_all(self):
        ret = self.buffer
        self.buffer = b''
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)

    def fstat(self): # syscall fstat will ignore it if return -1
        return -1

###
## DB helpers
###
import sqlite3

class MyDB():
	"""Some sqlite convenience stuff"""
	def __init__(self, dbname, table, create_str, insert_str):
		
		self.dbname = dbname
		self.table = table
		self.create_str = create_str
		self.insert_str = insert_str

		self.con = sqlite3.connect(self.dbname)
		self.cur = self.con.cursor()
		create_sql = f"CREATE TABLE {self.table}({self.create_str})"
		print(create_sql)
		self.cur.execute(create_sql)
		self.con.commit()
		
	def add_row(self, *args):
		qms = ','.join(['?']*len(self.insert_str.split(' ')))
		insert_sql = f'''INSERT INTO {self.table}({self.insert_str}) VALUES({qms})'''
		self.cur.execute(insert_sql, args) 
		self.con.commit()
		# try:
		# 	self.con.commit()
		# except Exception as e:
		# 	print(e)
		# 	print("commit failed, try again with next commit")

###
## tqdm product wrapper
## https://github.com/tqdm/tqdm/blob/f0e01446d97193118d19d5f7f6617c9c88e9e5d9/tqdm/contrib/itertools.py
###
from tqdm.auto import tqdm as tqdm_auto
import itertools

# Build the tqdm class by running down the iterators once
def tproduct_builder(*iterables, **tqdm_kwargs):
    kwargs = tqdm_kwargs.copy()
    tqdm_class = kwargs.pop("tqdm_class", tqdm_auto)
    try:
        lens = list(map(len, iterables))
    except TypeError:
        total = None
    else:
        total = 1
        for i in lens:
            total *= i
        kwargs.setdefault("total", total)
    return tqdm_class(**kwargs)

# The iterator
def tproduct(t, *iterables):
    for i in itertools.product(*iterables):
        yield i
        t.update()

