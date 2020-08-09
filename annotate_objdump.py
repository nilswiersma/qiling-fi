import re
import sqlite3
import tqdm

OBJDUMP_FILE = 'ifelse.objdump'
OUT_FILE = 'ifelse.objdump+randomized' #'ifelse.objdump+singlebit'
DB_FILE = 'ifelse.sqlite'# 'ifelse_singlebit_sequential.py.sqlite'
TABLE_NAME = 'log_1596825211001'# 'log_1596829289562'
# OUT_FILE = 'ifelse.objdump+singlebit'
# DB_FILE = 'ifelse_singlebit_sequential.py.sqlite'
# TABLE_NAME = 'log_1596829289562'

regex_addr = r'   ([0-9a-fA-F]+):(.*)'

con = sqlite3.connect(f'{DB_FILE}')
cur = con.cursor()

table = f'{TABLE_NAME}'

query = f"""SELECT disasm,random FROM {TABLE_NAME} WHERE hex(data) LIKE "46524545%" """
cur.execute(query)
free_beer_rows = cur.fetchall()

query = f"""SELECT disasm,random,exception FROM {TABLE_NAME} WHERE exception IS NOT '' """ 
cur.execute(query)
exception_rows = cur.fetchall()


with open(OBJDUMP_FILE, 'r') as in_file:
	with open(OUT_FILE, 'w') as out_file:
		for line in tqdm.tqdm(in_file.readlines()):
		# for line in in_file.readlines():
			line_stripped = line.replace('\t',' ').replace('\n', '')
			print(f'{line_stripped:<80} | ', file=out_file, end='')
			m = re.match(regex_addr, line_stripped)

			# Address row in objdump
			if m and len(m.groups()) == 2:
				addr = m.groups()[0]
				rest = m.groups()[1]

				free_beer_ctr = 0
				free_beer_ins = []
				for row in free_beer_rows:
					if row[0].startswith(f'0x{addr}'):
						free_beer_ctr += 1
						free_beer_ins.append(row)

				if free_beer_ctr > 0:
					print(f'FREE BEER ({free_beer_ctr})', file=out_file, end='')
					for ins in free_beer_ins:
						print(f'\n{"":<80} -  {ins[0]} ({ins[1]})', file=out_file, end='')
					print(f'\n{"":<80} | ', file=out_file, end='')

				# exception_ctr = 0
				# exception_ins = []
				# for row in exception_rows:
				# 	if row[0].startswith(f'0x{addr}'):
				# 		exception_ctr += 1
				# 		exception_ins.append(row)

				# if exception_ctr > 0:
				# 	print(f'EXCEPTION ({exception_ctr})', file=out_file, end='')
				# 	for ins in exception_ins:
				# 		print(f'\n{"":<80} -  {ins[0]} ({ins[1]}) [{ins[2]}]', file=out_file, end='')
			print('', file=out_file, end='\n')
