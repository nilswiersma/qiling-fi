###
## QilingFi
##
###

from qiling import Qiling

def disasm(ql, addr, size, buf=None):
	if not buf:
		buf = ql.mem.read(addr, size)

	# print(type(buf), buf, buf.hex())
	t = ''
	# for i in ql.md.disasm(buf, addr):
	# 	t += ql.trace_fstring.format(i.address, buf[::-1].hex(), i.mnemonic, i.op_str)
	for address,size,mnemonic,op_str in ql.md.disasm_lite(buf, addr):
		t += ql.trace_fstring.format(address, buf[::-1].hex(), mnemonic, op_str)
		if ql.console:
			print(t)
	return t	

def asm_trace(ql, address, size):
	if address == ql.trace_start:
		ql.tracing = True
	if address == ql.trace_end:
		ql.tracing = False

	if ql.tracing:
		ql.trace.append(disasm(ql, address, size))	

class QilingFi(Qiling):
	"""Fault injection helpers for Qiling run"""
	def __init__(self, 
		# trace_start, trace_end, 
		# fi_model, fi_args,
		*args, **kwargs):

		self.trace_start = kwargs.pop('trace_start')
		self.trace_end = kwargs.pop('trace_end')
		self.fi_args = kwargs.pop('fi_args')
		self.fi_model = kwargs.pop('fi_model')
		self.md = kwargs.pop('md')

		super(QilingFi, self).__init__(*args, **kwargs)

		self.tracing = False
		self.trace = []
		self.trace_fstring = '{:x}:  {}  {} {}'

		self.hook_code(asm_trace)

	def run(self, *args, **kwargs):
		if self.fi_model:
			self.fi_model(self)
		super(QilingFi, self).run(*args, **kwargs)

	def patch(self, *args, **kwargs):
		if self.console:
			address = args[0]
			buf = self.mem.read(address, 4)
			print('[!] patching')
			print(' >', end=' ')
			disasm(self, address, 4)
			print(' <', end=' ')
			disasm(self, address, 4, args[1])

		super(QilingFi, self).patch(*args, **kwargs)

