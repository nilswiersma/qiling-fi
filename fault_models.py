import os

def flip_single_bit(ql):
    addr = ql.fi_args['addr']
    bitidx = ql.fi_args['bitidx']
    ins = ql.mem.read(addr, 4)
    ins = int.from_bytes(ins, 'big')
    ins ^= (1 << bitidx)
    ins = ins.to_bytes(4, 'big')
    ql.fi_args['ins'] = ins
    if ql.console:
	    print(ql.mem.read(addr, 4))
    ql.patch(addr, ins)
    if ql.console:
	    print(ql.mem.read(addr, 4))

def random_word(ql):
    addr = ql.fi_args['addr']
    ins = os.urandom(4)
    ql.fi_args['ins'] = ins 
    ql.patch(addr, ins)

def set_word(ql):
	addr = ql.fi_args['addr']
	ins = ql.fi_args['ins']
	ql.patch(addr, ins)
