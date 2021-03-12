from capstone import Cs
import capstone
import binascii
import hashlib
import os
import csv
from sys import argv


address = []
instr = []
names = []


def filter_memory_references(i, symbols, API, symbolic_call=True):
    inst = "" + i.mnemonic
    for op in i.operands:
        if (op.type == 1):
            inst = inst + " " + i.reg_name(op.reg)
        elif (op.type == 2):
            inst_int = binascii.hexlify(i.bytes).decode("utf-8")
            imm = op.imm
            symbol = 'SIMBOLNOEXISTENT'
            if imm in symbols:
                symbol = str(symbols[imm])
            if inst == 'call' and symbol in API and symbolic_call:
                inst = inst + " " + symbol
            elif (-int(5000) <= imm <= int(5000)):
                inst = inst + " " + str(hex(op.imm))
            else:
                #pass
                inst = inst + " " + str('HIMM')
        elif (op.type == 3):
            mem = op.mem
            if (mem.base == 0):
                r = "[" + "MEM" + "]"
            else:
                r = '[' + str(i.reg_name(mem.base)) + "*" + str(mem.scale) + "+" + str(mem.disp) + ']'
            inst = inst + " " + r
        if (len(i.operands) > 1):
            inst = inst + ","
    if "," in inst:
        inst = inst[:-1]
    inst = inst.replace(" ", "_")
    return str(inst)


def constantIndependt_hash(function1):
    string = ""
    for ins1 in function1:
        capstone_ins1 = ins1
        string = string + "<" + str(capstone_ins1.mnemonic)
        for op in capstone_ins1.operands:
            if (op.type == 1):
                string = string + ";" + str(op.reg)
        string = string + ">"
    m = hashlib.sha256()
    m.update(string.encode('UTF-8'))
    return m.hexdigest()


def filter_asm_and_return_instruction_list(address, asm, symbols, arch, API, symbolic_call=True):
    #n = int(asm, 2)
    binary = binascii.unhexlify(asm)
    #binary = binascii.unhexlify('%x' % n)
    #binary = asm
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    # md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == capstone.CS_ARCH_ARM:
        md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns = []
    cap_insns = []
    for i in md.disasm(binary, address):
        insns.append(filter_memory_references(i, symbols, API, symbolic_call=symbolic_call))
        cap_insns.append(i)
    del md
    return (constantIndependt_hash(cap_insns), insns)
    

def fetch_symbols():
	symbols_file = os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp", "symbols.csv")
	with open(symbols_file) as f:
		r = csv.reader(f)
		d = {int(row[0],16): row[1] for row in r}
		#print(d)
		#for i in d.keys():
		#print(type(i))
	return d


def __load_libc_API_unix():
    try:
    	libc_unix_file = os.path.join(os.path.expanduser("~"), "plugin_ghidra", "libc_unix.txt")
        with open(libc_unix_file, 'r') as f:
            api_sym = set([x.rstrip() for x in f.readlines()])
    except:
        print('failed to load api symbols list... everything will be unnamed')
        api_sym = set([])
        
    return api_sym

def build():
    temp_file = str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp", "temp.csv"))
    with open(temp_file, "r") as t:
    	r = csv.reader(t)
    	for row in r:
    	    names.append(row[1])
    	    address.append(int(row[0], 16))
    	    
    for n in names:
    	func_file = str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp", n+".bin"))
    	with open(func_file, "rb") as f:
    	    inst = binascii.hexlify(f.read())
    	    instr.append(inst)

    return
	

def filter_and_write_to_file():
    filtered_file = str(os.path.join(os.path.expanduser("~"), ".config", "plugin", "temp", "filtered.asm"))
    symbols = fetch_symbols()
    api = __load_libc_API_unix()
    with open(filtered_file, "w") as f:
        for i in range(len(address)):
            t = filter_asm_and_return_instruction_list(address[i], instr[i], symbols, capstone.CS_ARCH_X86, api, symbolic_call=True)
            l = t[1]
            for ii in range(len(l)):
                if ii == len(l)-1:
                    s = "X_"+l[ii]
                    f.write(s)
                    print("\n", file = f, end = "")
                else:
                    s = "X_"+l[ii]
                    f.write(s+" ")
        print(l)
        #print("\n", file = f, end = "")
        
    return
    

build()
filter_and_write_to_file()
