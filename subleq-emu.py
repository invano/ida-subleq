import sys
import struct
import string

code = []

def dispatch(a, b, c):
    code[b] = (code[b] - code[a])&0xffff
    code[b] = code[b] - 65536 if code[b] > 32767 else code[b]
    
    if c != 0:
        return code[b] <= 0
    else:
        return False


def exec_vm(entry, size):
    pc = entry
    while pc + 3 <= size:
        if dispatch(code[pc], code[pc+1], code[pc+2]):
            if code[pc+2] == -1:
                return
            pc = code[pc+2]
        
        else:
            pc += 3

        if code[4] == 1:
            code[4] = 0
            sys.stdout.write(chr(code[2]))
            code[2] = 0
        if code[3] == 1:
            code[3] = 0
            code[1] = ord(sys.stdin.read(1))

def subleq(fin, key=None):
    with open(fin, "rb") as f:
        dd = f.read()
    
    for i in range(0, len(dd), 2):
        code.append(struct.unpack("<h", dd[i:i+2])[0])
    
    if key:
        for i in range(len(key)):
            code[0x904+i] = ord(key[i])
    
    exec_vm(5, len(dd))

if __name__ == '__main__':
    flag = " Av0cad0_Love_2018@flare-on.com"
    subleq(sys.argv[1], flag)
