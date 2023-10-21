Kiểm tra 2 file mà chương trình cho

![](https://hackmd.io/_uploads/B1nw6Drc3.png)

Chương trình này sử dụng `glibc 2.23`

![](https://hackmd.io/_uploads/r19cTDrcn.png)


Khởi chạy chương trình thì chương trình không in gì ra mà chỉ nhận `1` input rồi kết thúc

![](https://hackmd.io/_uploads/HyS0pwr92.png)


Kiểm tra assembly của chương trình 

```
Dump of assembler code for function main:
   0x0000000000400536 <+0>:	push   rbp
   0x0000000000400537 <+1>:	mov    rbp,rsp
   0x000000000040053a <+4>:	sub    rsp,0x10
   0x000000000040053e <+8>:	lea    rax,[rbp-0x10]
   0x0000000000400542 <+12>:	mov    rdi,rax
   0x0000000000400545 <+15>:	mov    eax,0x0
   0x000000000040054a <+20>:	call   0x400430 <gets@plt>
   0x000000000040054f <+25>:	mov    eax,0x0
   0x0000000000400554 <+30>:	leave  
   0x0000000000400555 <+31>:	ret    
End of assembler dump.

```

Như vậy chương trình sử dụng hàm `gets` với đầu vào là `rbp - 0x10`

Checksec 

![](https://hackmd.io/_uploads/SydV0Drq2.png)

Ta thấy chương trình không sử dụng `stack canary` vậy thì có thể sử dụng bug buffer overflow

`PIE` không được bật vậy nên ta có thể điều hướng đến bất cứ đâu trong chương trình, `RelRO` là `Full` vậy nên không thể viết vào `GOT` của các hàm

Với hàm `gets` của `glibc 2.23` 

```cpp=
gets (char *__str)
{
  if (__bos (__str) != (size_t) -1)
    return __gets_chk (__str, __bos (__str));
  return __gets_warn (__str);
}
```
`__bos` ở đây chỉ là 1 hàm để tính độ dài của string nằm trên địa chỉ chúng ta pass cho `gets`

Nếu độ dài khác `-1` thì nó sẽ gọi `__getschk`

```cpp=
char *
__gets_chk (char *buf, size_t size)
{
  _IO_size_t count;
  int ch;
  char *retval;

  if (size == 0)
    __chk_fail ();

  _IO_acquire_lock (_IO_stdin);
  ch = _IO_getc_unlocked (_IO_stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
	 non-blocking mode. The error flag doesn't mean much in this
	 case. We return an error only when there is a new error. */
      int old_error = _IO_stdin->_IO_file_flags & _IO_ERR_SEEN;
      _IO_stdin->_IO_file_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (_IO_stdin, buf + 1, size - 1, '\n', 0) + 1;
      if (_IO_stdin->_IO_file_flags & _IO_ERR_SEEN)
	{
	  retval = NULL;
	  goto unlock_return;
	}
      else
	_IO_stdin->_IO_file_flags |= old_error;
    }
  if (count >= size)
    __chk_fail ();
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (_IO_stdin);
  return retval;
}
```

`_IO_acquire_lock` chỉ đơn giản set `*lock = NULL`

Về hàm `_IO_getc_unlocked`
```cpp=
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

`_IO_BE` đơn giản là 1 ` __builtin_expect`

Nếu điều kiện đúng thì gọi `__uflow`, nó gọi đến `__uflow` ở trong `vtable`
Cơ bản thì nó sẽ khởi tạo buffer trên heap nếu `fp->_IO_buf_base = NULL` và set up các con trỏ đọc, ghi trên `struct _IO_FILE`

Ta chú ý hàm ` _IO_getline (_IO_stdin, buf + 1, size - 1, '\n', 0)`

```cpp=
_IO_getline (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
	     int extract_delim)
{
  return _IO_getline_info (fp, buf, n, delim, extract_delim, (int *) 0);
}
```

Nó gọi đến ` _IO_getline_info`

```cpp=
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	  if (c == EOF)
	    {
	      if (eof)
		*eof = c;
	      break;
	    }
	  if (c == delim)
	    {
 	      if (extract_delim > 0)
		*ptr++ = c;
	      else if (extract_delim < 0)
		_IO_sputbackc (fp, c);
	      if (extract_delim > 0)
		++len;
	      return ptr - buf;
	    }
	  *ptr++ = c;
	  n--;
	}
      else
	{
	  char *t;
	  if ((_IO_size_t) len >= n)
	    len = n;
	  t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
	  if (t != NULL)
	    {
	      _IO_size_t old_len = ptr-buf;
	      len = t - fp->_IO_read_ptr;
	      if (extract_delim >= 0)
		{
		  ++t;
		  if (extract_delim > 0)
		    ++len;
		}
	      memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	      fp->_IO_read_ptr = t;
	      return old_len + len;
	    }
	  memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	  fp->_IO_read_ptr += len;
	  ptr += len;
	  n -= len;
	}
    }
  return ptr - buf;
```

Nó gọi `__uflow` để đọc các bytes trên buffer cho tới khi gặp `delim`(ở đây được pass là `\n`) rồi từ đấy cắt đoạn đó ra từ buffer rồi dùng `memcpy` để copy vào `ptr` ở đây là input ta pass cho hàm `gets` cuối cùng set cuối string là `NULL`

Tóm lại chúng ta có thể sử dụng `NULL` byte ở đây mà không bị ngắt(hàm chỉ ngắt tại newline`0xa`)
Với bài này thì chúng ta chỉ cần có libc rồi tạo rop chain là có thể gọi được shell

## leak libc

Ở đây mình sử dụng 1 vài gadgets ở `__libc_csu_init` đó là 

```
   0x00000000004005a0 <+64>:	mov    rdx,r13
   0x00000000004005a3 <+67>:	mov    rsi,r14
   0x00000000004005a6 <+70>:	mov    edi,r15d
   0x00000000004005a9 <+73>:	call   QWORD PTR [r12+rbx*8]
```

và

```
   0x00000000004005ba <+90>:	pop    rbx
   0x00000000004005bb <+91>:	pop    rbp
   0x00000000004005bc <+92>:	pop    r12
   0x00000000004005be <+94>:	pop    r13
   0x00000000004005c0 <+96>:	pop    r14
   0x00000000004005c2 <+98>:	pop    r15
   0x00000000004005c4 <+100>:	ret    
```

* Với gadget `call   QWORD PTR [r12+rbx*8]` nếu ta có địa chỉ libc ở `r12` hoặc `rbx` thì có thể coi đó là con trỏ hàm trỏ đến 1 hàm trong libc
* Ở đây mình sử dụng con trỏ hàm nằm trong `vtable` của `_IO_FILE_plus` structure

```
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

* Cụ thể là trỏ đến phần `__write` của table này

Sau khi sử dụng hàm `gets` thì trên stack còn sót lại 1 vài địa chỉ của libc

![](https://hackmd.io/_uploads/rkZW-drc3.png)


Nhưng mà mình không leak được stack để có thể pop được `rsp` về đó

* Nên ở đây mình sử dụng stack pivot, pop `rsp` về địa chỉ trên `bss` của chương trình, rồi pop `r12` ta được địa chỉ libc


Sau khi có được libc trên `r12`

![](https://hackmd.io/_uploads/ByKbIdr92.png)

* `r12` có giá trị bé hơn giá trị chúng ta muốn trỏ đến `IO_file_jumps + 120`, ở đây chỉ cần cho nó cộng thêm 1 số lớn hơn để lật cái bit cuối lên là được

![](https://hackmd.io/_uploads/Bkl_Lur9n.png)

* Vậy ở đây ta pass cho `rbx` là `0x1ffffffffffffdeb`

* Lưu ý sau gadget `call   QWORD PTR [r12+rbx*8]` là

```
   0x00000000004005ad <+77>:	add    rbx,0x1
   0x00000000004005b1 <+81>:	cmp    rbx,rbp
   0x00000000004005b4 <+84>:	jne    0x4005a0 <__libc_csu_init+64>

```

* Chúng ta không muốn thực hiện lệnh `jump` này nên `rbp` phải bằng `rbx + 1`

Rồi giờ đây chúng ta có thể gọi được `__IO_file_write`

Nhìn vào source code

```cpp=
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      _IO_ssize_t count = (__builtin_expect (f->_flags2
					     & _IO_FLAGS2_NOTCANCEL, 0)
			   ? write_not_cancel (f->_fileno, data, to_do)
			   : write (f->_fileno, data, to_do));
      if (count < 0)
	{
	  f->_flags |= _IO_ERR_SEEN;
	  break;
	}
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```

Tham số của nó là 1 `_IO_FILE` structure, `data` là con trỏ để hàm này write, `n` là số bytes nó in ra

Ở đây nó check `f->_flags2 & _IO_FLAGS2_NOTCANCEL`

>#define _IO_FLAGS2_NOTCANCEL 2

Để gọi `write_not_cancel` hoặc `write` với tham số ban đầu là `f->_fileno` (file descriptor)

Nhưng mà ta thấy

```cpp=
#define write_not_cancel(fd, buf, n) \
  __write (fd, buf, n)
```

```cpp=
# define write(FD, Buf, NBytes) __write (FD, Buf, NBytes)
```

* Nó đều call `__write` với cùng tham số :))) nên cái `_flags2` có là `2` hay không cũng đều sẽ in ra `data`
* Quan trọng là `f->_fileno` của chúng ta phải là `1` (stdout) để in ra màn hình
* Bài này không nhất thiết phải fake hẳn 1 cái FILE structure mà chỉ cần pass cho hàm `__IO_file_write` 1 con trỏ mà thỏa `*(pointer + 0x70) = 1` là được
* Sau khi có libc rồi thì mình tạo cái `ROPchain` cuối rồi gọi shell thôi

Ở đây mình lười sửa code nên để nguyên cái fake file struct đấy

Về idea thì đầu tiên là stack pivot `rsp` về địa chỉ của `bss` cho nó chạy 1 lần `main` rồi chúng ta có được vài địa chỉ libc còn xót lại trên đó rồi stack pivot lần nữa để pop giá trị libc vào `r12`, cứ thế vì biết giá trị của `rsp` khi đến câu lệnh `ret` thì chỉ cần viết `ROPchain` vào đó là được
