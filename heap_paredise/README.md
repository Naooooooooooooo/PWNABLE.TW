# HEAP PARADISE


Run the program and we see that it's a heap challenge

![](https://hackmd.io/_uploads/ryxYtS932.png)

## Decompile program

Checksec

![](https://hackmd.io/_uploads/SJTRtr92h.png)

`main` function

```cpp=
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  __int64 choice; // rax

  setbuf();
  while ( 1 )
  {
    while ( 1 )
    {
      menu(a1, a2);
      choice = get_choice();
      if ( choice != 2 )
        break;
      free_();
    }
    if ( choice == 3 )
      exit(0);
    if ( choice == 1 )
    {
      malloc_();
    }
    else
    {
      a1 = "Invalid Choice !";
      puts("Invalid Choice !");
    }
  }
}
```

It prints the menu and gets input from user

`malloc` function

```cpp=
int malloc_()
{
  unsigned __int64 size_; // rax
  int i; // [rsp+4h] [rbp-Ch]
  unsigned int size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      LODWORD(size_) = puts("You can't allocate anymore !");
      return size_;
    }
    if ( !arr[i] )
      break;
  }
  printf("Size :");
  size_ = get_choice();
  size = size_;
  if ( size_ <= 0x78 )
  {
    arr[i] = malloc(size_);
    if ( !arr[i] )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Data :");
    LODWORD(size_) = readdata(arr[i], size);
  }
  return size_;
}
```

* First it iterates an array, checking if the element is `NULL` then break
* Seems like we can only allocate `16` chunks
* The `size` of chunk we `malloc` must be less than or equal `0x78` so we can't allocate to get unsorted bin

`free` function

```cpp=
void free_()
{
  __int64 index; // [rsp+8h] [rbp-8h]

  printf("Index :");
  index = get_choice();
  if ( index <= 15 )
    free(*((void **)&arr + index));
}
```

* The function get an index then `free` the element with that index in `array`
* It doesn't clean the element in array after free so there's `double-free` bug here

## Exploit

### FSOP

* We can't allocate a big chunk to get unsorted bin so i have to fake a chunk in heap and we can't print the data of heap in this challenge
* Here i fake the `_IO_FILE` structure to leak libc by `puts` function

Here's the structure of `_IO_FILE`

```cpp=
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

The `puts` function

```cpp=
int
_IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}

#ifdef weak_alias
weak_alias (_IO_puts, puts)
```
* `weak_alias` is a `define` so when we call `puts` the program calls `_IO_puts`

We see that it calls `_IO_sputn`

```cpp=
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count);
      f->_IO_write_ptr += count;
#endif
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}

      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```

* Notice at line `50` there's `if(to_do + must_flush > 0)`. `to_do` is equal to the length of strings passed to `puts` and `must_flush` is a boolean (`1` or `0`) so the `if` statement is `true`. The program will call `_IO_OVERFLOW`

```cpp=
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
```

* It first check if the flag `_IO_NO_WRITES` is set to terminate the program so that flag must not be set

```cpp=
#define _IO_NO_WRITES 8 /* Writing not allowd */
```
* We don't want the `if` statement in line `11` to be true so i don't set that flag and the `_IO_write_base` is not `NULL`
* In line `46` the argument for `ch` is `EOF` so the program will call `_IO_do_write` with arguments are `_IO_write_base` and `_IO_write_ptr - _IO_write_base`

```cpp=
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

* The `if` statement in line `14`, the program will go to inside the `if` or inside the `else if` since `_IO_read_end != _IO_write_base`. The `else if` block will ruin every thing so i set `_IO_IS_APPENDING` flag

```cpp=
#define _IO_IS_APPENDING 0x1000
```
* Then the program call `_IO_SYSWRITE`

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
* It checks the `flag2` to call `write_not_cancel` or `write`. They both call `write` syscall. Remember the argument is `_IO_write_base`

![](https://hackmd.io/_uploads/rJJybIchn.png)

* I overwrite the least significant byte of `_IO_write_base` field to leak libc
* So to leak libc i craft some first fields of `_IO_2_1_stdout_` structure

```
flag = 0xfbad0000 | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING
Overwrite least significant byte of _IO_write_base
```
### Unsorted bin

* I create a fake structure in heap that has a `size` field larger enough to be put into unsorted bn
* I use the double-free to overwrite `fd` pointer of fastbin to redirect to fake chunk

![](https://hackmd.io/_uploads/SyIc4Uqhn.png)

* I craft the fake `size` field to `0x91` so then `free` it to get unsorted bin
* So now i have libc address on heap, i overwrite some first bytes of that then use fastbin attack to overwrite `stdout`
* I use fastbin attack to write to `stdout`. Before `stdout` structure there's a valid chunk size to put into fastbin

![](https://hackmd.io/_uploads/HkLIMLqh3.png)

After overwrite `stdout`, then the call to `puts` function

![](https://hackmd.io/_uploads/rklEHUcn2.png)

So i have libc

### Write to __malloc_hook

* After get libc, i use fastbin attack to write to `__malloc_hook` with `one_gadget`
* Then i get a shell

![](https://hackmd.io/_uploads/H1_3rLq22.png)

