Run the program


![](https://hackmd.io/_uploads/SJFmkBmhh.png)

It prompts a menu, looks like a heap challenge

## Decompile the program

`main`

```cpp=
void __fastcall __noreturn main(char *choice_, char **a2, char **a3)
{
  char choice[8]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  setvbuf__();
  while ( 1 )
  {
    menu();
    read(0, choice, 4uLL);
    switch ( (unsigned int)strtol(choice, 0LL, 10) )
    {
      case 1u:
        raise_flower();
        break;
      case 2u:
        visit_garden();
        break;
      case 3u:
        clear_1_free_name();
        break;
      case 4u:
        clear_arr_free_flower();
        break;
      case 5u:
        puts("See you next time.");
        exit(0);
      default:
        puts("Invalid choice");
        break;
    }
  }
}
```

`raise_flower`

```cpp=
int raise_flower()
{
  _QWORD *flower; // rbx
  void *name; // rbp
  _QWORD *v2; // rcx
  unsigned int v3; // edx
  _DWORD size[9]; // [rsp+4h] [rbp-24h] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  size[0] = 0;
  if ( flower_count > 0x63u )
    return puts("The garden is overflow");
  flower = malloc(0x28uLL);
  *flower = 0LL;
  flower[1] = 0LL;
  flower[2] = 0LL;
  flower[3] = 0LL;
  flower[4] = 0LL;
  __printf_chk(1LL, "Length of the name :");
  if ( (unsigned int)__isoc99_scanf("%u", size) == -1 )
    exit(-1);
  name = malloc(size[0]);
  if ( !name )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  __printf_chk(1LL, "The name of flower :");
  read(0, name, size[0]);
  flower[1] = name;
  __printf_chk(1LL, "The color of the flower :");
  __isoc99_scanf("%23s", flower + 2);
  *(_DWORD *)flower = 1;
  if ( arr[0] )
  {
    v2 = &arr[1];
    v3 = 1;
    while ( *v2 )
    {
      ++v3;
      ++v2;
      if ( v3 == 100 )
        goto LABEL_13;
    }
  }
  else
  {
    v3 = 0;
  }
  arr[v3] = flower;
LABEL_13:
  ++flower_count;
  return puts("Successful !");
}
```

* Basically it will require a `name size` and call `malloc` with that size to store name, create a struct and store that struct in an array
* The flower struct will be like

```
int bool;
char *name;
char color[23];
```

* The `array` store the pointers to `flower` struct which is returned by `malloc`
* The `bool` field is initialized as 1

`visit_garden` function

```cpp=
int visit_garden()
{
  __int64 i; // rbx
  __int64 flower; // rax

  i = 0LL;
  if ( flower_count )
  {
    do
    {
      flower = arr[i];
      if ( flower && *(_DWORD *)flower )
      {
        __printf_chk(1LL, "Name of the flower[%u] :%s\n", (unsigned int)i, *(const char **)(flower + 8));
        LODWORD(flower) = __printf_chk(
                            1LL,
                            "Color of the flower[%u] :%s\n",
                            (unsigned int)i,
                            (const char *)(arr[i] + 16LL));
      }
      ++i;
    }
    while ( i != 100 );
  }
  else
  {
    LODWORD(flower) = puts("No flower in the garden !");
  }
  return flower;
}
```

* It iterates the `array` then check if `bool` field is not `NULL` to print out the `name` and `color`

`remove_flower` function

```cpp=
int clear_1_free_name()
{
  _DWORD *flower; // rax
  unsigned int i; // [rsp+4h] [rbp-14h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( !flower_count )
    return puts("No flower in the garden");
  __printf_chk(1LL, "Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &i);
  if ( i <= 0x63 && (flower = (_DWORD *)arr[i]) != 0LL )
  {
    *flower = 0;
    free(*(void **)(arr[i] + 8LL));
    return puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    return 0;
  }
}
```

* It requires an index the check if that index in `array` is not `NULL` to `free` the `name` field
* It doesn't check if the `name` was `freed` so there's `double-free` vulnerability

`clean_garden` function


```cpp=
unsigned __int64 clear_arr_free_flower()
{
  _QWORD *pflower; // rbx
  _DWORD *flower; // rdi
  unsigned __int64 v3; // [rsp+8h] [rbp-20h]

  v3 = __readfsqword(0x28u);
  pflower = arr;
  do
  {
    flower = (_DWORD *)*pflower;
    if ( *pflower && !*flower )
    {
      free(flower);
      *pflower = 0LL;
      --flower_count;
    }
    ++pflower;
  }
  while ( pflower != &arr[100] );
  puts("Done!");
  return __readfsqword(0x28u) ^ v3;
}
```

* It interates the `array` and check if `name` field is `freed` (check if `bool` is `0` or not) to `free` the struct then zero out the `array`

## Exploit

### Leak heap

* To leak heap, first i trigger `double-free`, `malloc` `2` chunks then `free`

```python=
remove_flower(0)
remove_flower(1)
remove_flower(0)
```

Check in heap bins

![](https://hackmd.io/_uploads/By5UgH7nn.png)

We see that there's a loop in fastbin

* Now i `malloc` `3` chunks so `2` chunks will have the same `name` pointer, `free` a `name` and print it by another struct, i get the heap

### Leak libc

* To leak libc i use unsorted bin, abuse fastbin to fake the flower struct pointing to unsorted bin
* In a color `field` of a chunk i make it like

```
offset      0           8           0x10
                       0|           0x71|
```

* Abuse fastbin to point to that field

![](https://hackmd.io/_uploads/B1pXmBmn3.jpg)

After overwriting

![](https://hackmd.io/_uploads/SymI7BQhh.png)


Now we see that it points to libc and the `bool` field is not `0`

* Print the garden then i get libc


### Write to hook

* After get libc now i write `one_gadget` to `__malloc_hook`, but there's problem that there's no gadgets that i can meet the constraints so i write `realloc + n` to `__malloc_hook` and write `one_gadget` to `__realloc_hook`

![](https://hackmd.io/_uploads/SkE-9BXn3.png)

* `__malloc_hook` point to somewhere here(not the start) in `realloc` which can satisfy the constraints of `one_gadget`

Aftet that i get a shell

![](https://hackmd.io/_uploads/SyTfjHXh2.png)
