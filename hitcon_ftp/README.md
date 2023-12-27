# HITCON_FTP

* In this challenge, the program use some function like `msgpack...`, after searching i found that they're function of `msgpack`. You can read from [here](https://github.com/msgpack/msgpack-c)
* So to send the right format packet to challenge i use `msgpack` module of python

![Screenshot 2023-12-27 214002](https://hackmd.io/_uploads/B1fnPhKv6.png)

* In here it does some check about the type of unpacked data. `6` here might be a list, i don't read the source code of `msgpack` so i'm not sure but sending a packed list will be okay
* So next the `find_request` function. It just checks the `ip` and `port` to select request. If no request then return `NULL`
* The program handler ftpp request at `process_new`. Here we have `2` options in that function with opcode respectively `1` and `2`
* `1` we can read a file with a filepath we choose. The function filters absolute path and backtrace so we cannot read `flag`
* `2` the program open `/dev/null`
* Oh and you will see some `if` condition like this. That's for checking data type

```
2 for interger
5 for string
8 for bytes
```

* Here's the `request` struct i defined

![Screenshot 2023-12-27 214952](https://hackmd.io/_uploads/ByV2FntPa.png)

## BUGS

* The program has many bugs
* First in `process_new` function

![Screenshot 2023-12-27 215139](https://hackmd.io/_uploads/HkWG9nYPa.png)

* `file_name` field occupies `0x100` bytes in struct and we can pass `0x100` bytes to that and `strncpy` will not append `NULL` byte at the end if the lenght of copied string >= size of buffer

![Screenshot 2023-12-27 215511](https://hackmd.io/_uploads/ryGksntv6.png)

* Put some `../` on the `file_name` so we can leak `_IO_FILE` field which is heap address

* The second bug in `process_new` is it doesn't check type

![Screenshot 2023-12-27 215804](https://hackmd.io/_uploads/BkeisnKva.png)

* I think it should be a struct, but the function only check if `no_element > 0` so we can control all the struct
* The `0x10` field is a pointer and the data it points to will be copied to a global variable of binary then after will be sent to client by `send_oack` function
* We have heap so we can pass some head address pointing to some libc, after that we can leak everything

* Last bug in `main` at option `3`, in `check_crc32` function it calls `msgpack_object_print_buffer`
* The first argument is `&request.error_code` which is a stack address
* We can only pass string or bytes to that program so we can only use `2` option in `msgpack_object_print_buffer`
* When we pass string which is `5`

![Screenshot 2023-12-27 220502](https://hackmd.io/_uploads/BJaQ63FwT.png)

* `s` here is a stack address, `a9` here is a pointer to a string we send to. So here we get a `BOF`. So we just build ropchain and we win
* Notice when we send bytes, it will be different

![Screenshot 2023-12-27 220711](https://hackmd.io/_uploads/BJ73T3tDp.png)

* It will write some `\x` characters not the byte itself so we must use opcode `5`
* But the payload is byte type and we cannot decode them so i use a trick here

![Screenshot 2023-12-27 213517](https://hackmd.io/_uploads/B1rW03Kv6.png)

* Pack the payload and replace `\xc5` to `\xda` and it will be okay. Don't know any professional way to do that instead
* `main` function is in a `while(1)` loop, it only breaks if `select` function fails. A signal will cause it to fail. After `60s` a sig alarm will interupt so we can run our ropchain
