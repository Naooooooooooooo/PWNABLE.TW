# OMEGAGO

Run the binary 

![](https://hackmd.io/_uploads/Bylx9zqmT.png)

At first, i thought this is a tic tac toe game, but after searching omegago, i found out that this program is a program to play `Go`

Checksec

![](https://hackmd.io/_uploads/SyzP9z9X6.png)


## Reverse

The program is written in `c++` so it's kinda hard to reverse

`main` function

![Screenshot 2023-11-09 153919.png](https://hackmd.io/_uploads/HJ0T5f97p.png)


It just calls `setvbuf`, the actual program is at `main_loop`


`main_loop`

```cpp=
bool main_loop()
{
  _QWORD *ptr; // rbx
  _QWORD *ptr2; // rbx
  int num; // [rsp+Ch] [rbp-64h] BYREF
  int chr; // [rsp+10h] [rbp-60h] BYREF
  unsigned int bot_time; // [rsp+14h] [rbp-5Ch]
  double v6; // [rsp+18h] [rbp-58h]
  struct timeval tv; // [rsp+20h] [rbp-50h] BYREF
  struct timeval v8; // [rsp+30h] [rbp-40h] BYREF
  __int64 canary[6]; // [rsp+40h] [rbp-30h]

  canary[3] = __readfsqword(0x28u);
  init_0();
  bot_time = 1;
  ptr = (_QWORD *)operator new(8uLL);
  *ptr = 0LL;
  set_ptr_0x405040(ptr);                        // *ptr = 0x405040
  canary[0] = (__int64)ptr;
  ptr2 = (_QWORD *)operator new(8uLL);
  *ptr2 = 0LL;
  set_ptr_0x405020(ptr2);                       // *ptr2 = 0x405020
                                                // get choice function
  canary[1] = (__int64)ptr2;
  while ( (unsigned __int8)check_not_full(bot_time, &game_state) == 1 )
  {
    gettimeofday(&tv, 0LL);
    (**(void (__fastcall ***)(__int64, Game_State *, _QWORD, int *, int *))canary[bot_time - 1])(
      canary[bot_time - 1],
      &game_state,
      bot_time,
      &num,
      &chr);
    gettimeofday(&v8, 0LL);
    v6 = (double)(LODWORD(v8.tv_usec) - LODWORD(tv.tv_usec)) / 1000000.0
       + (double)(LODWORD(v8.tv_sec) - LODWORD(tv.tv_sec));
    if ( num == -1 || chr == -1 )               // surrender
      break;
    if ( num == -2 || chr == -2 )               // regret
    {
      if ( (unsigned __int8)backup() != 1 )
        puts_then_exit("No you cant't");
    }
    else
    {
      *((double *)&game_state.bot_time + (int)(bot_time - 1)) = *((double *)&game_state.bot_time + (int)(bot_time - 1))
                                                              - v6;
      if ( *((double *)&game_state.bot_time + (int)(bot_time - 1)) < 0.0 )
        puts_then_exit("Time's up");
      play(&game_state, num, chr, bot_time, 0);
      bot_time ^= 3u;
    }
  }
  count_XO();
  ask_view_history();
  return again_();
}
```

First is `init_0` function

```cpp=
unsigned __int64 init_0()
{
  int i; // [rsp+0h] [rbp-20h]
  int j; // [rsp+4h] [rbp-1Ch]
  int k; // [rsp+8h] [rbp-18h]
  int m; // [rsp+Ch] [rbp-14h]
  FILE *rand_fd; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  rand_fd = fopen("/dev/urandom", "rb");
  for ( i = 0; i <= 18; ++i )
  {
    for ( j = 0; j <= 18; ++j )
    {
      for ( k = 0; k <= 2; ++k )
      {
        if ( fread(&array_rand[57 * i + 3 * j + k], 1uLL, 8uLL, rand_fd) != 8 )
          puts_then_exit("WT..");
      }
    }
  }
  fclose(rand_fd);
  for ( m = 0; m < play_time; ++m )
  {
    operator delete(*(&history + m));
    *(&history + m) = 0LL;
  }
  init_some_field_2((__int64)&obj1);
  play_time = 0;
  init_some_field_0((__int64)&game_state);
  return __readfsqword(0x28u) ^ v6;
}
```

It opens `/dev/random` and read data from that to `array_rand`

Next it `delete` the `history` array, this array is for saving the game state, we will see about that later

`init_some_field_2` funciton

![Screenshot 2023-11-09 154358.png](https://hackmd.io/_uploads/HJ1yhzcQp.png)

It sets up some field of `obj1`, but i don't know what `obj1` is for

It sets `play_time = 0`, good since it clears the `history` array before so there's no bug here

```cpp=
init_some_field_0((__int64)&game_state);
```

Inits some field of `game_state`

![Screenshot 2023-11-09 154553.png](https://hackmd.io/_uploads/SJJ_3fq76.png)


Our current state is stored at a global variable called `game_state`

I defined the struct of `game_state`

```cpp=
size_t board[12];
int x;
int y;
size_t current_character;
size_t bot_time;
size_t player_time;
```

That's done for `init_0` function

Next in `main_loop`

![Screenshot 2023-11-09 154959.png](https://hackmd.io/_uploads/By4IaGqXp.png)

It sets some `canary` array element

`canary[3]` is for canary

`malloc` 2 chunk and you can see the comment for `set_ptr` function

See the `0x405040` and `0x405020` in ida

![Screenshot 2023-11-09 155320.png](https://hackmd.io/_uploads/rJAMCM97a.png)

They're vtable for `2` class `Human` and `AI` with `2` function on that is `get_choice` and `get_bot_coordinates`

They will be used later

Next in `main_loop`

```cpp=
while ( (unsigned __int8)check_not_full(bot_time, &game_state) == 1 )
```

`check_not_full` function

![Screenshot 2023-11-09 155540.png](https://hackmd.io/_uploads/rya9Cfq76.png)

So the table for the game is `19x19`, it iterates all element in board

`get_ele` function

![Screenshot 2023-11-09 155653.png](https://hackmd.io/_uploads/SkUkkX9ma.png)

It converts the coordinates to an index and pass it to `get_index_for_XO` function

![Screenshot 2023-11-09 155754.png](https://hackmd.io/_uploads/H1GQJXqXa.png)

To be simple, it returns the `index & 0x3f` bit of `board[index >> 6]` of `game_state`

The index after will be used to be an index for `XO_` array

![Screenshot 2023-11-09 155939.png](https://hackmd.io/_uploads/SkoYy797p.png)

In conclusion, the `board` will be stored using bits, `2` bits are for a element on board printed

```
00 -> .
01 -> O
10 -> X
11 -> \x00
```

So `get_ele` will return the character at a position on board

Next is `play` function

Notice that last argument is `0` ^^

```cpp=
__int64 __fastcall play(Game_State *game_state, int x_1, int y_1, int bot_turn, char not_save)
{
  int chr; // eax
  bool invalid; // al
  Game_State *v8; // rax
  int chr_1; // [rsp+Ch] [rbp-44h]
  int i; // [rsp+24h] [rbp-2Ch]
  unsigned int x; // [rsp+28h] [rbp-28h]
  unsigned int y; // [rsp+2Ch] [rbp-24h]
  Game_State *state; // [rsp+30h] [rbp-20h]

  if ( (unsigned __int8)get_ele(game_state, x_1, y_1) == '.' )
  {
    if ( bot_turn == 1 )
      chr = 'O';
    else
      chr = 'X';
    chr_1 = chr;
    set_XO_in_board(game_state, x_1, y_1, chr);
    game_state->x = x_1;
    game_state->y = y_1;
    for ( i = 0; i <= 3; ++i )                  // check all direction
    {
      x = x_direction[i] + x_1;
      y = y_direction[i] + y_1;
      invalid = !is_valid_coordinate(x) || !is_valid_coordinate(y);// check if <= 18
      if ( !invalid
        && (char)get_ele(game_state, x, y) == 0xA7 - chr_1// check if the other
        && !(unsigned int)get_libertys((__int64)game_state, x, y) )// check if close
      {
        set_dots((__int64)game_state, x, y);
      }
    }
    if ( (unsigned int)get_libertys((__int64)game_state, x_1, y_1) )
    {
      if ( (unsigned __int8)check_ko((__int64)game_state, not_save) )
      {
        if ( !not_save )
          puts_then_exit("Wanna Ko Fight?");
        return 0LL;
      }
      else
      {
        if ( not_save != 1 )                    // save
        {
          LODWORD(game_state->current_chr) = chr_1;
          v8 = (Game_State *)operator new(0x80uLL);
          *v8 = *game_state;
          state = v8;
          LODWORD(v8) = play_time++;
          (&history)[(int)v8] = (size_t *)state;// set history
        }
        return 1LL;
      }
    }
    else
    {
      if ( !not_save )
        puts_then_exit("Why you do this :((");
      return 0LL;
    }
  }
  else
  {
    if ( !not_save )
      puts_then_exit("You cheater!");
    return 0LL;
  }
}
```

First check if a position is `.`, if not then return `0`, and if the `not_save` is not set the program will `exit`

The program will set `X` or `O` on board by `bot_turn` argument

`set_XO_in_board` function

![Screenshot 2023-11-09 160552.png](https://hackmd.io/_uploads/rJCZbQc7T.png)

![Screenshot 2023-11-09 160556.png](https://hackmd.io/_uploads/SyzfWQ97p.png)

![Screenshot 2023-11-09 160601.png](https://hackmd.io/_uploads/HJUf-Xcmp.png)

Basically it just sets bits of `board` member for the corresponding character

![Screenshot 2023-11-09 160832.png](https://hackmd.io/_uploads/S1zibmcXT.png)

The function sets up `x`, `y` member then iterate all near position using `x_direction` and `y_direction` array

![Screenshot 2023-11-09 160947.png](https://hackmd.io/_uploads/H1jkGX57a.png)

According to `go` game when it runs out of libertys then the node will be cleared

Example

Before 

![Screenshot 2023-11-09 161230.png](https://hackmd.io/_uploads/SJEqM75mT.png)

After

![Screenshot 2023-11-09 161236.png](https://hackmd.io/_uploads/SJtcGXqmT.png)

If there's liberty then it won't clear anything

Next it checks for ko rule
![Screenshot 2023-11-09 161339.png](https://hackmd.io/_uploads/B1OymXq76.png)

I can't reverse the `check_ko` function, i name that bacause of the `puts_then_exit` below

Next it allocates a `game_state` struct and put on `history` array, increment `play_time`

The bug is here, the program doesn't check bound for `play_time` so here's `OOB` bug

And `not_save` is set as `0` by the call of `check_not_full` so `check_not_full` will simply return if the board is full


Next the while loop in `main_loop`

![Screenshot 2023-11-09 162314.png](https://hackmd.io/_uploads/rySfHmqmp.png)

You see that it calls the vtable of the class

For `Human` is `get_choice` function

![Screenshot 2023-11-09 162441.png](https://hackmd.io/_uploads/ryguHXq7p.png)

It just get the coordinates for board, `regret` is for re do the last play, `surrender` is for restarting the game

For `AI` if `get_bot_coodinates` function

```cpp=
unsigned __int64 __fastcall get_bot_coordinates(
        __int64 func_ptr,
        Game_State *obj_1,
        int bot_time,
        int *x_opposite,
        int *y_opposite)
{
  int i; // [rsp+38h] [rbp-118h]
  int j; // [rsp+3Ch] [rbp-114h]
  Game_State obj; // [rsp+40h] [rbp-110h] BYREF
  Game_State v12; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  if ( obj_1->x == -1 )                         // bot
  {
    *x_opposite = 9;
    *y_opposite = 9;
  }
  else
  {
    *x_opposite = 18 - obj_1->x;
    *y_opposite = 18 - obj_1->y;
    obj = *obj_1;
    if ( !(unsigned __int8)play(&obj, *x_opposite, *y_opposite, bot_time, 1) )
    {
      for ( i = 0; i <= 18; ++i )
      {
        for ( j = 0; j <= 18; ++j )
        {
          if ( (unsigned __int8)get_ele(obj_1, i, j) == '.' )
          {
            v12 = *obj_1;
            if ( (unsigned __int8)play(&v12, i, j, bot_time, 1) )
            {
              *x_opposite = i;
              *y_opposite = j;
              return __readfsqword(0x28u) ^ v13;
            }
          }
        }
      }
      *x_opposite = -1;
      *y_opposite = -1;
    }
  }
  return __readfsqword(0x28u) ^ v13;
}
```

It get the mirror coordinates for `Human`, if played then iterates the board and choose the first valid position

After getting coordinates for play

![Screenshot 2023-11-09 162747.png](https://hackmd.io/_uploads/HJ4QLmcm6.png)

For `regret` it calls `backup` function

![Screenshot 2023-11-09 162828.png](https://hackmd.io/_uploads/HJyIL7cmT.png)

It just deletes `2` last play and restrieve the last `game_state`

After done the game, it calls `count_XO`

```cpp=
unsigned __int64 count_XO()
{
  int X_cnt; // [rsp+8h] [rbp-18h]
  int Y_cnt; // [rsp+Ch] [rbp-14h]
  int i; // [rsp+10h] [rbp-10h]
  int j; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  X_cnt = 0;
  Y_cnt = 0;
  for ( i = 0; i <= 18; ++i )
  {
    for ( j = 0; j <= 18; ++j )
    {
      if ( (unsigned __int8)get_ele((__int64)game_state, i, j) == 'X' )
      {
        ++X_cnt;
      }
      else if ( (unsigned __int8)get_ele((__int64)game_state, i, j) == 'O' )
      {
        ++Y_cnt;
      }
    }
  }
  if ( Y_cnt <= X_cnt )
  {
    if ( X_cnt == Y_cnt )
    {
      puts("Tie.");
    }
    else if ( Y_cnt < X_cnt )
    {
      puts("Here's a fake flag: hitcon{<3 pusheen}");
    }
  }
  else
  {
    puts("This AI is too strong, ah?");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

It counts `X`, `O` appear times and do some thing that't not important

`ask_view_history` function

![Screenshot 2023-11-09 163023.png](https://hackmd.io/_uploads/Hk_6U75XT.png)

It asks for viewing the history 

`again` function

![Screenshot 2023-11-09 163104.png](https://hackmd.io/_uploads/rk2kv7q7a.png)

`Y` is we want to replay the game and the program will restart the `main_loop`

That's all

## Exploit

First we play many times to fill the `history` array, since the distance between `history` and `game_state` is large, so we have to play many times than the board can contain

Ez, we just need to clear some node 

![Screenshot 2023-11-09 180404.png](https://hackmd.io/_uploads/SJzNpVqQa.png)

![Screenshot 2023-11-09 180427.png](https://hackmd.io/_uploads/r1d4T4c7p.png)


Now we see that there's heap address on `game_state` 

![Screenshot 2023-11-09 180706.jpg](https://hackmd.io/_uploads/SJAx045QT.jpg)

Board

![Screenshot 2023-11-09 180714.png](https://hackmd.io/_uploads/BkFlC457p.png)


We see there're some `\x00` because of `\x11` on `game_state`


Function to decode board

```python=
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
```

So now i have heap

Notice that when we `surrender` the program doesn't `free` `Human` and `AI` object. We can make heap alignment of that

With the game, i can write `\x01` or `\x10` to anywhere that contains `\x00`
I overwrite the leaked chunk so that it's added `0x80`

![Screenshot 2023-11-09 181413.png](https://hackmd.io/_uploads/BJcz1BcQ6.png)

Now that when i choose `regret` the program will `free` `2` chunks `0xf80` and `0xec0` and we can have a libc leak at `0xe80`

![Screenshot 2023-11-09 181540.png](https://hackmd.io/_uploads/HyLuJSqm6.png)

But one problem is that

![Screenshot 2023-11-09 181546.png](https://hackmd.io/_uploads/SJq_JS5ma.png)

Time is now `0`, so if we continue play the program will ends

Luckily the first chunk now is `0x0` so we can `surrender` and restart the game with `libc` and `heap` we already have

The idea now is faking the vtable, so i craft fake chunk on `game_state` then i will `free` it

![Screenshot 2023-11-09 181925.jpg](https://hackmd.io/_uploads/ry5pgr5Xp.jpg)

So now next time program go to `main_loop` it will use chunk `0x110` and i can overlap it with chunk `0x0d0`

Last is a pointer that overwrite vtable, we can only use `\x01` and `\x10` byte

Luckily the `choice` global variable is okay, we will write one_gadget at `choice + 4` then we will get the shell

![Screenshot 2023-11-09 182406.png](https://hackmd.io/_uploads/H1yOZH9Qa.png)

