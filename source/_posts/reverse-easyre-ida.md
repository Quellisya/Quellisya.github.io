---
title: "[BUUCTF] easyre：IDA 里一眼看穿的两个整数比较"
date: 2026-10-30 10:40:00
updated: 2026-10-30 10:40:00
categories:
  - CTF
  - Reverse
  - 逆向入门
tags:
  - Reverse
  - IDA
  - 逆向
  - BUUCTF
description: 第一次打开 IDA 也能做：Shift+F12 搜 flag 字符串，或者 F5 看 main——读入两个整数，相等就打印 flag。本文把 IDA 的界面、快捷键和反汇编都讲清楚。
difficulty: 入门
topic: 逆向入门
series: Reverse 入门
series_order: 1
permalink: 2026/10/30/reverse-easyre-ida/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（适合第一次打开 IDA）
- **考点**：PE 文件识别、IDA 基本操作、字符串搜索、`main` 反编译、比较指令
- **工具**：IDA（Free 或 Pro 都行）、`file`、`strings`
- **关键操作**：`Shift+F12` 打开 Strings 窗口搜 `flag{`，或者 `F5` 反编译 `main`
- **flag**：`flag{this_Is_a_EaSyRe}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道程序有 `main` 函数、见过 `if` 和 `printf`、了解十六进制
- **工具**：IDA Free / IDA Pro（本文以 IDA 8.x 界面为准，7.x 也基本一致）
- **环境**：本地静态分析即可，**不需要运行程序**。如果要运行，请放在虚拟机里。
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`file 看类型` → `IDA 打开` → `Shift+F12 搜字符串` → `F5 看 main` → `看懂比较逻辑` → `得到 flag`
{% endnote %}

## 第一步：先看文件是什么

附件解压后是一个 `easyre.exe`。先别急着双击，用 `file` 看真实类型：

```bash
file easyre.exe
```

输出：

```text
easyre.exe: PE32+ executable for MS Windows 5.02 (console), x86-64, 18 sections
```

关键信息：

| 字段 | 含义 |
| --- | --- |
| `PE32+` | 64 位 Windows 可执行文件 |
| `console` | 控制台程序，不是窗口程序 |
| `x86-64` | 64 位，IDA 要选 64 位 |
| `18 sections` | 节区数量，普通 C++ 程序常见 |

再看一下字符串，很多时候 flag 就明文躺在里面：

```bash
strings -n 5 easyre.exe | grep -i flag
```

输出：

```text
flag{this_Is_a_EaSyRe}
```

{% note success %}
**逆向第一步永远是 `strings`。** 很多入门题根本不用反汇编，字符串里直接就有 flag、提示、错误信息。先跑一遍 `strings`，能省掉大量时间。
{% endnote %}

不过，光看到字符串还不能确定它就是答案——也可能是干扰项。下面用 IDA 确认它到底有没有被用到。

## 第二步：IDA 打开文件

打开 IDA，选择 **`New`**（新建），选中 `easyre.exe`，加载选项保持默认：

```text
Load a new file
  File: easyre.exe
  Load as: Portable executable (PE)
  Processor: x86-64 (64-bit)
```

点 `OK`。IDA 会做自动分析，等左下角的进度条跑完。

打开后你会看到几个主要窗口：

| 窗口 | 作用 |
| --- | --- |
| `IDA View-A` | 反汇编视图（默认） |
| `Functions` | 函数列表（左侧） |
| `Strings` | 字符串列表（`Shift+F12` 打开） |
| `Hex View` | 十六进制视图 |
| `Output` | 分析日志/报错 |
| `Pseudocode` | Hex-Rays 反编译窗口（按 `F5` 打开） |

{% note info %}
**IDA Free 和 IDA Pro 的区别**：Free 版功能少一些，但看 `main`、字符串、基本反汇编足够。`F5` 反编译在较新的 IDA Free 里也可用；如果你的版本没有 `F5`，就看反汇编，逻辑同样简单。
{% endnote %}

## 第三步：最快路径——Strings 窗口

按 **`Shift+F12`** 打开 `Strings` 窗口。默认会列出程序里所有可打印字符串。在窗口里按 **`Ctrl+F`**，搜索：

```text
flag{
```

会定位到：

```text
.rdata:0000000000429005  flag{this_Is_a_EaSyRe}
```

双击这一行，IDA 会跳到它在 `.rdata` 节里的地址 `0x429005`。然后按 **`X`**（交叉引用，xrefs），看看谁引用了这个字符串：

```text
Address         Type    Function
0x401521        call    main
```

说明 `main` 在 `0x401521` 附近调用了这个字符串。双击 xref，跳回 `main`，按 `F5` 反编译。

{% note info %}
**Strings 窗口的几个快捷键**

| 快捷键 | 作用 |
| --- | --- |
| `Shift+F12` | 打开 Strings 窗口 |
| `Ctrl+F` | 搜索字符串 |
| `X` | 查看交叉引用（谁用了这个字符串/函数） |
| `Esc` | 返回上一个位置 |
| `G` | 跳转到指定地址 |
{% endnote %}

## 第四步：F5 反编译 main

在 `main` 上按 **`F5`**，Hex-Rays 会生成类似下面的伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+20h] [rbp-8h]
  int v4; // [rsp+24h] [rbp-4h]

  __main();
  scanf("%d%d", &v4, &v3);
  if ( v4 == v3 )
    printf("flag{this_Is_a_EaSyRe}");
  else
    printf("sorry,you can't get flag");
  return 0;
}
```

逻辑非常直白：

1. `scanf("%d%d", &v4, &v3)` 读入**两个整数**；
2. 如果两个数相等（`v4 == v3`），打印 `flag{this_Is_a_EaSyRe}`；
3. 否则打印 `sorry,you can't get flag`。

也就是说，**flag 是硬编码的，不依赖你输入什么**；你只要输入两个相等的整数，程序就会把 flag 打印出来。

![main 的逻辑](01-main-flow.png)

*图 1：`scanf` 读两个整数 → 比较 → 相等就打印 flag，否则打印 sorry*

{% note warning %}
看到 `scanf("%d%d")` 不要慌。很多新手以为“要输入正确的 flag”，其实程序只比较两个整数。**先看比较的对象是什么**：这里比较的是 `v4 == v3`，两个都是你输入的数，不是 flag。
{% endnote %}

## 第五步：对一下反汇编

如果你按 `F5` 没反应，或者想确认伪代码对不对，可以看反汇编。`main` 在 `0x4014F0`：

```asm
004014F0  push    rbp
004014F1  mov     rbp, rsp
004014F4  sub     rsp, 30h
004014F8  call    __main
004014FD  lea     rdx, [rbp-8]
00401501  lea     rax, [rbp-4]
00401505  mov     r8, rdx
00401508  mov     rdx, rax
0040150B  lea     rcx, [rip+27AEEh]    ; 0x429000, "%d%d"
00401512  call    scanf
00401517  mov     edx, [rbp-4]
0040151A  mov     eax, [rbp-8]
0040151D  cmp     edx, eax
0040151F  jne     0040152F             ; 不相等 -> sorry
00401521  lea     rcx, [rip+27ADDh]    ; 0x429005, "flag{this_Is_a_EaSyRe}"
00401528  call    printf
0040152D  jmp     0040153B
0040152F  lea     rcx, [rip+27AE6h]    ; 0x42901C, "sorry,you can't get flag"
00401536  call    printf
0040153B  mov     eax, 0
00401540  jmp     0040154A
...
```

对照着看：

| 汇编 | 含义 |
| --- | --- |
| `lea rcx, [rip+27AEEh]` | 取 `0x429000` 的地址，是 `scanf` 的格式串 `%d%d` |
| `call scanf` | 读两个整数 |
| `mov edx, [rbp-4]` / `mov eax, [rbp-8]` | 把两个输入读到寄存器 |
| `cmp edx, eax` | 比较 |
| `jne 0040152F` | 不相等就跳到 sorry 分支 |
| `lea rcx, [rip+27ADDh]` | 取 `0x429005`，flag 字符串 |
| `call printf` | 打印 flag |
| `lea rcx, [rip+27AE6h]` | 取 `0x42901C`，sorry 字符串 |

再看 `.rdata` 里的原始字节：

```text
429000  25 64 25 64 00              %d%d
429005  66 6c 61 67 7b 74 68 69 73 5f 49 73 5f 61 5f 45 61 53 79 52 65 7d 00
        f  l  a  g  {  t  h  i  s  _  I  s  _  a  _  E  a  S  y  R  e  }
42901C  73 6f 72 72 79 2c 79 6f 75 20 63 61 6e 27 74 20 67 65 74 20 66 6c 61 67 00
        s  o  r  r  y  ,  y  o  u     c  a  n  '  t     g  e  t     f  l  a  g
```

字符串是连续的 ASCII，末尾 `00` 是 C 字符串的结束符。地址 `0x429005` 正好是 `flag{...}` 的起点。

## 第六步：验证——输入两个相等的数

如果你在虚拟机里运行，打开命令行：

```text
easyre.exe
1 1
```

输出：

```text
flag{this_Is_a_EaSyRe}
```

输入 `1 2` 则输出：

```text
sorry,you can't get flag
```

这验证了我们的判断：**比较的是两个输入整数，flag 是写死的。**

{% note warning %}
运行陌生二进制有风险。这道题虽然简单，也建议在**虚拟机/沙箱**里跑，不要在存有重要资料的主力机上直接双击。静态分析（IDA）已经足够拿到 flag，运行只是验证。
{% endnote %}

## 第七步：IDA 常用操作速成

第一次用 IDA，记住这几个就够做题了：

| 快捷键 | 作用 | 使用场景 |
| --- | --- | --- |
| `Shift+F12` | 打开 Strings 窗口 | 找 flag、提示、错误信息 |
| `Ctrl+F` | 搜索 | 在 Strings/反汇编里搜关键字 |
| `F5` | 反编译当前函数 | 看 C 伪代码，最快理解逻辑 |
| `X` | 查看交叉引用 | 谁调用了这个函数/字符串 |
| `G` | 跳转到地址 | 输入 `0x4014F0` 直接到 main |
| `Space` | 切换图形/文本视图 | 看控制流图 |
| `N` | 重命名变量/函数 | 把 `v3` 改成 `a`，更好读 |
| `;` | 添加注释 | 标记关键地址 |
| `Esc` | 返回上一个位置 | 跳转后回退 |
| `F9` | 运行调试 | 动态验证（需要调试器） |

{% note info %}
**找不到 `main` 怎么办？**

1. 在 `Functions` 窗口按 `Ctrl+F` 搜 `main`；
2. 或者按 `G`，输入 `0x4014F0`（本题 main 的地址）；
3. 或者从 `entry` / `start` 开始，跟到 `mainCRTStartup` → `main`。

本题符号没有剥离，`Functions` 窗口里能直接看到 `main`。
{% endnote %}

## 工具速查卡

| 工具/操作 | 用途 | 关键点 |
| --- | --- | --- |
| `file` | 判断文件类型 | PE32+ / x86-64 |
| `strings` | 快速找明文 | `strings -n 5 easyre.exe` |
| IDA `New` | 加载文件 | 选 PE、x86-64 |
| `Shift+F12` | Strings 窗口 | 搜 `flag{` |
| `X` | 交叉引用 | 确认字符串被谁使用 |
| `F5` | 反编译 | 看 `main` 的 C 逻辑 |
| `Space` | 图形视图 | 看分支 |
| `F9` | 运行 | 输入 `1 1` 验证 |

## 新手常见问题

{% note info **Q1：IDA 打开时选 32 位还是 64 位？** %}
看 `file` 的输出。本题是 `PE32+ ... x86-64`，选 64 位。选错会看到一堆乱码/无法分析。
{% endnote %}

{% note info **Q2：`F5` 没反应？** %}
可能是 IDA Free 版本不带反编译器，或者当前光标不在函数体内。先点一下 `main` 的函数名/第一行，再按 `F5`。没有反编译就看反汇编，本题逻辑很简单。
{% endnote %}

{% note info **Q3：Strings 里有很多 `flag`，怎么知道哪个是真的？** %}
用 `X` 看交叉引用。真正被 `main` 引用的那个才有意义；只有字符串、没有 xref 的，可能是干扰项或库函数里的。
{% endnote %}

{% note info **Q4：为什么要输入两个相等的整数？** %}
`main` 里是 `scanf("%d%d", &a, &b)`，然后 `cmp` 比较 `a` 和 `b`，相等才走打印 flag 的分支。flag 不参与比较，它是硬编码的。
{% endnote %}

{% note info **Q5：flag 是 `flag{this_Is_a_EaSyRe}`，大小写要注意吗？** %}
注意。`this_Is_a_EaSyRe` 的大小写是混合的，直接复制，不要手打。提交前对照 IDA 里的字符串。
{% endnote %}

{% note info **Q6：程序双击闪退？** %}
这是控制台程序，双击后它等待输入，输入完就退出，窗口可能一闪而过。用命令行运行，或者在 IDA 里 `F9` 调试。
{% endnote %}

{% note info **Q7：`scanf` 的 `%d%d` 是什么意思？** %}
读两个十进制整数。输入时用空格、Tab 或换行分隔，比如 `1 1`、`42 42`。输入 `1,1` 可能只读到第一个数。
{% endnote %}

{% note info **Q8：这道题需要动态调试吗？** %}
不需要。Strings + `main` 反编译就能拿到 flag。动态运行只是验证。入门逆向先练静态分析，别一上来就上调试器。
{% endnote %}

## 顺手聊聊：硬编码的秘密

这道题的 flag 直接写在 `.rdata` 里，`strings` 就能看到。真实软件里也常见类似问题：

- 把 API Key、数据库密码、加密密钥硬编码在客户端；
- 把“管理员口令”写在二进制里做比较；
- 把 license 校验逻辑放在本地，改个跳转就绕过。

防护思路：

| 问题 | 建议 |
| --- | --- |
| 密钥硬编码 | 放到服务端，客户端只拿短期 token |
| 本地校验 | 关键逻辑放服务端，客户端校验只做体验 |
| 明文字符串 | 至少做混淆/加密，但别把它当唯一防线 |
| 调试符号 | 发布版剥离符号，增加分析成本 |
| 反调试 | 只能提高门槛，不能阻止有耐心的分析者 |

{% note success %}
**一条经验**：客户端是不可信的。只要代码/数据在用户机器上，用户就有办法看到它。真正的秘密应该留在服务端，客户端只保留“必要且不敏感”的逻辑。
{% endnote %}
