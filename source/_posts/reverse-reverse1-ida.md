---
title: "[BUUCTF] reverse1：在 IDA 里看懂 Str2 的字符替换"
date: 2026-11-01 09:20:00
updated: 2026-11-01 09:20:00
categories:
  - CTF
  - Reverse
  - 逆向入门
tags:
  - Reverse
  - IDA
  - 字符串比较
  - 逆向
  - BUUCTF
description: main 只是个 thunk，真正的逻辑在 main_0：先把 Str2 里的 o 全部换成 0，再拿你的输入和它做 strncmp。本文把 IDA 的 thunk、伪代码、数据修复、交叉引用一次讲清。
difficulty: 入门
topic: 逆向入门
series: Reverse 入门
series_order: 2
permalink: 2026/11/01/reverse-reverse1-ida/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（会打开 IDA 就能做）
- **考点**：PE 文件识别、IDA 的 `main`/`main_0` thunk、`F5` 反编译、数据类型修复、交叉引用、`strncmp`
- **工具**：IDA（Free / Pro 均可）、`file`、`strings`
- **关键操作**：`F5` 看 `main_0` → 看懂 `Str2[j] == 'o' → '0'` → 按 `X` 看 `Str2` 的原始值
- **flag**：`flag{hell0_w0rld}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 C 的 `char` 数组、`for` 循环、`strcmp`；知道十六进制和 ASCII
- **工具**：IDA 8.x（7.x 界面基本一致）；`file`、`strings` 可选
- **环境**：本地静态分析即可，**不需要运行程序**
- **配套阅读**：[easyre：IDA 里一眼看穿的两个整数比较](/2026/10/30/reverse-easyre-ida/) 讲的是「不看输入、直接找硬编码字符串」；本文讲的是「输入要和一段被处理过的字符串比较」
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`file/strings 侦察` → `IDA 打开` → `main` 是 thunk，进 main_0` → `F5 反编译` → `逐行读循环` → `修复 Str2 类型` → `X 看 Str2 原始值` → `手算 o→0` → `提交 flag`
{% endnote %}

## 第一步：先看文件，再打开 IDA

附件解压后是 `reverse_1.exe`。先确认文件类型：

```bash
file reverse_1.exe
```

输出类似：

```text
reverse_1.exe: PE32+ executable for MS Windows (console) x86-64, for MS Windows
```

| 字段 | 含义 |
| --- | --- |
| `PE32+` | 64 位 Windows 可执行文件 |
| `console` | 控制台程序，运行时是一个黑窗口 |
| `x86-64` | 64 位，IDA 里要按 64 位加载 |

再跑一遍字符串，很多时候能直接看到提示：

```bash
strings -n 5 reverse_1.exe | grep -Ei "flag|input|right|wrong|hello"
```

可能会看到：

```text
input the flag:
this is the right flag!
wrong flag
{hello_world}
```

`{hello_world}` 很像答案，但别急。逆向题里明文出现的字符串可能是干扰项，也可能只是**处理前**的原料。我们要在 IDA 里确认它到底怎么被使用。

## 第二步：IDA 打开，`main` 只是个「壳」

用 IDA 打开 `reverse_1.exe`，加载选项保持默认（PE、x86-64），等自动分析跑完。

在左侧 `Functions` 窗口找到 `main`，按 `F5` 反编译，会看到：

```c
// attributes: thunk
int __fastcall main(int argc, const char **argv, const char **envp)
{
  return main_0(argc, argv, envp);
}
```

![main 只是跳转到 main_0](image.png)

*图 1：`main` 的函数体只有一句 `return main_0(argc, argv, envp);`*

很多新手到这里会疑惑：说好的逻辑呢？

`// attributes: thunk` 是 IDA 给的提示：这个 `main` 是一个**跳转桩（thunk）**，它不干活，只把参数原样转交给 `main_0`。编译器/链接器在 64 位 Windows 下经常生成这种包装函数，真正的主逻辑在 `main_0` 里。

所以下一步很明确：**双击 `main_0`**（或者把光标放在函数名上按 `Enter`），进入真正的函数。

{% note info %}
**thunk 是什么？**

可以理解成「转发函数」：`main` 的位置是编译器固定要求存在的，但实际代码被编译器放在了 `main_0`，于是 `main` 只写一句跳转。除了 `main_0`，你可能还会遇到 `j_main`、`_main_0` 之类的命名，逻辑一样：**看到 thunk 就跟着跳过去**。
{% endnote %}

## 第三步：`F5` 反编译 `main_0`

进入 `main_0` 后按 `F5`，得到类似下面的伪代码（不同 IDA 版本变量名可能略有差异）：

```c
int __fastcall main_0(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 i; // rcx
  size_t v5; // rax
  char v7; // [rsp+0h] [rbp-20h] BYREF
  int j; // [rsp+24h] [rbp+4h]
  char Str1[224]; // [rsp+48h] [rbp+28h] BYREF
  __int64 v10; // [rsp+128h] [rbp+108h]

  v3 = &v7;
  for ( i = 'R'; i; --i )
  {
    *(_DWORD *)v3 = -858993460;
    v3 += 4;
  }

  for ( j = 0; ; ++j )
  {
    v10 = j;
    if ( j > j_strlen(Str2) )
      break;
    if ( Str2[j] == 'o' )
      Str2[j] = '0';
  }

  sub_1400111D1("input the flag:");
  sub_14001128F("%20s", Str1);
  v5 = j_strlen(Str2);
  if ( !strncmp(Str1, Str2, v5) )
    sub_1400111D1("this is the right flag!\n");
  else
    sub_1400111D1("wrong flag\n");

  return 0;
}
```

![main_0 的伪代码](image-1.png)

*图 2：`main_0` 里真正干了三件事：初始化栈、处理 `Str2`、读输入并比较*

看着长，其实可以拆成三段。下面逐段读。

## 第四步：逐行读懂 `main_0`

### 4.1 第一段：栈初始化，和 flag 无关

```c
v3 = &v7;
for ( i = 'R'; i; --i )
{
  *(_DWORD *)v3 = -858993460;
  v3 += 4;
}
```

这段是 MSVC 调试版程序自动插入的**栈填充**代码：

- `'R'` 的 ASCII 是 `82`，循环 82 次；
- 每次写 4 字节（`_DWORD`），所以一共写 `82 × 4 = 328` 字节；
- 写入的值 `-858993460` 换成十六进制是 `0xCCCCCCCC`；
- `0xCC` 是调试器常用的「未初始化内存」填充字节，对应 `int3` 指令。

IDA 的注释 `[rsp+0h]`、`[rbp-20h]` 是在告诉你变量在栈上的偏移；`BYREF` 表示这个变量取过地址（被 `&v7` 用过）。

**这一段可以直接跳过**，它只是编译器的调试辅助代码，不参与真正的校验。

{% note info %}
看到 `-858993460` 不要慌。用计算器转一下十六进制就是 `0xCCCCCCCC`，这是 MSVC Debug 版的特征。Release 版通常没有这段，题目给 Debug 版只是为了方便分析。
{% endnote %}

### 4.2 第二段：把 `Str2` 里的 `o` 全换成 `0`

```c
for ( j = 0; ; ++j )
{
  v10 = j;
  if ( j > j_strlen(Str2) )
    break;
  if ( Str2[j] == 'o' )
    Str2[j] = '0';
}
```

这是本题的核心。逐句翻译：

1. `j` 从 0 开始，每次加 1；
2. 当 `j > strlen(Str2)` 时退出。也就是说，会**遍历 `Str2` 的每一个字符**（包括末尾的 `\0`，多跑一次也无害）；
3. 如果当前字符是 `'o'`，就把它改成 `'0'`。

注意这里是**原地修改全局数组 `Str2`**。程序运行时，`Str2` 会从：

```text
{hello_world}
```

变成：

```text
{hell0_w0rld}
```

然后在下一段拿你的输入和**修改后**的 `Str2` 比较。

`j_strlen` 这个名字已经暴露了它的身份：`strlen`。IDA 对静态链接进来的库函数常常用 `j_` 前缀重命名。

### 4.3 第三段：读输入，做比较

```c
sub_1400111D1("input the flag:");
sub_14001128F("%20s", Str1);
v5 = j_strlen(Str2);
if ( !strncmp(Str1, Str2, v5) )
    sub_1400111D1("this is the right flag!\n");
else
    sub_1400111D1("wrong flag\n");
```

三个 `sub_` 函数怎么认：

| 伪代码 | 真实函数 | 判断依据 |
| --- | --- | --- |
| `sub_1400111D1("input the flag:")` | `printf` | 第一个参数是格式化字符串，没有输出缓冲区 |
| `sub_14001128F("%20s", Str1)` | `scanf` | 第一个参数是 `%20s`，第二个参数是要写入的缓冲区 `Str1` |
| `j_strlen(Str2)` | `strlen` | 名字里有 `strlen`，参数是字符串 |

比较逻辑：

- `v5 = strlen(Str2)`，即 `Str2` 修改后的长度；
- `strncmp(Str1, Str2, v5)` 比较输入 `Str1` 和 `Str2` 的前 `v5` 个字符；
- 返回值是 0 表示相等，前面加 `!` 就是「相等时成立」；
- 相等打印 `this is the right flag!`，否则打印 `wrong flag`。

所以程序要你输入的，就是**处理后的 `Str2`**。

{% note warning %}
`strncmp` 只比较前 `v5` 个字符，不是整串比较。理论上如果你输入比 `v5` 长的字符串，多出来的部分不参与比较；但这不是本题的重点，知道有这个细节即可。
{% endnote %}

## 第五步：修复数据类型，让 `Str2` 以字符串显示

伪代码里 `Str2` 可能显示成一串数字，或者类型识别得不对。IDA 默认不一定知道它是个 `char` 数组，这时需要手动修一下。

draft 里说的「按 `R` 键修复为 char」，具体操作分两种视图：

| 视图 | 快捷键 | 作用 |
| --- | --- | --- |
| 反汇编/数据视图（IDA View-A） | `R` | 把数据按**字符**显示（char） |
| 反汇编/数据视图 | `A` | 把数据按**字符串**显示（ASCII） |
| 反编译窗口（F5） | `Y` | 修改变量/数据的**类型**，比如 `char[13]` |
| 任意视图 | `X` | 查看交叉引用（谁引用了它） |
| 任意视图 | `N` | 重命名，把 `Str2` 改成你能看懂的名字 |

推荐流程：

1. 在 `main_0` 里双击 `Str2`，跳到它的定义处（通常在 `.data` 或 `.rdata` 节）；
2. 按 `A`，让它以字符串形式显示；
3. 如果显示不对，按 `Y`，把类型改成 `char[13]`（按实际长度调整）；
4. 按 `X`，确认它被 `main_0` 引用，排除同名干扰项。

修复后你会看到 `Str2` 的原始值：

```text
"{hello_world}"
```

这是**替换前**的原始字符串，也就是后续 `o → 0` 的原料。

对 `Str2` 按 `X` 还能看到：

```text
Address         Type    Function
0x140001000     data    main_0
```

说明这个字符串确实被 `main_0` 使用，不是干扰项。

{% note info %}
如果按 `X` 看到多个引用，按 `Esc` 返回，逐个看哪个在 `main_0` 的比较逻辑里。逆向题里经常放几个长得像的字符串迷惑你，**以实际引用位置为准**。
{% endnote %}

## 第六步：手算出 flag

现在逻辑已经完全清楚了：

| 步骤 | 值 |
| --- | --- |
| `Str2` 原始值 | `{hello_world}` |
| 循环把 `'o'` 换成 `'0'` | `{hell0_w0rld}` |
| 程序要求输入 | `{hell0_w0rld}` |
| 题目要求的 flag 格式 | `flag{hell0_w0rld}` |

注意替换的是**字母 o**，不是数字 0：

```text
hello   → hell0
world   → w0rld
{hello_world} → {hell0_w0rld}
```

所以最终提交：

```text
flag{hell0_w0rld}
```

{% note warning %}
别把 `hello_world` 和 `hell0_w0rld` 搞混。程序比较的是**替换之后**的字符串；你直接输入 `{hello_world}` 会得到 `wrong flag`。大小写、下划线、花括号都要原样保留。
{% endnote %}

## 第七步：验证——运行或模拟

### 方式一：在虚拟机里运行

```text
reverse_1.exe
input the flag:{hell0_w0rld}
this is the right flag!
```

输入 `{hell0_w0rld}` 能通过；输入 `{hello_world}` 会得到 `wrong flag`。

### 方式二：用 Python 模拟一遍逻辑

不想运行陌生程序，可以用 Python 复刻它的核心逻辑：

```python
s = "{hello_world}"          # Str2 的原始值
s = s.replace("o", "0")      # 对应循环里的 Str2[j] == 'o' -> '0'
print(s)                     # {hell0_w0rld}
print("flag" + s)            # flag{hell0_w0rld}
```

输出：

```text
{hell0_w0rld}
flag{hell0_w0rld}
```

{% note info %}
`str.replace("o", "0")` 和程序里的循环等价：都是把**所有**小写字母 `o` 替换成数字 `0`。在 Python 里验证逻辑，比反复运行二进制更快，也更安全。
{% endnote %}

## IDA 常用操作补充

上一篇讲过基础快捷键，这里补充几个本题会用到的：

| 快捷键 | 作用 | 本题用途 |
| --- | --- | --- |
| `Enter` | 跟随函数/跳转 | 从 `main` 进入 `main_0` |
| `F5` | 反编译 | 看 `main_0` 的 C 伪代码 |
| `X` | 交叉引用 | 确认 `Str2` 被谁使用 |
| `A` | 按字符串显示 | 让 `Str2` 显示成 `{hello_world}` |
| `R` | 按字符显示 | 逐字节查看数据 |
| `Y` | 修改类型 | 把 `Str2` 改成 `char[13]` |
| `N` | 重命名 | 把 `sub_1400111D1` 改成 `printf` |
| `G` | 跳转地址 | 直接跳到 `Str2` 的地址 |
| `Esc` | 返回 | 看完 xref 回到原处 |
| `Space` | 图形/文本视图切换 | 看控制流 |

{% note success %}
**遇到 `sub_xxxx` 不要跳过。** 先用参数和字符串猜它的身份，再双击进去看函数体确认。本题的 `printf`/`scanf`/`strlen` 都是这样认出来的。认出来之后，伪代码就和普通 C 代码一样好读。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么 `main` 里只有一句 `return main_0(...)`？** %}
这是编译器的 thunk。真正的逻辑在 `main_0`，双击进去即可。看到 `// attributes: thunk` 就说明这是个转发函数。
{% endnote %}

{% note info **Q2：`-858993460` 是什么？** %}
十六进制的 `0xCCCCCCCC`，MSVC Debug 版用来填充未初始化栈内存的标记。这段循环只是初始化栈，不参与 flag 校验。
{% endnote %}

{% note info **Q3：为什么 `'o'` 在伪代码里显示成 `111`，`'0'` 显示成 `48`？** %}
因为 IDA 把字符按整数显示了。`'o'` 的 ASCII 是 111，`'0'` 是 48。按 `R` 或 `Y` 修一下类型，就会显示成字符形式。
{% endnote %}

{% note info **Q4：`Str1` 和 `Str2` 分别是什么？** %}
`Str1` 是你的输入缓冲区（`char Str1[224]`，`scanf("%20s")` 最多读 20 个字符）；`Str2` 是程序里预置的全局字符串，比较前会先被 `o → 0` 处理。
{% endnote %}

{% note info **Q5：`strncmp` 和 `strcmp` 有什么区别？** %}
`strcmp` 比较到 `\0` 为止；`strncmp(a, b, n)` 只比较前 `n` 个字符。本题 `n = strlen(Str2)`，所以实际上比较了 `Str2` 的全部有效字符。
{% endnote %}

{% note info **Q6：找不到 `main_0` / 函数列表里没有 `main`？** %}
可以先 `Shift+F12` 打开 Strings 窗口，搜 `input the flag:`，按 `X` 看交叉引用，双击就能跳到调用它的函数。这条路不依赖符号表。
{% endnote %}

{% note info **Q7：按 `F5` 没有反应？** %}
确认光标在函数体内（点一下函数名或第一行），再按 `F5`。如果 IDA Free 版本不带反编译器，就看反汇编；本题逻辑简单，对照 `cmp`/`jne` 也能读。
{% endnote %}

{% note info **Q8：flag 到底是 `{hell0_w0rld}` 还是 `flag{hell0_w0rld}`？** %}
程序内部比较的是 `{hell0_w0rld}`；按题目平台要求的格式提交时，前面加上 `flag`，即 `flag{hell0_w0rld}`。不同平台的提交格式可能不同，以题目说明为准。
{% endnote %}

## 工具速查卡

| 工具/操作 | 用途 | 关键点 |
| --- | --- | --- |
| `file` | 判断文件类型 | PE32+ / x86-64 |
| `strings` | 快速找明文 | 可能看到 `{hello_world}` 和提示语 |
| `F5` | 反编译 | 本题核心是 `main_0` |
| `Enter` | 跟随 thunk | `main` → `main_0` |
| `A` / `R` / `Y` | 修复显示/类型 | 让 `Str2` 显示成字符串 |
| `X` | 交叉引用 | 确认字符串被 `main_0` 使用 |
| `N` | 重命名 | 把 `sub_` 改成 `printf`/`scanf` |
| `Esc` | 回退 | 看完 xref 返回 |

## 顺手聊聊：字符串混淆与本地校验

这道题的思路很典型：**flag 不直接以明文出现，而是经过一层简单变换后再比较**。

现实中的软件也常这么做，但强度完全不同：

| 做法 | 强度 | 说明 |
| --- | --- | --- |
| 明文硬编码 | 几乎没有 | `strings` 就能看到 |
| 简单替换/异或 | 很低 | 逆向者跟一遍逻辑就能还原 |
| 多层加密 + 运行时解密 | 中等 | 提高分析成本，但密钥仍在客户端 |
| 服务端校验 | 高 | 客户端拿不到判定逻辑和密钥 |

{% note success %}
**一条经验**：客户端里的任何校验都只能提高门槛，不能真正保密。只要数据和逻辑在用户机器上，就有办法被看到、被修改。真正的秘密应该留在服务端。
{% endnote %}

对防御方来说，与其把 flag（或密钥）藏进客户端的字符串里，不如：

- 把关键判定放到服务端；
- 客户端只保留「体验层」的校验；
- 发布版剥离符号、开启优化，增加分析成本；
- 不要以为改个变量名、做个字符替换就能挡住逆向。
