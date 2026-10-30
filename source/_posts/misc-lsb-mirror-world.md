---
title: "[BUUCTF] 镜子里面的世界：用 StegSolve 提取 LSB 隐写"
date: 2026-10-30 10:00:00
updated: 2026-10-30 10:00:00
categories:
  - CTF
  - Misc
  - 隐写
tags:
  - Misc
  - LSB
  - StegSolve
  - 图片隐写
  - BUUCTF
description: 一张写着“Look very closely”的放大镜图片，真正的秘密藏在每个像素的最低位。用 StegSolve 的 Data Extract 勾选 R/G/B 的 bit 0，直接读出密钥。
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 1
permalink: 2026/10/30/misc-lsb-mirror-world/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：LSB 图片隐写、StegSolve 的 Data Extract
- **工具**：StegSolve（Java 小工具）
- **关键操作**：`Analyse → Data Extract`，勾选 `Red 0`、`Green 0`、`Blue 0`，`Bit Order` 选 `MSB First`
- **flag**：`flag{st3g0_saurus_wr3cks}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道图片由像素组成、每个像素有 R/G/B 三个颜色通道（0–255）
- **工具**：StegSolve（需要 Java）。文末给了一张**练习图**，可以下载后用同样的步骤提取，不用担心没有靶场。
- **环境**：本地分析，不需要联网靶机。
- 本文仅用于**授权题目和教学**，请勿用于未授权的图片分析。
{% endnote %}

{% note default %}
**做题路线**

`看图片` → `怀疑 LSB` → `StegSolve 打开` → `Analyse → Data Extract` → `勾 R/G/B 的 bit 0` → `Preview 读出文本` → `包上 flag{}`
{% endnote %}

## 第一步：观察图片

解压附件，只有一张 PNG：

```text
镜子里面的世界/
└── steg.png
```

打开一看，是一个放大镜，镜片里写着：

![题目图片](01-steg.png)

*图 1：`Look very closely ;)`——“仔细看”，这基本就是隐写题的标准开场白*

图片本身没有二维码、没有明显的文字，文件也不大（约 233 KB）。这种“让你仔细看，但肉眼看不出”的题，第一反应就是 **LSB 隐写**。

{% note info %}
**LSB 是什么？**

每个像素的颜色由 R、G、B 三个 0–255 的整数组成。比如白色是 `(255, 255, 255)`，写成二进制：

```text
255 = 11111111
```

如果我把最后一位从 `1` 改成 `0`，颜色变成 `254`，肉眼看不出任何区别。**最低位（Least Significant Bit，LSB）** 就是用来藏数据的地方：把秘密的二进制位依次写进每个像素的最低位，图片看起来几乎不变。
{% endnote %}

## 第二步：StegSolve 是什么

StegSolve 是一个用 Java 写的图片隐写分析小工具，界面很朴素，但功能很适合 Misc 入门：

- 按通道/位平面浏览图片（R/G/B/A，bit 0–7）；
- `Data Extract` 提取 LSB 数据；
- `Frame Browser` 看 GIF 帧；
- `Stereogram Solver` 解立体图；
- `Image Combiner` 合并两张图。

**安装/启动**：

1. 下载 `StegSolve.jar`（搜索引擎搜 “StegSolve jar 下载” 即可，很多 CTF 工具包里有）；
2. 电脑装好 Java（命令行能运行 `java -version`）；
3. 双击 jar，或者命令行：

```bash
java -jar StegSolve.jar
```

{% note warning %}
StegSolve 是 Java 程序，**不是**双击就能跑的 `.exe`。如果双击没反应，先确认 Java 装好了；Windows 上可以用 `java -jar` 启动，macOS/Linux 同理。
{% endnote %}

打开后点 `File → Open`，选择 `steg.png`。主窗口下方有一排按钮，可以切换 R/G/B 通道和 bit 0–7 的位平面；键盘左右方向键也能切换。

## 第三步：用 Data Extract 提取 LSB

这是本题的核心操作，跟着点就行：

1. 菜单栏点 **`Analyse`**；
2. 选择 **`Data Extract`**，会弹出一个对话框；
3. 在 `Bit Planes` 区域，勾选：
   - **`Red 0`**
   - **`Green 0`**
   - **`Blue 0`**
4. `Bit Order` 选 **`MSB First`**（默认就是它）；
5. `Extract By` 保持 **`Row`**（按行扫描）；
6. 点 **`Preview`**。

对话框大概长这样（不同版本文字略有差异）：

```text
┌─ Data Extract ─────────────────────────────┐
│  Bit Planes                                │
│   [x] Red 0    [ ] Red 1   ...             │
│   [x] Green 0  [ ] Green 1 ...             │
│   [x] Blue 0   [ ] Blue 1  ...             │
│                                            │
│  Bit Order:  (•) MSB First  ( ) LSB First  │
│  Extract By: (•) Row        ( ) Column     │
│                                            │
│  [ Preview ]  [ Save Bin ]  [ Cancel ]     │
└────────────────────────────────────────────┘
```

点 `Preview` 后，下方会显示提取出来的文本：

```text
Hey I think we can write safely in this file without anyone seeing it.
Anyway, the secret key is: st3g0_saurus_wr3cks
```

{% note success %}
看到可读英文，说明勾对了。点 **`Save Bin`** 可以保存为二进制文件，用记事本 / VSCode 打开也能看到同样的内容。
{% endnote %}

## 第四步：从密钥到 flag

文本里写的是：

```text
the secret key is: st3g0_saurus_wr3cks
```

题目要求提交 `flag{}` 格式，所以把密钥包进去：

```text
flag{st3g0_saurus_wr3cks}
```

{% note info %}
注意：图片里给的是 **secret key**，不是完整 flag。CTF 里经常这样：先给你一段 key/口令，再让你按题目要求拼成 `flag{...}`。看清楚题目说明里的格式要求。
{% endnote %}

## 第五步：为什么勾 R/G/B 的 0 位？

这是 LSB 题最常问的问题。把三个通道的最低位拿出来，按 R→G→B 的顺序拼成比特流：

```text
像素 1: R=254(11111110) G=255(11111111) B=254(11111110)
        LSB: 0 1 0
像素 2: R=254(11111110) G=254(11111110) B=255(11111111)
        LSB: 0 0 1
...
拼起来: 010001... → 每 8 位一个字节 → ASCII 文本
```

为什么是 **0 位**？因为 bit 0 是最低位，改动它只让颜色值变化 1，肉眼几乎察觉不到。bit 7 是最高位，改一下颜色就天差地别，没人会把秘密藏在那里。

为什么三个通道都勾？因为出题人可能把数据依次写进 R、G、B 的最低位，三个通道一起取才能还原完整的字节流。只勾一个通道，提取出来的可能是乱码。

| 勾选 | 结果 |
| --- | --- |
| R/G/B 的 0 位 | ✅ 本题正确，得到可读文本 |
| 只勾 R 的 0 位 | ❌ 只拿到 1/3 的比特，乱码 |
| 勾 1 位、2 位 | ❌ 本题数据不在这些位 |
| `Bit Order` 选 `LSB First` | ❌ 本题会乱码（有些题需要） |

{% note warning %}
如果 `Preview` 出来是乱码，不要急着放弃。按顺序试：

1. `Bit Order` 换成 `LSB First`；
2. 只勾一个通道（R/G/B 分别试）；
3. 换 bit 1、bit 2；
4. `Extract By` 换成 `Column`；
5. 用 `zsteg`、`stegonline`、`aperisolve` 等工具交叉验证。

LSB 题没有“万能勾选”，但“RGB 的 0 位 + MSB First + Row”覆盖了大多数入门题。
{% endnote %}

## 第六步：跟着做——用练习图复现

没有靶场也能练。下面这张图是我用同样的方法生成的练习图，隐藏信息在 R/G/B 的最低位：

![LSB 练习图](02-lsb-lab.png)

*图 2：下载这张图，用 StegSolve 的 Data Extract 提取，看看你能不能读出 `flag{lsb_practice}`*

操作步骤和上面完全一样：

1. `File → Open` 打开练习图；
2. `Analyse → Data Extract`；
3. 勾 `Red 0`、`Green 0`、`Blue 0`；
4. `Bit Order = MSB First`，`Extract By = Row`；
5. `Preview`。

你应该能看到：

```text
Practice makes perfect. The secret word is: flag{lsb_practice}
```

{% note info %}
`Preview` 里文本后面可能跟着一长串空白/NUL 字符，这是图片剩余像素的最低位都是 0 造成的，忽略即可。原题提取时也会看到类似情况。
{% endnote %}

{% note success %}
**练习的意义**：当你能在一张自己知道答案的图上稳定提取出文本，再去做新题就不会慌了。换一张图、换一个 bit 位、换一个 Bit Order，多试几次，手感就出来了。
{% endnote %}

## 第七步：想验证原理？用 Python 看一眼

GUI 够用，但如果你想知道 StegSolve 背后做了什么，可以用几行 Python 复现同样的提取过程。**这一段不是做题必需，只是帮助理解。**

```python
from PIL import Image
import numpy as np

img = Image.open("steg.png").convert("RGB")
a = np.array(img)

# 取 R/G/B 的最低位，按 R→G→B 顺序拼成一维比特流
bits = np.stack([a[:, :, i] & 1 for i in range(3)], axis=-1).reshape(-1)

# 每 8 位组成一个字节（MSB First）
out = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for bit in bits[i:i + 8]:
        byte = (byte << 1) | int(bit)
    out.append(byte)

print(out.split(b"\x00")[0].decode("latin1"))
```

输出就是那段英文。对照一下 StegSolve 的 `Preview`，结果一致。

{% note info %}
为什么按 `R→G→B` 的顺序？因为 StegSolve 的 Data Extract 就是按这个顺序把勾选的位平面串起来的。不同工具的顺序可能不同，所以换工具时要以实际输出为准。
{% endnote %}

## 工具速查卡

| 操作 | 路径/快捷键 | 说明 |
| --- | --- | --- |
| 打开图片 | `File → Open` | 支持 PNG/BMP/GIF 等 |
| 切换位平面 | 左右方向键 / 底部按钮 | 看 R/G/B 的 bit 0–7 |
| 提取数据 | `Analyse → Data Extract` | 本题核心 |
| 预览 | `Preview` | 直接看提取结果 |
| 保存 | `Save Bin` | 保存为二进制，用文本编辑器打开 |
| 看 GIF 帧 | `Analyse → Frame Browser` | 动图题常用 |
| 合并图片 | `Analyse → Image Combiner` | 两张图做 XOR/加法等 |

## 新手常见问题

{% note info **Q1：StegSolve 双击没反应？** %}
先装 Java，然后在命令行运行 `java -jar StegSolve.jar`。如果报 `UnsupportedClassVersionError`，说明 Java 版本太新/太旧，换一个 Java 8 或 11 试试。
{% endnote %}

{% note info **Q2：Data Extract 里全是乱码？** %}
按“Bit Order → 通道 → bit 位 → Extract By”的顺序逐个试。最常见的是 `MSB First` 和 `LSB First` 选错，或者只勾了一个通道。
{% endnote %}

{% note info **Q3：为什么不能直接看图片？** %}
LSB 只改每个颜色值的最低位，肉眼分辨不出 254 和 255 的区别。要用工具把最低位单独抽出来看。
{% endnote %}

{% note info **Q4：JPG 图片也能做 LSB 吗？** %}
JPG 是有损压缩，保存/重新压缩会破坏最低位，所以 LSB 题通常用 PNG、BMP 这类无损格式。拿到 JPG 先看文件头，也可能是改了后缀的 PNG。
{% endnote %}

{% note info **Q5：除了 StegSolve 还有什么工具？** %}
`zsteg`（命令行，Ruby）、`stegonline`（网页）、`aperisolve`（网页，自动跑多种分析）、`Binwalk`（看文件结构）。入门先用 StegSolve 建立直觉，再换工具。
{% endnote %}

{% note info **Q6：提取出来的文本只有一半？** %}
可能数据不在文件开头，或者 `Preview` 只显示了前几百字节。点 `Save Bin` 保存完整数据，再用文本编辑器搜索 `flag`、`key`、`secret`。
{% endnote %}

{% note info **Q7：flag 格式不对？** %}
图片给的是 `st3g0_saurus_wr3cks`，题目要求包 `flag{}`，所以提交 `flag{st3g0_saurus_wr3cks}`。注意大小写和下划线，别手打错。
{% endnote %}

{% note info **Q8：为什么练习图能提取，原题却不行？** %}
每道题的通道、bit 位、Bit Order 可能不同。练习图只是帮你熟悉操作，真正做题时要按上面的顺序多试几种组合。
{% endnote %}

## 顺手聊聊：LSB 为什么“脆弱”

LSB 隐写的特点是**容量大、实现简单、但非常脆弱**：

- 图片重新保存为 JPG、缩放、裁剪、调色，都可能破坏最低位；
- 用统计方法（卡方分析、RS 分析）可以检测出 LSB 平面异常；
- 所以真实场景里的隐写会用更鲁棒的方法（DCT 域、扩频、纠错码等）。

CTF 里的 LSB 题主要是让你理解“**数据可以藏在看起来无害的载体里**”。做题时记住三件事：

1. 先看文件类型和大小；
2. 用 StegSolve 逐位看，重点看 bit 0；
3. 提取结果可能是文本、二维码、压缩包、另一张图——不要只盯着“flag”三个字母。

{% note success %}
**一条经验**：Misc 题不怕工具多，就怕不动手。StegSolve 的 Data Extract 点十次，比看十篇 writeup 更有用。
{% endnote %}
