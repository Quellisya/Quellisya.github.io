---
title: "[BUUCTF] N种方法解决：一个假的 KEY.exe，真身是 Base64 藏图"
date: 2026-10-30 10:10:00
updated: 2026-10-30 10:10:00
categories:
  - CTF
  - Misc
  - 隐写
tags:
  - Misc
  - Base64
  - CyberChef
  - 二维码
  - BUUCTF
description: 附件叫 KEY.exe，file 一看却是 ASCII 文本。去掉 data:image/...;base64, 前缀，用 CyberChef 的 From Base64 还原成二维码，扫码拿到 KEY，再包成 flag。
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 2
permalink: 2026/10/30/misc-base64-nways/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：文件类型识别、Data URI、Base64 解码、二维码
- **工具**：`file` / 记事本、CyberChef、二维码扫描器
- **关键操作**：删掉 `data:image/jpg;base64,` 前缀，`From Base64`，得到 PNG，扫码
- **flag**：`flag{dca57f966e4e4e31fd5b15417da63269}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 Base64 是一种文本编码、见过 `data:` 开头的图片链接
- **工具**：CyberChef（网页版即可）、任意二维码扫描器（手机、ZXing、微信/QQ 扫码都行）
- **环境**：本地分析，不需要靶机。
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`看附件` → `file 判断类型` → `记事本看开头` → `识别 Data URI` → `CyberChef From Base64` → `得到二维码` → `扫码` → `包 flag{}`
{% endnote %}

## 第一步：附件只有一个 KEY.exe

解压后只有一个文件：

```text
KEY.exe    3,870 字节
```

名字叫 `.exe`，但大小只有 3.8 KB，对 Windows 程序来说小得可疑。先别双击运行，用 `file` 看一下真实类型：

```bash
file KEY.exe
```

输出：

```text
KEY.exe: ASCII text, with very long lines (3870), with no line terminators
```

**它根本不是可执行文件，而是一个纯文本文件。** Windows 只认扩展名，`file` 认的是文件内容——这是 Misc 题最常见的第一层伪装。

{% note warning %}
拿到陌生的 `.exe`，**不要直接双击运行**。先用 `file`、`strings`、十六进制查看器确认它到底是什么。CTF 附件也不例外，养成先看再做的好习惯。
{% endnote %}

## 第二步：用记事本打开，看到 Data URI

用记事本、VSCode 或任意文本编辑器打开 `KEY.exe`，会看到**一行**很长的文本，开头是：

![KEY.exe 的开头](02-data-uri.png)

*图 1：文件开头是 `data:image/jpg;base64,`，后面跟着一长串 Base64*

完整结构是：

```text
data:image/jpg;base64,iVBORw0KGgoAAAANSUhEUgAAAIUAAACFCAYAAAB12js8...
```

这是一种 **Data URI**（数据 URI），语法是：

```text
data:[<MIME 类型>][;base64],<数据>
```

拆开看：

| 部分 | 含义 |
| --- | --- |
| `data:` | 协议头，表示“数据直接写在 URL 里” |
| `image/jpg` | 声明的 MIME 类型 |
| `;base64` | 后面的数据用 Base64 编码 |
| `,` 之后 | 真正的 Base64 数据 |

所以这道题的意思很直白：**把逗号后面的 Base64 解出来，就是一张图片。**

{% note info %}
注意一个矛盾：MIME 写的是 `image/jpg`，但 Base64 的开头是 `iVBORw0KGgo`。

Base64 的 `iVBORw0KGgo` 解码后是 PNG 的文件头 `89 50 4E 47 0D 0A 1A 0A`。也就是说，**它其实是一张 PNG，不是 JPG**。出题人故意把 MIME 写错，增加一点迷惑性。判断文件类型永远看**文件头（magic bytes）**，不要信扩展名，也不要信 MIME。
{% endnote %}

## 第三步：CyberChef 解码（图形界面版）

打开 [CyberChef](https://gchq.github.io/CyberChef/)，按下面步骤操作：

**1. 准备输入**

把 `KEY.exe` 里的内容复制出来，**删掉**开头的：

```text
data:image/jpg;base64,
```

只保留逗号后面的 Base64。也可以直接把整行粘进去，再用 CyberChef 的 `Find / Replace` 把前缀替换成空。

**2. 添加 From Base64**

在左侧 `Operations` 搜索框输入 `From Base64`，把它拖到中间的 `Recipe` 区域。

**3. 看 Output**

Output 区域会从文本变成一堆乱码/字节。CyberChef 右上角有一个小眼睛图标（`Render Image` / `Preview`），点一下，就能直接看到图片：

![解码出来的二维码](01-key-qr.png)

*图 2：Base64 解码后的 PNG，是一个 133×133 的二维码*

**4. 保存图片**

点 Output 区域的下载按钮，保存为 `key.png`。如果 CyberChef 没有自动识别成图片，可以用 `Save output to file`，文件名写成 `key.png`。

{% note success %}
CyberChef 的 `Magic` 操作也可以自动识别：把整行（含前缀）粘进去，`Magic` 通常会自动去掉 Data URI 前缀并做 Base64 解码。但初学建议手动做一遍，知道每一步在干什么。
{% endnote %}

## 第四步：扫码，拿到 KEY

用手机、微信/QQ、ZXing、或者任意在线二维码扫描器扫这张图，内容是：

```text
KEY{dca57f966e4e4e31fd5b15417da63269}
```

题目要求提交 `flag{}` 格式，所以把 `KEY{...}` 里的内容取出来，包成：

```text
flag{dca57f966e4e4e31fd5b15417da63269}
```

{% note info %}
为什么不是直接提交 `KEY{...}`？因为 BUUCTF 的题目说明写了“得到的 flag 请包上 flag{} 提交”。不同平台的格式要求不同，做题前先看题目描述。
{% endnote %}

## 第五步：不用 CyberChef 的几种方法

这道题叫“N种方法解决”，确实有很多种做法。下面几种都可以，选你顺手的：

**方法一：命令行 Base64**

```bash
sed 's|^data:image/jpg;base64,||' KEY.exe | base64 -d > key.png
```

`sed` 删掉前缀，`base64 -d` 解码，输出重定向到 `key.png`。然后打开图片扫码。

**方法二：Python**

```python
import base64

data = open("KEY.exe", "r").read()
b64 = data.split(",", 1)[1]
open("key.png", "wb").write(base64.b64decode(b64))
```

**方法三：浏览器地址栏**

有些浏览器支持直接打开 Data URI：把整行 `data:image/jpg;base64,...` 粘到地址栏回车，图片会直接显示。但文本太长时地址栏可能截断，不如 CyberChef 稳。

**方法四：在线 Base64 转图片**

搜索“Base64 to image online”，把逗号后面的内容粘进去，下载图片。注意选对输出格式（PNG），或者让工具根据文件头自动判断。

| 方法 | 适合谁 | 注意点 |
| --- | --- | --- |
| CyberChef | 喜欢图形界面 | 记得删前缀 |
| `sed + base64 -d` | Linux/macOS/Git Bash | `base64 -d` 在 macOS 上可能是 `base64 -D` |
| Python | 会一点编程 | 用 `split(",", 1)` 只切第一个逗号 |
| 浏览器地址栏 | 应急 | 长文本可能被截断 |

## 第六步：文件头速查——为什么一眼看出是 PNG

Base64 的开头能直接暴露文件类型。记住几个常见的：

| 文件类型 | 文件头（十六进制） | Base64 开头 |
| --- | --- | --- |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `iVBORw0KGgo` |
| JPEG | `FF D8 FF` | `/9j/` |
| GIF | `47 49 46 38` | `R0lGOD` |
| ZIP | `50 4B 03 04` | `UEsDB` |
| PDF | `25 50 44 46` | `JVBERi` |

本题开头是 `iVBORw0KGgo`，所以是 PNG。Data URI 里写的 `image/jpg` 是假的。

{% note warning %}
CTF 里经常用“改扩展名”“改 MIME”“双扩展名”来迷惑人。判断文件类型的三板斧：

1. `file 文件名`；
2. `xxd 文件名 | head` 看文件头；
3. 看 Base64 解码后的前几个字节。

扩展名只是给人看的，文件头才是文件真实的身份。
{% endnote %}

## 第七步：跟着做——自己做一个 Data URI

想彻底理解，可以反过来做一遍：把一张图片编码成 Data URI，再用 CyberChef 解回来。

**1. 准备一张小图片**，比如 `test.png`。

**2. 用 Python 生成 Data URI**

```python
import base64

raw = open("test.png", "rb").read()
b64 = base64.b64encode(raw).decode()
data_uri = "data:image/png;base64," + b64
open("test.txt", "w").write(data_uri)
```

**3. 打开 `test.txt`**，会看到和题目一样的长文本。

**4. 用 CyberChef 的 `From Base64` 解码**，确认能还原成原图。

**5. 试试把前缀改成 `data:image/jpg;base64,`**，再解码——图片依然是 PNG。这样你就亲手复现了题目里的“MIME 骗人”。

{% note success %}
这个小实验能同时练三件事：Base64 编码、Data URI 结构、文件头识别。以后看到 `data:` 开头的东西，就不会陌生了。
{% endnote %}

## 工具速查卡

| 操作 | 工具 | 说明 |
| --- | --- | --- |
| 判断文件类型 | `file` | 不信扩展名，信内容 |
| 看十六进制 | `xxd` / `hexdump` | 看文件头 magic bytes |
| Base64 解码 | CyberChef `From Base64` | 图形界面，最直观 |
| Base64 解码 | `base64 -d` | 命令行，配合 `sed` 去前缀 |
| 扫码 | 手机/ZXing/在线工具 | 二维码内容可能是 flag 的一半 |
| 图片预览 | CyberChef `Render Image` | 不用保存也能看 |

## 新手常见问题

{% note info **Q1：`file` 说 ASCII text，但它叫 `.exe`，能双击吗？** %}
不能，也不建议。它只是文本文件，双击不会运行；更重要的是，**陌生 exe 不要直接运行**。先用 `file`、`strings`、十六进制确认。
{% endnote %}

{% note info **Q2：CyberChef 解码出来是乱码？** %}
最常见的原因是没有删掉 `data:image/jpg;base64,` 前缀。前缀里的字母也是合法 Base64 字符，会混进解码结果。用 `Find / Replace` 或手动删除，只保留逗号后的内容。
{% endnote %}

{% note info **Q3：为什么 MIME 写 `image/jpg`，解出来却是 PNG？** %}
MIME 是文本里写的，可以随便改；文件头 `iVBORw0KGgo` 才是真实格式。出题人故意写错，考你会不会看文件头。
{% endnote %}

{% note info **Q4：二维码扫不出来？** %}
图片只有 133×133，比较小。用图片查看器放大，或者用 CyberChef 的 `Render Image` 放大；扫码时对准、保持清晰。也可以换一个扫码 App（ZXing、微信、QQ 都试试）。
{% endnote %}

{% note info **Q5：`base64 -d` 报错？** %}
确认前缀已删掉，且没有换行/空格混进去。macOS 的 `base64` 解码参数可能是 `-D`；Windows Git Bash 一般用 `-d`。
{% endnote %}

{% note info **Q6：扫码得到 `KEY{...}`，直接提交行不行？** %}
看题目说明。BUUCTF 这题要求包 `flag{}`，所以提交 `flag{dca57f...}`。如果平台接受 `KEY{...}`，题目会明说。
{% endnote %}

{% note info **Q7：为什么叫“N种方法解决”？** %}
因为解法很多：CyberChef、命令行、Python、浏览器、在线工具都能做。名字也在提醒你：**Misc 题不要死磕一种工具**。
{% endnote %}

{% note info **Q8：Data URI 有什么用？** %}
前端开发里常用来把小图标直接嵌进 HTML/CSS，减少请求。但它也能被滥用：钓鱼页面、恶意文件、绕过上传检查，都可能用 Data URI 藏内容。看到 `data:` 开头的长字符串，先警惕。
{% endnote %}

## 顺手聊聊：文件类型识别与上传安全

这道题的核心不是 Base64，而是**“文件名/扩展名/MIME 都不可信”**。真实的安全场景里也一样：

- 上传文件时，不能只看扩展名（`shell.php.jpg`）；
- 不能只看 `Content-Type`（客户端可以随便改）；
- 要检查文件头（magic bytes），必要时重新编码/压缩；
- 图片上传后最好用图像库重新生成，去掉隐藏的元数据和附加数据；
- 不要把用户上传的文件放在可执行目录，文件名要重命名。

{% note success %}
**一条经验**：CTF Misc 里，`file`、`xxd`、`strings` 是三个最朴素也最有效的工具。先搞清楚“它到底是什么”，再谈怎么解。
{% endnote %}
