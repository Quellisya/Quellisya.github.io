---
title: "[BUUCTF] easycap：Wireshark 跟流，发现每包只带一个字符"
date: 2026-10-30 10:20:00
updated: 2026-10-30 10:20:00
categories:
  - CTF
  - Misc
  - 流量分析
tags:
  - Misc
  - Wireshark
  - TCP 流
  - 流量分析
  - BUUCTF
description: 一个只有 82 个包的小 pcap。用 Wireshark 的 Follow TCP Stream 跟一下，发现客户端每个包只发一个字符，拼起来就是 FLAG:...
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 3
permalink: 2026/10/30/misc-traffic-easycap/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：Wireshark 基本使用、TCP 流跟踪、单字节隐蔽信道
- **工具**：Wireshark
- **关键操作**：`Statistics → Conversations` 找到流 → 右键 `Follow → TCP Stream`
- **flag**：`flag{385b87afc8671dee07550290d16a8071}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 TCP 有源端口/目的端口、序列号，见过 Wireshark 的包列表
- **工具**：Wireshark（官网免费下载）。文中的菜单以 Wireshark 4.x 为准，3.x 也基本一致。
- **环境**：本地分析 pcap，不需要靶机。
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`打开 pcap` → `看协议分布` → `Statistics → Conversations` → `锁定 TCP 流` → `Follow TCP Stream` → `读出 FLAG`
{% endnote %}

## 第一步：打开 pcap，先看全貌

附件解压后是一个很小的流量包：

```text
easycap.pcap    6,802 字节
```

用 Wireshark 打开。第一眼看到的是包列表，只有 82 个包，说明这不是那种几万包的大流量题，不用怕。

先看几列基本信息：

| 列 | 看什么 |
| --- | --- |
| `No.` | 包序号，本题 1–82 |
| `Time` | 时间戳，判断流量是否连续 |
| `Source` / `Destination` | 谁和谁在通信 |
| `Protocol` | 本题几乎全是 TCP |
| `Length` | 包长度，本题都很短 |
| `Info` | 端口、Flags、Seq/Ack、Len |

{% note info %}
**Wireshark 界面速览**

- 最上面是**包列表**（Packet List）；
- 中间是**包详情**（Packet Details），按协议分层展开；
- 最下面是**十六进制/字节视图**（Packet Bytes）；
- 顶部过滤器栏可以输入 `tcp.port == 7890` 这样的显示过滤器。

刚开始不用记住所有字段，先学会看 `Source`、`Destination`、`Protocol`、`Length`、`Info` 这五列就够了。
{% endnote %}

## 第二步：Statistics → Conversations 找流

菜单栏点 **`Statistics → Conversations`**（统计 → 会话），切到 **`TCP`** 标签页。你会看到一条 TCP 会话：

```text
Address A              Port A   Address B          Port B   Packets   Bytes
172.31.98.199          46046    192.155.81.86      7890     42        38
192.155.81.86          7890     172.31.98.199      46046    40        0
```

几个关键点：

- 只有**一条** TCP 连接，端口是 `7890`；
- 客户端发了 42 个包，但**总字节数只有 38**；
- 服务器回了 40 个包，**总字节数为 0**（只有 ACK，没有数据）。

42 个包只带了 38 字节，平均每个包不到 1 字节——这非常反常。正常的 HTTP/FTP 不会这样。**每个包只带 1 个字符**，这正是这道题的核心。

{% note warning %}
网上有些 writeup 把 `easycap` 和 VoIP/RTP 混在一起，那是另一道题（`voip`）。这道 `easycap` 的流量是 **TCP**，没有 RTP，也没有音频。做题时以自己抓到的包为准，不要被别人的标题带偏。
{% endnote %}

## 第三步：过滤出这条流

在过滤器栏输入：

```text
tcp.port == 7890
```

回车，包列表就只剩这条连接。再点一个客户端发出的包，看中间的 `Packet Details`：

```text
Transmission Control Protocol, Src Port: 46046, Dst Port: 7890, Seq: ..., Ack: ..., Len: 1
```

展开 `TCP` 层，注意 `Len: 1`——每个包的数据长度都是 1 字节。包列表的 `Info` 列也会显示类似：

```text
46046 → 7890 [PSH, ACK] Seq=1 Ack=1 Win=... Len=1
```

`Len=1` 是关键线索。你可以再加一个过滤器验证：

```text
tcp.len == 1
```

如果几乎所有业务包都满足 `tcp.len == 1`，基本可以确定这是**单字节隐蔽信道**：把一句话拆成一个个字符，每个 TCP 包只发一个。

## 第四步：右键 Follow → TCP Stream

选中任意一个客户端发出的包，右键 → **`Follow → TCP Stream`**（跟随 → TCP 流）。Wireshark 会弹出一个小窗口，把这条 TCP 连接的双向数据按序列号重新拼起来：

![Follow TCP Stream 的输出](01-follow-stream.png)

*图 1：Follow TCP Stream 把 38 个单字节包拼成了一行文本*

窗口底部有方向选择：

- `Client → Server`：客户端发给服务器的数据；
- `Server → Client`：服务器回给客户端的数据；
- `Entire conversation`：双向全部。

本题数据在 `Client → Server` 方向。如果默认显示的是另一个方向（空的），在窗口底部切换一下。

{% note success %}
**Follow TCP Stream 是流量题的第一神器。** 它会自动处理 TCP 的分段、重传、乱序，把应用层数据还原成可读文本。你不需要手动点 38 个包、按 Seq 排序再拼接。
{% endnote %}

## 第五步：从 FLAG 到 flag

流里读到的是：

```text
FLAG:385b87afc8671dee07550290d16a8071
```

题目要求 `flag{}` 格式，所以提交：

```text
flag{385b87afc8671dee07550290d16a8071}
```

## 第六步：如果没有 Wireshark，怎么手动还原？

理解原理很有用。每个 TCP 包有一个序列号（Seq），数据按 Seq 排序后拼接即可。用 Python 解析 pcap 的核心思路：

```python
import struct

data = open("easycap.pcap", "rb").read()
off = 24  # pcap 全局头 24 字节
segments = []

while off + 16 <= len(data):
    ts, tu, incl, orig = struct.unpack("<IIII", data[off:off + 16])
    off += 16
    pkt = data[off:off + incl]
    off += incl

    ip = pkt[14:]                 # 跳过以太网头
    ihl = (ip[0] & 0x0f) * 4
    if ip[9] != 6:                # 只处理 TCP
        continue

    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    tcp = ip[ihl:]
    sport, dport = struct.unpack(">HH", tcp[:4])
    doff = (tcp[12] >> 4) * 4
    seq = struct.unpack(">I", tcp[4:8])[0]
    payload = tcp[doff:]

    if payload and sport == 46046:
        segments.append((seq, payload))

segments.sort()
print(b"".join(p for _, p in segments).decode())
```

输出同样是：

```text
FLAG:385b87afc8671dee07550290d16a8071
```

{% note info %}
这段代码只是帮你理解 “Follow TCP Stream” 做了什么。实际做题优先用 Wireshark 的图形界面，快得多。手动解析要注意：以太网头 14 字节、IP 头长度由 `IHL` 决定、TCP 头长度由 `Data Offset` 决定，写错一个偏移就会读出乱码。
{% endnote %}

## 第七步：跟着做——用过滤器练习

打开 pcap 后，依次在过滤器栏输入这些，观察包列表变化：

| 过滤器 | 作用 |
| --- | --- |
| `tcp` | 只看 TCP |
| `tcp.port == 7890` | 只看这条连接 |
| `tcp.len == 1` | 只看携带 1 字节数据的包 |
| `tcp.flags.push == 1` | 只看 PSH 包（本题数据包基本都是） |
| `tcp contains "FLAG"` | 在单个 TCP 包里搜 `FLAG`——本题每包只有 1 字节，通常搜不到，用 Follow 更靠谱 |
| `ip.addr == 172.31.98.199` | 只看某个 IP 相关的包 |

再试一次 `Statistics → Conversations`，把 `Bytes` 列排序，看看哪条流的“包数/字节数”比例最反常。**异常比例本身就是线索。**

{% note success %}
Wireshark 的过滤器是流量分析的基本功。记住三个：

- `ip.addr == x.x.x.x`：按 IP；
- `tcp.port == 端口`：按端口；
- `tcp contains "关键字"`：按内容。

这三个能解决大部分入门流量题。
{% endnote %}

## 工具速查卡

| 操作 | 路径 | 说明 |
| --- | --- | --- |
| 打开 pcap | `File → Open` | 也支持 pcapng |
| 会话统计 | `Statistics → Conversations` | 看哪条流最可疑 |
| 协议分层 | `Statistics → Protocol Hierarchy` | 看协议分布 |
| 跟随 TCP | 右键 → `Follow → TCP Stream` | 本题核心 |
| 跟随 UDP | 右键 → `Follow → UDP Stream` | UDP 题用 |
| 导出对象 | `File → Export Objects` | HTTP 传文件时用 |
| 显示过滤器 | 顶部过滤栏 | `tcp.port ==`、`tcp.len ==` |

## 新手常见问题

{% note info **Q1：为什么全是 TCP，没有 UDP/RTP？** %}
这道 `easycap` 就是 TCP 单字节流。VoIP/RTP 是另一道题（`voip`），别混了。拿到 pcap 先看 `Statistics → Protocol Hierarchy`，以实际协议为准。
{% endnote %}

{% note info **Q2：怎么发现“每包 1 字节”的？** %}
看 `Statistics → Conversations` 的 `Packets` 和 `Bytes` 比例：42 个包才 38 字节，明显不正常。再点开包看 `TCP Len`，发现都是 1。
{% endnote %}

{% note info **Q3：Follow TCP Stream 出来是空的？** %}
切换窗口底部的方向：`Client → Server` / `Server → Client` / `Entire conversation`。本题数据只在客户端→服务器方向。
{% endnote %}

{% note info **Q4：流里出现乱码怎么办？** %}
在 Follow 窗口底部把 `Show data as` 切成 `ASCII` 或 `UTF-8`。如果还是乱码，可能是二进制协议或加密流量，需要换思路（导出对象、看文件头）。
{% endnote %}

{% note info **Q5：为什么序列号是连续的？** %}
TCP 用序列号保证可靠传输。本题每个包 1 字节，所以 Seq 每次加 1；按 Seq 排序拼接就是完整文本。如果有重传/乱序，Follow TCP Stream 会自动处理。
{% endnote %}

{% note info **Q6：`tcp contains "FLAG"` 为什么能命中？** %}
Wireshark 会在 TCP 载荷里做字符串搜索。本题的载荷就是逐个字符发出去的，拼起来包含 `FLAG`；但单个包里可能只有 `F`、`L`、`A`、`G`，所以 `contains` 不一定命中——**Follow TCP Stream 更可靠**。
{% endnote %}

{% note info **Q7：flag 前缀是 `FLAG:`，提交要去掉吗？** %}
提交格式是 `flag{...}`，把冒号后面的十六进制串放进花括号即可：`flag{385b87...}`。`FLAG:` 只是流量里的提示标签。
{% endnote %}

{% note info **Q8：这个 pcap 能用 tshark 分析吗？** %}
可以：

```bash
tshark -r easycap.pcap -q -z conv,tcp
tshark -r easycap.pcap -Y 'tcp.port==7890' -T fields -e tcp.payload
```

但初学先用 Wireshark 图形界面，`Follow TCP Stream` 更直观。
{% endnote %}

## 顺手聊聊：单字节隐蔽信道

正常的 TCP 连接不会每个包只带 1 字节——TCP/IP 头加起来至少 40 字节，为了 1 字节数据发一个包，开销是 40 倍以上。这种流量在真实网络里非常可疑：

- 可能是**隐蔽信道**（covert channel），用合法的 TCP 连接偷偷传数据；
- 可能是**心跳/保活**，但心跳一般不带业务数据；
- 可能是**恶意软件 C2**，每个包传一个字符/一个比特，躲避检测；
- 也可能是出题人故意构造的 CTF 流量。

检测思路：

| 思路 | 做法 |
| --- | --- |
| 包长异常 | 统计 `tcp.len` 分布，找大量 1 字节包 |
| 包数/字节比 | `Conversations` 里包多字节少 |
| 固定端口/固定间隔 | 看时间间隔是否规律 |
| 载荷熵 | 单字符载荷的熵很低，像明文 |
| 关联分析 | 多个短连接是否指向同一目的 |

{% note success %}
**一条经验**：流量分析先看“比例”和“异常”，不要一上来就逐包点。82 个包不可怕，可怕的是不知道自己在找什么。先 `Conversations`，再 `Follow`，最后才逐包看。
{% endnote %}
