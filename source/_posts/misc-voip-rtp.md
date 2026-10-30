---
title: "[BUUCTF] voip：Wireshark RTP 播放器听出 flag"
date: 2026-10-30 10:30:00
updated: 2026-10-30 10:30:00
categories:
  - CTF
  - Misc
  - 流量分析
tags:
  - Misc
  - Wireshark
  - VoIP
  - RTP
  - SIP
  - BUUCTF
description: 一个 SIP 通话的 pcap。用 Wireshark 的 Telephony → VoIP Calls 找到通话，再用 RTP Player 播放，音频里直接念出了 flag。
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 4
permalink: 2026/10/30/misc-voip-rtp/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：Wireshark VoIP 分析、SIP 信令、RTP 音频
- **工具**：Wireshark（Telephony 菜单 + RTP Player）
- **关键操作**：`Telephony → VoIP Calls` 找到通话 → `Player` 播放 RTP 流
- **flag**：`flag{9001IVR}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 UDP、端口、Wireshark 的包列表和过滤器
- **工具**：Wireshark。RTP Player 需要能播放音频的环境；没有声音也可以看波形/导出音频。
- **环境**：本地分析 pcap，不需要靶机。
- 本文仅用于**授权题目和教学**。窃听未授权的通话是违法的，请只在 CTF/授权环境练习。
{% endnote %}

{% note default %}
**做题路线**

`打开 pcap` → `看协议分布` → `Telephony → VoIP Calls` → `找到 SIP 通话` → `打开 RTP Player` → `播放音频` → `听出 flag`
{% endnote %}

## 第一步：打开 pcap，先认协议

附件是一个 533 KB 的 pcap，2302 个包。用 Wireshark 打开，先看 `Statistics → Protocol Hierarchy`（协议分层）：

| 协议 | 作用 | 本题占比 |
| --- | --- | --- |
| `SIP` | 通话信令：建立、振铃、挂断 | 很少，十几条 |
| `RTP` | 真正传输语音的协议 | 绝大多数 |
| `UDP` | SIP 和 RTP 的底层传输 | 全部 |
| `TCP` | 本题几乎没有 | 0 |

看到 SIP + RTP，基本可以确定这是一通 **VoIP 电话**。SIP 负责“打电话”（信令），RTP 负责“说话”（媒体）。

{% note info %}
**SIP 和 RTP 的分工**

- **SIP**（Session Initiation Protocol）：类似“拨号 + 振铃 + 接通 + 挂断”的信令。常见方法有 `INVITE`、`ACK`、`BYE`、`OPTIONS`。默认走 UDP 5060。
- **RTP**（Real-time Transport Protocol）：真正承载语音/视频的包。每个包有序列号、时间戳、SSRC，接收方按这些字段排序、播放。
- **SDP**：SIP 消息体里的一段描述，告诉对方“我的媒体地址、端口、编码格式是什么”。

本题的 SIP 走 UDP 5060，RTP 走 UDP 5066 ↔ 14728，编码是 PCMU（G.711 μ-law，8 kHz）。
{% endnote %}

## 第二步：Telephony → VoIP Calls

Wireshark 专门为 VoIP 准备了一个菜单：**`Telephony`**（电话）。

点 **`Telephony → VoIP Calls`**，会弹出一个窗口，列出它识别到的所有 SIP 通话：

```text
Call                       From              To                State
8a9697a4-...@localhost     2001              9001              Completed
```

选中这通电话，底部有几个按钮：

| 按钮 | 作用 |
| --- | --- |
| `Flow` | 画出 SIP 信令的时序图（谁发了 INVITE、谁回了 200 OK） |
| `Player` | 打开 RTP Player，播放这通电话的音频 |
| `Graph` | 类似 Flow，带更多细节 |
| `Prepare Filter` | 自动生成过滤这通电话的显示过滤器 |

点 **`Player`**，就进入本题的核心：**RTP Player**。

{% note warning %}
如果 `VoIP Calls` 窗口是空的，说明 Wireshark 没有把这段 SIP 识别成一通完整通话（可能缺少 SDP、端口不标准、或者 pcap 不完整）。别慌，直接走 `Telephony → RTP → RTP Player`，它会列出所有 RTP 流，手动选一条播放。
{% endnote %}

## 第三步：看 SIP 信令，理解通话过程

点 `Flow` 可以看到类似下面的时序：

![SIP 通话时序](03-sip-flow.png)

*图 1：2001 呼叫 9001，先被 401 要求认证，带 Authorization 重发 INVITE，最后 200 OK 接通，通话结束后 BYE*

对应的关键消息：

| 方向 | 消息 | 含义 |
| --- | --- | --- |
| 2001 → 9001 | `INVITE sip:9001` | 发起呼叫 |
| 9001 → 2001 | `401 Unauthorized` | 要求认证 |
| 2001 → 9001 | `ACK` | 确认收到 401 |
| 2001 → 9001 | `INVITE` + `Authorization` | 带认证信息重发 |
| 9001 → 2001 | `100 Trying` | 正在处理 |
| 9001 → 2001 | `200 OK` | 接通，SDP 里带媒体地址/端口/编码 |
| 2001 → 9001 | `ACK` | 确认接通 |
| 双向 | `RTP` | 开始传语音 |
| 9001 → 2001 | `BYE` | 挂断 |
| 2001 → 9001 | `200 OK` | 确认挂断 |

在 `200 OK` 的 SDP 里，你能看到类似：

```text
m=audio 14728 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```

- `m=audio 14728`：媒体端口 14728；
- `RTP/AVP 0`：payload type 0，对应 PCMU；
- `PCMU/8000`：G.711 μ-law，8 kHz 采样。

这些信息解释了为什么 RTP 流是 `5066 ↔ 14728`，以及为什么每个 RTP 包是 160 字节（20 ms 的 8 kHz μ-law 音频）。

## 第四步：RTP Player 播放音频

`Telephony → VoIP Calls → Player` 打开的 **RTP Player** 长这样（不同版本略有差异）：

```text
┌─ RTP Player ───────────────────────────────────────────────┐
│  [▶ Play]  [■ Stop]  [Save]        Streams: 2              │
│                                                            │
│  SSRC 3857925270   ────────                               │
│  SSRC 1503454853   ████████████████████████████████████    │
│                                                            │
│  Time: 0.0s ─────────────────────────────────────── 24.0s  │
└────────────────────────────────────────────────────────────┘
```

操作顺序：

1. 在流列表里**勾选**要播放的流（本题有两条，两个方向各一条）；
2. 点 **`Play`**；
3. 听音频。

本题的音频内容大致是：

```text
Hi, this is Echo IVR Service.
Please press 1 to listen to the flag.
Press 9 to exit.
The flag is S-E-C-C-O-N, open brace 9-0-0-1-I-V-R, close brace.
Only capital letters, no spaces.
```

也就是说，语音在念：

```text
SECCON{9001IVR}
```

{% note success %}
**听不清怎么办？** RTP Player 里可以放大波形、拖动时间轴、单独播放某一条流。两个方向都听一遍，通常只有一条有声音（另一条是静音或回声）。如果电脑没有声音，可以点 `Save` 导出音频，再用播放器听。
{% endnote %}

## 第五步：从语音到 flag

语音里念的是原始题目的 flag：

```text
SECCON{9001IVR}
```

BUUCTF 迁移后，题目要求提交 `flag{}` 格式。这里要注意：**`SECCON` 是原比赛的 flag 前缀，不是内容**。实际提交时把里面的内容 `9001IVR` 包进 `flag{}`：

```text
flag{9001IVR}
```

{% note warning %}
这是一个很容易踩的坑：语音里明明念的是 `SECCON{9001IVR}`，但直接提交 `flag{SECCON{9001IVR}}` 会被判错。BUUCTF 的迁移题通常只保留**花括号里的内容**，再套上平台的 `flag{}`。做题时先看题目描述里的格式要求，再决定怎么包。
{% endnote %}

## 第六步：没有声音？看波形和频谱

如果 RTP Player 播不出声音（声卡、编码器、远程桌面等原因），可以从视觉上确认哪条流有语音。

**波形**：把 RTP 载荷按 PCMU 解码后，能看到明显的语音段落（有声音的地方振幅大，静音处接近 0）：

![RTP 语音波形](01-waveform.png)

*图 2：重建出来的 24 秒语音波形，中间有明显的说话段落和停顿*

**频谱**：语音的共振峰在频谱图上看得很清楚，静音处几乎没有能量：

![RTP 语音频谱](02-spectrogram.png)

*图 3：0–4 kHz 的频谱图，横轴是时间，亮的地方是语音能量*

这两张图不是做题必需，但能帮你判断“这条流到底有没有人说话”，避免在静音流上浪费时间。

{% note info %}
RTP 的 payload type 0 是 PCMU（G.711 μ-law），每个字节是一个 8 kHz 采样点。把 μ-law 解码成 16 位 PCM，再按 8000 Hz 写成 WAV，就能用任意播放器听。Wireshark 的 RTP Player 内部做的就是这件事。
{% endnote %}

## 第七步：跟着做——用过滤器定位 RTP

打开 pcap 后，依次在过滤器栏输入：

| 过滤器 | 作用 |
| --- | --- |
| `sip` | 只看 SIP 信令 |
| `rtp` | 只看 RTP 媒体包 |
| `udp.port == 5060` | 只看 SIP |
| `udp.port == 5066` | 只看其中一个方向的 RTP |
| `rtp.ssrc == 3857925270` | 只看某个 SSRC 的流 |

再打开 `Statistics → Conversations → UDP`，按 `Packets` 排序，你会看到两条大的 RTP 流和几条小的 SIP/RTCP 流。**包数最多、持续最久的那两条就是语音。**

{% note success %}
VoIP 题的标准流程：

1. `Telephony → VoIP Calls` 找通话；
2. `Player` 播放；
3. 听不清就 `Save` 导出；
4. 还是没有就 `Telephony → RTP → Show All Streams`，逐条分析。

90% 的入门 VoIP 题，到第 2 步就结束了。
{% endnote %}

## 工具速查卡

| 操作 | 路径 | 说明 |
| --- | --- | --- |
| 通话列表 | `Telephony → VoIP Calls` | 找 SIP 通话 |
| 信令时序 | `VoIP Calls → Flow` | 看 INVITE/200/BYE |
| 播放音频 | `VoIP Calls → Player` | 本题核心 |
| RTP 流列表 | `Telephony → RTP → Show All Streams` | 没有 VoIP Calls 时用 |
| RTP 分析 | `Telephony → RTP → RTP Player` | 选流、播放、保存 |
| 导出音频 | RTP Player → `Save` | 保存为音频文件 |
| 过滤器 | `sip`、`rtp`、`udp.port ==` | 快速定位 |

## 新手常见问题

{% note info **Q1：VoIP Calls 窗口是空的？** %}
说明 Wireshark 没识别出完整通话。直接走 `Telephony → RTP → RTP Player`，或者先用过滤器 `rtp` 看有没有 RTP 包。只要能播放 RTP，就能听到 flag。
{% endnote %}

{% note info **Q2：RTP Player 没有声音？** %}
先确认系统音量、输出设备；再确认勾选了正确的流；然后点 `Play`。如果还是没声音，点 `Save` 导出音频，用本地播放器听。远程桌面/虚拟机可能没有音频设备，导出是最稳的。
{% endnote %}

{% note info **Q3：两条流，听哪一条？** %}
两个方向各一条。通常只有一条有说话声，另一条是静音/回声。两条都点一下 `Play`，有声音的那条就是。也可以看波形：有振幅变化的那条有语音。
{% endnote %}

{% note info **Q4：音频是断断续续的？** %}
RTP 包可能乱序、丢包，或者你只选了一条流。RTP Player 会按序列号/时间戳排序；如果丢包严重，听起来会断。CTF 题一般不会故意丢包，检查是不是选错了流。
{% endnote %}

{% note info **Q5：为什么语音里是 `SECCON{...}`，提交却是 `flag{...}`？** %}
`SECCON` 是原比赛的 flag 前缀；BUUCTF 迁移后要求用平台的 `flag{}` 格式，只保留花括号里的内容。以题目描述为准。
{% endnote %}

{% note info **Q6：SIP 里的 401 和 Authorization 是什么？** %}
SIP 的认证流程：服务器先回 `401 Unauthorized`，客户端带 `Authorization` 头重发 `INVITE`。这不是题目考点，但看懂时序图有帮助。
{% endnote %}

{% note info **Q7：RTP 和 RTCP 怎么区分？** %}
RTP 通常走偶数端口，承载媒体；RTCP 走相邻的奇数端口，传统计信息。本题主要看 RTP。过滤器 `rtp` 只匹配 RTP，`rtcp` 匹配 RTCP。
{% endnote %}

{% note info **Q8：能用 tshark 提取音频吗？** %}
可以，但初学不建议手写。Wireshark 的 RTP Player 已经帮你解码、排序、播放。需要批量处理时再研究 `tshark` 的 RTP 导出功能。
{% endnote %}

## 顺手聊聊：VoIP 窃听与防护

VoIP 把电话搬到了 IP 网络上，方便的同时也带来了新风险：

- **SIP 默认不加密**：信令里的号码、认证信息、媒体地址都可能被嗅探；
- **RTP 默认不加密**：同一网段的人抓到包就能还原语音；
- **认证强度**：弱口令/默认密码的 SIP 账号容易被冒用；
- **网络边界**：把 VoIP 和办公网混在一起，攻击面更大。

防护思路：

| 措施 | 说明 |
| --- | --- |
| **SIP over TLS** | 加密信令，防窃听/篡改 |
| **SRTP** | 加密 RTP 媒体，抓包也听不到 |
| **网络分段** | VoIP 走独立 VLAN，限制嗅探范围 |
| **强认证** | 复杂密码、定期更换、禁用默认账号 |
| **最小权限** | SIP 账号只能呼指定号码/区域 |
| **监控异常** | 大量短通话、异常注册、非工作时间呼叫 |

{% note success %}
**一条经验**：CTF 里的 VoIP 题是“用 Wireshark 听电话”，真实世界里对应的就是“未加密的语音通话可以被窃听”。做题时学会工具，写代码时记得给信令和媒体都加上加密。
{% endnote %}
