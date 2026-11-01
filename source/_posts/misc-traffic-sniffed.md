---
title: "[BUUCTF] 被嗅探的流量：用 HTTP 过滤器从 POST 上传里捞出 flag"
date: 2026-11-01 09:00:00
updated: 2026-11-01 09:00:00
categories:
  - CTF
  - Misc
  - 流量分析
tags:
  - Misc
  - Wireshark
  - 显示过滤器
  - HTTP
  - POST
  - 流量分析
  - BUUCTF
description: 一个混杂着 DNS、SSDP、TCP 的 pcap。先用 Conversations 和 Protocol Hierarchy 看清全貌，再用 http.request.method == "POST" 把上传请求筛出来，Follow HTTP Stream 就能看到混在 JPEG 数据里的 flag。
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 5
permalink: 2026/11/01/misc-traffic-sniffed/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：Wireshark 显示过滤器、HTTP 请求结构、POST 上传、`multipart/form-data`
- **工具**：Wireshark（本文以 4.x 为准，3.x 菜单基本一致）
- **关键过滤器**：`http.request.method == "POST"`
- **关键操作**：命中后右键 → `Follow → HTTP Stream`，在流里搜 `flag`
- **flag**：`flag{d73d88936010da1eeb36e95eac4b97}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：会打开 pcap；知道 HTTP 请求由「请求行 + 请求头 + 请求体」组成；知道 TCP 有源/目的端口
- **工具**：Wireshark 官网免费下载；不想装图形界面可以用同目录的 `tshark`
- **环境**：纯本地分析，不需要靶机
- **配套阅读**：[easycap：Wireshark 跟流](/2026/10/30/misc-traffic-easycap/) 讲的是「一条 TCP 流里每包一个字符」，本文讲的是「HTTP 过滤器 + 上传文件」
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`打开 pcap` → `Statistics → Protocol Hierarchy / Conversations 看全貌` → `过滤 http.request.method == "POST"` → `锁定带图片的那条` → `Follow HTTP Stream` → `搜 flag` → `Export Objects 交叉验证`
{% endnote %}

## 这道题到底在考什么

题目叫「被嗅探的流量」。附件是一个抓包文件，里面混着 DNS 查询、SSDP 组播、TCP 握手、HTTP 上传等一大堆流量。

新手最容易犯的错是：**打开 pcap 后从第一个包开始逐个点**。几百个包点下来，眼睛花了，flag 还是没找到。

这道题真正考的是两件事：

1. 会不会用**显示过滤器**把无关流量一刀切掉；
2. 知不知道 **HTTP 的 POST 请求体里可能带着文件**，以及怎么把分段的 HTTP 请求重新拼成完整内容。

只要过滤器写对，这题其实只有两三步。

## 第一步：打开 pcap，先看全貌

用 Wireshark 打开附件，先不要急着点包，先看顶部的包列表：

![打开 pcap 后的包列表](image.png)

*图 1：列表里同时出现 DNS、SSDP、TCP、HTTP，说明这是一个「混合流量」包*

重点看这几列：

| 列 | 本题里看到什么 | 说明 |
| --- | --- | --- |
| `No.` | 包序号 | 后面跟流、讲步骤时用它定位 |
| `Time` | 相对时间 | 判断哪些包属于同一次交互 |
| `Source` | `172.16.66.100`、`172.16.80.120`、`114.114.114.114` 等 | 内网主机、Web 服务器、DNS 服务器 |
| `Destination` | 同上 | 谁发给谁 |
| `Protocol` | `DNS`、`SSDP`、`TCP`、`HTTP` | **先看协议分布** |
| `Length` | 几十到几百字节不等 | 异常长度往往是线索 |
| `Info` | `Standard query`、`POST /upload.php`、`[SYN]`…… | 最有信息量的一列 |

从这张图已经能读出几个事实：

- `114.114.114.114` 是常见的公共 DNS，前几十个包是 DNS 查询，和题目无关；
- `239.255.255.250` 是 SSDP 组播地址，属于设备发现协议，也和题目无关；
- 真正值得看的是 `172.16.66.100` 和 `172.16.80.120` 之间的 **HTTP** 流量；
- 已经能看到 `POST /upload.php` —— 这是一个**上传接口**。

{% note info %}
**先看协议分布，是流量题的第一习惯。**

菜单栏 `Statistics → Protocol Hierarchy`（统计 → 协议分级）会按协议统计包数和字节数。如果 90% 是 DNS/SSDP，那它们大概率是噪音；如果 HTTP 占比很小但出现了 `POST`、`upload` 这类关键词，那里才是主战场。

另一个入口是 `Statistics → Conversations`（统计 → 会话），按 IP/端口聚合。本题可以直接看到 `172.16.80.120:80` 这条 TCP 会话，包数和字节数都明显大于其他会话。
{% endnote %}

## 第二步：显示过滤器怎么写

Wireshark 顶部有一条绿色输入框，叫**显示过滤器**（Display Filter）。它不会丢弃已经抓到的包，只是把不匹配的隐藏起来，所以可以随时改、随时撤销。

新手只要记住三种写法就够用了：

| 想按什么筛 | 写法 | 例子 |
| --- | --- | --- |
| 协议 | 直接写协议名 | `http`、`dns`、`tcp` |
| 地址/端口 | `ip.addr`、`tcp.port` | `ip.addr == 172.16.80.120`、`tcp.port == 80` |
| 内容 | `contains` / `matches` | `http contains "flag"` |

再记住几个比较运算符：

| 运算符 | 含义 | 例子 |
| --- | --- | --- |
| `==` | 等于 | `http.response.code == 200` |
| `!=` | 不等于 | `tcp.port != 80` |
| `contains` | 包含字符串（区分大小写） | `http.request.uri contains "upload"` |
| `matches` | 正则匹配 | `http.host matches "ctf"` |
| `&&` / `and` | 与 | `http && ip.addr == 172.16.66.100` |
| `\|\|` / `or` | 或 | `http \|\| dns` |
| `!` / `not` | 非 | `!arp` |

{% note warning %}
两个容易踩的坑：

1. **字符串要加双引号**：`http.request.method == POST` 是错的，必须写 `http.request.method == "POST"`。
2. **区分显示过滤器和捕获过滤器**：抓包前设置的 BPF 过滤器（如 `tcp port 80`）是捕获过滤器，语法不同；这里在顶部输入的是显示过滤器，随便改，不影响已抓到的包。
{% endnote %}

## 第三步：只看 POST 请求

本题的线索是上传，所以直接把请求方法限定为 POST：

```text
http.request.method == "POST"
```

回车后，包列表只剩两条记录：

![过滤 POST 后的结果](image-1.png)

*图 2：过滤器命中两条 POST 记录，其中一条被 Wireshark 标注为 `(JPEG JFIF image)`*

从 `Info` 列能读出关键信息：

| 记录 | Info 里写了什么 | 怎么理解 |
| --- | --- | --- |
| 第 54 号 | `POST /upload.php HTTP/1.1` | 一条普通的 POST 请求 |
| 第 233 号 | `POST /upload.php HTTP/1.1 (JPEG JFIF image)` | Wireshark 在请求体里识别出了 **JPEG 图片** |

`JFIF` 是 JPEG 文件头里的标识。Wireshark 能直接在 `Info` 列标出图片类型，说明这个 POST 的请求体不是普通的表单文本，而是**文件上传**。

选中第 233 号包，看中间的包详情，可以看到：

```text
Hypertext Transfer Protocol
    POST /upload.php HTTP/1.1
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...
    ...
    [Reassembled TCP Segments: ...]
```

底部状态栏还会显示类似：

```text
[Reassembled TCP Segments (164748 bytes): #69, #70, #146, ...]
```

这说明这个上传请求**很大，被拆成了很多个 TCP 分段**。你在列表里点到的第 233 号只是其中一段，单看它当然看不全 flag。

{% note success %}
**只要看到 `Reassembled TCP Segments`，就不要单包读。** 右键 → `Follow → HTTP Stream`（或 `TCP Stream`），让 Wireshark 按序列号把所有分段拼回完整的 HTTP 请求，才是正确姿势。
{% endnote %}

## 第四步：Follow HTTP Stream，读出 flag

选中第 233 号包，右键 → **`Follow → HTTP Stream`**（跟随 → HTTP 流）。弹窗里会显示这次请求的完整内容：

- 请求行：`POST /upload.php HTTP/1.1`
- 请求头：`Host`、`Content-Type: multipart/form-data; boundary=...`
- 请求体：一长串二进制，开头是 JPEG 的 `JFIF` 标识
- 在二进制中间，夹着一段可读的 ASCII

把弹窗底部的 `Show data as` 切成 `ASCII`，或者在弹窗里按 `Ctrl+F` 搜 `flag`，就能看到：

```text
flag{d73d88936010da1eeb36e95eac4b97}
```

在图 2 下方的十六进制/ASCII 视图里，也能看到这段字符串混在 JPEG 二进制中（右侧 ASCII 区域）。

为什么 flag 会出现在图片数据里？因为这是一个 `multipart/form-data` 上传：

```http
POST /upload.php HTTP/1.1
Host: 172.16.80.120
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="file"; filename="xxx.jpg"
Content-Type: image/jpeg

<JPEG 二进制数据，中间夹着 flag 明文>
------WebKitFormBoundary...--
```

图片本身是二进制，但 flag 是以**明文 ASCII** 写进去的（可能在 EXIF 注释、JPEG 的 COM 段，或者直接追加在文件末尾）。用眼睛看图片看不出来，但在十六进制/ASCII 视图里一目了然。

{% note info %}
**为什么不用 `http contains "flag"` 直接搜？**

可以试，但不一定命中。这个上传请求有 16 万字节、被拆成很多 TCP 分段，`http contains` 是对**单个包**做匹配，而 flag 可能跨包；更稳妥的是先 `Follow` 拼出完整流，再在流里搜。

同理，`tcp contains "flag"` 也是单包匹配，不是全流搜索。
{% endnote %}

## 第五步：换个姿势——导出对象

除了 Follow，还可以让 Wireshark 把 HTTP 传输的文件直接导出来：

1. 菜单 `File → Export Objects → HTTP`（文件 → 导出对象 → HTTP）；
2. 列表里会列出这次抓包里所有通过 HTTP 传输的对象；
3. 找到 `upload.php` 对应的那条（通常带 `filename` 或 `image/jpeg` 类型），点 `Save` 保存；
4. 对保存下来的文件跑：

```bash
strings uploaded.jpg | grep -i flag
```

同样能得到：

```text
flag{d73d88936010da1eeb36e95eac4b97}
```

也可以用 `binwalk`、`foremost` 之类的工具拆文件，但这道题用 `strings` 就够了。

{% note warning %}
`Export Objects` 只对**完整的、Wireshark 能识别的 HTTP 对象**有效。如果对象太大、被分块传输（`Transfer-Encoding: chunked`）或者压缩过，列表里可能看不到，或者导出的是压缩后的内容。这时还是回到 `Follow HTTP Stream`，它最稳。
{% endnote %}

## 第六步：用 tshark 验证（可选）

不想开图形界面，可以用命令行版 Wireshark：

```bash
# 只看 POST 请求的 URI
tshark -r 被嗅探的流量.pcap -Y 'http.request.method == "POST"' -T fields -e frame.number -e http.request.uri

# 把 HTTP 对象导出到 out 目录
tshark -r 被嗅探的流量.pcap --export-objects http,out

# 跟随某条 TCP 流（这里假设是第 2 条流）
tshark -r 被嗅探的流量.pcap -q -z follow,tcp,ascii,2
```

第 1 条命令的输出应该能看到类似：

```text
54    /upload.php
233   /upload.php
```

和图形界面里过滤出来的两条记录完全对得上。这也说明：**过滤器写对了，工具只是外壳。**

## 过滤器速查卡

| 过滤器 | 作用 | 本题用途 |
| --- | --- | --- |
| `http` | 所有 HTTP 报文 | 先看 HTTP 占比 |
| `http.request` | 只看请求 | 排除响应 |
| `http.request.method == "POST"` | 只看 POST | **本题核心** |
| `http.request.uri contains "upload"` | URI 含 upload | 定位上传接口 |
| `http.response.code == 200` | 只看 200 响应 | 看上传结果 |
| `http.host == "172.16.80.120"` | 按 Host 过滤 | 锁定目标站 |
| `ip.addr == 172.16.66.100` | 按 IP 过滤 | 看某台主机 |
| `tcp.port == 80` | 按端口过滤 | 只看 Web 流量 |
| `tcp.stream eq 2` | 只看第 2 条 TCP 流 | 跟流时非常有用 |
| `tcp.len > 0` | 只看带数据的包 | 排除纯 ACK |
| `http contains "flag"` | 单包内容搜索 | 快速试探，但可能跨包失败 |
| `frame contains "flag"` | 整帧搜索 | 同上 |

{% note info %}
**怎么知道 `tcp.stream` 的编号？**

随便点一个包，展开 `Transmission Control Protocol`，里面有一行 `[Stream index: 2]`。或者在过滤器里输入 `tcp.stream eq 2` 一个个试。本题截图底部就写着 `[Stream index: 2]`。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么列表里前几十个包都是 DNS？** %}
抓包环境里有主机在做域名解析（包括反向解析 `PTR`），这些和题目无关。用 `Statistics → Protocol Hierarchy` 看一眼，心里有数就行，不必逐包分析。
{% endnote %}

{% note info **Q2：过滤 POST 后为什么有两条？** %}
一条是请求本身，另一条是携带 JPEG 数据的分段。Wireshark 把同一次 HTTP 交互拆成了多条记录显示。选带 `(JPEG JFIF image)` 标记的那条，再 Follow 即可。
{% endnote %}

{% note info **Q3：Follow 窗口里全是乱码怎么办？** %}
把 `Show data as` 切成 `ASCII` 或 `Hex Dump`。二进制文件在 ASCII 视图下本来就会夹杂乱码，重点是在乱码中间找连续的、可读的 `flag{...}`。
{% endnote %}

{% note info **Q4：Follow HTTP Stream 和 Follow TCP Stream 有什么区别？** %}
- `Follow TCP Stream`：按 TCP 连接顺序拼接，包含 TCP 层重组，适合普通流；
- `Follow HTTP Stream`：按 HTTP 消息边界拼接，会把请求行、请求头、请求体分清楚，更适合本题这种上传请求。

两个都能用；HTTP 题优先用 HTTP Stream。
{% endnote %}

{% note info **Q5：为什么 `flag` 前面的内容是乱码？** %}
那是 JPEG 的二进制数据（`FF D8 FF E0 ... JFIF ...`）。flag 是被人为写进图片里的明文，不是图片本身的内容，所以周围必然是二进制。
{% endnote %}

{% note info **Q6：`Export Objects` 里找不到上传的图片？** %}
可能是因为请求体太大、被分段，或者 Wireshark 没有识别出完整的对象。直接 Follow 流更可靠；也可以先用 `tshark --export-objects` 试试。
{% endnote %}

{% note info **Q7：pcap 和 pcapng 有区别吗？** %}
都是抓包格式。`pcap` 更老、兼容性最好；`pcapng` 支持多接口、注释等扩展。Wireshark 两种都能直接打开，做题时不用纠结。
{% endnote %}

{% note info **Q8：为什么 flag 是 `flag{...}`，不是 `FLAG:` 开头？** %}
不同题目的提交格式不同。本题流量里的明文就是完整的 `flag{d73d88936010da1eeb36e95eac4b97}`，直接原样提交即可。遇到 `FLAG:xxx` 这种，再按平台要求转换格式。
{% endnote %}

## 工具速查卡

| 操作 | 路径 | 说明 |
| --- | --- | --- |
| 打开 pcap | `File → Open` | 支持 pcap / pcapng |
| 协议分级 | `Statistics → Protocol Hierarchy` | 看协议分布，找噪音 |
| 会话统计 | `Statistics → Conversations` | 看哪条流包多/字节多 |
| 显示过滤器 | 顶部绿色输入框 | 本题核心，`http.request.method == "POST"` |
| 跟随 HTTP 流 | 右键 → `Follow → HTTP Stream` | 推荐 |
| 跟随 TCP 流 | 右键 → `Follow → TCP Stream` | 通用备选 |
| 导出 HTTP 对象 | `File → Export Objects → HTTP` | 保存上传的文件 |
| 搜索 | `Ctrl+F`（Follow 窗口内） | 搜 `flag` |
| 查看流编号 | 展开 TCP 层 → `[Stream index: N]` | 配合 `tcp.stream eq N` |
| 时间显示 | `View → Time Display Format` | 切换相对/绝对时间 |

## 顺手聊聊：明文 HTTP 的代价

这道题的名字叫「被嗅探的流量」，本身就点出了现实里的问题：**HTTP 是明文协议**。同一个局域网里，只要攻击者能抓到包，就能看到：

- 你访问了哪个路径、提交了什么参数；
- 你上传/下载了什么文件；
- 表单里的用户名、密码、token（如果没有额外加密）。

对应的防护思路：

| 风险 | 防护 |
| --- | --- |
| 流量被嗅探 | 全站 HTTPS，开启 HSTS，禁用明文 HTTP |
| 上传内容泄露 | 上传走 TLS；敏感文件加密后再传 |
| 内网横向抓包 | 网络分段、交换机端口安全、802.1X |
| 事后取证 | 保留 pcap，结合 `Conversations` 和 `Follow` 快速定位 |

{% note success %}
**一条经验**：流量分析题不要一上来就逐包点。先 `Protocol Hierarchy` 看协议分布，再 `Conversations` 看会话，然后用过滤器缩小范围，最后 `Follow` 拼内容。顺序对了，几百个包也只是几分钟的事。
{% endnote %}
