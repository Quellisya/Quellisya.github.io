---
title: "[JBCTF] wireshark：从 HTTP 登录表单里找出 password"
date: 2026-11-01 10:20:00
updated: 2026-11-01 10:20:00
categories:
  - CTF
  - Misc
  - 流量分析
tags:
  - Misc
  - Wireshark
  - HTTP
  - POST
  - 表单
  - 流量分析
  - JBCTF
description: 题目要求找 password。pcap 里混着 DNS 和 TCP，但真正的线索是第 20 号包：一个发往登录接口的 HTTP POST，请求体是 application/x-www-form-urlencoded，password 字段的值就是 flag 的内容。
difficulty: 入门
topic: Misc
series: Misc 入门
series_order: 6
permalink: 2026/11/01/misc-wireshark-password/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：Wireshark 显示过滤器、HTTP POST、`application/x-www-form-urlencoded` 表单解析
- **工具**：Wireshark（或 `tshark`）
- **关键过滤器**：`http contains "password"`，也可以用 `http.request.method == "POST"`
- **关键字段**：`HTML Form URL Encoded → password`
- **flag**：`flag{ffb7567a1d4f4abdffdb54e022f8facd}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 HTTP 请求由请求行、请求头、请求体组成；见过 Wireshark 的包列表和包详情
- **工具**：Wireshark 4.x（3.x 菜单基本一致）；不想开图形界面可以用 `tshark`
- **环境**：纯本地分析 pcap，不需要靶机，也不需要访问包里的域名
- **配套阅读**：[被嗅探的流量：用 HTTP 过滤器从 POST 上传里捞出 flag](/2026/11/01/misc-traffic-sniffed/) 讲的是「POST + 文件上传」，本文讲的是「POST + 登录表单」
- 本文仅用于**授权题目和教学**。
{% endnote %}

{% note default %}
**做题路线**

`打开 pcap` → `看协议分布` → `过滤 http contains "password"` → `锁定登录 POST` → `展开 HTML Form URL Encoded` → `读出 password` → `包上 flag{}`
{% endnote %}

## 这道题在考什么

题目只有一句话：**找 password**。附件是一个 2015 年的抓包文件：

```text
dianli_jbctf_MISC_T10075_20150707_wireshark.pcap
```

这类题不考解密，也不考协议逆向。它考的是：

1. 能不能从一堆 DNS、TCP 握手里，快速定位到**登录请求**；
2. 知不知道 HTTP 的 `application/x-www-form-urlencoded` 表单在 Wireshark 里长什么样；
3. 能不能把表单里的 `password` 字段值准确抄下来。

只要过滤器用对，这题一分钟就能出结果。

## 第一步：打开 pcap，先看全貌

用 Wireshark 打开附件。包列表里有 DNS 查询、TCP 握手、HTTP 请求，看起来又是一道「混合流量」题：

![打开 pcap 后的包列表](image-2.png)

*图 1：第 20 号包是一条 POST 请求，Info 列写着 `/user.php?action=login&do=login`*

先看几列关键信息：

| 列 | 第 20 号包的内容 | 说明 |
| --- | --- | --- |
| `No.` | `20` | 后面定位就靠它 |
| `Source` | `192.168.1.102` | 客户端（内网主机） |
| `Destination` | `115.231.236.116` | 服务器 |
| `Protocol` | `HTTP` | 明文 HTTP，内容可读 |
| `Length` | `863` | 请求比较大，说明带了不少数据 |
| `Info` | `POST /user.php?action=login&do=login HTTP/1.1 (application/x-www-form-urlencoded)` | **登录接口 + 表单提交** |

`Info` 列已经给了三个关键词：

- `POST`：提交数据；
- `login`：登录；
- `application/x-www-form-urlencoded`：传统的 HTML 表单编码。

题目要找 `password`，而登录请求的请求体里最可能出现的字段就是 `password`。方向明确了。

{% note info %}
**看到混合流量，先做减法。**

包列表上方 `Statistics → Protocol Hierarchy` 可以看协议分布；`Statistics → Conversations` 可以看哪条会话包最多。本题的 DNS 查询（`nslcick.baidu.com`、`hm.baidu.com` 等）和 TCP 握手都是噪音，真正带业务数据的是那条 HTTP 会话。

减掉噪音之后，剩下的包越少，越不容易看漏。
{% endnote %}

## 第二步：用过滤器把 password 筛出来

Wireshark 顶部有一条显示过滤器输入框。题目要找 `password`，最直接的办法就是按内容搜：

```text
http contains "password"
```

回车后，包列表只剩第 20 号包：

![过滤 http contains "password"](image-3.png)

*图 2：只有一条记录命中，说明这个 HTTP 请求里确实出现了 `password`*

也可以换几种等价写法：

| 过滤器 | 作用 | 本题结果 |
| --- | --- | --- |
| `http contains "password"` | 在 HTTP 层按内容搜 | 命中第 20 号 |
| `http.request.method == "POST"` | 只看 POST | 也能命中第 20 号 |
| `http.request.uri contains "login"` | URI 里带 login | 也能命中 |
| `urlencoded-form.key == "password"` | 只看表单里 key 为 password 的字段 | 精确命中 |
| `http.host == "www.wooyun.org"` | 按 Host 过滤 | 命中同一条会话 |

{% note warning %}
两个常见的写法错误：

1. **字符串必须加双引号**：`http contains password` 是错的，要写 `http contains "password"`。
2. **大小写**：`contains` 默认区分大小写。表单里的字段名是小写 `password`，所以搜小写；如果题目写的是 `Password`，就要对应改。

另外，`http contains` 搜的是**单个包**的 HTTP 层内容。如果表单被拆到多个 TCP 分段里，单个包可能搜不全；这时用 `Follow HTTP Stream` 或 `tcp contains` 配合分段查看。
{% endnote %}

## 第三步：展开包详情，读表单字段

选中第 20 号包，看中间的包详情。展开 `Hypertext Transfer Protocol`，再展开 `HTML Form URL Encoded`，会看到：

```text
HTML Form URL Encoded: application/x-www-form-urlencoded
    Form item: "email" = "flag"
        Key: email
        Value: flag
    Form item: "password" = "ffb7567a1d4f4abdffdb54e022f8facd"
        Key: password
        Value: ffb7567a1d4f4abdffdb54e022f8facd
    ...
```

其中最关键的两行：

```text
Key: password
Value: ffb7567a1d4f4abdffdb54e022f8facd
```

这就是题目要找的 `password`。右侧的十六进制/ASCII 视图也能看到同一段数据：

```text
...password=ffb7567a1d4f4abdffdb54e022f8facd...
```

{% note success %}
**Wireshark 已经把表单拆好了，不需要自己解析。**

看到 `application/x-www-form-urlencoded`，Wireshark 会自动把请求体解析成 `Form item` 列表。你只要展开 `HTML Form URL Encoded`，找到 `password` 对应的 `Value` 即可。

如果包详情里没有这个节点，可能是版本差异，或者请求体没有被识别；这时用 `Follow → HTTP Stream` 看原始请求体，一样能找到。
{% endnote %}

### 3.1 顺便看懂 `x-www-form-urlencoded`

请求体大概是这个形状：

```text
email=flag&key=email&value=flag&password=ffb7567a1d4f4abdffdb54e022f8facd&...
```

规则很简单：

| 规则 | 例子 |
| --- | --- |
| 字段之间用 `&` 分隔 | `a=1&b=2` |
| 键和值用 `=` 连接 | `password=xxx` |
| 特殊字符做 URL 编码 | 空格 → `+` 或 `%20`，中文/符号 → `%XX` |

所以 `password=ffb7567a...` 就是「字段名 password，值 ffb7567a...」。

## 第四步：换一种看法——Follow HTTP Stream

如果包详情里的字段太多、看不清，可以右键第 20 号包 → **`Follow → HTTP Stream`**。弹窗会把整个请求还原出来：

```http
POST /user.php?action=login&do=login HTTP/1.1
Host: www.wooyun.org
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 65

email=flag&key=email&value=flag&password=ffb7567a1d4f4abdffdb54e022f8facd&...
```

在弹窗里按 `Ctrl+F` 搜 `password`，直接跳到对应位置。

{% note info %}
**Follow HTTP Stream 和包详情的区别：**

- 包详情：按协议字段分层展示，适合**精确读某个字段**；
- Follow HTTP Stream：按 HTTP 消息还原原始文本，适合**看整体结构**、搜关键字、确认请求体有没有被截断。

两个都用一遍，互相验证，最稳。
{% endnote %}

## 第五步：提交 flag

题目说「找到 value 的值，包裹 `flag{}`」。所以：

```text
password = ffb7567a1d4f4abdffdb54e022f8facd
flag     = flag{ffb7567a1d4f4abdffdb54e022f8facd}
```

提交：

```text
flag{ffb7567a1d4f4abdffdb54e022f8facd}
```

{% note warning %}
抄写时注意：

- 这是 32 位十六进制字符串，**全是小写**；
- 不要漏字符、不要多空格；
- 不要把它当成 MD5 去「解密」——题目要的就是这个值本身，flag 内容已经给出来了。

如果不放心，可以在 Wireshark 里选中 `Value` 右键 → `Copy → Value`，避免手抄出错。
{% endnote %}

## 第六步：用 tshark 验证（可选）

不想开图形界面，可以用命令行版 Wireshark：

```bash
# 只看命中 password 的请求 URI
tshark -r dianli_jbctf_MISC_T10075_20150707_wireshark.pcap \
  -Y 'http contains "password"' \
  -T fields -e frame.number -e http.request.uri

# 直接提取表单里的 password 字段
tshark -r dianli_jbctf_MISC_T10075_20150707_wireshark.pcap \
  -Y 'urlencoded-form.key == "password"' \
  -T fields -e urlencoded-form.value
```

第二条命令应该直接输出：

```text
ffb7567a1d4f4abdffdb54e022f8facd
```

也可以先跑一遍 `strings` 做快速试探：

```bash
strings dianli_jbctf_MISC_T10075_20150707_wireshark.pcap | grep -i password
```

如果 pcap 没有压缩，通常能看到：

```text
password=ffb7567a1d4f4abdffdb54e022f8facd
```

{% note info %}
`strings` 只适合**未压缩、未加密**的明文流量。遇到 HTTPS、gzip 压缩或者二进制协议，`strings` 可能什么都搜不到，这时还是回到 Wireshark 的协议解析和 Follow Stream。
{% endnote %}

## 过滤器与字段速查卡

| 过滤器 / 字段 | 作用 | 本题用法 |
| --- | --- | --- |
| `http` | 所有 HTTP 报文 | 先缩小到 HTTP |
| `http.request` | 只看请求 | 排除响应 |
| `http.request.method == "POST"` | 只看 POST | 找登录/提交 |
| `http.request.uri contains "login"` | URI 含 login | 定位登录接口 |
| `http contains "password"` | HTTP 层按内容搜 | **本题核心** |
| `urlencoded-form.key == "password"` | 表单 key 精确匹配 | 最精确 |
| `urlencoded-form.value` | 表单 value 字段 | 提取值 |
| `tcp contains "password"` | TCP 载荷按内容搜 | 备用 |
| `frame contains "password"` | 整帧按内容搜 | 备用 |
| `http.host == "www.wooyun.org"` | 按 Host 过滤 | 锁定站点 |
| `tcp.stream eq N` | 只看某条 TCP 流 | 配合 Follow |

{% note info %}
**怎么知道 `urlencoded-form` 这个字段名？**

在包详情里点一下 `Form item: "password"` 那一行，Wireshark 底部状态栏会显示对应的显示过滤器字段名，例如 `urlencoded-form.key`。这是学习过滤器字段最快的方法：**点字段，看底部提示**。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么 `http contains "password"` 能匹配到？** %}
因为这是明文 HTTP，`password=...` 直接出现在请求体里。`http contains` 会在 HTTP 协议层的数据中做字符串搜索，请求行、请求头、请求体都算在内。
{% endnote %}

{% note info **Q2：为什么我搜不到？** %}
常见原因：

1. 忘了加双引号；
2. 大小写写错（`contains` 区分大小写）；
3. 流量是 HTTPS，内容被 TLS 加密，Wireshark 只能看到加密数据；
4. 请求体被 gzip 压缩；
5. 关键字跨了多个 TCP 分段，单个包不含完整字符串。

先确认协议和端口，再换 `Follow HTTP Stream` 看原始内容。
{% endnote %}

{% note info **Q3：`http contains`、`tcp contains`、`frame contains` 有什么区别？** %}
- `http contains`：只在 HTTP 协议层搜，适合 HTTP 题；
- `tcp contains`：在 TCP 载荷里搜，范围比 HTTP 大；
- `frame contains`：在整帧（包括链路层、IP 层）里搜，范围最大。

一般优先用范围最小的那个，结果最干净。
{% endnote %}

{% note info **Q4：`application/x-www-form-urlencoded` 是什么？** %}
HTML 表单默认的提交编码。格式是 `key1=value1&key2=value2`，特殊字符用 URL 编码。Wireshark 会自动把它解析成 `HTML Form URL Encoded` 节点。
{% endnote %}

{% note info **Q5：为什么 password 看起来像一串哈希？** %}
它是 32 位十六进制字符串，长度和 MD5 一样，很可能是客户端先对密码做了哈希再提交。但本题不要求还原明文，题目要的就是这个值本身。
{% endnote %}

{% note info **Q6：需要访问 `www.wooyun.org` 吗？** %}
不需要。这是 2015 年的历史抓包，域名现在早已不可用。所有分析都在本地 pcap 里完成。
{% endnote %}

{% note info **Q7：包列表里第 20 号包为什么这么大？** %}
`Length` 是 863 字节，里面除了请求行和请求头，还有 Cookie、User-Agent、Referer 和表单请求体。登录请求通常比普通 GET 大。
{% endnote %}

{% note info **Q8：`Follow HTTP Stream` 里内容显示不全 / 乱码？** %}
在弹窗底部切换 `Show data as`：`ASCII` 看文本，`Hex Dump` 看字节。如果请求体是 gzip 压缩的，需要先解压；本题是明文表单，直接看 ASCII 即可。
{% endnote %}

{% note info **Q9：flag 要不要去掉 `flag{}` 再提交？** %}
不要。题目要求「包裹 flag{}」，最终就是 `flag{ffb7567a1d4f4abdffdb54e022f8facd}` 整体提交。不同平台格式可能不同，以题目说明为准。
{% endnote %}

## 工具速查卡

| 操作 | 路径 / 命令 | 说明 |
| --- | --- | --- |
| 打开 pcap | `File → Open` | 支持 pcap / pcapng |
| 协议分布 | `Statistics → Protocol Hierarchy` | 先做减法 |
| 会话统计 | `Statistics → Conversations` | 找主要会话 |
| 显示过滤器 | 顶部输入框 | `http contains "password"` |
| 包详情字段 | 展开协议树 | `HTML Form URL Encoded` |
| 跟随 HTTP 流 | 右键 → `Follow → HTTP Stream` | 看原始请求体 |
| 搜索 | `Ctrl+F`（Follow 窗口内） | 搜 `password` |
| 复制字段值 | 右键 → `Copy → Value` | 避免手抄错 |
| 命令行过滤 | `tshark -Y '...'` | 批量/脚本化 |
| 快速试探 | `strings pcap \| grep password` | 仅限明文 |

## 顺手聊聊：明文登录的代价

这道题的现实意义非常直接：**登录请求里的 password 是明文传输的**（这里虽然看起来像哈希，但仍然是一个可直接使用的凭证值）。

在同一局域网、同一 Wi-Fi、或者任何一个能抓到包的位置，攻击者都能看到：

- 你登录了哪个站点、哪个接口；
- 你提交了哪些字段；
- `password` 字段的值是什么；
- Cookie、Token、Referer 等信息。

对应的防护思路：

| 风险 | 防护 |
| --- | --- |
| HTTP 明文传输 | 全站 HTTPS，登录页强制 TLS |
| 降级攻击 | 开启 HSTS，禁用 HTTP |
| 抓包泄露凭证 | 网络分段、无线加密（WPA2/WPA3）、802.1X |
| 日志/抓包留存 | 对 pcap 和日志做脱敏，限制访问权限 |
| 客户端哈希密码 | 不能替代 TLS；哈希值同样可能被重放 |

{% note success %}
**一条经验**：流量分析题先看「协议 + 内容关键词」，再看「字段」。本题的两个关键词就是 `POST` 和 `password`；找到包之后，Wireshark 已经把表单拆成了 `Key/Value`，直接读就行。真正需要练的不是逐包点，而是**知道该搜什么**。
{% endnote %}
