---
title: "[CTF2] BackupFile：.bak 备份文件泄露与 PHP 弱比较"
date: 2026-11-01 09:40:00
updated: 2026-11-01 09:40:00
categories:
  - CTF
  - Web
  - 源码泄露
tags:
  - 源码泄露
  - 备份文件
  - dirsearch
  - PHP 弱比较
  - 目录扫描
  - CTF2
description: 首页只有一句“Try to find out source file!”。dirsearch 扫出 index.php.bak，下载后看到 is_numeric + intval + 两个等号的弱比较，传 key=123 即可让“123”和“123ffws...”判等。
difficulty: 入门
topic: 源码泄露
series: 源码泄露
series_order: 1
permalink: 2026/11/01/web-ctf-backupfile/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：备份文件泄露、目录扫描、PHP 类型转换、`==` 弱比较
- **工具**：浏览器、dirsearch（或 gobuster / feroxbuster）、`curl`
- **关键路径**：`/index.php.bak`
- **关键 payload**：`?key=123`
- **flag**：`CTF2{1fdfcdd3-531c-4152-aca6-9cbee676c73f}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 HTTP GET 参数、PHP 基本语法、`if` 判断
- **工具**：Kali 自带的 dirsearch；没有的话 `pip install dirsearch` 或换用 gobuster / ffuf
- **环境**：文中的靶场地址是当时的临时环境，现在多半已失效。文末给了一个**本地复现实验**，照着搭一遍也能完整走通。
- 本文所有测试仅用于**授权靶场和本地环境**，请勿对未授权的站点做扫描。
{% endnote %}

{% note default %}
**做题路线**

`打开首页` → `看提示/源码/robots.txt` → `dirsearch 扫目录` → `下载 index.php.bak` → `读源码` → `分析弱比较` → `传 key=123` → `拿 flag`
{% endnote %}

## 第一步：打开页面，先读懂提示

访问靶场，页面只有一句话：

![首页提示](image.png)

*图 1：页面上只有 `Try to find out source file!`，没有输入框，也没有功能按钮*

这句话本身就是提示：**去找源码文件**。

新手常见反应是「页面没东西，是不是题坏了」。其实 Web 题的第一课就是：**看得见的页面不等于全部内容**。先做三件事：

1. `Ctrl+U` 看页面源码，找注释、隐藏链接、`display:none` 的元素；
2. 访问 `/robots.txt`，看有没有被禁止爬取的目录；
3. 如果都没有，就上**目录扫描**，找没被链接出来的文件。

本题前两步没有直接给答案，但第 3 步会有大收获。

{% note info %}
`robots.txt` 是给爬虫看的「访问约定」，里面常用 `Disallow:` 列出不想被索引的路径。真实站点里它经常泄露后台地址、备份目录、测试页面。做题时顺手看一眼，成本很低。
{% endnote %}

## 第二步：用 dirsearch 扫目录

dirsearch 是一个用字典逐条请求路径的工具：它对每个候选路径发请求，根据状态码和响应长度判断文件/目录是否存在。

在 Kali 里基本是开箱即用：

```bash
dirsearch -u http://77cd8267119b2adc368b180c.http-ctf2.dasctf.com/
```

输出里前面可能有一堆 `DeprecationWarning`，那是 Python 包版本的提示，不影响扫描，可以先忽略。真正有用的是下面这段：

```text
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Target: http://77cd8267119b2adc368b180c.http-ctf2.dasctf.com/

[23:26:56] Starting:
[23:27:17] 200 -    6KB - /favicon.ico
[23:27:18] 200 -    0B  - /flag.php
[23:27:19] 200 -    2B  - /health
[23:27:20] 200 -  347B  - /index.php.bak
[23:27:22] 200 -    9B  - /manager/jmxproxy/?get=BEANNAME&att=MYATTRIBUTE&key=MYKEY
[23:27:29] 200 -   46B  - /robots.txt

Task Completed
```

怎么读这份结果：

| 路径 | 状态码 | 响应大小 | 判断 |
| --- | --- | --- | --- |
| `/favicon.ico` | 200 | 6KB | 网站图标，通常没用 |
| `/flag.php` | 200 | 0B | 文件存在，但被 PHP 执行后没有输出 |
| `/health` | 200 | 2B | 健康检查接口，可能是框架自带 |
| `/index.php.bak` | 200 | 347B | **备份文件，重点目标** |
| `/manager/jmxproxy/...` | 200 | 9B | 看起来像误报或无关接口 |
| `/robots.txt` | 200 | 46B | 爬虫约定文件 |

最关键的是：

```text
/index.php.bak
```

`index.php` 是首页的源码，`.bak` 是常见的手工备份后缀。很多编辑器/运维人员在改文件前会复制一份 `xxx.php.bak`，改完忘了删。**服务器通常只把 `.php` 交给 PHP 解释器执行，`.bak` 会被当成普通静态文件直接返回**，于是源码就泄露了。

{% note success %}
**备份文件是 Web 入门题的高频入口。** 看到「找源码」「find source」这类提示，第一反应就应该是试常见备份后缀，而不是去猜参数。
{% endnote %}

## 第三步：下载并阅读 `index.php.bak`

浏览器直接访问：

```text
http://77cd8267119b2adc368b180c.http-ctf2.dasctf.com/index.php.bak
```

服务器会把文件原样返回（而不是执行），所以你看到的是 PHP 源码：

```php
<?php
include_once "flag.php";

if (isset($_GET['key'])) {
    $key = $_GET['key'];
    if (!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if ($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```

逐行拆开：

| 代码 | 含义 |
| --- | --- |
| `include_once "flag.php"` | 把 `flag.php` 包含进来，`$flag` 变量在这里定义 |
| `if (isset($_GET['key']))` | 必须传 `?key=...`，否则显示那句提示 |
| `if (!is_numeric($key)) exit("Just num!");` | `key` 必须是「数字字符串」，否则直接退出 |
| `$key = intval($key);` | 把 `key` 转成整数 |
| `$str = "123ffws..."` | 一串以数字开头的怪字符串 |
| `if ($key == $str) echo $flag;` | 用**两个等号**比较，相等就输出 flag |

注意到两个关键词：`is_numeric` 和 `==`。这就是本题的考点。

## 第四步：PHP 弱比较是怎么回事

### 4.1 `==` 和 `===` 的区别

| 运算符 | 名称 | 行为 |
| --- | --- | --- |
| `==` | 松散比较（弱比较） | 类型不同时**先转换再比较** |
| `===` | 严格比较 | 类型和值都必须相同，不转换 |

例如：

```php
"123" == 123      // true，字符串 "123" 被转成数字 123
"123" === 123     // false，一个是字符串，一个是整数
"abc" == 0        // PHP 7 里是 true（"abc" 转数字得 0），PHP 8 里是 false
```

本题的 `$key` 经过 `intval()` 后是**整数**，`$str` 是**字符串**。所以 `$key == $str` 触发类型转换：**字符串 `$str` 会被转成数字**。

### 4.2 字符串转数字：只认开头

PHP 把一个字符串转成数字时，会从开头尽可能多地读取数字，遇到第一个非数字字符就停：

```text
"123ffwsfwefwf..."  →  123
"12.5abc"           →  12.5
"abc123"            →  0
"0x1A"              →  0（不带 base 参数时，十六进制前缀不被识别）
```

本题的 `$str` 是：

```text
123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3
```

开头的 `123` 后面紧跟 `f`，于是转换成数字就是 `123`。所以只要 `$key` 是 `123`，`123 == "123ffws..."` 就成立。

### 4.3 `is_numeric` 和 `intval` 的分工

```php
$key = $_GET['key'];
if (!is_numeric($key)) exit("Just num!");   // 第一道门
$key = intval($key);                        // 第二道门
```

- `is_numeric($key)`：判断**整个字符串**是不是合法数字。`"123"` 是，`"123abc"` 不是，`"1e3"`、`"12.5"` 是。
- `intval($key)`：把字符串转成整数，**直接截断小数部分**。`intval("123.9")` 是 `123`，`intval("123abc")` 也是 `123`，但后者过不了 `is_numeric`。

所以：

| 输入 | `is_numeric` | `intval` 后 | 能否通过 |
| --- | --- | --- | --- |
| `key=123` | true | 123 | ✅ |
| `key=123.9` | true | 123 | ✅ |
| `key=0123` | true | 123 | ✅ |
| `key=1.23e2` | true | 123 | ✅ |
| `key=123abc` | **false** | - | ❌ 被 `Just num!` 拦下 |
| `key=abc` | false | - | ❌ |

{% note warning %}
**PHP 8 的行为变了。** 从 PHP 8.0 开始，整数和非数字字符串比较时，会把整数转成字符串再按字符串比较。也就是说，`123 == "123ffws..."` 在 PHP 8 里是 `false`，本题的 payload 就不灵了。

这道题能成立，说明靶场跑在 PHP 7.x 或更早版本。做老题遇到「弱比较不生效」时，先想想 PHP 版本，不要怀疑自己的 payload。
{% endnote %}

## 第五步：构造 payload，拿到 flag

既然 `$str` 会被截断成 `123`，传 `key=123` 就行：

```text
http://77cd8267119b2adc368b180c.http-ctf2.dasctf.com/index.php?key=123
```

页面上直接回显：

![拿到 flag](image-1.png)

*图 2：`?key=123` 通过校验，`echo $flag` 输出 flag*

最终 flag：

```text
CTF2{1fdfcdd3-531c-4152-aca6-9cbee676c73f}
```

用 `curl` 也能验证：

```bash
curl -s "http://77cd8267119b2adc368b180c.http-ctf2.dasctf.com/index.php?key=123"
```

{% note info %}
为什么不能直接访问 `/flag.php`？因为它会被 PHP 正常执行。`flag.php` 里只有变量定义、没有 `echo`，所以响应是 0 字节。想拿到 `$flag`，得通过 `index.php` 里那条 `echo $flag` 的分支。
{% endnote %}

## 第六步：本地复现一遍

靶场关掉之后，可以自己搭一个最小环境。新建目录 `backupfile-lab`，放两个文件：

`flag.php`：

```php
<?php
$flag = "CTF2{local_test_flag}";
```

`index.php`：

```php
<?php
include_once "flag.php";

if (isset($_GET['key'])) {
    $key = $_GET['key'];
    if (!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if ($key == $str) {
        echo $flag;
    }
} else {
    echo "Try to find out source file!";
}
```

启动 PHP 内置服务器：

```bash
php -S 127.0.0.1:8000
```

然后：

```bash
curl "http://127.0.0.1:8000/index.php?key=123"        # 输出本地 flag
curl "http://127.0.0.1:8000/index.php?key=123abc"      # Just num!
curl "http://127.0.0.1:8000/index.php"                 # Try to find out source file!
```

再把 `index.php` 复制一份成 `index.php.bak`，访问 `http://127.0.0.1:8000/index.php.bak`，你会发现 PHP 内置服务器也把它当静态文件返回。**亲手复现一次，比看十遍 writeup 印象深。**

{% note warning %}
本地实验里的 `$flag` 是假的，不要拿去提交。实验的目的是理解「备份文件为什么可读」和「弱比较为什么成立」。
{% endnote %}

## 第七步：如果没有 dirsearch，怎么手动找

不一定非要扫全字典。备份文件名有很强的规律性，可以手工试：

```text
/index.php.bak
/index.php~
/index.php.old
/index.php.save
/index.php.swp
/index.php.orig
/index.phps
/www.zip
/web.zip
/backup.zip
/source.zip
/.git/config
/.svn/entries
/.DS_Store
```

也可以结合提示猜文件名，比如首页提示 `source file`，就优先试 `index.php.bak`、`index.php~`、`www.zip`。

常用工具对比：

| 工具 | 特点 | 基本用法 |
| --- | --- | --- |
| dirsearch | Python，字典和扩展名配置方便 | `dirsearch -u URL -e php,zip,bak` |
| gobuster | Go，速度快 | `gobuster dir -u URL -w wordlist.txt -x php,bak` |
| feroxbuster | Rust，递归扫描强 | `feroxbuster -u URL -x php,bak` |
| ffuf | 灵活，适合 fuzz 参数/路径 | `ffuf -u URL/FUZZ -w wordlist.txt` |
| dirb | Kali 自带，简单 | `dirb URL` |

字典可以用 Kali 自带的：

```text
/usr/share/wordlists/dirb/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

{% note info %}
**状态码速记**：

| 状态码 | 含义 | 对扫描的意义 |
| --- | --- | --- |
| 200 | 正常返回 | 文件/目录存在 |
| 301 / 302 | 重定向 | 目录存在，可能缺尾部 `/` |
| 403 | 禁止访问 | 存在但没权限，值得继续挖 |
| 401 | 需要认证 | 存在，受保护 |
| 404 | 不存在 | 通常忽略 |
| 500 | 服务器错误 | 可能存在，参数/路径触发了异常 |

如果所有路径都返回 200，说明站点做了「通配 200」，这时要看**响应长度**差异，别被状态码骗了。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么 `.bak` 文件不会被 PHP 执行？** %}
Web 服务器（Nginx/Apache）通常只把 `.php` 后缀的请求交给 PHP-FPM/模块处理。`.bak` 不在映射表里，就按静态文件返回原始内容。**源码泄露的本质是「备份文件落在了 Web 根目录下」。**
{% endnote %}

{% note info **Q2：为什么 `/flag.php` 显示 0 字节？** %}
它被正常执行了。`flag.php` 里只有 `$flag = "..."`，没有 `echo`，所以页面什么都不输出。源码是通过 `index.php` 的 `include` 使用的，不是给你直接访问的。
{% endnote %}

{% note info **Q3：`key=123abc` 为什么不行？** %}
`is_numeric("123abc")` 是 `false`，会在 `intval` 之前就被 `exit("Just num!")` 拦下。`is_numeric` 要求**整个字符串**都是数字，不是只看开头。
{% endnote %}

{% note info **Q4：`intval` 和 `(int)` 有什么区别？** %}
功能基本一样，都是转整数。`intval($str, $base)` 还能指定进制（比如 `intval("1A", 16)` 得 26）。本题不涉及进制，理解成「截断取整」即可。
{% endnote %}

{% note info **Q5：`==` 和 `===` 在实战里怎么选？** %}
安全相关的比较一律用 `===`；比较用户输入和固定值时，还可以用 `hash_equals()` 防时序攻击。`==` 只适合你完全清楚两边类型、且不涉及安全的场景。
{% endnote %}

{% note info **Q6：为什么我本地 PHP 8 跑不出效果？** %}
PHP 8 修改了整数与字符串的比较规则。本题依赖 PHP 7 的行为；本地复现可以装 PHP 7.4，或者用 Docker：`docker run -p 8000:80 -v $PWD:/var/www/html php:7.4-apache`。
{% endnote %}

{% note info **Q7：dirsearch 扫得慢 / 被 WAF 拦怎么办？** %}
降低线程数、加延迟、减少扩展名：

```bash
dirsearch -u URL -t 5 --delay 1 -e php,bak,zip
```

授权测试时也可以换 IP、换 UA。**不要对未授权站点扫描。**
{% endnote %}

{% note info **Q8：扫出一堆 200，怎么判断哪个是真的？** %}
先看响应长度和内容。`/health` 只有 2 字节，`/flag.php` 0 字节，`/index.php.bak` 347 字节——大小和类型能帮你快速排序。可疑路径再手动访问确认。
{% endnote %}

{% note info **Q9：`/manager/jmxproxy/...` 是什么？** %}
看起来像扫描器命中的无关路径或误报，和本题的备份文件泄露没有关系。做题时不要被每一个 200 带偏，围绕题目提示（找源码）收敛目标。
{% endnote %}

{% note info **Q10：这题和 SQL 注入的弱比较是一回事吗？** %}
本质都是 PHP 的类型转换问题，但利用点不同。SQL 注入里的弱比较常见于登录绕过（`$password == $row['password']`）；本题是**本地变量比较**，参数先过 `is_numeric` 和 `intval`，再和一个数字开头的字符串比。
{% endnote %}

## 工具速查卡

| 工具/操作 | 用途 | 关键点 |
| --- | --- | --- |
| `Ctrl+U` | 查看页面源码 | 找注释、隐藏链接 |
| `/robots.txt` | 看爬虫约定 | 可能泄露目录 |
| dirsearch | 目录/文件扫描 | `-u URL -e php,bak,zip` |
| gobuster / feroxbuster | 扫描备选 | 速度快，支持递归 |
| `curl -i` | 看响应头/状态码 | 判断 200/302/403 |
| `intval()` | 字符串转整数 | 截断小数，前缀数字 |
| `is_numeric()` | 判断数字字符串 | 整串必须是数字 |
| `==` / `===` | 弱/严格比较 | 安全场景用 `===` |

## 顺手聊聊：源码泄露与弱比较的现实风险

### 备份文件泄露

这是真实渗透测试里最常见的问题之一：

| 泄露文件 | 可能包含 |
| --- | --- |
| `index.php.bak` / `.old` / `~` | 完整源码、数据库配置、注释里的测试账号 |
| `.git/` | 完整代码历史、提交记录、密钥 |
| `.svn/` / `.DS_Store` | 目录结构、文件名 |
| `www.zip` / `backup.zip` | 整站源码 + 配置 |
| `config.php.swp` | 数据库账号密码 |

防护建议：

- 备份文件不要放在 Web 根目录；放到 Web 根目录之外，或打包加密；
- 部署时用 `.gitignore` / 构建流程排除 `.git`、`.svn`、`.bak`；
- Nginx 显式拒绝敏感后缀：`location ~* \.(bak|old|swp|save|orig|zip|tar\.gz)$ { deny all; }`；
- 定期用扫描器自查，别等别人扫到。

### PHP 弱比较

`==` 的隐式转换在历史上造成过不少真实漏洞：

```php
if ($_POST['password'] == $stored_password) { ... }
```

如果一边是数字、一边是字符串，或者两边都是 `0e` 开头的「魔法哈希」，就可能被绕过。比如 PHP 7 里：

```php
"0e123456" == "0e987654"   // true，两个都被当成 0
```

因为 `0e...` 被解析成科学计数法 `0 × 10^n = 0`。

防护建议：

| 问题 | 建议 |
| --- | --- |
| 用 `==` 比较敏感值 | 改用 `===` |
| 比较哈希/口令 | 用 `hash_equals()` |
| 信任用户输入的类型 | 显式校验 + 白名单 |
| 依赖老版本 PHP 行为 | 升级并回归测试 |

{% note success %}
**一条经验**：源码泄露题的关键不是「扫得有多快」，而是「知道该找什么」。看到「find source file」，先想备份后缀和 `.git`；看到 `is_numeric` + `intval` + `==`，先想类型转换。工具只是把可能性列出来，判断还得靠人。
{% endnote %}
