---
title: "PHP 常见漏洞笔记：数组报错绕过、Cookie 信任与 php://filter 读源码"
date: 2026-11-14 09:00:00
updated: 2026-11-14 09:00:00
categories:
  - CTF
  - Web
  - PHP 安全
tags:
  - PHP
  - 数组绕过
  - 错误处理
  - Cookie
  - php://filter
  - 文件包含
  - 伪协议
  - 入门基础
description: 三个小案例串起 PHP 里最常见的三类问题：用数组制造 Array to string conversion，让 set_error_handler 把 flag 打出来；服务端无条件信任 username cookie，改个值就变 admin；include 自动补 .php 时用 php://filter 读源码，顺便解释 strpos 不加 !== false 的坑。
difficulty: 入门
topic: PHP 安全
series: PHP 安全
series_order: 1
permalink: 2026/11/14/web-knowledge-php-common-vulns/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（三个案例都只需要读懂十几行 PHP）
- **考点**：PHP 数组与字符串转换、`set_error_handler`、Cookie 信任、`php://filter` 伪协议、`strpos` 返回值陷阱
- **案例一**：`[Dest0g3 520迎新赛]EasyPHP`——时间条件走不通，用 `ctf[]=1` 触发数组转字符串警告，让错误处理器打印 flag
- **案例二**：`[BSidesCF 2019]Kookie`——服务端直接信任 `username` cookie，改成 `admin` 就登录
- **案例三**：`[BSidesCF 2020]Had a bad day`——`include` 自动补 `.php`，用 `php://filter` 把源码 base64 编码后读出来
- **一句话总结**：PHP 的“方便”和“弱类型”是很多漏洞的源头，输入一旦越界，就可能变成代码、文件路径或身份
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：PHP 基本语法、`$_GET` / `$_POST` / `$_COOKIE`、`include`、HTTP 请求的基本结构
- **工具**：浏览器 F12、Burp Suite（或 `curl`）、`base64` 命令
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地 PHP 环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`读源码，找可控变量` → `看有没有过滤/判断` → `找能触发错误的点` → `构造 payload` → `读回显` → `解码/拿 flag`
{% endnote %}

## 先看全貌：三类问题

这篇不是一道题，而是三个小案例的合集。它们看起来没关系，但都指向同一件事：**PHP 把用户输入当成了比自己想象中更“自由”的东西。**

| 案例 | 漏洞类型 | 一句话 |
| --- | --- | --- |
| EasyPHP | 类型/错误处理 | 数组参与字符串拼接会报错，错误处理器又把 flag 打了出来 |
| Kookie | 客户端状态信任 | `username` 存在 cookie 里，服务端不验签，改成 `admin` 就是管理员 |
| Had a bad day | 文件包含 + 伪协议 | `include` 自动补 `.php`，用 `php://filter` 读源码 |

下面按顺序看。

## 一、数组报错绕过：EasyPHP

### 题目源码

打开页面，直接给了源码：

![EasyPHP 源码](image.png)

*图 1：`highlight_file(__FILE__)` 把源码打印出来，flag 在 `fl4g.php` 里*

```php
<?php
highlight_file(__FILE__);
include "fl4g.php";
$dest0g3 = $_POST['ctf'];
$time = date("H");
$stimme = date("d");
$stimmme = date("i");
if(($time > "24") or ($stimme > "31") or ($stimmme > "60")){
    echo $fl4g;
}else{
    echo "Try harder!";
}
set_error_handler(
    function() use(&$fl4g) {
        print $fl4g;
    }
);
$fl4g .= $dest0g3;
?>
```

先别急着找 payload，逐行读一遍。

### 逐行读源码

| 代码 | 作用 |
| --- | --- |
| `highlight_file(__FILE__)` | 把当前文件源码高亮输出，等于白送源码 |
| `include "fl4g.php"` | 把 `fl4g.php` 包含进来，里面定义了 `$fl4g` |
| `$dest0g3 = $_POST['ctf'];` | 取 POST 参数 `ctf`，**完全可控** |
| `date("H")` | 当前小时，`00`–`23` |
| `date("d")` | 当前日期，`01`–`31` |
| `date("i")` | 当前分钟，`00`–`59` |
| `if (...)` | 三个条件只要有一个成立，就 `echo $fl4g` |
| `else` | 否则输出 `Try harder!` |
| `set_error_handler(...)` | 注册一个自定义错误处理器，打印 `$fl4g` |
| `$fl4g .= $dest0g3;` | 把用户输入拼到 `$fl4g` 后面 |

### 时间条件为什么走不通

三个判断分别是：

```php
$time    > "24"   // H 最大 23
$stimme  > "31"   // d 最大 31
$stimmme > "60"   // i 最大 59
```

`date()` 的取值范围决定了它们**永远不可能成立**：

| 变量 | 范围 | 比较 | 结果 |
| --- | --- | --- | --- |
| `$time` | `00`–`23` | `> "24"` | 永远假 |
| `$stimme` | `01`–`31` | `> "31"` | 永远假 |
| `$stimmme` | `00`–`59` | `> "60"` | 永远假 |

而且这里的比较是“数字字符串比数字字符串”，PHP 会按数值比较，不是字典序。所以 `"23" > "24"` 是假，`"31" > "31"` 也是假。

**时间这条路是死的，真正可控的只有 `$dest0g3`。**

### 关键：让 `$dest0g3` 变成数组

`$fl4g .= $dest0g3;` 是字符串拼接。如果 `$dest0g3` 是普通字符串，什么事都不会发生；如果它是**数组**，PHP 会尝试把数组转成字符串，触发：

```text
Warning: Array to string conversion
```

这个警告是 `E_WARNING`，而 `set_error_handler` 注册的处理器正好能接住它。处理器里写的是：

```php
function() use(&$fl4g) {
    print $fl4g;
}
```

于是警告一触发，`$fl4g` 就被打印出来了。

payload 很简单，把 `ctf` 写成数组：

```text
ctf[]=1
```

用 Burp 发 POST：

![发送 ctf[]=1](image-1.png)

*图 2：`ctf[]=1` 触发数组转字符串警告，响应里带回 flag*

响应大概是：

```text
Try harder!CTF2{fa22cb98-437b-4bbd-9ca0-0fa82d5926ed}
```

前面的 `Try harder!` 是 `else` 分支打的，后面的 flag 是错误处理器打的。

{% note warning %}
**为什么不能随便写 `ctf=1`？** 因为字符串拼接不会报错，`set_error_handler` 没有机会执行。必须是“能被当成字符串、但转换时会报错”的类型，数组正好符合。
{% endnote %}

### 为什么错误处理器能拿到 `$fl4g`

`use (&$fl4g)` 是闭包的按引用捕获。`$fl4g` 在 `include "fl4g.php"` 之后就已经有值了，处理器通过引用拿到它，所以 `print $fl4g` 打印的是真正包含进来的 flag。

如果写成 `use ($fl4g)`（没有 `&`），闭包会在定义时复制一份值；在这里值已经存在，所以也能打印，但按引用更符合“处理器随时能读最新值”的语义。

### 知识点：`set_error_handler`

`set_error_handler` 用来接管 PHP 的运行时错误。基本用法：

```php
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    echo "错误：$errstr";
    return true; // 返回 true 表示“已处理”，不再走默认处理器
});
```

几个要点：

| 要点 | 说明 |
| --- | --- |
| 能接住的错误 | `E_WARNING`、`E_NOTICE`、`E_USER_*`、`E_DEPRECATED`、`E_STRICT` 等 |
| 接不住的错误 | `E_ERROR`、`E_PARSE`、`E_CORE_ERROR`、`E_COMPILE_ERROR` 等致命错误 |
| 返回值 | 返回 `false` 会继续走 PHP 默认处理器；返回其它值则视为已处理 |
| 参数 | `$errno`、`$errstr`、`$errfile`、`$errline`，可以只写需要的参数 |
| 作用域 | 只对注册之后发生的错误生效 |

本题的处理器只写了 `function() use(&$fl4g)`，没有接收错误参数，PHP 允许这样写，多余的参数会被忽略。

### 知识点：PHP 的数组与字符串转换

PHP 是弱类型语言，很多地方会“自动转换”：

| 场景 | 结果 |
| --- | --- |
| `"abc" . 123` | `"abc123"` |
| `"abc" . [1,2]` | 警告 `Array to string conversion`，得到 `"abcArray"` |
| `[1,2] == "Array"` | PHP 8 下为 `false`，但比较过程会有类型 juggling |
| `md5([])` | PHP 7 警告并返回 `null`；PHP 8 抛 `TypeError` |
| `strpos([], "a")` | PHP 8 抛 `TypeError` |
| `in_array("1", [1])` | 默认松散比较，返回 `true` |

这也是很多“数组绕过”题的来源：有些函数对数组的行为和字符串完全不同，攻击者就利用这一点让校验失效或触发错误。

{% note info %}
**数组绕过不止这一种。** 常见的还有：

- `md5($a) === md5($b)`：传两个不同的数组，`md5()` 都返回 `null`，`null === null` 成立；
- `strcmp($a, $b)`：传数组会返回 `null`，松散比较时可能被当成“相等”；
- `preg_match`、`sha1`、`password_verify` 等函数对数组的参数处理也各不相同。

遇到“输入被塞进函数”的题，先想一下：**这个函数收到数组会怎样？**
{% endnote %}

## 二、Cookie 信任：Kookie

### 题目

打开页面，标题是 `Can you log in?`，下面写着：

```text
Log in as admin!
We found the account cookie / monster
```

![Kookie 页面与 Console](image-2.png)

*图 3：页面提示 cookie 是 `monster`，Console 里改完 cookie 后直接以 admin 登录*

翻译一下：**我们已经找到了你的账号 cookie，值是 `monster`。** 目标是以 `admin` 身份登录。

### 改 cookie

最直接的办法是在浏览器 Console 里改：

```javascript
document.cookie = "username=admin;path=/";
```

然后刷新页面，页面就变成了：

```text
Congratulations! You're logged in as admin! Your flag is:
CTF2{0a0d08f5-21e8-40dd-a918-3d3785a644b2}
```

### 为什么 `path=/` 很重要

Cookie 不是全局的，它有几个作用域属性：

| 属性 | 作用 |
| --- | --- |
| `Domain` | 这个 cookie 发给哪个域名 |
| `Path` | 这个 cookie 发给哪个路径 |
| `Expires` / `Max-Age` | 什么时候过期 |
| `Secure` | 只在 HTTPS 下发送 |
| `HttpOnly` | 禁止 JavaScript 读取 |
| `SameSite` | 跨站请求时是否发送 |

**要覆盖一个已存在的 cookie，`name`、`domain`、`path` 必须匹配。** 如果原来的 `username` 是 `path=/`，你在当前页面写一个 `path=/` 的 `username=admin`，就会覆盖它；如果写成别的 path，浏览器会当成两个同名不同路径的 cookie，服务端读哪一个就不一定了。

`path=/` 的意思是“整个站点的所有页面和接口都带上这个 cookie”，所以刷新任意页面都能生效。

### 为什么这能成功

因为服务端大概率是这么写的：

```php
if ($_COOKIE['username'] === 'admin') {
    echo "Congratulations! You're logged in as admin!";
    echo $flag;
}
```

它只检查 cookie 的**值**，没有签名、没有 session、没有服务端状态。**cookie 存在客户端，客户端想改成什么就改成什么。**

{% note warning %}
**`HttpOnly` 不是万能的。** `HttpOnly` 只能阻止 JavaScript 通过 `document.cookie` **读取** cookie，不能阻止用户通过开发者工具、Burp、curl 手动**设置** cookie。如果服务端信任 cookie 的值，`HttpOnly` 挡不住这种改包攻击；它主要防的是 XSS 偷 cookie。
{% endnote %}

### 知识点：Cookie 与 Session

| 方式 | 状态存在哪 | 安全性取决于 |
| --- | --- | --- |
| Cookie 直接存身份 | 客户端 | 服务端是否验签/校验 |
| Session | 服务端，客户端只存 Session ID | Session ID 是否随机、是否泄露 |
| JWT | 客户端，服务端验签 | 签名算法、密钥强度、是否校验 `alg` |

三种方式本身没有绝对好坏，关键是**服务端有没有验证**。这题的 cookie 是明文 `username=monster`，没有任何签名，等于把“我是谁”交给用户自己填。

### 常见变体

| 变体 | 利用方式 |
| --- | --- |
| `role=user` → `role=admin` | 直接改权限字段 |
| base64 cookie | 解码后改字段，再编码回去 |
| JSON cookie | 改 `{"is_admin":false}` 为 `true` |
| Flask session | 弱密钥可爆破，或用 `flask-unsign` 伪造 |
| JWT `alg:none` | 去掉签名，改 payload |
| JWT 弱密钥 | 爆破密钥后重新签名 |

{% note success %}
**判断方法**：拿到 cookie 后先看它长什么样。明文、base64、JSON、JWT，各有各的玩法。**能解码就先解码，能改字段就先改字段，改完看服务端认不认。**
{% endnote %}

## 三、php://filter 读源码：Had a bad day

文件包含的基础（`include` / `require`、常见伪协议、LFI 利用链）在 [文件包含基础](/2026/10/30/web-knowledge-file-inclusion-basics/) 里讲过，这里只挑这题用到的部分。

### 题目

页面叫 `Had a bad day?`，有两个按钮：

![Had a bad day 页面](image-3.png)

*图 4：`WOOFERS` 和 `MEOWERS` 两个选项*

点 `WOOFERS`，URL 变成：

```text
/index.php?category=woofers
```

页面显示 `Woof! Woof!` 和一张图：

![正常的 woofers 请求](image-4.png)

*图 5：`category=woofers` 正常返回内容*

先看源码、跑 `dirsearch`，都没有直接结果。那就换个思路：**这个 `category` 很可能被 `include` 了。**

### 先试 php://filter

PHP 的 `php://filter` 可以在读取文件时套一层过滤器。最常用的是 base64 编码：

```text
php://filter/read=convert.base64-encode/resource=index
```

放到 URL 里：

```text
/index.php?category=php://filter/read=convert.base64-encode/resource=index
```

**为什么用 base64？** 因为直接 `include("index.php")` 会让 PHP **执行**这个文件，你看到的是它输出的 HTML，不是源码。套上 `convert.base64-encode` 后，文件内容先被编码成 base64 字符串再交给 `include`，base64 里没有 `<?php`，不会被当成 PHP 代码执行，于是整段源码就以文本形式回显出来了。

### 第一个坑：include 自动补了 `.php`

如果写：

```text
?category=php://filter/read=convert.base64-encode/resource=index.php
```

页面会报：

```text
Warning: include(php://filter/read=convert.base64-encode/resource=index.php.php):
failed to open stream: operation failed
```

![多了一个 .php](image-5.png)

*图 6：`resource=index.php` 被代码又拼了一个 `.php`，变成 `index.php.php`*

原因是后端代码大概是：

```php
include($file . '.php');
```

它不管你传什么，都会在后面补 `.php`。所以 `resource=` 后面要写**不带后缀**的文件名：

```text
?category=php://filter/read=convert.base64-encode/resource=index
```

这样拼接后正好是 `index.php`。

### 读源码

修正后，页面回显一大段 base64：

![base64 源码](image-6.png)

*图 7：`resource=index` 读取成功，源码被 base64 编码后输出*

把 base64 复制出来解码：

```bash
echo 'PCEtLSBDYW4geW91IHJlYWQgdGhpcyBmbGFnPyAtLT4KPD9waHAKIC8vIENURjJ7NjAyYmE2YjMtNWZkYi00NGMxLWJhYjctOTU2ZDBmZDlmMDY4fQo/Pgo=' | base64 -d
```

得到：

```php
<!-- Can you read this flag? -->
<?php
// CTF2{602ba6b3-5fdb-44c1-bab7-956d0fd9f068}
?>
```

flag：

```text
CTF2{602ba6b3-5fdb-44c1-bab7-956d0fd9f068}
```

### 完整源码与 `strpos` 的坑

解码出来的源码里，关键逻辑是：

```php
<?php
    $file = $_GET['category'];

    if(isset($file))
    {
        if( strpos( $file, "woofers" ) !== false
            || strpos( $file, "meowers" ) !== false
            || strpos( $file, "index" ) )
        {
            include ($file . '.php');
        }
        else
        {
            echo "Sorry, we currently only support woofers and meowers.";
        }
    }
?>
```

前两个判断写得很规范：`strpos(...) !== false`，找不到返回 `false`，找到返回位置（包括 `0`）。

第三个判断少了一截：

```php
strpos($file, "index")
```

`strpos` 的返回值有三种情况：

| 情况 | 返回值 | 布尔值 |
| --- | --- | --- |
| 没找到 | `false` | 假 |
| 在位置 0 找到 | `0` | **假** |
| 在位置 > 0 找到 | 正整数 | 真 |

所以：

- 如果 `$file` 就是 `index`，`strpos($file, "index")` 返回 `0`，条件为假，页面会输出 `Sorry...`；
- 如果 `$file` 是 `php://filter/...resource=index`，`index` 出现在后面，返回值 > 0，条件为真，可以包含。

这就是为什么 `resource=index` 这个 payload 能过：**不是 `index` 这个词本身有问题，而是它出现的位置刚好不是 0。**

### 另一种绕法：把 `woofers` 塞进 filter 链

如果想让 payload 更“名正言顺”地满足前两个条件，可以写成：

```text
?category=php://filter/woofers/read=convert.base64-encode/resource=index
```

`php://filter` 会把 `/` 按段解析，`woofers` 被当成一个过滤器名字。PHP 找不到这个过滤器，会警告：

```text
Warning: include(): unable to locate filter "woofers"
Warning: include(): Unable to create filter (woofers)
```

但后面的 `convert.base64-encode` 仍然生效，`resource=index.php` 也仍然能被读取：

![woofers 过滤器警告](image-7.png)

*图 8：`woofers` 被当成过滤器名，警告不影响 base64 输出*

这个写法同时满足 `strpos($file, "woofers") !== false`，所以即使第三个条件的写法是严格的 `!== false`，也能过。**它利用的是“过滤器链里可以出现任意名字”这一点，而不是让 `woofers` 真的去过滤什么。**

{% note info %}
**`php://filter` 的语法**

```text
php://filter/[read=<过滤器>]/[write=<过滤器>]/resource=<目标>
```

- `read=`：读取时应用的过滤器；
- `write=`：写入时应用的过滤器；
- 不写 `read=` / `write=`，只写过滤器名，默认读写都应用；
- 多个过滤器用 `|` 连接，例如 `convert.base64-encode|string.rot13`；
- `resource=` 后面是被读取的目标，可以是相对路径、绝对路径，也可以是另一个流。

常用的过滤器：

| 过滤器 | 作用 |
| --- | --- |
| `convert.base64-encode` | base64 编码 |
| `convert.base64-decode` | base64 解码 |
| `string.rot13` | ROT13 |
| `string.toupper` / `string.tolower` | 大小写转换 |
| `zlib.deflate` / `zlib.inflate` | zlib 压缩/解压 |
| `convert.iconv.*` | 字符集转换，常被用来构造 RCE 链 |
{% endnote %}

### 其他常见伪协议

| 伪协议 | 用途 | 典型场景 |
| --- | --- | --- |
| `php://filter` | 读源码、编码转换 | LFI 读文件 |
| `php://input` | 读取 POST body | 文件包含 + 代码执行 |
| `data://` | 直接把数据当文件 | `data://text/plain;base64,...` |
| `file://` | 读本地文件 | 路径可控时 |
| `zip://` | 读 zip 内文件 | 上传 zip + 包含 |
| `phar://` | 触发反序列化 | 有 `phar` 文件时 |
| `expect://` | 执行命令 | 需要扩展，较少见 |

`php://filter` 本身通常只能读，不能直接执行代码；但在 LFI 题里，它经常和日志包含、session 文件、上传文件、`convert.iconv` 链组合，变成完整的 RCE。

## 新手常见问题

{% note info %}
**Q1：为什么 `ctf[]=1` 能触发，`ctf=1` 不行？**

`ctf=1` 让 `$dest0g3` 是字符串，字符串拼接不会报错；`ctf[]=1` 让 `$dest0g3` 是数组，数组参与字符串拼接会触发 `Array to string conversion`，自定义错误处理器才有机会执行。
{% endnote %}

{% note info %}
**Q2：`set_error_handler` 能捕获哪些错误？**

默认能捕获 `E_WARNING`、`E_NOTICE`、`E_USER_*`、`E_DEPRECATED`、`E_STRICT` 等运行时错误；捕获不了 `E_ERROR`、`E_PARSE`、`E_CORE_ERROR`、`E_COMPILE_ERROR` 这类致命错误。数组转字符串是 `E_WARNING`，所以在捕获范围内。
{% endnote %}

{% note info %}
**Q3：为什么错误处理器里能拿到 `$fl4g`？**

`include "fl4g.php"` 之后，`$fl4g` 已经在当前作用域里了；闭包用 `use (&$fl4g)` 按引用捕获它，处理器执行时就能直接 `print`。
{% endnote %}

{% note info %}
**Q4：Cookie 的 `path` 为什么重要？**

Cookie 按 `domain` + `path` 隔离。要覆盖已有的 `username`，新 cookie 的 `path` 必须和原来一致；写 `path=/` 能覆盖全站生效的那一个。如果 path 不匹配，浏览器会保留两个同名 cookie，服务端读哪个就不确定了。
{% endnote %}

{% note info %}
**Q5：`HttpOnly` 能防住改 Cookie 吗？**

不能。`HttpOnly` 只阻止 JavaScript 读取 cookie，不阻止用户通过开发者工具、Burp、curl 设置 cookie。它防的是 XSS 偷 cookie，不是防客户端篡改。真正要防篡改，得靠签名或服务端 session。
{% endnote %}

{% note info %}
**Q6：为什么 `resource=index.php` 会变成 `index.php.php`？**

因为后端写的是 `include($file . '.php')`，不管你传什么都会补 `.php`。你传 `index.php`，拼接后就是 `index.php.php`。改成 `resource=index`，拼接后正好是 `index.php`。
{% endnote %}

{% note info %}
**Q7：为什么要把源码 base64？**

直接 `include("index.php")` 会让 PHP 执行这个文件，你看到的是执行结果；`convert.base64-encode` 把文件内容先编码成 base64 文本，里面没有 `<?php`，`include` 不会执行它，于是源码被原样输出。
{% endnote %}

{% note info %}
**Q8：`strpos` 不加 `!== false` 为什么危险？**

`strpos` 找不到返回 `false`，在位置 0 找到返回 `0`。`0` 和 `false` 在布尔上下文里都是假。如果只写 `if (strpos($a, $b))`，那么“在开头找到”会被误判成“没找到”，校验逻辑就反了。正确写法是 `strpos($a, $b) !== false`。
{% endnote %}

{% note info %}
**Q9：为什么 payload 里要带 `woofers`？**

因为源码用 `strpos($file, "woofers") !== false` 做白名单判断。把 `woofers` 塞进 `php://filter` 的过滤器链里，既能满足字符串检查，又不会影响后面的 base64 读取。PHP 会警告“找不到 woofers 过滤器”，但不会中断。
{% endnote %}

{% note info %}
**Q10：`php://filter` 只能读源码吗？**

不只能读。它可以对任意流做编码、解码、压缩、字符集转换；配合 `php://input`、`data://`、`zip://`、`phar://` 等伪协议，可以做代码执行、反序列化、文件写入。不过很多利用需要 `allow_url_include=On` 或特定扩展，实际环境要看配置。
{% endnote %}

{% note info %}
**Q11：这三个漏洞有什么共同点？**

都是“用户输入越界”：数组越过了字符串的边界，cookie 越过了服务端的信任边界，`category` 越过了“只能选 woofers/meowers”的边界。PHP 的弱类型和动态特性让这些越界更容易发生。
{% endnote %}

{% note info %}
**Q12：怎么防？**

- 数组报错：不要用自定义错误处理器打印敏感变量；对输入做类型校验（`is_string`、`is_array`）；
- Cookie：不要信任客户端状态，用签名 cookie 或服务端 session；敏感字段不要放在 cookie 里；
- 文件包含：用白名单映射（`woofers` → `woofers.php`），不要直接拼接用户输入；`allow_url_include=Off`、`open_basedir` 限制目录。
{% endnote %}

## 完整流程速查

| 案例 | 步骤 | 操作 / payload | 结果 |
| --- | --- | --- | --- |
| EasyPHP | 1 | 读源码，发现时间条件永远为假 | 只能走错误处理器 |
| EasyPHP | 2 | POST `ctf[]=1` | 触发 `Array to string conversion` |
| EasyPHP | 3 | 错误处理器打印 `$fl4g` | 拿到 flag |
| Kookie | 1 | 页面提示 cookie 是 `monster` | 目标改成 `admin` |
| Kookie | 2 | `document.cookie = "username=admin;path=/"` | 覆盖 cookie |
| Kookie | 3 | 刷新页面 | 以 admin 登录，拿到 flag |
| Had a bad day | 1 | 试 `?category=woofers` | 正常回显，确认参数被使用 |
| Had a bad day | 2 | `php://filter/read=convert.base64-encode/resource=index.php` | 被补成 `.php.php`，报错 |
| Had a bad day | 3 | 改成 `resource=index` | 读到 base64 源码 |
| Had a bad day | 4 | base64 解码 | 拿到 flag |

## 顺手聊聊怎么防

三个案例对应三种防护思路：

| 问题 | 错误做法 | 正确做法 |
| --- | --- | --- |
| 数组触发错误泄露 flag | 用 `set_error_handler` 打印敏感变量 | 不要把 flag 放在错误处理器能碰到的作用域；对输入做类型校验 |
| Cookie 信任 | 直接读 `$_COOKIE['username']` 判断身份 | 用签名 cookie、JWT 验签或服务端 session；敏感字段不落客户端 |
| 文件包含 | `include($file . '.php')` 直接拼接 | 白名单映射；`basename()`；`allow_url_include=Off`；`open_basedir` |

具体的代码层面：

```php
// 1. 输入类型校验
if (!is_string($_POST['ctf'])) {
    die('invalid input');
}

// 2. 不要信任 cookie 里的身份
// 错误：if ($_COOKIE['username'] === 'admin')
// 正确：从服务端 session 取身份，cookie 只放随机的 session id

// 3. 文件包含用白名单
$allowed = ['woofers' => 'woofers.php', 'meowers' => 'meowers.php'];
$key = $_GET['category'] ?? '';
if (!isset($allowed[$key])) {
    die('invalid category');
}
include $allowed[$key];
```

{% note success %}
**一条原则**：PHP 的“自动转换”和“动态特性”让开发很方便，但也让边界变得模糊。**凡是用户能控制的变量，进入字符串、文件路径、身份判断之前，都要先问一句：它会不会变成别的东西？**
{% endnote %}

## 小结

三个案例，三种“越界”：

- **数组报错绕过**：`ctf[]=1` 让字符串拼接变成数组转字符串，`E_WARNING` 被 `set_error_handler` 接住，flag 跟着错误信息一起出来；
- **Cookie 信任**：`username=monster` 明文存在客户端，改成 `admin` 就是管理员；`path=/` 保证覆盖全站生效的那个 cookie；
- **php://filter 读源码**：`include($file . '.php')` 会自动补后缀，`resource=index` 才是正确写法；base64 让源码不执行、原样回显；
- **`strpos` 的坑**：返回 `0` 和返回 `false` 在布尔上下文里都是假，必须写 `!== false`；
- **共同点**：用户输入越过了它本该待着的位置——从数据变成代码、从客户端状态变成服务端身份、从选项变成文件路径。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| PHP 弱类型 | `==` / `===`、magic hash、数组比较 |
| 反序列化 | `unserialize`、POP 链、`phar://` |
| 文件包含进阶 | 日志包含、session 文件、`convert.iconv` RCE 链 |
| 签名与 JWT | 弱密钥、`alg:none`、密钥混淆 |
| 错误处理 | 自定义 handler 泄露、异常栈信息 |

{% note success %}
**一条经验**：PHP 题先读源码，再找“用户能控制什么”。可控变量进入的每一个函数、每一个判断、每一个拼接，都是潜在的边界。**漏洞往往不在你盯着的那一行，而在你以为“它只是个字符串”的地方。**
{% endnote %}
