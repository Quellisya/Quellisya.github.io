---
title: "[ZJCTF 2019] NiZhuanSiWei：data:// 绕过、php://filter 读源码与 __toString 反序列化"
date: 2026-11-19 12:00:00
updated: 2026-11-19 12:00:00
categories:
  - CTF
  - Web
  - 反序列化
tags:
  - PHP
  - 反序列化
  - __toString
  - php://filter
  - data://
  - Stream Wrapper
  - 文件包含
  - ZJCTF
description: 先用 data:// 让 file_get_contents 读出 welcome to the zjctf，再用 php://filter 把 useless.php 的源码以 base64 读出来；看到 Flag 类的 __toString 后，构造 O:4:"Flag":1:{...} 让 echo $password 触发它，最后 file_get_contents("flag.php") 把 flag 打在源码里。
difficulty: 入门
topic: 反序列化
series: 反序列化
series_order: 2
permalink: 2026/11/19/web-ctf-nizhuansiwei/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（建议先看 [文件包含基础](/2026/10/30/web-knowledge-file-inclusion-basics/) 和 [piapiapia](/2026/11/03/web-ctf-piapiapia/)）
- **考点**：PHP Stream Wrapper、`data://`、`php://filter`、文件包含、PHP 序列化/反序列化、`__toString`
- **入口**：`text` 必须让 `file_get_contents` 读出 `welcome to the zjctf`；`file` 不能包含 `flag`；`include($file)`；`unserialize($password)`；`echo $password`
- **路线**：`data://` 过 `text` → `php://filter` 读 `useless.php` 源码 → 分析 `Flag` 类 → 最后 `file=useless.php` + 序列化 `password` → `__toString` 读 `flag.php`
- **关键 payload**：`?text=data://text/plain,welcome%20to%20the%20zjctf&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}`
- **flag**：`CTF2{a911662a-ca7d-4a40-83b7-deae1adc83ff}`
- **思考题**：文中有 8 道，答案默认折叠，建议先自己想一遍
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：PHP 文件包含、`php://filter` 的基本用法、PHP 序列化格式。没看过的话，可以先补 [文件包含基础](/2026/10/30/web-knowledge-file-inclusion-basics/) 和 [Secret File](/2026/10/30/web-ctf-file-inclusion-secret-file/)。
- **工具**：浏览器、CyberChef（或命令行 `base64 -d`）、PHP 环境（用来生成序列化字符串）
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`看源码` → `data:// 过 text` → `php://filter 读 useless.php` → `base64 解码看 Flag 类` → `构造序列化 password` → `file=useless.php` 触发 `__toString` → `看页面源码拿 flag`
{% endnote %}

## 题目：源码直接摆在页面上

打开网站，页面直接把一部分源码显示出来了：

![页面上的源码](01-source.png)

*图 1：`else` 分支里调用了 `highlight_file(__FILE__)`，所以条件不满足时会把当前文件高亮输出*

```php
<?php
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];

if(isset($text) && (file_get_contents($text, 'r') === "welcome to the zjctf")){
    echo "<br><h1>" . file_get_contents($text, 'r') . "</h1></br>";

    if(preg_match("/flag/", $file)){
        echo "Not now!";
        exit();
    } else {
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
} else {
    highlight_file(__FILE__);
}
?>
```

先把三个参数看清楚：

| 参数 | 用途 | 限制 |
| --- | --- | --- |
| `text` | 交给 `file_get_contents` 读 | 读出来的内容必须**严格等于** `welcome to the zjctf` |
| `file` | 交给 `include` 包含 | 字符串里不能出现 `flag` |
| `password` | 交给 `unserialize` 反序列化 | 没有过滤，但最后会被 `echo` |

这段代码其实把利用链拆得很清楚：

```text
text 过判断  →  file 过黑名单  →  include  →  unserialize  →  echo
```

我们一段一段来。

## 第一步：text 怎么过

首先，`text` 要让 `file_get_contents` 读出 `welcome to the zjctf`。

这里要怎么绕过呢？

想想 `file_get_contents` 这个函数有什么“漏洞”可以利用？

它接收的参数是**文件名或流路径**，不是一段普通的字符串。你写 `text=welcome to the zjctf`，PHP 会去找一个名字叫 `welcome to the zjctf` 的文件，当然找不到，返回值不是我们要的字符串。

### PHP 的 Stream Wrapper

`file_get_contents()` 以及其他文件操作函数，在收到路径时，PHP 会先看它的**前缀**，也就是所谓的 Stream Wrapper（流包装器）：

- 如果是 `http://`，PHP 会发起网络请求，去目标网站下载数据；
- 如果是 `file://`，PHP 会去本地硬盘读文件；
- 如果是 `data://`，PHP 会直接在内存中把后面的字符串当成文件内容；
- 如果是 `php://`，PHP 会走自己内部的一些流，比如 `php://input`、`php://filter`。

思考一下，这里用的是哪个？

用的是 `data://`。因为这样我们能够**自己构造内容**，让 `file_get_contents` 读出来的正好是 `welcome to the zjctf`，从而绕过判断。

```text
?text=data://text/plain,welcome%20to%20the%20zjctf
```

![用 data:// 过掉 text](02-data-wrapper.png)

*图 2：页面回显 `welcome to the zjctf`，说明 `text` 条件已经过了*

拆开看：

| 部分 | 含义 |
| --- | --- |
| `data://` | 使用 data 流包装器 |
| `text/plain` | 媒体类型，随便写，不影响内容 |
| `,` | 分隔媒体类型和真正的数据 |
| `welcome%20to%20the%20zjctf` | 数据本身，`%20` 是空格 |

URL 里的空格要编码成 `%20`，Web 服务器解码后，PHP 拿到的 `text` 值是：

```text
data://text/plain,welcome to the zjctf
```

`file_get_contents` 读这个流，返回的就是 `welcome to the zjctf`，和右边的字符串**严格相等**（`===`），条件成立。

注意这里是 `===`，不是 `==`。返回值必须类型和内容都一致，多一个换行、少一个空格都不行。用 `data://` 的好处是内容完全由我们控制，想要什么就是什么。

{% note info %}
**顺便说一句：`file_get_contents($text, 'r')` 里的 `'r'` 不是打开模式。**

`file_get_contents` 的第二个参数是 `use_include_path`（布尔值），不是 `fopen` 的 `mode`。这里传 `'r'` 会被当成 `true`，只是让 PHP 在 include_path 里找文件，对 `data://` 的读取没有影响。

别把它理解成“以只读方式打开”，这是 `fopen($file, 'r')` 的写法，不是 `file_get_contents` 的。
{% endnote %}

{% note think **思考 01｜为什么 `text=welcome to the zjctf` 不行？** %}
因为 `file_get_contents` 把参数当成**路径**，不是字面量。

`text=welcome to the zjctf` 会让它去找一个名字叫 `welcome to the zjctf` 的文件。这个文件不存在，`file_get_contents` 返回 `false`，和字符串比较自然不成立。

`data://` 的作用就是“把 URL 后面的内容伪装成一个文件”，让 `file_get_contents` 读到的不是磁盘文件，而是我们写在 URL 里的数据。
{% endnote %}

{% note think **思考 02｜为什么用 `data://`，不用 `http://` 或 `php://input`？** %}
三种都能让 `file_get_contents` 读到内容，但成本和稳定性不一样：

- `http://`：需要自己搭一个服务器，让它的响应体正好是 `welcome to the zjctf`；多一次网络请求，还可能被出网限制。
- `php://input`：读 POST body，内容可控，但代码里 `file_get_contents($text)` 调用了两次（判断一次、`echo` 一次）。`php://input` 不一定能重复读，第二次可能读到空。
- `data://`：内容直接写在 URL 里，不依赖外部服务，读多少次都是同一段字符串，最稳。

需要注意：`data://` 需要 `allow_url_fopen=On`（默认就是 On）。如果题目把它关了，再考虑 `php://input` 或本地文件。
{% endnote %}

## 第二步：file 怎么读源码

`text` 过了之后，接下来是 `file`。

首先不能直接写 `file=flag.php`，因为前面有一句：

```php
if(preg_match("/flag/", $file)){
    echo "Not now!";
    exit();
}
```

只要 `$file` 这个**字符串**里出现 `flag`，就直接 `exit`。所以 `flag.php`、`php://filter/.../resource=flag.php` 这种都过不去。

那怎么办？看下面这行：

```php
include($file);  //useless.php
```

注释里已经把文件名告诉我们了：`useless.php`。

回忆一下，`include` 漏洞有什么？

最经典的就是 **`php://filter` 读取**。

在文件包含场景下，`include` 会直接执行 PHP 文件中的代码。如果这个文件里没有输出，你包含它只会“定义了一些东西”，页面什么都不显示。如果想**读取源码而不是执行它**，就可以利用 `php://filter`。

### php://filter 的写法

```text
php://filter/read=convert.base64-encode/resource=useless.php
```

| 部分 | 作用 |
| --- | --- |
| `php://filter` | 使用 filter 流包装器 |
| `read=convert.base64-encode` | 读取时先把内容做 base64 编码 |
| `resource=useless.php` | 真正要读的文件 |

把它放进 `file`：

```text
?text=data://text/plain,welcome%20to%20the%20zjctf&file=php://filter/read=convert.base64-encode/resource=useless.php
```

![php://filter 读出 base64](03-base64.png)

*图 3：页面输出一长串 base64，说明 `useless.php` 的源码被编码后当成文本输出了*

成功读取！

为什么这样能读到源码，而不是执行它？

- `include` 打开的是 `php://filter` 这个流；
- 流在读取时先经过 `convert.base64-encode`，输出的是 base64 字符串；
- base64 的字符集里没有 `<` 和 `?`，所以整段内容里**不会出现 `<?php`**；
- PHP 解析这段内容时，没有看到 PHP 开标签，就把它当成普通文本输出。

如果直接 `include('useless.php')`，PHP 会执行里面的 `class Flag{...}`，类被定义，但没有任何输出。我们看不到源码，也就不知道 `Flag` 类里有什么。

`preg_match("/flag/", $file)` 这里也没有拦住，因为 `php://filter/read=convert.base64-encode/resource=useless.php` 这个字符串里没有 `flag`。

{% note think **思考 03｜为什么 base64 编码后 `include` 不会执行源码？** %}
因为 `include` 会把读到的内容当 PHP 代码解析，而 base64 字符串里没有 `<?php` 开标签。

PHP 解析器看到一段没有开标签的文本，就把它当普通 HTML 输出。所以我们看到的是 base64，而不是执行结果。

如果不用 base64，直接 `include('useless.php')`，里面的 `<?php` 会被识别，类定义被执行，页面什么也不输出。
{% endnote %}

## 第三步：useless.php 里有什么

把 base64 放到 CyberChef 里，用 `From Base64` 解码：

![CyberChef 解码](04-cyberchef.png)

*图 4：解码后能看到 `Flag` 类，以及它的 `__tostring()` 方法*

```php
<?php

class Flag{  //flag.php
    public $file;

    public function __tostring(){
        if(isset($this->file)){
            echo file_get_contents($this->file);
            echo "<br>";
            return ("U R SO CLOSE !///COME ON PLZ");
        }
    }
}
```

逐行看：

| 代码 | 含义 |
| --- | --- |
| `class Flag` | 类名是 `Flag` |
| `public $file;` | 有一个公开属性 `$file`，默认是 `null` |
| `__tostring()` | 当对象被当成字符串使用时，会自动调用这个方法 |
| `isset($this->file)` | 如果 `$file` 被赋值了 |
| `file_get_contents($this->file)` | 读取 `$file` 指向的文件并输出 |
| `return ("U R SO CLOSE !///COME ON PLZ")` | 返回一个字符串，作为对象的“字符串表示” |

PHP 的方法名不区分大小写，所以源码里的 `__tostring` 就是魔术方法 `__toString`，`echo` 时会被调用。

注释 `//flag.php` 是提示：把 `$file` 设成 `flag.php`，就能读到 flag。

这里要注意一个细节：**实际源码里 `$file` 没有默认值**，是 `public $file;`。草稿里写成 `public $file="flag.php";`，那是我们构造对象时给它赋的值，不是源码自带的。

`file_get_contents` 只读文件内容，不会执行 PHP。所以就算 `flag.php` 里有 `if(2===3){ return ("CTF2{...}"); }`，它也只是一个字符串，被原样读出来。

## 第四步：反序列化，触发 __toString

现在我们知道 `Flag` 类能读文件，但还差一步：**怎么让程序创建一个 `Flag` 对象，并让它的 `$file` 等于 `flag.php`？**

看最后两行：

```php
$password = unserialize($password);
echo $password;
```

`unserialize` 会把我们传入的字符串还原成对象；`echo $password` 会把对象当成字符串输出，于是触发 `Flag::__toString()`。

于是可以想到反序列化漏洞：**自己构造一个 `Flag` 对象，把 `$file` 设成 `flag.php`，序列化后传给 `password`。**

### 先构造对象

```php
<?php
class Flag{
    public $file = "flag.php";
}

$password = new Flag();
echo serialize($password);
?>
```

运行得到：

```text
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

逐段拆开：

| 片段 | 含义 |
| --- | --- |
| `O:4:"Flag"` | 对象（Object），类名 `Flag`，长度 4 |
| `:1:` | 有 1 个属性 |
| `{...}` | 属性列表 |
| `s:4:"file"` | 字符串（string），属性名 `file`，长度 4 |
| `s:8:"flag.php"` | 字符串，值 `flag.php`，长度 8 |

这里的数字都是**字节长度**，不是随便写的。`Flag` 是 4 个字符，`file` 是 4 个字符，`flag.php` 是 8 个字符。写错一个数字，`unserialize` 就可能失败。

{% note think **思考 04｜序列化字符串里的数字分别是什么意思？长度写错会怎样？** %}
`O:4:"Flag":1:{...}` 里：

- `O` 表示对象；
- `4` 是类名 `Flag` 的长度；
- `1` 是属性个数；
- `s:4:"file"` 里的 `4` 是属性名 `file` 的长度；
- `s:8:"flag.php"` 里的 `8` 是值 `flag.php` 的长度。

长度必须和实际字节数一致。写错的话，`unserialize` 会解析失败，通常返回 `false`，还可能伴随一个 `Notice`。如果属性名或值的长度对不上，后面的内容会整体错位。
{% endnote %}

### 最后一步：include 真正的 useless.php

构造好序列化字符串之后，`file` 要写什么？

不是 `php://filter`，而是 **`useless.php`**。

因为这一步需要 `Flag` 类**真的被定义**，`unserialize` 才能创建出 `Flag` 对象。如果 `file` 还用 `php://filter`，`include` 只会输出 base64 文本，`Flag` 类不会被定义；`unserialize` 创建出来的是一个不完整的对象，`echo` 也不会触发我们的 `__toString`。

最终 payload：

```text
?text=data://text/plain,welcome%20to%20the%20zjctf&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

![最终回显](05-flag.png)

*图 5：页面显示 `oh u find it` 和 `U R SO CLOSE !///COME ON PLZ`，flag 在页面源码的注释/`<?php ... ?>` 里*

页面正文里能看到：

```text
oh u find it
U R SO CLOSE !///COME ON PLZ
```

但 flag 不在正文里，而是在页面源码里：

```html
<!-- i cant give it to u now -->
<?php if(2===3){ return ("CTF2{a911662a-ca7d-4a40-83b7-deae1adc83ff}"); } ?>
```

*图 5 里按 F12 打开 Elements，可以直接看到这段源码。*

拿到 flag 了。

为什么 `if(2===3)` 里的 flag 会被读到？

因为 `__toString()` 用的是 `file_get_contents($this->file)`，它只是**读文件内容**，不会执行 `flag.php`。`if(2===3)` 是假，本来就不会返回 flag；但源码里的字符串被原样读出来了，所以 flag 就出现在页面源码里。

{% note think **思考 05｜为什么最后 `file` 不能继续用 `php://filter`？** %}
因为最后一步需要 `Flag` 类先被定义，`unserialize` 才能把它还原成 `Flag` 对象。

- `file=php://filter/...`：`include` 输出的是 base64 文本，`class Flag` 不会被执行，`Flag` 类不存在；
- `file=useless.php`：`include` 执行 `class Flag{...}`，类被定义，后面的 `unserialize` 才能创建对象。

所以两步要分开：**先 filter 读源码，再 plain include 定义类。**
{% endnote %}

{% note think **思考 06｜黑名单只检查 `$file`，为什么没拦住 `password` 里的 `flag.php`？** %}
因为它只检查 `$file`，不检查 `$password`。

```php
if(preg_match("/flag/", $file)){ ... }
```

黑名单的作用范围只有 `file` 参数。`password` 里的序列化字符串虽然包含 `flag.php`，但完全不经过这个正则，所以能顺利传进去。

这也是黑名单常见的问题：**拦了一个入口，却漏了另一个入口。**
{% endnote %}

{% note think **思考 07｜`__toString` 是什么时候被调用的？** %}
当对象被当成**字符串**使用时，PHP 会自动调用 `__toString()`。常见触发场景：

- `echo $obj;`
- `$str = "prefix" . $obj;`
- `strlen($obj);`
- `preg_match($pattern, $obj);`
- `in_array($obj, $array);`（比较时可能触发）

这题用的是最直接的 `echo $password;`。如果代码只 `include` 不 `echo`，也没有其他字符串操作，`__toString` 就不会触发，这条链也就断了。
{% endnote %}

{% note think **思考 08｜为什么 flag 在页面源码里，正文看不到？** %}
因为 `file_get_contents("flag.php")` 读的是**文件源码**，不是执行结果。

`flag.php` 里的 flag 写在一个 `if(2===3){ return ("CTF2{...}"); }` 里。这个条件永远为假，正常执行根本不会返回它；但 `file_get_contents` 会把整段源码原样读出来，包括这个字符串。

浏览器拿到这段源码后，`oh u find it` 会显示成正文，`<!-- ... -->` 会被当成注释隐藏，`<?php ... ?>` 会被当成未知标签/文本。所以正文看不到 flag，按 F12 看 Elements 或查看网页源代码就能看到。
{% endnote %}

## 知识点补充

### 1. 常见 Stream Wrapper

| Wrapper | 作用 | 典型利用 | 前提 |
| --- | --- | --- | --- |
| `file://` | 读本地文件 | `file:///etc/passwd` | 无特殊要求 |
| `http://` / `https://` | 发起网络请求 | SSRF、远程包含 | `allow_url_fopen`（包含还需 `allow_url_include`） |
| `data://` | 把 URI 内容当数据 | 构造任意文件内容 | `allow_url_fopen` |
| `php://input` | 读 POST body | 构造内容、绕过 | 通常可用 |
| `php://filter` | 对流做过滤/编码 | 读源码、编码绕过 | 通常可用 |
| `phar://` | 访问 phar 归档 | 反序列化、文件读取 | 需要 phar 文件 |
| `zip://` | 访问 zip 内文件 | 上传图片马后包含 | 需要 zip 文件 |

这题用了两个：`data://` 过 `text`，`php://filter` 读 `file`。

### 2. data:// 的两种写法

```text
data://text/plain,welcome to the zjctf
data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=
```

| 写法 | 特点 |
| --- | --- |
| 明文 | 直观，但内容里可能有空格、逗号、`&`，需要 URL 编码 |
| base64 | 内容全是安全字符，不用担心里面的特殊字符，适合放二进制或带特殊符号的数据 |

第二种的 `d2VsY29tZSB0byB0aGUgempjdGY=` 就是 `welcome to the zjctf` 的 base64。如果明文里的空格、`&` 把 URL 搞乱，可以换成 base64 写法。

### 3. php://filter 的常用过滤器

| 过滤器 | 作用 |
| --- | --- |
| `convert.base64-encode` | 读取时 base64 编码 |
| `convert.base64-decode` | 读取时 base64 解码 |
| `string.rot13` | ROT13 |
| `string.toupper` / `string.tolower` | 大小写转换 |
| `zlib.deflate` / `zlib.inflate` | 压缩/解压 |

还可以用 `|` 串联多个过滤器：

```text
php://filter/read=string.toupper|convert.base64-encode/resource=useless.php
```

`read=` 表示读取时应用；不写 `read=` 时，默认读写都应用。读源码一般用 `read=` 更明确。

### 4. include 和 file_get_contents 的区别

| 函数 | 行为 |
| --- | --- |
| `include($file)` | 把文件当 PHP 代码**执行**；有 `<?php` 就解析，没有就原样输出 |
| `file_get_contents($file)` | 只读内容，**不执行** |
| `require($file)` | 和 include 类似，但失败时是 fatal error |

这题先用 `include` + `php://filter` 读源码，再用 `__toString` 里的 `file_get_contents` 读 `flag.php`。两个函数的行为差异，正好构成了这条链的两半。

### 5. PHP 序列化格式速查

| 类型 | 格式 | 例子 |
| --- | --- | --- |
| 对象 | `O:<类名长度>:"<类名>":<属性数>:{...}` | `O:4:"Flag":1:{...}` |
| 字符串 | `s:<长度>:"<值>"` | `s:8:"flag.php"` |
| 整数 | `i:<值>` | `i:123` |
| 布尔 | `b:<0/1>` | `b:1` |
| 数组 | `a:<元素数>:{...}` | `a:1:{i:0;s:1:"a";}` |
| null | `N` | `N;` |

几个容易忽略的点：

- 长度是**字节数**，不是字符数；中文、特殊字符要注意。
- `public` 属性直接写属性名；`private` 属性名前面有 `\0类名\0`，`protected` 是 `\0*\0`，长度要把这些空字节算进去。
- `unserialize` **不会调用 `__construct`**，对象是直接“拼”出来的。
- `unserialize` 可能触发 `__wakeup`、`__destruct` 等魔术方法，这也是很多反序列化链的入口。
- 反序列化用户输入非常危险，这题就是故意留的。

### 6. 魔术方法速查

| 方法 | 触发时机 |
| --- | --- |
| `__construct` | `new` 对象时 |
| `__destruct` | 对象被销毁时 |
| `__toString` | 对象被当字符串使用时 |
| `__wakeup` | `unserialize` 时 |
| `__sleep` | `serialize` 时 |
| `__invoke` | 对象被当函数调用时 |
| `__get` / `__set` | 读写不可访问属性时 |

这题只用到 `__toString`，触发点是 `echo $password`。

### 7. 黑白名单的检查位置

这题的黑名单只检查 `$file`：

```php
preg_match("/flag/", $file)
```

它没有检查 `$password`，也没有检查 `text`。所以：

- `file` 里不能出现 `flag`，但可以用 `useless.php`；
- `password` 里可以出现 `flag.php`，因为根本不经过这个正则；
- `text` 里也可以出现任意内容，因为它是另一个参数。

做黑名单题时，先看清楚**每个参数分别经过哪些检查**，不要默认“有一个黑名单就全都拦了”。

## 几个容易踩的坑

| # | 坑 | 现象 | 正确做法 |
| --- | --- | --- | --- |
| 1 | `text` 里的空格没编码 | 条件不成立，页面回到源码 | 空格写 `%20` |
| 2 | `data://` 被禁用 | `file_get_contents` 返回 `false` | 换 `php://input` 或本地文件 |
| 3 | 直接 `file=flag.php` | 页面显示 `Not now!` | 用 `useless.php` 或 `php://filter` |
| 4 | 用 `php://filter` 读 `flag.php` | 字符串里含 `flag`，被正则拦 | 先读 `useless.php`，再从类里读 flag |
| 5 | 最后还用 `php://filter` | base64 文本被输出，`Flag` 类没定义 | 最后 `file=useless.php` |
| 6 | 序列化长度写错 | `unserialize` 失败，页面无输出 | 用 PHP 的 `serialize()` 生成 |
| 7 | `password` 里的引号/花括号没编码 | 参数被截断或解析错误 | URL 编码 `%22`、`%3A`、`%7B`、`%7D` |
| 8 | 只在正文找 flag | 正文只有 `oh u find it` | 按 F12 看 Elements 或查看源代码 |

## 完整流程速查

| 步骤 | 目的 | 操作 / payload | 结果 |
| --- | --- | --- | --- |
| 1 | 看源码 | 直接访问页面 | `highlight_file` 输出源码 |
| 2 | 过 text | `text=data://text/plain,welcome%20to%20the%20zjctf` | 回显 `welcome to the zjctf` |
| 3 | 读 useless.php | `file=php://filter/read=convert.base64-encode/resource=useless.php` | 得到 base64 |
| 4 | 解码 | CyberChef `From Base64` | 看到 `Flag` 类和 `__tostring` |
| 5 | 构造对象 | `class Flag{public $file="flag.php";}` + `serialize()` | `O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}` |
| 6 | 触发 | `file=useless.php&password=<序列化字符串>` | `__toString` 读 `flag.php` |
| 7 | 拿 flag | 查看页面源码 / Elements | `CTF2{...}` |

## 小结

这道题其实是一条很典型的 PHP 链：

- **`data://`**：让 `file_get_contents` 读到的不是文件，而是我们写在 URL 里的字符串；
- **`php://filter`**：让 `include` 读到的是 base64 编码后的源码，而不是执行结果；
- **`include`**：负责把 `useless.php` 里的 `Flag` 类定义出来；
- **`unserialize` + `__toString`**：构造对象，让 `echo` 触发魔术方法；
- **`file_get_contents`**：在 `__toString` 里读取 `flag.php`，把源码（包括 flag）输出到页面。

每一步都在利用不同函数对“输入”的理解差异：`file_get_contents` 把字符串当路径，`include` 把内容当代码，`unserialize` 把字符串当对象，`echo` 把对象当字符串。把这些差异串起来，就是这条链。

最后留三个问题，你可以自己想一想：

1. 如果 `allow_url_fopen=Off`，`data://` 用不了，你还能怎么让 `file_get_contents` 返回指定字符串？
2. 如果 `Flag` 类的 `$file` 是 `private`，序列化字符串要怎么改？
3. 如果最后没有 `echo $password`，还有什么办法能触发 `__toString`？
