---
title: "[SUCTF 2019] EasySQL：黑名单、堆叠注入与反推源码"
date: 2026-10-22 21:40:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - 堆叠注入
  - 黑名单绕过
  - Burp Suite
  - SUCTF
description: UNION 用不了时怎么办：先用 Intruder 摸清黑名单，用分号堆叠查询，再根据回显反推后端结构，最后用 *,1 绕开关键字过滤。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 3
permalink: 2026/10/22/web-ctf-sql-easysql-suctf/
---


前两篇用的都是 `UNION`，思路很顺：数清列数，把数据塞进回显位，收工。这道题会把这个惯性彻底打破——`UNION` 一次都用不上。

下面按**我看到什么 → 我想到什么 → 我试了什么**的顺序走一遍。中间遇到的每个新东西，都在用到它的当下解释清楚。

## 拿到题：只有一个输入框

打开靶场，页面朴素得有点可疑：

![SUCTF EasySQL 首页](17-suctf-index.png)

*图 14：一行提示 + 一个输入框，连登录框都没有*

提示语是 `Give me your flag, I will tell you if the flag is right.`，直译过来是"把你的 flag 交出来，我告诉你对不对"。出题人显然在开玩笑——页面当然不知道 flag。别被文字带偏，真正要看的是这个输入框把数据送到哪。

按 F12，在 Elements 面板里看表单的写法：

```html
<form action="" method="post">
  <input type="text" name="query">
  <input type="submit">
</form>
```

三行代码给出三个信息：

- `method="post"` —— 参数在**请求体**里，不在地址栏，所以不能像前两篇那样直接改 URL；
- `action=""` —— 提交回当前页面；
- `name="query"` —— **参数名是 `query`**。后面所有的 payload，都是这个参数的值。

{% note info %}
不做题也要知道：`name` 属性的值就是后端接收时用的键名。看到一个输入框却不知道参数叫什么，F12 看一眼表单就够了，不用猜。
{% endnote %}

因为参数在 POST 体里，后面统一用 Burp Suite 的 Repeater 发包（Proxy 里拦截到请求后右键 → Send to Repeater，改完点 Send）。没有 Burp 也能做：F12 → Network → 提交一次 → 右键请求 → Copy as cURL，贴到命令行里改。

## 第一次试探：`1'`

做前两篇时的肌肉记忆是先加个单引号，看数据库会不会抱怨：

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=1'
```

页面**没有报错**，只在 `</html>` 后面多了一行字：

![单引号被拦截](18-blacklist-nonono.png)

*图 15：响应正常返回 200，`</html>` 之后追加了一行 `Nonono.`*

这里有一个非常关键的判断，新手最容易看漏：

> `Nonono.` **不是数据库的报错**。

MySQL 的语法错误长这样：

```text
You have an error in your SQL syntax; check the manual that corresponds to
your MySQL server version for the right syntax to use near ...
```

而 `Nonono.` 是一句带着情绪的英文，显然是**程序自己打印的**。也就是说：我们的输入根本没走到数据库，在半路就被程序拦下来了。

为了验证这个判断，把单引号去掉再发一次：

| 输入 | 页面末尾 |
| --- | --- |
| `1` | `Array ( [0] => 1 )` |
| `1'` | `Nonono.` |

两次都是 HTTP 200，页面主体完全一样，区别只在末尾那一行。

结论：后端用的不是"转义"，而是**黑名单**——输入里出现某些字符或单词，程序就直接输出 `Nonono.` 结束，压根不查库。

所以在这道题里，"数字型还是字符型"这个问题没有意义：单引号连门都进不去。

## 黑名单里有什么？用 Intruder 一次问清楚

现在的问题是：到底哪些字符能用？

一条条手敲太慢，而且你永远不知道漏了哪个。标准做法是**字典爆破**：把可能被拦的字符和关键字列成清单，让工具替我们逐个提交，再对比哪些响应"正常"。

Burp Suite 的 **Intruder** 模块就是干这个的：它把请求里被标记的位置，依次替换成字典里的每一个词，批量发出去，再把所有响应排成一张表。

**操作步骤**

1. 在 Burp 里选中刚才那条请求，右键 → **Send to Intruder**（快捷键 Ctrl+I）：

   ![Burp 中 Send to Intruder](19-send-to-intruder.png)

   *图 16：右键菜单里的 Send to Intruder*

2. 切到 **Positions** 标签，点右边的 `Clear §` 清空自动标记，然后手动选中 `query=` 后面的值，点 `Add §`。现在请求里应该只剩一对标记：`query=§1§`；
3. 切到 **Payloads** 标签，Payload type 选 `Simple list`，把字典贴进下面的框里：

   ```text
   '
   "
   #
   --
   ;
   (
   )
   ,
   select
   union
   or
   and
   flag
   information_schema
   ```

4. 点右上角的 **Start attack**，等表格跑完。

**怎么读结果**

每一行是一次请求。我们要找的是**响应和正常输入一致**的那些——它们说明那个字符没被拦。

![Intruder 爆破结果](20-intruder-result.png)

*图 17：`(` 和 `;` 两行的响应完全一致，都在放行之列*

在几十行结果里，`(` 和 `;` 的表现与正常输入相同。其中 `;` 是重点中的重点：

{% note info %}
**为什么 `;` 这么关键**

`;` 是 SQL 的**语句结束符**。程序本来只打算执行一条语句，但如果它能接受 `;`，我们就能在后面再"叠"上一条自己的语句。这叫**堆叠注入（Stacked Injection）**。

和前面 `UNION` 那一篇对比一下就清楚了：

- `UNION` 是把新查询**接在**原查询后面，仍然是一条语句，所以列数必须严格对齐；
- 堆叠注入是**另起一条**语句，两条互不相干，`show tables`、`insert`、`update` 想用哪个用哪个。

它能不能成立，取决于后端调用的接口：`mysqli_multi_query()` 或 PDO 的 `exec()` 支持多语句，而普通的 `mysqli_query()` 只执行第一条，后面的直接丢弃。
{% endnote %}

看到 `;` 没被拦只是一条线索，能不能真跑起来还得实测。

## 实测堆叠：`1;show tables;`

既然想找表，就先查表名。`show tables` 是 MySQL 的元命令，作用是列出当前数据库里所有的表：

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=1;show tables;
```

响应里出现了两段：

![show tables 结果](21-show-tables.png)

*图 18：第一段是原查询的结果，第二段是 `show tables` 的结果 `Flag`*

```text
Array
(
    [0] => 1
)

Array
(
    [0] => Flag
)
```

这个回显格式要读明白：**一个 `Array` 就是一个结果集**，`[0]` 表示这个结果集第一行的第一列。所以：

- 第一段 `[0] => 1`：原查询的结果。说明输入 `1` 真的被执行了（`select 1` 的结果就是数字 1）；
- 第二段 `[0] => Flag`：我们叠上去的 `show tables` 的结果。库里只有一张表，名字叫 `Flag`。

一次成功，两个收获：堆叠注入可用，表名到手。

{% note info %}
`Array ( ... )` 是 PHP `print_r()` 的输出格式。作者八成是在开发时用它调试，上线忘了删。这类把内部数据结构直接暴露给用户的行为，本身就是一种信息泄露——生产环境应当关掉 `display_errors`，用日志记录错误。
{% endnote %}

## 想直接读表：`show columns from Flag`

有了表名，下一步自然是看表里有哪些列：

```text
query=1;show columns from Flag;
```

结果又变回 `Nonono.`：

![show columns 被拦截](22-columns-blocked.png)

*图 19：payload 里出现了 `Flag`，直接命中黑名单*

同样的语法，`show tables` 能过，`show columns from Flag` 却不能过。差别只在于我们亲手敲下的那三个字母。

于是得到一个非常重要的结论：

> 黑名单检查的是**我们输入的文字**，检查不了**数据库返回的数据**。

证据就在上一张截图里：`show tables` 的输出中明明白白写着 `Flag`，但那次请求一点事没有——因为 `Flag` 是从数据库吐出来的，不是我们打进去的。

这条规律直接决定了后面的战术：**让数据库自己把 flag 拿出来，而不是我们亲手写 `flag`。**

{% note info %}
严格讲，`show columns from Flag` 里有两个可能触发黑名单的新词：`columns` 和 `Flag`。想确认到底拦的是哪个，可以自己试一条 `query=1;select * from Flag;`——`select` 和 `from` 前面的测试已经证明可用，如果这条也返回 `Nonono.`，那被拦的就是 `Flag`。
{% endnote %}

## 先把线索整理清楚

别急着试 payload。现在手里的信息其实不少，先把能确定的定下来，把不确定的单独圈出来。

**先做两组对照实验**

上一节的 `select` 已经能跑，那就拿它探一探原查询长什么样。

第一组，`select` 后面跟个数字：

```text
query=1;select 1;
```

![1;select 1;](23-stacked-select-1.png)

*图 20：两个结果集，各有一个 `1`*

两个 `Array`，每个都是 `[0] => 1`。原查询一个，我们叠的 `select 1` 一个，符合预期。

第二组，`select` 后面跟个字母：

```text
query=1;select a;
```

![1;select a;](24-stacked-select-a.png)

*图 21：第二个结果集消失了*

只剩**一个** `Array` 了。

为什么 `select 1` 有结果、`select a` 没有？差别在于 `a` 没有加引号。**没加引号的 `a` 在 SQL 里是列名**，而这张表里没有叫 `a` 的列，语句直接报错。报错就没有结果集，PHP 自然也打不出第二段 `Array`。

由此得到一个关键结论：**我们的输入是原样拼进 SQL 语法的**，没有加引号、没有转义，可以直接改变 SQL 的结构。另外要注意，报错信息不会回显给我们，只会表现为"少一段输出"——所以后面判断成败，得靠**数结果集**。

**能排除的四种写法**

*排除 1：程序只是把我们输入的东西打印出来？*

```php
echo $_POST['query'];
```

如果真是这样，输入 `1;show tables;` 时页面应该把这串字符原样显示，而不是返回表名。可它真的去查了库。

→ 排除。

*排除 2：后端是 `update` 或 `insert`？*

这两类语句**不返回结果集**，执行完只告诉你影响了几行。可我们的 `select 1`、`show tables` 都拿到了数据。

→ 排除。后端一定用了 `select`（或 `show`）。

*排除 3：注入点在 `where` 条件里，比如 `select * from Flag where id=$query`？*

输入 `1` 时，页面回显的是 `Array ( [0] => 1 )`——`[0]` 的值是**字面量 `1`**。如果输入是被塞进 `where` 里当条件的，返回的应该是**表里某一行的数据**，`[0]` 会是那个字段的值，而不是数字 1。

→ 排除。我们的输入是被当成**字段**求值的，所以注入点在 `select` 的字段列表里。

*排除 4：原查询本来就返回两列，比如 `select 1, $query from Flag`？*

看图 20 的第一段——里面只有 `[0]` 一个元素。两列的话应该同时有 `[0]` 和 `[1]`。

→ 排除。第一条查询只返回**一列**。

**排完之后，能确定的**

1. 输入是**原样拼进 SQL** 的——`a` 没加引号，被当成列名报错，第二段 `Array` 才会消失；
2. 拼接位置在 `select` 的**字段列表**，不是 `where`；
3. 第一条查询只返回一列；
4. 多语句可以执行，堆叠注入可用。

**还没确定的**

- 表里有哪些列。`flag` 三个字母被黑名单挡着，`show columns` 走不通；
- 我们的输入**后面还有没有别的东西**。

第二条其实有线索。首页那句 `I will tell you if the flag is right` 不是随便写的：如果后端真会"判断 flag 对不对"，那它就必须拿**我们输入的东西**和**数据库里的 flag** 做比较。单纯写 `select $query from Flag` 是做不到这件事的。

所以一个合理的猜测是：

```php
$sql = "select $_POST['query'] || flag from Flag";
```

{% note warning %}
**这只是猜测，还没验证。**

我们并不知道那一列到底叫不叫 `flag`——这个词连黑名单都过不去，`show columns` 根本查不出来。也不知道中间那个符号是不是 `||`，`=`、`like`、`and` 都有可能。

把它写出来，是因为下一步要构造一个**同时兼容"后面有东西"和"后面没东西"**的 payload。如果一上来就把宝押在某个具体结构上，猜错就是报错。
{% endnote %}

## `*,1`：不赌结构的探针

面对"不知道列名、也不知道后面接了什么"的局面，最稳的打法是不猜——**造一个不管哪种情况都能跑通的 payload**。

关键工具是 `*`。`select` 里的 `*` 表示"这张表的所有列"，**不需要知道任何列名**。这正好绕开了"`flag` 打不出来"的死结。

但直接发一个 `*` 是有风险的：如果后端真的在我们输入后面接了东西，`select * || flag from Flag` 会变成语法错误——`*` 没办法参加运算。

所以要给后面那部分安排一个落脚的字段，这就是 `,1` 的由来：

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=*,1
```

两种猜测下分别会拼成什么：

| 猜测 | 实际执行的语句 | 预期结果 |
| --- | --- | --- |
| 后面没东西：`select $query from Flag` | `select *,1 from Flag` | 列出所有列，外加一列 `1` |
| 后面有东西：`select $query \|\| flag from Flag` | `select *,1 \|\| flag from Flag` | 列出所有列，外加 `1 \|\| flag` |

两条路都能跑通，而且都能把表里的列全部打出来。这就是"不赌结构"的好处：**先拿到数据，再回头谈结论**。

回显：

![拿到 flag](25-suctf-flag.png)

*图 22：`[0]` 是真正的 flag，`[1]` 是那列"凑数"的 `1`*

```text
Array
(
    [0] => CTF2{00fb9a58-059d-48ce-9485-fa936a4ff50c}
    [1] => 1
)
```

```text
CTF2{00fb9a58-059d-48ce-9485-fa936a4ff50c}
```

## 回显反过来验证了前面的猜测

`[0]` 就是我们要的东西，`[1]` 是 `1`。

到这一步才敢说：后端确实是 `select $_POST['query'] || flag from Flag`。

注意这里的先后顺序——**它不是我们动手前就知道的前提，而是 `*,1` 成功之后回过头确认的结果**。`[1]` 恰好等于 `1`，正好符合"`1 || flag` 逻辑或恒为真"的推演。

这也是为什么探针要设计成"两头都能成立"：如果当时赌 `select * from Flag`，会直接撞黑名单；如果赌 `select <猜的列名> from Flag`，猜错就是一片空白。而 `*,1` 不要求你事先知道任何一件事，它把"确认结构"放在了拿到数据之后。

## 顺带一提：另一种解法

`[1] => 1` 还透露了一点：中间那个符号很可能是 `||`，因为我们输入 `1` 它就返回 `1`，像是"逻辑或"的结果。

如果这个判断成立，那就还有一条路：把 `||` 的语义从"逻辑或"改成"字符串连接"，让后端自己把 flag 拼出来。

```text
query=1;set sql_mode=PIPES_AS_CONCAT;select 1
```

后端拼出来是三条语句：

```sql
select 1;
set sql_mode=PIPES_AS_CONCAT;
select 1 || flag from Flag;
```

- 第一条 `select 1`：返回一个结果集，打印 `[0] => 1`；
- 第二条 `set`：不返回结果集，什么都不打印；
- 第三条：此时 `sql_mode` 已经改成拼接模式，`1 || flag` 等价于 `concat(1, flag)`，结果是 `1CTF2{...}`。

所以页面会看到两段 `Array`，第二段就是 `1CTF2{...}`，把前面多出来的 `1` 去掉即可。

顺带说，这条 payload 本身也是一次**验证**：如果后端根本没有 `||`，它只会回显两个 `1`，不会出现 flag。

{% note info %}
`set sql_mode=...` 只对**当前连接**生效，而且必须和后面的 `select` 在**同一次请求**里执行——分两次发的话，连接一断设置就失效了。这也是堆叠注入的另一个价值：可以在同一个连接里先改环境，再查询。
{% endnote %}

## 复盘：这道题教会我们什么

1. **先判过滤，再谈 payload**。看到的是自定义提示（`Nonono.`）而不是数据库报错，就该知道有黑名单，别再浪费时间试 `UNION`；
2. **字典爆破比手工试靠谱**。Intruder 把"哪些字符能用"一次性摊开，`;` 就是从表里看出来的；
3. **信息不足时，选"不赌结构"的 payload**。`*,1` 在两种猜测下都能成立，先用它把数据拿到手，再回头确认结构——这比先猜源码再赌一把稳得多；
4. **黑名单只能拦输入，拦不住数据**。`show tables` 的输出里有 `Flag` 却安然无恙，就是最好的证明。

## 系列小结

这三道题其实是一条递进的学习路径：

- **EasySQL（极客大挑战）** 教会我们：找到注入点 → 闭合引号 → 注释掉密码判断 → 万能密码登录；
- **LoveSQL** 教会我们：登录只是开始，真正的数据要靠 `UNION SELECT` 去查；
- **EasySQL（SUCTF）** 教会我们：当 `UNION` 用不了时，先摸过滤规则，再考虑堆叠注入，最后从回显反推后端结构。

前两篇的套路可以记成一句话：

> **判注入 → 定列数 → 找回显 → 爆库 → 爆表 → 爆字段 → 拖数据**

这一篇则说明了另一件事：**注入不是一个固定模板，而是"读懂后端写了什么"的过程**。搞清楚 `select $query || flag from Flag` 这一句，`*,1` 是水到渠成的；如果只背 payload，题目稍微改一下就会卡住。

把这几条流程在自己搭的靶场上手动走几遍，比背 payload 有用得多。接下来可以继续练习盲注、报错注入和时间盲注。
