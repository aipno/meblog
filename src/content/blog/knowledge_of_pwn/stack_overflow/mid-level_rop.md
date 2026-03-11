---
title: 中级ROP
pubDate: 2026-03-09T15:48:00
category: Pwn小知识
tags:
  - Stack
---
## ret2csu

在 x64 Linux 环境下，函数调用的前三个参数是通过寄存器 `rdi`, `rsi`, `rdx` 传递的。

如果我们想调用 `write(1, buf, len)` 或 `execve("/bin/sh", 0, 0)`，我们需要控制这三个寄存器。在大型程序中，我们可以很容易找到 `pop rdi; ret` 这样的指令片段（Gadgets）。但在小型程序中，这种完美的 Gadget 往往不存在。

ret2csu 的原理在于利用程序中几乎都会存在的 `__libc_csu_init` 函数。这个函数用来初始化 libc，因此几乎所有动态链接的程序里都有它。在这个函数内部，恰好有一段代码可以用来控制寄存器并调用函数。

### 深入剖析 `__libc_csu_init`

我们要利用的是该函数中的两段代码片段（Gadgets）。

#### Gadget 1 (这也是通常攻击链的入口)

位于函数的尾部，用于将栈上的数据弹出到寄存器中：

```x86asm
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

```x86asm
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

| 目标参数寄存器   | 来源寄存器 (在 Gadget 1 中控制) | 注意事项                                                         |
| ---------------- | ------------------------------- | ---------------------------------------------------------------- |
| Argument 3 (RDX) | `pop r15`                       | 完全控制 (64位)                                                  |
| Argument 2 (RSI) | `pop r14`                       | 完全控制 (64位)                                                  |
| Argument 1 (RDI) | `pop r13`                       | 受限！只能控制 `edi` (低32位)，高32位会被清零。                  |
| Call Target      | `pop r12`                       | `r12` 必须指向函数地址的指针 (例如 GOT 表地址)，而不是函数本身。 |
| 控制流逻辑       | `pop rbx`                       | 设置为 0                                                         |
| 控制流逻辑       | `pop rbp`                       | 设置为 1                                                         |

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

## ret2reg

ret2reg (Return-to-Register) 是一种经典的缓冲区溢出利用技术。

它的核心思想是：当攻击者无法预知 Shellcode 在栈上的精确绝对地址，但知道某个 CPU 寄存器恰好指向 Shellcode 所在的位置时，利用程序中的跳转指令（如 `jmp eax`, `call ebx` 等）作为“跳板”，间接跳转到 Shellcode 执行。

这种技术通常用于绕过环境差异导致的栈地址随机化（即栈基址在不同运行环境中会微小浮动），或者在没有开启 NX（堆栈不可执行）保护的旧系统中。

### Ret2Reg 的核心原理

#### 问题背景

在传统的栈溢出攻击中，我们需要覆盖返回地址（Return Address），将其指向 Shellcode 的起始地址。

* 难点：在实际环境中，栈的绝对地址往往是不固定的（受环境变量、调试器干扰、ASLR 微弱抖动影响）。如果硬编码一个栈地址（如 `0xbffff123`），一旦实际运行偏移了 16 字节，攻击就会失败。

#### 观察现象

在函数返回（执行 `ret` 指令）的一瞬间，虽然我们不知道栈顶的绝对地址，但 CPU 的某些通用寄存器（如 `eax`, `edx`, `esp` 等）往往保存着相关的数据指针。

* 例如，`strcpy(dst, src)` 执行完后，`eax` 寄存器通常会保存 `dst` 缓冲区的地址（即 Shellcode 的存放位置）。

#### 解决方案（跳板）

我们不再硬编码栈地址，而是寻找程序代码段（`.text`）或动态库中一条现成的指令，这条指令的内容是跳转到那个寄存器。

* Gadget：寻找 `jmp eax`、`call eax`、`jmp esp` 或 `call esp` 等指令。
* 操作：将栈上的“返回地址”覆盖为这条指令的地址。

#### 执行流程

1. 函数执行完毕，`ret` 弹出我们覆盖的地址。
2. CPU 跳转到该指令地址（例如找到的 `jmp eax` 的地址）。
3. CPU 执行 `jmp eax`。
4. 因为 `eax` 正指向我们的 Shellcode，程序流被引入 Shellcode。
5. Shellcode 执行。

### Ret2Reg 攻击示例

假设我们攻击一个简单的 32 位 Linux 程序。

#### 漏洞代码

```c
// vulnerable.c
#include <string.h>
#include <stdio.h>

void func(char *str) {
    char buffer[100];
    // 典型的栈溢出漏洞
    strcpy(buffer, str); 
}

int main(int argc, char **argv) {
    if (argc > 1) {
        func(argv[1]);
    }
    return 0;
}
```

#### 分析与调试

假设该程序编译时关闭了 NX 保护（栈可执行），但我们不知道 `buffer` 的确切地址。

第一步：确认寄存器状态
我们用 GDB 调试，在 `func` 函数 `ret` 的位置断点。我们发现：

* 由于 `strcpy` 的特性，它会将目标缓冲区的地址作为返回值放在 EAX 寄存器中。
* 此时，EAX 正指向 buffer 的开头（也就是我们将要放入 Shellcode 的地方）。

第二步：寻找跳板 (Trampoline)
我们需要在程序中找到 `jmp eax` 或 `call eax` 指令。
使用工具（如 `ROPgadget` 或 `objdump`）：

```bash
$ ROPgadget --binary vulnerable --opcode "ffe0"  # ffe0 是 jmp eax 的机器码
# 输出:
# 0x0804834b : jmp eax
```

我们要利用的地址是 `0x0804834b`。

#### 构造 Payload

我们需要填充 buffer，溢出覆盖 EBP，最后覆盖返回地址。

* Buffer 大小: 100 字节。
* EBP 大小: 4 字节（32位系统）。
* 总偏移: 104 字节后是返回地址。

Payload 结构：
`[ Shellcode ] + [ Padding ] + [ 覆盖返回地址 ]`

1. Shellcode: 假设长度为 25 字节。
2. Padding: 填充垃圾数据，填满到 104 字节。长度 = 104 - 25 = 79 字节。
3. 返回地址: 填入 `jmp eax` 的地址 `0x0804834b`。

最终 Payload (Hex 概念)：

```text
[ Shellcode (25 bytes) ] + [ 'A' * 79 ] + [ \x4b\x83\x04\x08 ]
```

> 注意：地址是小端序

#### 攻击执行流

1. `func` 执行 `strcpy`，我们的 Shellcode 被复制到栈上。
2. `strcpy` 结束，EAX 寄存器指向栈上 Shellcode 的开头。
3. `func` 执行 `ret`。
4. 程序跳转到栈上保存的返回地址：`0x0804834b`。
5. CPU 执行 `0x0804834b` 处的指令：`jmp eax`。
6. 程序跳转到 EAX 指向的地址（即栈顶的 Shellcode）。
7. Shellcode 成功运行，获得 Shell。

#### 总结

Ret2Reg 是一种利用寄存器定位来对抗栈地址不确定性的技术。

* 前提：
    1. 溢出后，某个寄存器指向可控内存区域（Shellcode）。
    2. 程序代码段或库中存在 `jmp/call reg` 指令。
    3. 目标内存区域（栈）具有可执行权限（No NX）。
* 对比 Ret2Shellcode：Ret2Shellcode 是硬编码栈地址，Ret2Reg 是软编码（通过寄存器中转），后者更稳定。

## JOP

JOP (Jump-Oriented Programming)** 是一种代码复用攻击技术，它是 ROP 的另一种进化形式。

如果说 ROP 的核心是 `ret`，COP 的核心是 `call`，那么 JOP 的核心就是 `jmp`（间接跳转）。

### JOP 的核心原理

JOP 旨在绕过那些依赖于“函数调用栈”检查的防御机制（如 Shadow Stack 或针对 `ret` 指令的 CFI）。在 JOP 攻击中，攻击者不使用栈来驱动控制流，而是维护一个自定义的“虚拟控制流表”。

#### 1. 核心组件

一个典型的 JOP 攻击包含三个主要部分：

1. Dispatcher Gadget（分发器代码片）：
    * 这是 JOP 的心脏，相当于 CPU 的“取指-译码-执行”循环。
    * 它的作用是：更新指向“分发表”的指针 -> 加载下一个 Gadget 的地址 -> 跳转执行。
2. Dispatch Table（分发表）：
    * 这是攻击者在内存中构造的数据结构（通常是一组地址列表）。
    * 它相当于 JOP 程序的“机器码”，决定了 Gadget 的执行顺序。
3. Functional Gadgets（功能代码片）：
    * 执行具体任务的代码（如赋值寄存器、计算等）。
    * 关键特征：它们不以 `ret` 结尾，而是以 `jmp` 结尾，跳回到 Dispatcher（或者跳向下一个 Gadget）。

#### 2. 控制流差异

* ROP: 控制流依赖栈顶指针 (`rsp`)。执行完一个 gadget，`ret` 自动从栈顶弹射到下一个。
* JOP: 必须指定一个通用寄存器（如 `rbx`）作为“虚拟指令指针 (vPC)”。Dispatcher 负责操作这个寄存器来切换执行流。

### JOP 攻击示例

假设目标是一个 64 位 Linux 程序，我们的目标是执行 `system("/bin/sh")`。

#### 场景设定

1. 防御：开启了 Shadow Stack（严防 `ret`）和 NX。
2. 初始状态：攻击者控制了堆内存，并且能通过漏洞将 `rbx` 寄存器指向这块内存。
3. 目标：
    * `rdi` = `"/bin/sh"`
    * 调用 `system`

#### 构造组件

1. 寻找 Dispatcher Gadget
我们需要一段能够推进指针并跳转的代码。假设在 `0x400800` 找到了：

```x86asm
; Dispatcher (地址: 0x400800)
add rbx, 8        ; 将 rbx 指针向下移动 8 字节 (指向表中的下一项)
mov rax, [rbx]    ; 将 rbx 指向的内容 (下一个 Gadget 地址) 取出放入 rax
jmp rax           ; 跳转执行
```

*注：这里 `rbx` 就充当了“虚拟指令指针”。*

1. 寻找功能 Gadgets
我们需要设置参数。

* Gadget A (设置参数) - 地址 `0x400100`:

    ```x86asm
    pop rdi           ; 这是一个混合 gadget，利用栈来取数据，或者用 mov rdi, const
    jmp 0x400800      ; **关键**：执行完后，硬编码跳转回 Dispatcher 继续循环
    ```

    *(注：纯粹的 JOP 很难找，通常会混用 pop 指令，但结尾必须是 jmp)*

* Gadget B (最终执行) - 地址 `0x400200`:

    ```x86asm
    call system       ; 调用系统函数
    ```

1. 构造 Dispatch Table (内存布局)
攻击者在内存地址 `0x600000` 处构造如下数据表：

| 内存地址 | 内容 (数值) | 说明 |
| :--- | :--- | :--- |
| `0x600000` | `0x400100` | **Gadget A 的地址** |
| `0x600008` | `0x400200` | **Gadget B 的地址** |
| `...` | `...` | ... |

#### 攻击执行流程

1. 劫持控制流：
    通过漏洞触发，将 `rbx` 设置为 `0x5FFFF8` (比表头少8字节)，并将 CPU 的 `rip` 指向 Dispatcher (`0x400800`)。

2. 进入 Dispatcher (第一轮)：
    * `add rbx, 8` -> `rbx` 变为 `0x600000`。
    * `mov rax, [rbx]` -> `rax` 变为 `0x400100` (Gadget A)。
    * `jmp rax` -> 跳转到 Gadget A。

3. 执行 Gadget A：
    * `pop rdi` (或其他指令) -> 将 `rdi` 设置为 `"/bin/sh"`。
    * `jmp 0x400800` -> 跳回 Dispatcher。

4. 回到 Dispatcher (第二轮)：
    * `add rbx, 8` -> `rbx` 变为 `0x600008`。
    * `mov rax, [rbx]` -> `rax` 变为 `0x400200` (Gadget B)。
    * `jmp rax` -> 跳转到 Gadget B。

5. 执行 Gadget B：
    * `call system` -> 此时 `rdi` 已经是 `"/bin/sh"`。
    * Shell Get!

### 总结：ROP vs COP vs JOP

| 特性    | ROP (Return)   | COP (Call)                      | JOP (Jump)            |
| :---- | :------------- | :------------------------------ | :-------------------- |
| 驱动指令  | `ret`          | `indirect call`                 | `indirect jmp`        |
| 控制流状态 | 栈指针 (`rsp`)    | 栈指针 + 寄存器                       | 通用寄存器 (Virtual PC)    |
| 核心结构  | 栈上的 Gadget 地址链 | Gadget 链 + `pop/ret`清除栈         | Dispatcher + 内存表      |
| 防御目标  | 绕过 NX (DEP)    | 绕过针对 `ret` 的 CFI / Shadow Stack | 绕过针对 `ret/call` 的 CFI |
| 主要难点  | 最容易，Gadget 丰富  | 容易导致栈失衡                         | 最难，Dispatcher 难找      |

JOP 是一种非常强大的技术，因为它彻底抛弃了对“程序栈”作为控制流驱动器的依赖，使得很多基于栈完整性检查的防御手段完全失效。

## COP

COP (Call-Oriented Programming) 是一种代码复用攻击技术，它是 ROP (Return-Oriented Programming) 的一种变体或进化形式。

如果说 BROP 是为了解决“没有二进制文件”的问题，那么 COP 主要是为了解决“针对 ROP 的防御机制”（特别是 CFI 控制流完整性和影子栈 Shadow Stack）。

### COP 的核心原理

#### 1. 背景：为什么要用 COP？

传统的 ROP 依赖于 `ret` 指令。防御者开发出了影子栈 (Shadow Stack) 等技术，通过监控 `call` 和 `ret` 的配对关系来防御 ROP。

- 当程序执行 `call` 时，返回地址被压入影子栈。
- 当程序执行 `ret` 时，系统会检查栈顶的地址是否与影子栈记录的一致。
- 由于 ROP 频繁使用 `ret` 跳转到非预期的地址（Gadgets），这种检查会直接拦截 ROP。

COP 的思路是：既然 `ret` 被严防死守，那我就不使用 `ret`，而是只使用 `call` 指令来进行跳转。

#### 2. 运作机制

COP 不依赖栈上的返回地址来控制程序流，而是利用间接调用 (Indirect Call) 指令。

- 指令形式：`call reg` (如 `call rax`) 或 `call [reg]` (如 `call [rbx]`)。
- Gadget 特征：COP 的 Gadget 是一段以间接 `call` 结束的代码片段。
  - 例如：`mov rdi, rbx; call rcx;`
- 控制流链接：在 ROP 中，`ret` 会自动从栈上弹出一个地址跳过去；在 COP 中，攻击者必须提前安排好寄存器或内存的值，使得当前 Gadget 结尾的 `call` 指令能够准确跳到下一个 Gadget 的起始地址。

#### 3. 难点与特性

- 副作用：`call` 指令会将返回地址压栈。如果不处理，连续的 COP Gadgets 会导致栈无限增长（Stack Overflow）。但在实际攻击的短链中，这通常不是问题。
- Dispatcher（分发器）：这是 COP 的核心概念。因为不能像 ROP 那样自动利用 `rsp` 滑行，COP 通常需要寻找一个“分发器 Gadget”，它的作用是更新指向下一个 Gadget 的指针，维持攻击链的运行。

### COP 攻击示例

假设我们要攻击一个 64 位的 Linux 程序，目标是执行 `system("/bin/sh")`。

#### 场景假设

1. 漏洞：存在堆溢出或能够控制某些关键寄存器（如 `rbx`, `rcx`, `rax`）的初始状态。
2. 防御：开启了针对 `ret` 的检测，无法使用传统 ROP。
3. 目标：
   - 设置 `rdi` 寄存器指向 `"/bin/sh"` 字符串的地址。
   - 调用 `system` 函数。

#### 构造 COP 链

我们需要寻找以 `call` 结尾的 Gadgets。

Gadget 1 (设置参数):
地址 `0x400100`:

```x86asm
mov rdi, rbx   ; 将 rbx 的值（/bin/sh 的地址）赋给 rdi
call rcx       ; 跳转到 rcx 指向的地址（即 Gadget 2）
```

Gadget 2 (执行调用):
地址 `0x400200`:

```x86asm
; 假设这个 gadget 直接就是 system 函数的入口，或者跳向 system
call system_addr
```

#### 攻击执行流程（内存与寄存器布局）

为了让上述链条跑通，攻击者需要在触发漏洞前，将寄存器布局控制如下：

1. RBX: 设置为 `0x600000` (假设这是我们写入 `"/bin/sh"` 字符串的内存地址)。
2. RCX: 设置为 `0x400200` (这是 Gadget 2 的地址)。
3. RIP (指令指针): 被劫持指向 `0x400100` (这是 Gadget 1 的地址)。

执行步骤：

1. 程序跳转到 Gadget 1 (`0x400100`)。
2. 执行 `mov rdi, rbx`。此时 `rdi` 变成了 `"/bin/sh"` 的地址（完成了参数准备）。
3. 执行 `call rcx`。因为 `rcx` 是 `0x400200`，程序跳转到 Gadget 2。
    - *注意：此时栈上被压入了一个无用的返回地址，但我们不关心它。*
4. 程序到达 Gadget 2 (`0x400200`)。
5. 执行 `call system_addr`。
6. `system("/bin/sh")` 被执行，获得 Shell。

### 进阶：带有 Dispatcher 的 COP（更通用的模型）

上面的例子比较简单，是一次性的。如果是复杂的攻击链，需要一个分发器 (Dispatcher)。

假设我们找到一段代码（Dispatcher Gadget）：

```x86asm
; Dispatcher at 0x400900
add rbx, 8        ; rbx 指向一个函数指针数组，向下移动一项
call [rbx]        ; 调用数组中的下一个函数（Gadget）
```

攻击布局：

1. 攻击者在内存中构造一个伪造的“函数指针表”（类似虚函数表），里面依次存放：`[地址A, 地址B, 地址C, system地址]`。
2. 将 `rbx` 指向这个表的头部。
3. 寻找的所有 Gadget 都必须以 `jmp 0x400900` (回到 Dispatcher) 或者类似的逻辑结尾。

流程：

- 执行 Dispatcher -> `call` 表中第1项 (Gadget A) -> Gadget A 做事 -> 跳回 Dispatcher。
- Dispatcher `add rbx, 8` -> `call` 表中第2项 (Gadget B) -> Gadget B 做事 -> 跳回 Dispatcher。
- ...
- 最后 `call system`。

### 总结

- BROP：利用 Crash 反馈，在未知二进制的情况下进行 ROP。
- ROP：利用 `ret` 指令连接代码片段。
- COP：利用 `call` 指令连接代码片段，旨在绕过针对 `ret` 指令的防御机制 (CFI/Shadow Stack)。

COP 证明了即使完全禁用了 `ret` 指令（或者严格监控它），只要程序中存在间接跳转指令（`indirect call/jmp`），攻击者依然可以图灵完备地构造恶意代码执行流。

## BROP

BROP (Blind Return-Oriented Programming) 是一种高级的 ROP 攻击技术。

通常的 ROP 攻击前提是攻击者拥有目标程序的二进制文件（或者能获取其内存镜像），从而可以在本地分析并寻找 gadgets（代码片段）。然而，BROP 旨在解决攻击者既没有源代码，也没有二进制文件（Blind）的情况。

这一技术最早由斯坦福大学的 Andrea Bittau 在 2014 年的 IEEE S&P 论文《Hacking Blind》中提出。

### BROP 的核心原理

BROP 的核心利用了服务器应用程序的一个常见特性：崩溃重启与内存复用。

#### 1. 前提条件

- 栈溢出漏洞：存在已知的栈溢出点。
- 服务特性：目标服务（如 Nginx, Apache, MySQL 等）在 crash 后会自动重启，或者是多进程模型（Fork server）。
  - 关键点：使用 `fork()` 系统调用的服务，其子进程的内存布局（包括 Canary 值、ASLR 的基地址、代码段地址）与父进程完全一致。
- 64位架构：BROP 主要针对 x64，利用寄存器传参。

#### 2. 攻击步骤（原理详解）

BROP 攻击通常分为以下四个阶段：

**第一阶段**：绕过 Stack Canary（栈哨兵）
由于服务器 crash 后重启（或 fork 新进程）且内存布局不变，Canary 的值是固定的。

- 攻击者可以进行逐字节爆破。
- 假设 Canary 是 8 字节，攻击者尝试覆盖第 1 个字节。如果服务崩溃（连接断开），说明猜错了；如果服务正常（或返回特定的错误信息），说明猜对了。
- 重复 8 次，即可获取完整的 Canary。

**第二阶段**：寻找 Stop Gadget
在绕过 Canary 后，我们需要寻找 ROP gadgets。但我们不知道代码地址。我们需要一种反馈机制来判断某个地址是否是有效的代码地址。

- Stop Gadget 指的是一段能让程序进入“挂起”或“无限循环”状态，从而保持连接不中断的代码地址。
- 扫描方法：将返回地址覆盖为猜测的地址。
  - 如果连接立即断开 -> 程序 crash -> 地址无效。
  - 如果连接保持开启（超时） -> 程序进入死循环或阻塞 -> 找到 Stop Gadget。

**第三阶段**：寻找 BROP Gadget (通用 Gadget)
这是 BROP 的精髓。在 Linux x64 的程序（尤其是 libc 链接的程序）中，通常都有 `__libc_csu_init` 函数。这个函数尾部有一段非常有用的 gadgets 序列：

```assembly
pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
```

这段代码允许攻击者连续控制 6 个寄存器。通过改变通过这段代码的偏移量，攻击者可以控制 `pop` 的数量。

- 攻击者利用 Stop Gadget 作为锚点，扫描栈上的返回地址，寻找这种连续弹出寄存器最后返回的特征行为。
- 一旦找到这个 gadget，就可以控制 `rdi`, `rsi` 等寄存器（通过配合 `__libc_csu_init` 中的另一段代码 `mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]`），从而实现函数调用传参。

**第四阶段**：Dump 内存与攻击

- 寻找 `puts` 或 `write` 的 PLT 地址：利用上面找到的 gadgets 控制参数（如 `rdi`），猜测并调用输出函数。如果攻击者收到了数据回显，说明找到了输出函数的 PLT 条目。
- Dump 内存：利用输出函数，从 `0x400000`（ELF 头部标准地址）开始打印内存内容。
- 本地分析：将 dump 下来的二进制文件在本地进行反编译，寻找 `system` 函数地址、`/bin/sh` 字符串等，构建最终的 ROP 链拿到 Shell。
