---
title: COP (Call-oriented programming)
date: 2026-02-04 00:46:14
tags:
  - Pwn
---

COP (Call-Oriented Programming) 是一种代码复用攻击技术，它是 ROP (Return-Oriented Programming) 的一种变体或进化形式。

如果说 BROP 是为了解决“没有二进制文件”的问题，那么 COP 主要是为了解决“针对 ROP 的防御机制”（特别是 CFI 控制流完整性和影子栈 Shadow Stack）。


### COP 的核心原理

#### 1. 背景：为什么要用 COP？
传统的 ROP 依赖于 `ret` 指令。防御者开发出了影子栈 (Shadow Stack) 等技术，通过监控 `call` 和 `ret` 的配对关系来防御 ROP。
*   当程序执行 `call` 时，返回地址被压入影子栈。
*   当程序执行 `ret` 时，系统会检查栈顶的地址是否与影子栈记录的一致。
*   由于 ROP 频繁使用 `ret` 跳转到非预期的地址（Gadgets），这种检查会直接拦截 ROP。

COP 的思路是：既然 `ret` 被严防死守，那我就不使用 `ret`，而是只使用 `call` 指令来进行跳转。

#### 2. 运作机制
COP 不依赖栈上的返回地址来控制程序流，而是利用间接调用 (Indirect Call) 指令。

*   指令形式：`call reg` (如 `call rax`) 或 `call [reg]` (如 `call [rbx]`)。
*   Gadget 特征：COP 的 Gadget 是一段以间接 `call` 结束的代码片段。
    *   例如：`mov rdi, rbx; call rcx;`
*   控制流链接：在 ROP 中，`ret` 会自动从栈上弹出一个地址跳过去；在 COP 中，攻击者必须提前安排好寄存器或内存的值，使得当前 Gadget 结尾的 `call` 指令能够准确跳到下一个 Gadget 的起始地址。

#### 3. 难点与特性
*   副作用：`call` 指令会将返回地址压栈。如果不处理，连续的 COP Gadgets 会导致栈无限增长（Stack Overflow）。但在实际攻击的短链中，这通常不是问题。
*   Dispatcher（分发器）：这是 COP 的核心概念。因为不能像 ROP 那样自动利用 `rsp` 滑行，COP 通常需要寻找一个“分发器 Gadget”，它的作用是更新指向下一个 Gadget 的指针，维持攻击链的运行。


### COP 攻击示例

假设我们要攻击一个 64 位的 Linux 程序，目标是执行 `system("/bin/sh")`。

#### 场景假设
1.  漏洞：存在堆溢出或能够控制某些关键寄存器（如 `rbx`, `rcx`, `rax`）的初始状态。
2.  防御：开启了针对 `ret` 的检测，无法使用传统 ROP。
3.  目标：
    *   设置 `rdi` 寄存器指向 `"/bin/sh"` 字符串的地址。
    *   调用 `system` 函数。

#### 构造 COP 链

我们需要寻找以 `call` 结尾的 Gadgets。

Gadget 1 (设置参数):
地址 `0x400100`:
```assembly
mov rdi, rbx   ; 将 rbx 的值（/bin/sh 的地址）赋给 rdi
call rcx       ; 跳转到 rcx 指向的地址（即 Gadget 2）
```

Gadget 2 (执行调用):
地址 `0x400200`:
```assembly
; 假设这个 gadget 直接就是 system 函数的入口，或者跳向 system
call system_addr
```

#### 攻击执行流程（内存与寄存器布局）

为了让上述链条跑通，攻击者需要在触发漏洞前，将寄存器布局控制如下：

1.  RBX: 设置为 `0x600000` (假设这是我们写入 `"/bin/sh"` 字符串的内存地址)。
2.  RCX: 设置为 `0x400200` (这是 Gadget 2 的地址)。
3.  RIP (指令指针): 被劫持指向 `0x400100` (这是 Gadget 1 的地址)。

执行步骤：

1.  程序跳转到 Gadget 1 (`0x400100`)。
2.  执行 `mov rdi, rbx`。此时 `rdi` 变成了 `"/bin/sh"` 的地址（完成了参数准备）。
3.  执行 `call rcx`。因为 `rcx` 是 `0x400200`，程序跳转到 Gadget 2。
    *   *注意：此时栈上被压入了一个无用的返回地址，但我们不关心它。*
4.  程序到达 Gadget 2 (`0x400200`)。
5.  执行 `call system_addr`。
6.  `system("/bin/sh")` 被执行，获得 Shell。

### 进阶：带有 Dispatcher 的 COP（更通用的模型）

上面的例子比较简单，是一次性的。如果是复杂的攻击链，需要一个分发器 (Dispatcher)。

假设我们找到一段代码（Dispatcher Gadget）：
```assembly
; Dispatcher at 0x400900
add rbx, 8        ; rbx 指向一个函数指针数组，向下移动一项
call [rbx]        ; 调用数组中的下一个函数（Gadget）
```

攻击布局：
1.  攻击者在内存中构造一个伪造的“函数指针表”（类似虚函数表），里面依次存放：`[地址A, 地址B, 地址C, system地址]`。
2.  将 `rbx` 指向这个表的头部。
3.  寻找的所有 Gadget 都必须以 `jmp 0x400900` (回到 Dispatcher) 或者类似的逻辑结尾。

流程：
*   执行 Dispatcher -> `call` 表中第1项 (Gadget A) -> Gadget A 做事 -> 跳回 Dispatcher。
*   Dispatcher `add rbx, 8` -> `call` 表中第2项 (Gadget B) -> Gadget B 做事 -> 跳回 Dispatcher。
*   ...
*   最后 `call system`。

### 总结

*   BROP：利用 Crash 反馈，在未知二进制的情况下进行 ROP。
*   ROP：利用 `ret` 指令连接代码片段。
*   COP：利用 `call` 指令连接代码片段，旨在绕过针对 `ret` 指令的防御机制 (CFI/Shadow Stack)。

COP 证明了即使完全禁用了 `ret` 指令（或者严格监控它），只要程序中存在间接跳转指令（`indirect call/jmp`），攻击者依然可以图灵完备地构造恶意代码执行流。