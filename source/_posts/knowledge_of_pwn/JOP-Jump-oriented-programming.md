---
title: JOP (Jump-oriented programming)
date: 2026-02-04 00:46:59
tags:
  - Pwn
---

JOP (Jump-Oriented Programming)** 是一种代码复用攻击技术，它是 ROP 的另一种进化形式。

如果说 ROP 的核心是 `ret`，COP 的核心是 `call`，那么 JOP 的核心就是 `jmp`（间接跳转）。

### JOP 的核心原理

JOP 旨在绕过那些依赖于“函数调用栈”检查的防御机制（如 Shadow Stack 或针对 `ret` 指令的 CFI）。在 JOP 攻击中，攻击者不使用栈来驱动控制流，而是维护一个自定义的“虚拟控制流表”。

#### 1. 核心组件
一个典型的 JOP 攻击包含三个主要部分：

1.  Dispatcher Gadget（分发器代码片）：
    *   这是 JOP 的心脏，相当于 CPU 的“取指-译码-执行”循环。
    *   它的作用是：更新指向“分发表”的指针 -> 加载下一个 Gadget 的地址 -> 跳转执行。
2.  Dispatch Table（分发表）：
    *   这是攻击者在内存中构造的数据结构（通常是一组地址列表）。
    *   它相当于 JOP 程序的“机器码”，决定了 Gadget 的执行顺序。
3.  Functional Gadgets（功能代码片）：
    *   执行具体任务的代码（如赋值寄存器、计算等）。
    *   关键特征：它们不以 `ret` 结尾，而是以 `jmp` 结尾，跳回到 Dispatcher（或者跳向下一个 Gadget）。

#### 2. 控制流差异
*   ROP: 控制流依赖栈顶指针 (`rsp`)。执行完一个 gadget，`ret` 自动从栈顶弹射到下一个。
*   JOP: 必须指定一个通用寄存器（如 `rbx`）作为“虚拟指令指针 (vPC)”。Dispatcher 负责操作这个寄存器来切换执行流。


### JOP 攻击示例

假设目标是一个 64 位 Linux 程序，我们的目标是执行 `system("/bin/sh")`。

#### 场景设定
1.  防御：开启了 Shadow Stack（严防 `ret`）和 NX。
2.  初始状态：攻击者控制了堆内存，并且能通过漏洞将 `rbx` 寄存器指向这块内存。
3.  目标：
    *   `rdi` = `"/bin/sh"`
    *   调用 `system`

#### 构造组件

1. 寻找 Dispatcher Gadget
我们需要一段能够推进指针并跳转的代码。假设在 `0x400800` 找到了：
```assembly
; Dispatcher (地址: 0x400800)
add rbx, 8        ; 将 rbx 指针向下移动 8 字节 (指向表中的下一项)
mov rax, [rbx]    ; 将 rbx 指向的内容 (下一个 Gadget 地址) 取出放入 rax
jmp rax           ; 跳转执行
```
*注：这里 `rbx` 就充当了“虚拟指令指针”。*

2. 寻找功能 Gadgets
我们需要设置参数。
*   Gadget A (设置参数) - 地址 `0x400100`:
    ```assembly
    pop rdi           ; 这是一个混合 gadget，利用栈来取数据，或者用 mov rdi, const
    jmp 0x400800      ; **关键**：执行完后，硬编码跳转回 Dispatcher 继续循环
    ```
    *(注：纯粹的 JOP 很难找，通常会混用 pop 指令，但结尾必须是 jmp)*

*   Gadget B (最终执行) - 地址 `0x400200`:
    ```assembly
    call system       ; 调用系统函数
    ```

3. 构造 Dispatch Table (内存布局)
攻击者在内存地址 `0x600000` 处构造如下数据表：

| 内存地址 | 内容 (数值) | 说明 |
| :--- | :--- | :--- |
| `0x600000` | `0x400100` | **Gadget A 的地址** |
| `0x600008` | `0x400200` | **Gadget B 的地址** |
| `...` | `...` | ... |

#### 攻击执行流程

1.  劫持控制流：
    通过漏洞触发，将 `rbx` 设置为 `0x5FFFF8` (比表头少8字节)，并将 CPU 的 `rip` 指向 Dispatcher (`0x400800`)。

2.  进入 Dispatcher (第一轮)：
    *   `add rbx, 8` -> `rbx` 变为 `0x600000`。
    *   `mov rax, [rbx]` -> `rax` 变为 `0x400100` (Gadget A)。
    *   `jmp rax` -> 跳转到 Gadget A。

3.  执行 Gadget A：
    *   `pop rdi` (或其他指令) -> 将 `rdi` 设置为 `"/bin/sh"`。
    *   `jmp 0x400800` -> 跳回 Dispatcher。

4.  回到 Dispatcher (第二轮)：
    *   `add rbx, 8` -> `rbx` 变为 `0x600008`。
    *   `mov rax, [rbx]` -> `rax` 变为 `0x400200` (Gadget B)。
    *   `jmp rax` -> 跳转到 Gadget B。

5.  执行 Gadget B：
    *   `call system` -> 此时 `rdi` 已经是 `"/bin/sh"`。
    *   Shell Get!

### 总结：ROP vs COP vs JOP

| 特性 | ROP (Return) | COP (Call) | JOP (Jump) |
| :--- | :--- | :--- | :--- |
| 驱动指令 | `ret` | `indirect call` | `indirect jmp` |
| 控制流状态 | 栈指针 (`rsp`) | 栈指针 + 寄存器 | 通用寄存器 (Virtual PC) |
| 核心结构 | 栈上的 Gadget 地址链 | Gadget 链 + `pop/ret`清除栈 | Dispatcher + 内存表 |
| 防御目标 | 绕过 NX (DEP) | 绕过针对 `ret` 的 CFI / Shadow Stack | 绕过针对 `ret/call` 的 CFI |
| 主要难点 | 最容易，Gadget 丰富 | 容易导致栈失衡 | 最难，Dispatcher 难找 |

JOP 是一种非常强大的技术，因为它彻底抛弃了对“程序栈”作为控制流驱动器的依赖，使得很多基于栈完整性检查的防御手段完全失效。