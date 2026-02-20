---
title: BROP (Blind ROP)
date: 2026-01-26 09:51:07
tags: 
  - Pwn
---

BROP (Blind Return-Oriented Programming) 是一种高级的 ROP 攻击技术。

通常的 ROP 攻击前提是攻击者拥有目标程序的二进制文件（或者能获取其内存镜像），从而可以在本地分析并寻找 gadgets（代码片段）。然而，BROP 旨在解决攻击者既没有源代码，也没有二进制文件（Blind）的情况。

这一技术最早由斯坦福大学的 Andrea Bittau 在 2014 年的 IEEE S&P 论文《Hacking Blind》中提出。


### BROP 的核心原理

BROP 的核心利用了服务器应用程序的一个常见特性：崩溃重启与内存复用。

#### 1. 前提条件
*   栈溢出漏洞：存在已知的栈溢出点。
*   服务特性：目标服务（如 Nginx, Apache, MySQL 等）在 crash 后会自动重启，或者是多进程模型（Fork server）。
    *   关键点：使用 `fork()` 系统调用的服务，其子进程的内存布局（包括 Canary 值、ASLR 的基地址、代码段地址）与父进程完全一致。
*   64位架构：BROP 主要针对 x64，利用寄存器传参。

#### 2. 攻击步骤（原理详解）

BROP 攻击通常分为以下四个阶段：

第一阶段：绕过 Stack Canary（栈哨兵）
由于服务器 crash 后重启（或 fork 新进程）且内存布局不变，Canary 的值是固定的。
*   攻击者可以进行逐字节爆破。
*   假设 Canary 是 8 字节，攻击者尝试覆盖第 1 个字节。如果服务崩溃（连接断开），说明猜错了；如果服务正常（或返回特定的错误信息），说明猜对了。
*   重复 8 次，即可获取完整的 Canary。

第二阶段：寻找 Stop Gadget
在绕过 Canary 后，我们需要寻找 ROP gadgets。但我们不知道代码地址。我们需要一种反馈机制来判断某个地址是否是有效的代码地址。
*   Stop Gadget 指的是一段能让程序进入“挂起”或“无限循环”状态，从而保持连接不中断的代码地址。
*   扫描方法：将返回地址覆盖为猜测的地址。
    *   如果连接立即断开 -> 程序 crash -> 地址无效。
    *   如果连接保持开启（超时） -> 程序进入死循环或阻塞 -> 找到 Stop Gadget。

第三阶段：寻找 BROP Gadget (通用 Gadget)
这是 BROP 的精髓。在 Linux x64 的程序（尤其是 libc 链接的程序）中，通常都有 `__libc_csu_init` 函数。这个函数尾部有一段非常有用的 gadgets 序列：

```assembly
pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
```

这段代码允许攻击者连续控制 6 个寄存器。通过改变通过这段代码的偏移量，攻击者可以控制 `pop` 的数量。
*   攻击者利用 Stop Gadget 作为锚点，扫描栈上的返回地址，寻找这种连续弹出寄存器最后返回的特征行为。
*   一旦找到这个 gadget，就可以控制 `rdi`, `rsi` 等寄存器（通过配合 `__libc_csu_init` 中的另一段代码 `mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword ptr [r12+rbx*8]`），从而实现函数调用传参。

第四阶段：Dump 内存与攻击
*   寻找 `puts` 或 `write` 的 PLT 地址：利用上面找到的 gadgets 控制参数（如 `rdi`），猜测并调用输出函数。如果攻击者收到了数据回显，说明找到了输出函数的 PLT 条目。
*   Dump 内存：利用输出函数，从 `0x400000`（ELF 头部标准地址）开始打印内存内容。
*   本地分析：将 dump 下来的二进制文件在本地进行反编译，寻找 `system` 函数地址、`/bin/sh` 字符串等，构建最终的 ROP 链拿到 Shell。


