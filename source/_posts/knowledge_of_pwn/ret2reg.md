---
title: ret2reg
date: 2026-02-04 00:47:47
tags:
  - Pwn
---

Ret2Reg (Return-to-Register) 是一种经典的缓冲区溢出利用技术。

它的核心思想是：当攻击者无法预知 Shellcode 在栈上的精确绝对地址，但知道某个 CPU 寄存器恰好指向 Shellcode 所在的位置时，利用程序中的跳转指令（如 `jmp eax`, `call ebx` 等）作为“跳板”，间接跳转到 Shellcode 执行。

这种技术通常用于绕过环境差异导致的栈地址随机化（即栈基址在不同运行环境中会微小浮动），或者在没有开启 NX（堆栈不可执行）保护的旧系统中。


### Ret2Reg 的核心原理

#### 1. 问题背景
在传统的栈溢出攻击中，我们需要覆盖返回地址（Return Address），将其指向 Shellcode 的起始地址。
*   难点：在实际环境中，栈的绝对地址往往是不固定的（受环境变量、调试器干扰、ASLR 微弱抖动影响）。如果硬编码一个栈地址（如 `0xbffff123`），一旦实际运行偏移了 16 字节，攻击就会失败。

#### 2. 观察现象
在函数返回（执行 `ret` 指令）的一瞬间，虽然我们不知道栈顶的绝对地址，但 CPU 的某些通用寄存器（如 `eax`, `edx`, `esp` 等）往往保存着相关的数据指针。
*   例如，`strcpy(dst, src)` 执行完后，`eax` 寄存器通常会保存 `dst` 缓冲区的地址（即 Shellcode 的存放位置）。

#### 3. 解决方案（跳板）
我们不再硬编码栈地址，而是寻找程序代码段（`.text`）或动态库中一条现成的指令，这条指令的内容是跳转到那个寄存器。
*   Gadget：寻找 `jmp eax`、`call eax`、`jmp esp` 或 `call esp` 等指令。
*   操作：将栈上的“返回地址”覆盖为这条指令的地址。

#### 4. 执行流程
1.  函数执行完毕，`ret` 弹出我们覆盖的地址。
2.  CPU 跳转到该指令地址（例如找到的 `jmp eax` 的地址）。
3.  CPU 执行 `jmp eax`。
4.  因为 `eax` 正指向我们的 Shellcode，程序流被引入 Shellcode。
5.  Shellcode 执行。


### Ret2Reg 攻击示例

假设我们攻击一个简单的 32 位 Linux 程序。

#### 1. 漏洞代码
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

#### 2. 分析与调试
假设该程序编译时关闭了 NX 保护（栈可执行），但我们不知道 `buffer` 的确切地址。

第一步：确认寄存器状态
我们用 GDB 调试，在 `func` 函数 `ret` 的位置断点。我们发现：
*   由于 `strcpy` 的特性，它会将目标缓冲区的地址作为返回值放在 EAX 寄存器中。
*   此时，EAX 正指向 buffer 的开头（也就是我们将要放入 Shellcode 的地方）。

第二步：寻找跳板 (Trampoline)
我们需要在程序中找到 `jmp eax` 或 `call eax` 指令。
使用工具（如 `ROPgadget` 或 `objdump`）：
```bash
$ ROPgadget --binary vulnerable --opcode "ffe0"  # ffe0 是 jmp eax 的机器码
# 输出:
# 0x0804834b : jmp eax
```
我们要利用的地址是 `0x0804834b`。

#### 3. 构造 Payload
我们需要填充 buffer，溢出覆盖 EBP，最后覆盖返回地址。

*   Buffer 大小: 100 字节。
*   EBP 大小: 4 字节（32位系统）。
*   总偏移: 104 字节后是返回地址。

Payload 结构：
`[ Shellcode ] + [ Padding ] + [ 覆盖返回地址 ]`

1.  Shellcode: 假设长度为 25 字节。
2.  Padding: 填充垃圾数据，填满到 104 字节。长度 = 104 - 25 = 79 字节。
3.  返回地址: 填入 `jmp eax` 的地址 `0x0804834b`。

最终 Payload (Hex 概念):
```text
[ Shellcode (25 bytes) ] + [ 'A' * 79 ] + [ \x4b\x83\x04\x08 ]
```
*(注意：地址是小端序)*

#### 4. 攻击执行流
1.  `func` 执行 `strcpy`，我们的 Shellcode 被复制到栈上。
2.  `strcpy` 结束，EAX 寄存器指向栈上 Shellcode 的开头。
3.  `func` 执行 `ret`。
4.  程序跳转到栈上保存的返回地址：`0x0804834b`。
5.  CPU 执行 `0x0804834b` 处的指令：`jmp eax`。
6.  程序跳转到 EAX 指向的地址（即栈顶的 Shellcode）。
7.  Shellcode 成功运行，获得 Shell。

### 总结

Ret2Reg 是一种利用寄存器定位来对抗栈地址不确定性的技术。

*   前提：
    1.  溢出后，某个寄存器指向可控内存区域（Shellcode）。
    2.  程序代码段或库中存在 `jmp/call reg` 指令。
    3.  目标内存区域（栈）具有可执行权限（No NX）。
*   对比 Ret2Shellcode：Ret2Shellcode 是硬编码栈地址，Ret2Reg 是软编码（通过寄存器中转），后者更稳定。