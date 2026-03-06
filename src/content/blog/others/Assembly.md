---
title: 汇编语言（Assembly）
pubDate: 2026-03-02T16:35:00
updateDate: 2026-03-06T22:57:00
---
汇编语言是一种低级编程语言，与特定的计算机架构紧密相关，是机器语言的人类可读形式，通过助记符来代表机器指令。

主要组成部分

助记符：代表操作的简短英文缩写

寄存器（Registers）：CPU内部的高速存储单元，用于暂存数据和地址

操作数：指令作用的对象，可以是寄存器、内存地址或立即数（常量）

标签：用于标记代码中的特定位置，常作为跳转指令的目标

伪指令：给汇编器的指令，不生成机器码，用于定义数据段、分配内存等

## x86 / x86-64 架构（intel/AMD）助记符

### 数据传送类

| 分类         | 助记符              | 全称                                | 功能描述                                           | 示例                         | 备注                                     |
| ------------ | ------------------- | ----------------------------------- | -------------------------------------------------- | ---------------------------- | ---------------------------------------- |
| 通用数据传输 | mov                 | move                                | 基础数据复制（源->目的）                           | mov eax,ebx                  | 最常用，不影响标志位                     |
|              | movzx               | move with zero extend               | 小位数->大位数，高位补0                            | movzx eax,al                 | 无符号数扩展                             |
|              | movsx               | move with sign extend               | 小位数->大位数，高位补符号位                       | movsx eax,al                 | 有符号数扩展                             |
| 累加器专用   | in                  | input from port                     | 从I/O端口读入累加器                                | in al，0x60                  | 仅用al/ax/eax                            |
|              | out                 | output to port                      | 从累加器写到I/O端口                                |                              | 仅用al/ax/eax                            |
|              | xlat                | translate                           | 查表：ds:ebx\[al\]->al                             |                              | 又称“换码指令”                           |
| 地址传送     | lea                 | load effective address              | 取有效地址（偏移量）到寄存器                       | lea eax，\[ebx+ecx\*2+0x10\] | 不访问内存，仅计算地址，不影响标志位     |
|              | lds/les/lfs/lgs/lss | load data/extra/fs/gs/stack segment | 加载远指针（段寄存器 + 通用寄存器）                | lds eax，\[0x1234\]          | 32位常用，64位极少用段寄存器             |
| 累加器扩展   | cbw                 | convert byte to word                | al 符号位扩展 -> ax                                |                              | 8位->16位                                |
|              | cwd                 | convert word to doubleword          | ax 符号位扩展 -> dx:ax                             |                              | 16位->32位（dx存高位）                   |
|              | cdq                 | convert doubleword to quadword      | eax 符号位扩展 -> edx:eax                          |                              | 32位->64位（edx存高位）                  |
|              | cqo                 | convert quadword to octaword        | rax 符号位扩展 -> rdx:rax                          |                              | 64位专用                                 |
| 数据交换     | xchg                | exchange                            | 交换两个操作数的值                                 | xchg eax，ebx                | 不影响标志位                             |
|              | bswap               | bytes swap                          | 反转寄存器字节序（大小端转换）                     |                              | 32位/64位通用                            |
|              | xadd                | exchange and add                    | 交换后相加，和存目的                               |                              | 先交换，再eax=原eax+原ebx                |
|              | cmpxchg             | compare add exchange                | 比较累加器与目的，相等则源->目的，否则目的->累加器 |                              | 比较eax 与 ebx                           |
| 栈操作       | push                | push onto stack                     | 数据压入栈（栈顶减后存）                           | push eax                     | 32位 esp-4，64位rsp-8                    |
|              | pop                 | pop from stack                      | 栈顶弹出数据（取后栈顶加）                         | pop ebx                      | 32位 esp+4，64位rsp+8                    |
|              | pusha/popa          | push/pop all general registers      | 压入/弹出所有通用寄存器                            |                              | 仅32位，64位用pushfq/popfq（标志寄存器） |

### 算术运算类

| 分类      | 助记符 | 全称                              | 功能描述                             | 示例          | 备注                                       |
| --------- | ------ | --------------------------------- | ------------------------------------ | ------------- | ------------------------------------------ |
| 加法类    | add    | add                               | 基础加法：目的=目的+源               | add eax，5    | 影响CF/OF/ZF/SF/PF标志位                   |
|           | adc    | add with carry                    | 带进位加法：目的=目的+源+CF          |               | 用于多字节/大数加法（配合add）             |
|           | inc    | increment                         | 自增1：操作数=操作数+1               | inc ecx       |                                            |
| 减法类    | sub    | subtract                          | 基础减法：目的=目的-源               | sub eax，ebx  |                                            |
|           | sbb    | subtract with borrow              | 带借位减法：目的=目的-源-CF          |               |                                            |
|           | dec    | decrement                         | 自减1：操作数=操作数-1               | dec edx       |                                            |
|           | neg    | negate                            | （取负）求补：操作数=0-操作数        | neg eax       |                                            |
| 乘法类    | mul    | multiply（unsigned）              | 无符号乘法                           | imul eax，ebx | 操作数非0则CF=1，否则CF=0；影响OF/ZF/SF/PF |
|           | imul   | integer multiply（signed）        | 有符号乘法                           |               | 单操作数同mul；双/三操作数更灵活，CTF常用  |
| 除法类    | div    | divide（unsigned）                | 无符号除法                           | idiv ebx      |                                            |
|           | idiv   | integer divide（signed）          | 有符号除法                           |               |                                            |
| 比较类    | cmp    | compare                           | 比较（做减法但不存结果，仅改标志位） |               |                                            |
| BCD调整类 | daa    | decimal adjust after subtraction  | 加法后BCD码调整                      |               | 仅用于8位BVD数加法，现代极少用             |
|           | das    | decimal adjust after subtraction  | 减法后BCD码调整                      |               | 仅用于8位BVD数减法，现代极少用             |
|           | aaa    | ascii adjust after addition       | 加法后ASCII码调整                    |               | 仅用于ASCII数字加法，现代极少用            |
|           | aas    | ascii adjust after subtraction    | 减法后ASCII码调整                    |               | 仅用于ASCII数字减法，现代极少用            |
|           | aam    | ascii adjust after multiplication | 乘法后ASCII码调整                    |               | 仅用于ASCII数字乘法，现代极少用            |
|           | aad    | ascii adjust before division      | 除法前ASCII码调整                    |               | 仅用于ASCII数字除法，现代极少用            |

### 逻辑运算类

| 助记符  | 全称                   | 功能描述                           | 示例 |
| ------- | ---------------------- | ---------------------------------- | ---- |
| and     | and                    | 按位与                             |      |
| or      | or                     | 按位或                             |      |
| xor     | exclusive or           | 按位异或（常用于清零寄存器）       |      |
| not     | not                    | 按位取反                           |      |
| test    | test                   | 按位与但不保存结果（仅影响标志位） |      |
| shl/sal | shift left             | 左移                               |      |
| shr     | shift right            | 逻辑右移                           |      |
| sar     | shift arithmetic right | 算术右移（保留符号位）             |      |
| rol/ror | rotate left/right      | 循环左移/右移                      |      |

### 控制流类

| 助记符  | 全称                       | 功能描述                      | 示例             |
| ------- | -------------------------- | ----------------------------- | ---------------- |
| jmp     | iump                       | 无条件跳转                    | jmp lable_start  |
| je/jz   | jump if equal/zero         | 相等/为零时跳转               | je lable_equal   |
| jne/jnz | jump if not equal/not zero | 不相等/不为零时跳转           | jne lable_loop   |
| jg/jnle | jump if greater            | 大于时跳转（有符号）          | jg lable_greater |
| jl/jnge | jump if less               | 小于时跳转（有符号）          | jl lable_less    |
| ja/jnbe | jump if above              | 高于时跳转（无符号）          | ja lable_above   |
| jb/jnae | jump if below              | 低于时跳转（无符号）          | jb lable_below   |
| call    | call                       | 调用子程序                    | call printf      |
| ret     | return                     | 从子程序返回                  | ret              |
| loop    | loop                       | 循环（cx/ecx/rcx减1非零则跳） | loop lable_start |

### 字符串与特殊操作

| 助记符                   | 功能描述                                 |
| ------------------------ | ---------------------------------------- |
| cmp                      | 比较（执行减法但不保存结果，只改标志位） |
| nop                      | 空操作（no operation），常用于占位或延时 |
| int                      | 触发软件中断（如int 0x80系统调用）       |
| stos/movs/lods/cmps/scas | 字符串操作指令（配合rep前缀使用）        |
