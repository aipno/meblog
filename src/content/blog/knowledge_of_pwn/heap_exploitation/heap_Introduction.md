---
title: 堆介绍
pubDate: 2026-01-26T09:51:06
updateDate: 2026-03-06T13:09:00
tags:
  - Pwn
  - Heap
category: Pwn小知识
---
**堆 (Heap)** 是计算机内存管理中用于**动态内存分配**的一个区域。

与栈（Stack）不同，堆上的内存**不由编译器自动管理**，而是由程序员通过代码显式地申请（`malloc`/`new`）和释放（`free`/`delete`）。如果在高级语言（如 Java, Python）中，则由垃圾回收器（GC）负责回收。

## 堆 vs 栈：宏观对比

理解堆的最好方式是将其与栈进行对比：

| 特性   | 栈 (Stack)        | 堆 (Heap)               |
| :--- | :--------------- | :--------------------- |
| 分配方式 | 静态/自动：函数调用时自动压栈。 | 动态/手动：程序运行时决定分配多少。     |
| 生命周期 | 函数返回时自动释放。       | 直到程序员 `free` 或程序结束才释放。 |
| 生长方向 | 高地址 -> 低地址       | 低地址 -> 高地址 (通常情况)      |
| 内存布局 | 连续的线性区域。         | 碎片化的，由链表连接的离散区域。       |
| 管理效率 | 极高（仅需移动 SP 指针）。  | 较低（涉及复杂的算法寻找合适空块）。     |
| 主要用途 | 局部变量、函数参数、返回地址。  | 大的数据结构、对象、文件缓冲区。       |

## 堆的物理布局

Linux堆由多个连续的内存区域组成，其布局遵循以下规则：

- start_brk：初始堆起始地址
- brk：当前堆的末尾指针
- top chunk：位于堆末尾的未分配内存块，通过brk系统调用拓展
- fast bins/small bins：管理不同大小的空闲内存块
- mmap区域：独立于主堆的大块内存区域（≥128KB默认）

堆的扩展主要通过两种系统调用实现：

- brk/sbrk：用于主堆的连续拓展（<128KB默认）
- mmap：用于大块内存分配或子线程堆的创建

## 堆相关数据结构（ptmalloc2实现）

### 微观结构（用于具体管理内存块）

#### `malloc_chunk`（堆的基本单位）

这是堆中内存块的表示结构，无论内存块处于分配状态还是释放状态，都使用同一结构：

```c
struct malloc_chunk {
    INTERNAL_SIZE_T prev_size;  /* Size of previous chunk (if free). */
    INTERNAL_SIZE_T size;       /* Size in bytes, including overhead. */
    struct malloc_chunk *fd;    /* double links -- used only if free. */
    struct malloc_chunk *bk;    /* Only used for large blocks: pointer to next larger size. */
    struct malloc_chunk *fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk *bk_nextsize;
};
```

**关键字段解释**：

- `prev_size`：前一个chunk的大小（如果前一个chunk是空闲的）
- `size`：当前chunk的大小（包括头部），低3位为标记位
  - `PREV_INUSE`（P位）：前一个chunk是否已分配
  - `IS_MMAPPED`：是否通过mmap分配
  - `NON_MAIN_ARENA`：是否不属于主线程
- `fd`/`bk`：空闲时用于双向链表连接
- `fd_nextsize`/`bk_nextsize`：仅用于large chunk，用于快速查找

#### chunk相关宏

- `chunk2mem(p)`：从chunk指针转换到用户数据指针
- `mem2chunk(mem)`：从用户数据指针转换到chunk指针
- `MINSIZE`：最小chunk大小
- `request2size(req)`：将请求大小转换为实际分配大小
- `chunksize(p)`：获取chunk大小（忽略标记位）
- `next_chunk(p)`：获取下一个物理相邻的chunk
- `prev_chunk(p)`：获取前一个物理相邻的chunk

#### chunk的三种状态

##### 分配状态

当chunk被程序使用时，处于分配状态：

- 及使用prev_size和size两个字段
- prev_size记录前一个chunk的大小（当且仅当前一个chunk未分配时有效）
- size字段的最低三位存储标志位

	- PREV_INUSE（0x01）：前一个chunk是否在使用
	- IS_MAPPED（0x02）：是否通过mmap分配
	- NON Main Arena（0x04）：是否属于主线程堆

##### 空闲状态（Free Chunk）

当chunk被释放后，处于空闲状态：

- 使用fd和bk指针构成双向链表
- 根据大小被管理到不同的bin中
- size的最低3位标志位被重置

##### 顶块状态（Top Chunk）

顶块是堆的特殊部分，用于管理未分配的内存：

- 位于所有分配的chunk之后
- 通过brk系统调用扩展或收缩
- size的PREV_INUSE位始终为1，防止被前一个chunk合并
- 不属于任何bin，而是直接由malloc_state管理

#### chunk的大小计算

用户申请的内存大小与实际分配的chunl大小之间存在差异，ptmalloc2通过以下计算公式计算实际需要的chunk大小：

```text
实际chunk大小 = (请求大小 + prev_size + MALLOC对自己对其掩码) & ~MALLOC对自己对其掩码
```

在64位系统中，这意味着：

- 用户请求的大小会被向上补齐到16字节的倍数
- 实际分配的chunk大小比用户请求的大小大16-32字节（包含prev_size和size字段）

### Bin结构（用于管理空闲内存块）

ptmalloc2将空闲内存块按大小分为4类bin：

#### Fast Bin

- 管理范围：<64字节的空闲chunk
- 管理结构：单项链表（及使用fd指针）
- 特点：分配速度快，但存在碎片化问题
- 操作机制：

	- malloc时直接从fast bin头部取块
	- free时直接插入到fast bin头部
	- 不合并相邻块以提高效率

#### Small Bin

- 管理范围：64B-512B的空闲chunk
- 管理结构：双向循环链表
- 索引规则：每个bin对应固定大小，index=floor(size/8)
- 操作机制：

	- 按固定大小索引（如index=2对应16B）
	- 支持相邻块合并，减少碎片

#### Large Bin

- 管理范围：>512B的空闲chunk
- 管理结构：双向链表
- 分组规则：分为6组，每组公差依次为64B，512B，4096B，32768B，262144B等
- 操作机制：

	- 按大小范围分组管理
	- 使用fd_nextsize和bk_nextsize指针加速查找
	- 支持快速查找但允许一定碎片

#### Unsorted Bin

- 管理范围：所有大小的空闲chunk
- 管理特点：双向链表
- 特点：

	- 临时存放释放的chunk
	- 合并相邻块后分类到其他bin
	- malloc_consolidate()函数会处理unsorted bin中的chunk

### 宏观结构（用于管理堆的基本信息）

#### `arena`

- 堆的管理区域，每个线程有自己的arena
- 主线程有main_arena，其他线程有thread arena
- 64位系统：arena数量 = 8 * 核数
- 32位系统：arena数量 = 2 * 核数

#### `heap_info`

- 用于记录heap的基本信息
- 主要用于非主线程（thread arena）的堆管理
- 包含`ar_ptr`（对应的arena）、`prev`（前一个heap）、`size`（当前大小）等

#### `malloc_state`

- 管理堆的状态信息
- 主要包含：
  - `mutex`：锁，用于串行访问
  - `flags`：分配区标志
  - `fastbinsY`：fast bins
  - `top`：top chunk指针
  - `last_remainder`：最后分割剩余的chunk
  - `bins`：small bins和large bins
  - `binmap`：bin的位图，快速判断bin是否为空

### 堆的组织结构

```text
main_arena (全局变量，数据段中)
|
├── malloc_state (管理堆状态)
│   ├── fastbinsY[10] (fast bins)
│   ├── bins[126] (small bins和large bins)
│   ├── unsorted bin (下标1)
│   ├── top (top chunk)
│   └── last_remainder (最后分割剩余)
|
└── heap_info (thread arena的heap信息)
    ├── ar_ptr (对应malloc_state)
    ├── prev (前一个heap)
    ├── size (当前heap大小)
    └── mprotect_size (mprotect的大小)
```

这些数据结构共同构成了ptmalloc2堆管理器的核心，是堆溢出、use-after-free等漏洞利用的基础。理解这些数据结构对于Pwn攻防至关重要。

