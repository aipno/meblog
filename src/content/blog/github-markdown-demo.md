---
title: GitHub风格Markdown渲染示例
pubDate: 2026-01-22T18:35:33Z
tags: ['技术分享', 'Markdown']
description: 展示优化后的GitHub风格Markdown渲染效果，包括代码块、表格、通知框等元素
---

## 标题样式演示

这是H2标题，带有下划线边框效果。

### H3标题样式

#### H4标题样式

##### H5标题样式

###### H6标题样式

## 文本样式

这是普通的段落文本。**这是粗体文本**，*这是斜体文本*，~~这是删除线文本~~。

这是一个[链接示例](https://github.com)。

## 列表样式

### 无序列表
- 第一项
- 第二项
  - 子项1
  - 子项2
- 第三项

### 有序列表
1. 第一步
2. 第二步
3. 第三步

### 任务列表
- [x] 已完成的任务
- [ ] 待完成的任务
- [ ] 另一个待办事项

## 引用块

> 这是一个引用块示例。
> 
> 可以包含多行内容。

> ## 引用中的标题
> 引用块中也可以包含其他Markdown元素。

## 代码样式

行内代码示例：使用 `console.log()` 来输出信息。

### 代码块示例

```javascript
// JavaScript代码示例
function greet(name) {
  console.log(`Hello, ${name}!`);
  return `Welcome to our site, ${name}`;
}

const user = {
  name: 'Alice',
  age: 25,
  isActive: true
};

greet(user.name);
```

```python
# Python代码示例
def fibonacci(n):
    """计算斐波那契数列"""
    if n <= 1:
        return n
    else:
        return fibonacci(n-1) + fibonacci(n-2)

# 生成前10个斐波那契数
for i in range(10):
    print(f"F({i}) = {fibonacci(i)}")
```

```bash
# Bash命令示例
git clone https://github.com/user/repo.git
cd repo
npm install
npm run dev
```

## 表格样式

| 功能     | 描述           | 状态   |
| -------- | -------------- | ------ |
| 标题渲染 | 支持H1-H6标题  | ✅ 完成 |
| 代码高亮 | 语法高亮显示   | ✅ 完成 |
| 表格样式 | GitHub风格表格 | ✅ 完成 |
| 通知框   | 各种提示样式   | ✅ 完成 |

## 通知框样式

> 📝 **Note**
> 这是一个注意事项，用于提供重要信息。

> 💡 **Tip**
> 这是一个提示信息，帮助用户更好地理解内容。

> ⚠️ **Warning**
> 这是一个警告信息，提醒用户注意潜在问题。

> ⭐ **Important**
> 这是一个重要信息，需要特别关注。

> 🔥 **Caution**
> 这是一个谨慎提示，可能存在风险。

## 图片样式

![示例图片](https://picsum.photos/800/400)

图片会自动适应容器宽度，并带有圆角和阴影效果。

## 水平分割线

---

以上就是GitHub风格Markdown渲染的主要特性展示。