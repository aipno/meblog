# 时间处理工具使用指南

## 概述

本项目提供了专门的时间处理工具，帮助你在撰写博客时自动生成带东八区时区的时间戳，避免手动添加时区信息的麻烦。

## 工具函数

### `generateChinaTime(date?: Date): string`

生成符合 ISO 8601 格式的东八区时间戳。

**参数：**

- `date` (可选): Date 对象，默认为当前时间

**返回值：**

- 字符串格式：`YYYY-MM-DDTHH:mm:ss+08:00`

**使用示例：**

```typescript
import { generateChinaTime } from '@/utils/blogUtils';

// 生成当前时间的东八区时间戳
const currentTime = generateChinaTime();
console.log(currentTime); // 输出类似：2026-01-26T10:30:45+08:00

// 生成指定日期的东八区时间戳
const specificTime = generateChinaTime(new Date('2026-01-26'));
console.log(specificTime); // 输出类似：2026-01-26T00:00:00+08:00
```

### `convertToChinaTime(utcDate: string | Date): Date`

将 UTC 时间转换为东八区时间的 Date 对象。

**参数：**

- `utcDate`: UTC 时间字符串或 Date 对象

**返回值：**

- 东八区时间的 Date 对象

## 在 Markdown 文件中的使用

### 方法一：使用 VS Code 代码片段（推荐）

你可以在 VS Code 中创建一个代码片段，快速插入带时区的时间戳。

1. 打开 VS Code 设置
2. 搜索 "用户代码片段"
3. 选择 "markdown.json"
4. 添加以下代码片段：

```json
{
  "Frontmatter with China Time": {
    "prefix": "frontmatter-china",
    "body": [
      "---",
      "title: $1",
      "pubDate: ${2:${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}T${CURRENT_HOUR}:${CURRENT_MINUTE}:${CURRENT_SECOND}+08:00}",
      "tags:",
      "  - $3",
      "---",
      "",
      "$0"
    ],
    "description": "生成带东八区时间戳的博客前言"
  }
}
```

使用方法：在 Markdown 文件中输入 `frontmatter-china` 然后按 Tab 键。

### 方法二：手动使用工具函数

在开发工具控制台中运行：

```javascript
// 在浏览器开发者工具中运行
copy(generateChinaTime()) // 复制当前时间戳到剪贴板
```

然后粘贴到你的 Markdown 文件中。

## FormattedDate 组件增强

更新后的 `FormattedDate` 组件支持更多时区显示选项：

### 基本用法

```astro
---
import FormattedDate from "@/components/FormattedDate.astro";
---

<!-- 默认显示（本地时区）-->
<FormattedDate date={post.data.pubDate} />

<!-- 显示东八区时间 -->
<FormattedDate date={post.data.pubDate} timezone="china" />

<!-- 显示 UTC 时间 -->
<FormattedDate date={post.data.pubDate} timezone="utc" />

<!-- 显示带时区信息的时间 -->
<FormattedDate date={post.data.pubDate} showTimezone={true} />

<!-- 组合使用 -->
<FormattedDate 
  date={post.data.pubDate} 
  timezone="china" 
  showTimezone={true} 
/>
```

### 参数说明

- `date`: 必需，Date 对象
- `showTimezone`: 可选，布尔值，默认 `false`，是否显示时区名称
- `timezone`: 可选，`'local' | 'china' | 'utc'`，默认 `'local'`

## 实际应用示例

### 博客文章头部示例

```markdown
---
title: 堆介绍
pubDate: 2026-01-26T09:51:06+08:00
tags:
  - Pwn
  - Heap
---

文章内容...
```

### 归档页面时间显示

```astro
<li>
  <a href={`/blog/${post.id}/`} class="archive-item">
    <span class="date">
      <FormattedDate 
        date={post.data.pubDate} 
        timezone="china"
        showTimezone={false}
      />
    </span>
    <span class="title">{post.data.title}</span>
  </a>
</li>
```

## 注意事项

1. **向后兼容性**：现有的 UTC 时间格式仍然可以正常工作
2. **统一标准**：建议新文章统一使用东八区时间格式
3. **时区转换**：系统会自动处理不同时区间的转换显示
4. **SEO 友好**：使用标准的 ISO 8601 时间格式，有利于搜索引擎识别

## 迁移现有文章

如果你想要将现有文章的时间格式统一改为东八区，可以使用以下脚本：

```bash
# 在项目根目录运行
node scripts/migrate-timezone.js
```

脚本会自动扫描所有 Markdown 文件并将 UTC 时间转换为东八区时间格式。
