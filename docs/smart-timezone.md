# 智能时区处理说明

## 功能特点

系统现在支持智能时区处理，无需手动添加时区信息：

### 自动识别和转换

- ✅ `2026-01-26T09:51:06Z` (UTC时间) → 自动转换为东八区显示
- ✅ `2026-01-26T09:51:06+08:00` (已有东八区) → 直接使用
- ✅ `2026-01-26T09:51:06` (无时区) → 默认按东八区处理

## 使用方法

### 1. 在 Markdown 文件中（推荐简单写法）

```markdown
---
title: 堆介绍
pubDate: 2026-01-26T09:51:06  # 不需要加Z，系统自动按东八区处理
tags:
  - Pwn
  - Heap
---
```

### 2. 使用UTC格式（也会自动转换）

```markdown
---
title: 堆介绍
pubDate: 2026-01-26T01:51:06Z  # UTC时间，系统会自动+8小时转换
tags:
  - Pwn
  - Heap
---
```

### 3. 明确指定东八区

```markdown
---
title: 堆介绍
pubDate: 2026-01-26T09:51:06+08:00  # 明确的东八区时间
tags:
  - Pwn
  - Heap
---
```

## 在组件中使用

### 基本用法

```astro
---
import FormattedDate from "@/components/FormattedDate.astro";
---

<!-- 传入Date对象 -->
<FormattedDate date={post.data.pubDate} />

<!-- 传入ISO时间字符串 -->
<FormattedDate date="2026-01-26T09:51:06" />

<!-- 显示带时区信息 -->
<FormattedDate date={post.data.pubDate} showTimezone={true} />
```

## 实际效果

无论你写哪种格式，显示时都会统一转换为东八区时间：

- `2026-01-26T01:51:06Z` → 显示为 "2026年1月26日" (东八区)
- `2026-01-26T09:51:06` → 显示为 "2026年1月26日" (东八区)
- `2026-01-26T09:51:06+08:00` → 显示为 "2026年1月26日" (东八区)

## VS Code 代码片段推荐

为了方便写作，建议在 VS Code 中添加以下代码片段：

```json
{
  "Blog Frontmatter": {
    "prefix": "blog-front",
    "body": [
      "---",
      "title: $1",
      "pubDate: ${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}T${CURRENT_HOUR}:${CURRENT_MINUTE}:${CURRENT_SECOND}",
      "tags:",
      "  - $2",
      "---",
      "",
      "$0"
    ],
    "description": "博客文章前言模板（自动东八区）"
  }
}
```

这样每次输入 `blog-front` 就能快速生成正确的格式！
