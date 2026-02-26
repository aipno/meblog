# MeBlog - 安全技术博客

基于 [Astro](https://astro.build/) 框架构建的现代化静态博客网站，专注于二进制安全、漏洞利用技术与CTF竞赛经验分享。

## 🌟 特性

- 🚀 **高性能**: 基于 Astro 的静态站点生成，极致加载速度
- 📝 **Markdown 支持**: 原生 Markdown 和 MDX 支持，代码高亮完美集成
- 🔍 **SEO 友好**: 自动生成 sitemap.xml 和 RSS 订阅
- 📱 **响应式设计**: 移动端友好，适配各种设备
- ⚡ **开发体验**: 热重载、TypeScript 类型检查、Vite 构建工具
- 🎨 **美观界面**: GitHub Markdown 风格，简洁优雅的设计

## 🛠️ 技术栈

| 类别         | 技术                                  |
| ------------ | ------------------------------------- |
| **框架**     | [Astro v5.17.1](https://astro.build/) |
| **语言**     | TypeScript + Markdown + MDX           |
| **样式**     | 原生 CSS (GitHub Markdown 风格)       |
| **构建工具** | Vite (内置)                           |
| **部署**     | 支持 Netlify、Vercel、GitHub Pages 等 |

## 🚀 快速开始

### 环境要求

- Node.js >= 18.0.0
- npm 或 yarn

### 安装与运行

```bash
# 克隆项目
git clone https://github.com/yourusername/meblog.git
cd meblog

# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览构建结果
npm run preview
```

访问 `http://localhost:4321` 查看您的博客！

## 📁 项目结构

```text
meblog/
├── public/                 # 静态资源文件
│   └── fontawesome/        # Font Awesome 图标字体
├── src/
│   ├── assets/             # 站点资源文件
│   ├── components/         # 可复用的 Astro 组件
│   │   ├── ArticleMeta.astro      # 文章元信息
│   │   ├── CodeBlock.astro        # 代码块组件
│   │   ├── Header.astro           # 头部导航
│   │   ├── TableOfContents.astro  # 目录导航
│   │   └── ...
│   ├── content/            # 博客文章内容
│   │   ├── blog/knowledge_of_pwn/ # PWN 知识系列
│   │   └── blog/writeup/          # CTF 题解
│   ├── layouts/            # 页面布局模板
│   │   └── BlogPost.astro         # 博客文章布局
│   ├── pages/              # 路由页面
│   │   ├── blog/                  # 博客路由
│   │   ├── categories/            # 分类页面
│   │   ├── tags/                  # 标签页面
│   │   └── index.astro            # 首页
│   ├── styles/             # 样式文件
│   │   ├── components/            # 组件样式
│   │   ├── github-markdown.css    # Markdown 样式
│   │   └── global.css             # 全局样式
│   ├── utils/              # 工具函数
│   │   ├── blogUtils.ts           # 博客工具函数
│   │   └── tocUtils.ts            # 目录工具函数
│   ├── consts.ts           # 全局常量配置
│   └── content.config.ts   # 内容集合配置
├── astro.config.mjs        # Astro 配置文件
├── package.json            # 项目依赖配置
└── tsconfig.json           # TypeScript 配置
```

## 📝 写作指南

### 创建新文章

在 `src/content/blog/` 目录下创建新的 Markdown 文件：

```markdown
---
title: 文章标题
description: 文章简介
pubDate: 2024-01-01
updatedDate: 2024-01-02  # 可选
tags: ['标签1', '标签2']
category: '分类名称'
---

# 文章标题

文章内容...

```

### 支持的功能

- ✅ 代码高亮（Shiki）
- ✅ 数学公式（LaTeX）
- ✅ 表格渲染
- ✅ 目录自动生成
- ✅ 图片优化
- ✅ 响应式表格
