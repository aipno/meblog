# MeBlog - 安全技术博客

基于 Astro 框架构建的静态博客网站，专注于二进制安全与漏洞利用技术分享。

## 技术栈

- **框架**: Astro v5.17.1
- **语言**: TypeScript + Markdown
- **样式**: CSS (GitHub Markdown 风格)
- **构建**: Vite (内置)

## 快速开始

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览构建结果
npm run preview
```

## 项目结构

```text
src/
├── content/          # 博客文章内容
├── layouts/          # 页面布局组件
├── pages/            # 路由页面
├── components/       # 可复用组件
├── styles/           # 样式文件
└── utils/            # 工具函数
```

## 部署

支持部署到 Netlify、Vercel、GitHub Pages 等静态托管平台。
