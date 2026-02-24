/**
 * 博客工具函数库
 * 
 * 作用：
 * - 提供博客内容检索和处理的工具函数
 * - 实现文章搜索、过滤、排序功能
 * - 处理目录结构组织和分类统计
 * - 提供分页计算和数据处理逻辑
 * 
 * 相关文件：
 * - src/content.config.ts：内容集合配置
 * - src/pages/blog/index.astro：博客列表页面
 * - src/pages/blog/page/[page].astro：分页页面
 * - src/pages/blog/[...slug].astro：文章详情页面
 * - src/components/Pagination.astro：分页组件
 * 
 * 主要功能：
 * - BlogRetriever类：文章检索核心类
 * - searchPosts：文章搜索和过滤
 * - getPostsByDirectory：按目录组织文章
 * - getAllDirectories：获取所有目录列表
 * - getCategoryStats：统计分类文章数量
 */
