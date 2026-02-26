/**
 * Astro内容集合配置文件
 * 
 * 作用：
 * - 定义博客内容集合的结构和验证规则
 * - 配置Markdown文件的加载方式和处理选项
 * - 设置frontmatter字段的类型验证
 * - 配置代码高亮语言支持
 * 
 * 相关文件：
 * - src/content/blog/：博客文章Markdown文件目录
 * - src/pages/blog/[...slug].astro：动态路由处理单篇文章
 * - src/utils/blogUtils.ts：博客工具函数
 * - astro.config.mjs：Astro主配置文件
 * 
 * 配置内容：
 * - blog集合：定义文章的必需字段和可选字段
 * - schema验证：确保frontmatter数据格式正确
 * - shikiConfig：代码块语法高亮配置
 * - glob模式：指定Markdown文件的查找模式
 */

import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';
import { optional } from 'astro:schema';

const blog = defineCollection({
	// Load Markdown and MDX files in the `src/content/blog/` directory.
	loader: glob({
		base: './src/content/blog',
		pattern: '{knowledge_of_pwn,writeup}/**/*.{md,mdx}',
	}),
	// Type-check frontmatter using a schema
	schema: ({ image }) =>
		z.object({
			title: z.string(),
			description: z.string().optional(),
			tags: z.array(z.string()).optional(),
			category: z.string().optional(),
			// Transform string to Date object
			pubDate: z.coerce.date(),
			updatedDate: z.coerce.date().optional(),
			heroImage: image().optional(),
		}),
});

export const collections = { blog };
