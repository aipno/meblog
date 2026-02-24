/**
 * Astro框架配置文件
 * 
 * 作用：
 * - 配置Astro构建工具的核心选项
 * - 集成各种Astro官方插件
 * - 设置站点基本信息（baseUrl、sitemap等）
 * - 配置开发服务器选项
 * 
 * 相关文件：
 * - package.json：项目依赖配置
 * - tsconfig.json：TypeScript配置
 * - src/content.config.ts：内容集合配置
 * - src/pages/：页面路由目录
 * - src/layouts/：布局组件目录
 * 
 * 集成的插件：
 * - @astrojs/mdx：MDX文件支持
 * - @astrojs/sitemap：自动生成站点地图
 * - @astrojs/rss：RSS订阅功能
 */

// @ts-check

import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = resolve(__filename, '..');

// https://astro.build/config
export default defineConfig({
	site: 'https://me.iswxl.cn',
	integrations: [mdx(), sitemap()],
	vite: {
		resolve: {
			alias: {
				'@': resolve(__dirname, './src'),
				// 你也可以添加其他别名，比如：
				// '@components': resolve(__dirname, './src/components')
			},
		},

	},
});
