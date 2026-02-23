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
