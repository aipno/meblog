/**
 * 目录工具函数
 * 
 * 作用：
 * - 提供目录生成和管理的辅助函数
 * - 处理标题解析和ID生成
 * - 支持目录数据的序列化和反序列化
 * - 提供性能优化的工具方法
 * 
 * 相关文件：
 * - src/components/TableOfContents.astro：使用这些工具函数
 * - src/layouts/BlogPost.astro：可能使用目录数据
 * 
 * 主要功能：
 * - 标题元素解析
 * - 目录结构生成
 * - ID唯一性保证
 * - 性能监控和优化
 */

// 目录项接口定义
export interface TocItem {
	id: string;
	text: string;
	level: number;
	element: HTMLElement;
	children?: TocItem[];
}

// 配置选项接口
export interface TocOptions {
	/**
	 * 要扫描的标题选择器
	 * @default 'h1, h2, h3, h4, h5, h6'
	 */
	headingSelector?: string;

	/**
	 * 标题最小级别
	 * @default 1
	 */
	minLevel?: number;

	/**
	 * 标题最大级别
	 * @default 6
	 */
	maxLevel?: number;

	/**
	 * 是否跳过没有ID的标题
	 * @default false
	 */
	skipWithoutId?: boolean;

	/**
	 * ID生成策略
	 */
	idGenerator?: (text: string, index: number) => string;

	/**
	 * 文本清理函数
	 */
	textProcessor?: (text: string) => string;
}

// 默认配置
const DEFAULT_OPTIONS: Required<TocOptions> = {
	headingSelector: 'h1, h2, h3, h4, h5, h6',
	minLevel: 1,
	maxLevel: 6,
	skipWithoutId: false,
	idGenerator: (text: string, index: number) => {
		return `toc-${index}-${text.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
	},
	textProcessor: (text: string) => {
		return text.trim().replace(/\s+/g, ' ');
	}
};

/**
 * 解析标题元素生成目录项
 * @param element 标题元素
 * @param index 索引
 * @param options 配置选项
 * @returns 目录项或null
 */
export function parseHeadingElement(
	element: HTMLElement,
	index: number,
	options: TocOptions = {}
): TocItem | null {
	const config = { ...DEFAULT_OPTIONS, ...options };

	// 检查级别是否在范围内
	const level = parseInt(element.tagName.charAt(1), 10);
	if (level < config.minLevel || level > config.maxLevel) {
		return null;
	}

	// 获取文本内容
	const rawText = element.textContent || '';
	const text = config.textProcessor(rawText);

	// 跳过空文本
	if (!text) {
		return null;
	}

	// 处理ID
	let id = element.id;
	if (!id) {
		if (config.skipWithoutId) {
			return null;
		}
		id = config.idGenerator(text, index);
		element.id = id;
	}

	return {
		id,
		text,
		level,
		element
	};
}

/**
 * 从容器中收集所有标题元素
 * @param container 容器元素
 * @param options 配置选项
 * @returns 目录项数组
 */
export function collectHeadings(
	container: HTMLElement | Document = document,
	options: TocOptions = {}
): TocItem[] {
	const config = { ...DEFAULT_OPTIONS, ...options };
	const selector = config.headingSelector;
	const elements = Array.from(container.querySelectorAll(selector)) as HTMLElement[];

	return elements
		.map((element, index) => parseHeadingElement(element, index, config))
		.filter((item): item is TocItem => item !== null);
}

/**
 * 将扁平的目录项转换为树形结构
 * @param items 扁平的目录项数组
 * @returns 树形结构的目录项
 */
export function buildTocTree(items: TocItem[]): TocItem[] {
	if (items.length === 0) return [];

	const root: TocItem = {
		id: 'root',
		text: 'Root',
		level: 0,
		element: document.createElement('div'),
		children: []
	};

	const stack: TocItem[] = [root];

	items.forEach(item => {
		const currentItem = { ...item, children: [] };

		// 找到合适的父节点
		while (stack.length > 1 && stack[stack.length - 1].level >= item.level) {
			stack.pop();
		}

		// 添加到父节点
		const parent = stack[stack.length - 1];
		if (parent.children) {
			parent.children.push(currentItem);
		}

		// 将当前项压入栈
		stack.push(currentItem);
	});

	return root.children || [];
}

/**
 * 扁平化树形目录结构
 * @param tree 树形目录结构
 * @param flatArray 用于存储结果的数组
 * @returns 扁平化的目录项数组
 */
export function flattenTocTree(tree: TocItem[], flatArray: TocItem[] = []): TocItem[] {
	tree.forEach(item => {
		flatArray.push(item);
		if (item.children && item.children.length > 0) {
			flattenTocTree(item.children, flatArray);
		}
	});
	return flatArray;
}

/**
 * 生成目录HTML结构
 * @param items 目录项数组
 * @param options 渲染选项
 * @returns HTML字符串
 */
export function generateTocHtml(
	items: TocItem[],
	options: {
		wrapInNav?: boolean;
		className?: string;
		linkPrefix?: string;
	} = {}
): string {
	const { wrapInNav = true, className = 'toc-list', linkPrefix = '#' } = options;

	const listItems = items.map(item => {
		const indent = '  '.repeat(Math.max(0, item.level - 1));
		const linkClass = `toc-link level-${item.level}`;
		const escapedText = escapeHtml(item.text);

		return `${indent}<li class="toc-item">
${indent}  <a href="${linkPrefix}${item.id}" class="${linkClass}">
${indent}    <span class="toc-link-bullet" aria-hidden="true"></span>
${indent}    <span class="toc-link-label">${escapedText}</span>
${indent}  </a>
${indent}</li>`;
	}).join('\n');

	const listHtml = `<ul class="${className}">\n${listItems}\n</ul>`;

	return wrapInNav
		? `<nav class="table-of-contents" aria-label="文章目录">\n${listHtml}\n</nav>`
		: listHtml;
}

/**
 * HTML转义函数
 * @param text 待转义的文本
 * @returns 转义后的HTML
 */
export function escapeHtml(text: string): string {
	const div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

/**
 * 性能监控工具
 */
export class TocPerformanceMonitor {
	private startTime: number = 0;
	private measurements: Map<string, number[]> = new Map();

	start(): void {
		this.startTime = performance.now();
	}

	end(label: string): number {
		const elapsed = performance.now() - this.startTime;
		if (!this.measurements.has(label)) {
			this.measurements.set(label, []);
		}
		this.measurements.get(label)!.push(elapsed);
		return elapsed;
	}

	getStats(label: string): { avg: number; min: number; max: number; count: number } | null {
		const times = this.measurements.get(label);
		if (!times || times.length === 0) return null;

		const sum = times.reduce((a, b) => a + b, 0);
		return {
			avg: sum / times.length,
			min: Math.min(...times),
			max: Math.max(...times),
			count: times.length
		};
	}

	logStats(): void {
		console.group('TOC Performance Stats');
		this.measurements.forEach((_, label) => {
			const stats = this.getStats(label);
			if (stats) {
				console.log(`${label}: avg=${stats.avg.toFixed(2)}ms, min=${stats.min.toFixed(2)}ms, max=${stats.max.toFixed(2)}ms (${stats.count} samples)`);
			}
		});
		console.groupEnd();
	}
}

/**
 * 目录缓存管理器
 */
export class TocCache {
	private cache: Map<string, TocItem[]> = new Map();
	private timestamps: Map<string, number> = new Map();
	private maxSize: number;

	constructor(maxSize: number = 100) {
		this.maxSize = maxSize;
	}

	set(key: string, items: TocItem[]): void {
		// 如果缓存已满，删除最老的项
		if (this.cache.size >= this.maxSize) {
			const oldestKey = this.getOldestKey();
			if (oldestKey) {
				this.delete(oldestKey);
			}
		}

		this.cache.set(key, items);
		this.timestamps.set(key, Date.now());
	}

	get(key: string): TocItem[] | undefined {
		this.timestamps.set(key, Date.now());
		return this.cache.get(key);
	}

	has(key: string): boolean {
		return this.cache.has(key);
	}

	delete(key: string): boolean {
		this.timestamps.delete(key);
		return this.cache.delete(key);
	}

	clear(): void {
		this.cache.clear();
		this.timestamps.clear();
	}

	private getOldestKey(): string | null {
		let oldestKey: string | null = null;
		let oldestTime = Infinity;

		this.timestamps.forEach((timestamp, key) => {
			if (timestamp < oldestTime) {
				oldestTime = timestamp;
				oldestKey = key;
			}
		});

		return oldestKey;
	}

	get size(): number {
		return this.cache.size;
	}
}

// 导出默认实例
export const tocCache = new TocCache();
export const perfMonitor = new TocPerformanceMonitor();

// 类型守卫
export function isTocItem(obj: any): obj is TocItem {
	return obj &&
		typeof obj.id === 'string' &&
		typeof obj.text === 'string' &&
		typeof obj.level === 'number' &&
		obj.element instanceof HTMLElement;
}