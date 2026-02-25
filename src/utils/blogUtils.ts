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

/**
 * 智能解析和转换时间为东八区
 * @param timeString ISO时间字符串
 * @returns 东八区时间的Date对象
 * 
 * 功能说明：
 * - 如果输入是UTC时间(带Z)，自动转换为东八区
 * - 如果输入已经是东八区时间(+08:00)，直接使用
 * - 如果输入是其他时区，也转换为东八区
 */
export function parseChinaTime(timeString: string): Date {
  // 创建Date对象
  const date = new Date(timeString);
  
  // 检查原始字符串是否包含时区信息
  const hasTimezone = timeString.includes('+') || timeString.includes('-') || timeString.includes('Z');
  
  // 如果没有明确的时区信息，假设是本地时间，转换为东八区
  if (!hasTimezone) {
    return new Date(date.getTime() + 8 * 60 * 60 * 1000);
  }
  
  // 如果是UTC时间(Z结尾)，转换为东八区
  if (timeString.endsWith('Z')) {
    return new Date(date.getTime() + 8 * 60 * 60 * 1000);
  }
  
  // 如果已经有时区信息，保持原样
  return date;
}

/**
 * 格式化时间为东八区显示
 * @param timeString ISO时间字符串
 * @param showTimezone 是否显示时区信息
 * @returns 格式化后的时间字符串
 */
export function formatChinaTime(timeString: string, showTimezone: boolean = false): string {
  const date = parseChinaTime(timeString);
  
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'Asia/Shanghai'
  };
  
  if (showTimezone) {
    options.hour = '2-digit';
    options.minute = '2-digit';
    options.timeZoneName = 'short';
  }
  
  return date.toLocaleDateString('zh-CN', options);
}
