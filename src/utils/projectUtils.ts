/**
 * 项目工具函数库
 * 
 * 作用：
 * - 提供项目相关的通用工具函数
 * - 处理项目状态、分类等业务逻辑
 * - 统一项目数据处理方式
 * 
 * 相关文件：
 * - src/pages/projects/index-dev.astro：项目展示页面
 * - src/pages/projects/index.astro：项目列表页面（如果存在）
 * 
 * 主要功能：
 * - 项目状态处理
 * - 项目数据格式化
 * - 项目分类统计
 */

export interface Project {
    id: string;
    title: string;
    description: string;
    tags: string[];
    githubUrl?: string;
    demoUrl?: string;
    status: 'completed' | 'in-progress' | 'planned';
    year: number;
}

/**
 * 获取项目状态对应的CSS类名
 * @param status 项目状态
 * @returns CSS类名
 */
export function getStatusColorClass(status: Project['status']): string {
    switch (status) {
        case 'completed': return 'status-completed';
        case 'in-progress': return 'status-in-progress';
        case 'planned': return 'status-planned';
        default: return 'status-default';
    }
}

/**
 * 获取项目状态的显示文本
 * @param status 项目状态
 * @returns 显示文本
 */
export function getStatusText(status: Project['status']): string {
    switch (status) {
        case 'completed': return '已完成';
        case 'in-progress': return '进行中';
        case 'planned': return '计划中';
        default: return '未知';
    }
}

/**
 * 按年份对项目进行分组
 * @param projects 项目数组
 * @returns 按年份分组的对象
 */
export function groupProjectsByYear(projects: Project[]): Record<number, Project[]> {
    return projects.reduce((acc, project) => {
        if (!acc[project.year]) {
            acc[project.year] = [];
        }
        acc[project.year].push(project);
        return acc;
    }, {} as Record<number, Project[]>);
}

/**
 * 获取排序后的年份列表（降序）
 * @param projectsByYear 按年份分组的项目对象
 * @returns 排序后的年份数组
 */
export function getSortedYears(projectsByYear: Record<number, Project[]>): number[] {
    return Object.keys(projectsByYear)
        .map(year => parseInt(year))
        .sort((a, b) => b - a);
}

/**
 * 统计各状态的项目数量
 * @param projects 项目数组
 * @returns 各状态的数量统计
 */
export function getStatusStats(projects: Project[]): Record<Project['status'], number> {
    return projects.reduce((acc, project) => {
        acc[project.status] = (acc[project.status] || 0) + 1;
        return acc;
    }, {} as Record<Project['status'], number>);
}