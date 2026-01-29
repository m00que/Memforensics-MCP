"""
工具搜索模块 - AI 入口点
AI 应首先调用此工具，通过关键词搜索找到合适的取证工具
"""

import json
import os
from typing import List, Optional

# 工具索引文件路径
INDEX_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools_index.json")

# 缓存工具索引
_TOOLS_INDEX = None


def _load_index():
    """加载工具索引"""
    global _TOOLS_INDEX
    if _TOOLS_INDEX is None:
        with open(INDEX_PATH, 'r', encoding='utf-8') as f:
            _TOOLS_INDEX = json.load(f)
    return _TOOLS_INDEX


def register_search_tools(mcp):
    """注册搜索工具"""
    
    @mcp.tool()
    def search_tools(search: str) -> dict:
        """
        🔍 内存取证工具搜索 (AI入口点)
        
        通过关键词搜索合适的取证工具。AI应首先调用此工具找到合适的分析工具。
        
        Args:
            search: 搜索关键词，如 "进程"、"网络"、"密码"、"恶意"、"SID" 等
        
        Returns:
            匹配的工具列表，包含工具名、引擎、分类和功能描述
        
        Examples:
            - search="进程" → 返回所有进程相关工具
            - search="密码" → 返回凭据提取工具
            - search="恶意" → 返回恶意检测工具
            - search="网络连接" → 返回网络分析工具
            - search="SID" → 返回获取SID的工具
        """
        index = _load_index()
        keywords = search.lower().split()
        
        results = []
        for tool in index["tools"]:
            # 计算匹配分数
            score = 0
            
            # 检查工具名
            tool_name_lower = tool["name"].lower()
            for kw in keywords:
                if kw in tool_name_lower:
                    score += 3
            
            # 检查描述
            desc_lower = tool["description"].lower()
            for kw in keywords:
                if kw in desc_lower:
                    score += 2
            
            # 检查关键词列表
            tool_keywords = [k.lower() for k in tool["keywords"]]
            for kw in keywords:
                for tk in tool_keywords:
                    if kw in tk or tk in kw:
                        score += 1
            
            # 检查分类
            if any(kw in tool["category"].lower() for kw in keywords):
                score += 2
            
            if score > 0:
                results.append({
                    "name": tool["name"],
                    "engine": tool["engine"],
                    "category": tool["category"],
                    "description": tool["description"],
                    "score": score
                })
        
        # 按分数排序
        results.sort(key=lambda x: x["score"], reverse=True)
        
        # 移除分数字段
        for r in results:
            del r["score"]
        
        return {
            "search_query": search,
            "total_matches": len(results),
            "tools": results[:20]  # 最多返回20个结果
        }
    
    @mcp.tool()
    def list_tools_by_category(category: Optional[str] = None) -> dict:
        """
        按分类列出工具
        
        Args:
            category: 分类名称，如 "进程分析"、"凭据提取"。为空则返回所有分类
        
        Returns:
            指定分类的工具列表，或所有可用分类
        """
        index = _load_index()
        
        if category is None:
            # 返回所有分类统计
            category_stats = {}
            for tool in index["tools"]:
                cat = tool["category"]
                if cat not in category_stats:
                    category_stats[cat] = {"count": 0, "engines": set()}
                category_stats[cat]["count"] += 1
                category_stats[cat]["engines"].add(tool["engine"])
            
            # 转换 set 为 list
            for cat in category_stats:
                category_stats[cat]["engines"] = list(category_stats[cat]["engines"])
            
            return {
                "total_categories": len(category_stats),
                "categories": category_stats
            }
        else:
            # 返回指定分类的工具
            tools = []
            for tool in index["tools"]:
                if category.lower() in tool["category"].lower():
                    tools.append({
                        "name": tool["name"],
                        "engine": tool["engine"],
                        "description": tool["description"]
                    })
            
            return {
                "category": category,
                "total": len(tools),
                "tools": tools
            }
    
    @mcp.tool()
    def list_tools_by_engine(engine: str) -> dict:
        """
        按引擎列出工具
        
        Args:
            engine: 引擎名称 ("MemProcFS" / "Volatility2" / "Volatility3")
        
        Returns:
            指定引擎的所有工具
        """
        index = _load_index()
        
        engine_map = {
            "mem": "MemProcFS",
            "memprocfs": "MemProcFS",
            "vol2": "Volatility2",
            "volatility2": "Volatility2",
            "vol3": "Volatility3",
            "volatility3": "Volatility3"
        }
        
        engine_name = engine_map.get(engine.lower(), engine)
        
        tools = []
        categories = {}
        
        for tool in index["tools"]:
            if tool["engine"].lower() == engine_name.lower():
                tools.append({
                    "name": tool["name"],
                    "category": tool["category"],
                    "description": tool["description"]
                })
                
                cat = tool["category"]
                if cat not in categories:
                    categories[cat] = 0
                categories[cat] += 1
        
        return {
            "engine": engine_name,
            "total": len(tools),
            "by_category": categories,
            "tools": tools
        }
    
    @mcp.tool()
    def get_tool_info(tool_name: str) -> dict:
        """
        获取单个工具的详细信息
        
        Args:
            tool_name: 工具名称，如 "vol3_getsids"
        
        Returns:
            工具详细信息
        """
        index = _load_index()
        
        for tool in index["tools"]:
            if tool["name"].lower() == tool_name.lower():
                return {
                    "found": True,
                    "tool": {
                        "id": tool["id"],
                        "name": tool["name"],
                        "engine": tool["engine"],
                        "category": tool["category"],
                        "description": tool["description"],
                        "keywords": tool["keywords"]
                    }
                }
        
        # 模糊搜索
        matches = []
        for tool in index["tools"]:
            if tool_name.lower() in tool["name"].lower():
                matches.append(tool["name"])
        
        return {
            "found": False,
            "message": f"未找到工具 '{tool_name}'",
            "similar": matches[:5]
        }
    
    @mcp.tool()
    def get_unique_features() -> dict:
        """
        获取各引擎独有功能
        
        Returns:
            各引擎的独有/特色功能
        """
        return {
            "MemProcFS": {
                "特点": "快速实时分析，无需Profile，虚拟文件系统",
                "独有功能": [
                    "mem_pypykatz - pypykatz凭据提取",
                    "mem_regsecrets - 注册表凭据提取",
                    "mem_timeline_all - 7种时间线合并",
                    "mem_console - 控制台输出提取",
                    "mem_kerberos_tickets - Kerberos票据导出"
                ]
            },
            "Volatility2": {
                "特点": "经典成熟，插件丰富，社区支持",
                "独有功能": [
                    "vol2_mimikatz - Mimikatz凭据提取(可获明文密码)",
                    "vol2_screenshot - 窗口截图重建",
                    "vol2_clipboard - 剪贴板内容",
                    "vol2_chromehistory - Chrome浏览历史",
                    "vol2_firefoxhistory - Firefox浏览历史",
                    "vol2_iehistory - IE浏览历史",
                    "vol2_bitlocker - BitLocker密钥提取",
                    "vol2_truecryptsummary - TrueCrypt分析",
                    "vol2_windows/wintree/deskscan - 窗口GUI分析"
                ]
            },
            "Volatility3": {
                "特点": "现代架构，自动检测，新检测技术",
                "独有功能": [
                    "vol3_hollowprocesses - 进程镂空检测",
                    "vol3_processghosting - 进程幽灵检测",
                    "vol3_direct_syscalls - 直接系统调用检测(EDR逃逸)",
                    "vol3_indirect_syscalls - 间接系统调用检测",
                    "vol3_suspicious_threads - 可疑线程检测",
                    "vol3_suspended_threads - 挂起线程检测",
                    "vol3_skeleton_key - 骨架密钥攻击检测",
                    "vol3_getsids - 完整SID列表(含组成员)"
                ]
            },
            "推荐选择": {
                "快速分析": "MemProcFS (mem_*)",
                "凭据提取": "vol2_mimikatz 或 mem_pypykatz",
                "SID查询": "vol3_getsids (最详细) 或 vol2_getsids",
                "恶意检测": "Vol3 (最强) > Vol2 > MemProcFS",
                "浏览器历史": "Volatility2",
                "时间线分析": "MemProcFS"
            }
        }
