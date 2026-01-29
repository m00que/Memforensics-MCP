"""
MemForensics MCP Server - 内存取证分析服务
整合 MemProcFS + Volatility 2 + Volatility 3
共 138 个工具 + 5 个搜索工具
"""

from mcp.server.fastmcp import FastMCP
import os
import sys

# 添加模块路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入搜索工具模块 (AI入口点)
from tools.search import register_search_tools

# 导入三大引擎的工具模块
from tools.mem import register_all_mem_tools
from tools.vol2 import register_all_vol2_tools
from tools.vol3 import register_all_vol3_tools

# 创建 MCP 服务器实例
mcp = FastMCP("MemForensics-MCP-Server")

# ===== 注册所有工具 =====

# 0. 搜索工具 (5个) - AI 入口点，应首先调用
register_search_tools(mcp)

# 1. MemProcFS 工具 (35个) - 快速实时分析
register_all_mem_tools(mcp)

# 2. Volatility 2 工具 (55个) - 经典分析 + 独有功能
register_all_vol2_tools(mcp)

# 3. Volatility 3 工具 (48个) - 现代分析 + 新检测技术
register_all_vol3_tools(mcp)

# ===== 服务信息 =====

@mcp.tool()
def forensics_help() -> dict:
    """
    获取内存取证 MCP 服务帮助信息
    
    Returns:
        工具分类和使用指南
    """
    return {
        "service": "MemForensics MCP Server",
        "version": "1.0.0",
        "total_tools": 143,
        "usage": "首先调用 search_tools(search='关键词') 搜索合适的工具",
        "search_tools": [
            "search_tools - 🔍 关键词搜索工具 (AI入口点)",
            "list_tools_by_category - 按分类列出工具",
            "list_tools_by_engine - 按引擎列出工具",
            "get_tool_info - 获取工具详情",
            "get_unique_features - 获取各引擎独有功能"
        ],
        "engines": {
            "MemProcFS": {
                "count": 35,
                "prefix": "mem_",
                "features": ["快速分析", "实时虚拟文件系统", "无需Profile", "pypykatz凭据提取", "时间线分析"]
            },
            "Volatility2": {
                "count": 55,
                "prefix": "vol2_",
                "features": ["经典分析", "丰富插件", "mimikatz凭据", "浏览器历史", "GUI/窗口分析", "BitLocker/TrueCrypt"]
            },
            "Volatility3": {
                "count": 48,
                "prefix": "vol3_",
                "features": ["现代分析", "自动检测", "进程镂空检测", "进程幽灵检测", "系统调用检测", "线程分析"]
            }
        },
        "categories": {
            "系统信息": ["mem_info", "vol2_imageinfo", "vol3_info"],
            "进程分析": ["mem_pslist", "vol2_pslist", "vol3_pslist", "vol3_getsids"],
            "网络分析": ["mem_netstat", "vol2_netscan", "vol3_netscan"],
            "注册表": ["mem_autoruns", "vol2_printkey", "vol3_printkey"],
            "凭据提取": ["mem_pypykatz", "vol2_mimikatz", "vol3_hashdump"],
            "恶意检测": ["mem_findevil", "vol2_malfind", "vol3_hollowprocesses"],
            "时间线": ["mem_timeline_all", "vol2_timeliner"]
        },
        "unique_features": {
            "MemProcFS独有": ["7种时间线", "pypykatz集成", "控制台输出"],
            "Vol2独有": ["mimikatz", "浏览器历史", "截图重建", "剪贴板", "BitLocker密钥"],
            "Vol3独有": ["进程镂空检测", "进程幽灵检测", "直接/间接系统调用检测", "可疑线程检测"]
        }
    }


if __name__ == "__main__":
    mcp.run()
