"""
内存取证工具模块
整合 MemProcFS + Volatility 2 + Volatility 3
"""

# 导入搜索工具 (AI入口点)
from .search import register_search_tools

# 导入各引擎的工具注册函数
from .mem import register_all_mem_tools
from .vol2 import register_all_vol2_tools
from .vol3 import register_all_vol3_tools

__all__ = [
    'register_search_tools',
    'register_all_mem_tools',
    'register_all_vol2_tools', 
    'register_all_vol3_tools',
]
