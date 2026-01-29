"""
Volatility 2 工具模块 (55个工具)
基于 vol.py 命令行调用
"""

from .system import register_vol2_system_tools
from .process import register_vol2_process_tools
from .network import register_vol2_network_tools
from .filesystem import register_vol2_filesystem_tools
from .registry import register_vol2_registry_tools
from .credentials import register_vol2_credentials_tools
from .malware import register_vol2_malware_tools
from .kernel import register_vol2_kernel_tools
from .gui import register_vol2_gui_tools
from .browser import register_vol2_browser_tools
from .misc import register_vol2_misc_tools


def register_all_vol2_tools(mcp):
    """注册所有 Volatility 2 工具"""
    register_vol2_system_tools(mcp)
    register_vol2_process_tools(mcp)
    register_vol2_network_tools(mcp)
    register_vol2_filesystem_tools(mcp)
    register_vol2_registry_tools(mcp)
    register_vol2_credentials_tools(mcp)
    register_vol2_malware_tools(mcp)
    register_vol2_kernel_tools(mcp)
    register_vol2_gui_tools(mcp)
    register_vol2_browser_tools(mcp)
    register_vol2_misc_tools(mcp)
