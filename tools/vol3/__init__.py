"""
Volatility 3 工具模块 (48个工具)
基于 volatility3 框架
"""

from .system import register_vol3_system_tools
from .process import register_vol3_process_tools
from .threads import register_vol3_threads_tools
from .network import register_vol3_network_tools
from .filesystem import register_vol3_filesystem_tools
from .registry import register_vol3_registry_tools
from .credentials import register_vol3_credentials_tools
from .malware import register_vol3_malware_tools
from .kernel import register_vol3_kernel_tools
from .misc import register_vol3_misc_tools


def register_all_vol3_tools(mcp):
    """注册所有 Volatility 3 工具"""
    register_vol3_system_tools(mcp)
    register_vol3_process_tools(mcp)
    register_vol3_threads_tools(mcp)
    register_vol3_network_tools(mcp)
    register_vol3_filesystem_tools(mcp)
    register_vol3_registry_tools(mcp)
    register_vol3_credentials_tools(mcp)
    register_vol3_malware_tools(mcp)
    register_vol3_kernel_tools(mcp)
    register_vol3_misc_tools(mcp)
