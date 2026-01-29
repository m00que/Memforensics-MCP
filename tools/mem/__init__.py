"""
MemProcFS 工具模块 (35个工具)
基于 vmmpyc.pyd Python API
"""

from .system import register_mem_system_tools
from .process import register_mem_process_tools
from .network import register_mem_network_tools
from .filesystem import register_mem_filesystem_tools
from .registry import register_mem_registry_tools
from .services import register_mem_services_tools
from .credentials import register_mem_credentials_tools
from .malware import register_mem_malware_tools
from .timeline import register_mem_timeline_tools


def register_all_mem_tools(mcp):
    """注册所有 MemProcFS 工具"""
    register_mem_system_tools(mcp)
    register_mem_process_tools(mcp)
    register_mem_network_tools(mcp)
    register_mem_filesystem_tools(mcp)
    register_mem_registry_tools(mcp)
    register_mem_services_tools(mcp)
    register_mem_credentials_tools(mcp)
    register_mem_malware_tools(mcp)
    register_mem_timeline_tools(mcp)
