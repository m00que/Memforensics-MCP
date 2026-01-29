"""
Volatility 2 网络分析工具 (2个)
54. vol2_netscan - 网络连接扫描
55. vol2_connections - 网络连接 (XP)
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_network_tools(mcp):
    """注册 Volatility 2 网络分析工具"""
    
    @mcp.tool()
    def vol2_netscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #54] 网络连接扫描 (Vista/7/8/10)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            网络连接列表 (TCP/UDP)
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("netscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_connections(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #55] 网络连接 (Windows XP)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            网络连接列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("connections")
        except Exception as e:
            return {"success": False, "error": str(e)}
