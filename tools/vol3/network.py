"""
Volatility 3 网络分析工具 (2个)
135. vol3_netscan - 网络扫描
136. vol3_netstat - 网络状态
"""

from core.vol3_runner import Vol3Runner


def register_vol3_network_tools(mcp):
    """注册 Volatility 3 网络分析工具"""
    
    @mcp.tool()
    def vol3_netscan(mempath: str) -> dict:
        """
        [Vol3 #135] 网络连接扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络连接列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.netscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_netstat(mempath: str) -> dict:
        """
        [Vol3 #136] 网络状态
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络状态信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.netstat")
        except Exception as e:
            return {"success": False, "error": str(e)}
