"""
Volatility 3 系统信息工具 (4个)
113. vol3_info - 系统信息
114. vol3_crashinfo - 崩溃信息
115. vol3_verinfo - 版本信息
116. vol3_envars - 环境变量
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_system_tools(mcp):
    """注册 Volatility 3 系统信息工具"""
    
    @mcp.tool()
    def vol3_info(mempath: str) -> dict:
        """
        [Vol3 #113] 获取系统/镜像信息
        
        自动检测系统类型，无需指定 Profile
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统信息 (OS版本、架构等)
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.info")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_crashinfo(mempath: str) -> dict:
        """
        [Vol3 #114] 获取崩溃转储信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            崩溃转储信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.crashinfo", output_format="quick")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_verinfo(mempath: str) -> dict:
        """
        [Vol3 #115] 获取 PE 版本信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            PE 文件版本信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.verinfo")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_envars(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #116] 获取环境变量
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            环境变量列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.envars", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
