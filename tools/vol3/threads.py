"""
Volatility 3 线程分析工具 (4个) ⭐独有
131. vol3_threads - 线程列表
132. vol3_thrdscan - 线程扫描
133. vol3_suspicious_threads - 可疑线程
134. vol3_suspended_threads - 挂起线程
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_threads_tools(mcp):
    """注册 Volatility 3 线程分析工具"""
    
    @mcp.tool()
    def vol3_threads(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #131] ⭐ 获取线程列表 (Vol3 独有)
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            线程列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.threads", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_thrdscan(mempath: str) -> dict:
        """
        [Vol3 #132] ⭐ 线程扫描 (Vol3 独有)
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            线程扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.thrdscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_suspicious_threads(mempath: str) -> dict:
        """
        [Vol3 #133] ⭐ 可疑线程检测 (Vol3 独有)
        
        检测可能被注入或恶意的线程
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            可疑线程列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.suspicious_threads")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_suspended_threads(mempath: str) -> dict:
        """
        [Vol3 #134] ⭐ 挂起线程检测 (Vol3 独有)
        
        检测处于挂起状态的线程 (常用于注入技术)
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            挂起线程列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.suspended_threads")
        except Exception as e:
            return {"success": False, "error": str(e)}
