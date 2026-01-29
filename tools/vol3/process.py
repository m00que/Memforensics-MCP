"""
Volatility 3 进程分析工具 (14个)
117-130
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_process_tools(mcp):
    """注册 Volatility 3 进程分析工具"""
    
    @mcp.tool()
    def vol3_pslist(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #117] 获取进程列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选，过滤)
        
        Returns:
            进程列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.pslist", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_psscan(mempath: str) -> dict:
        """
        [Vol3 #118] 进程扫描 (包括隐藏/终止进程)
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.psscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_pstree(mempath: str) -> dict:
        """
        [Vol3 #119] 获取进程树
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程树结构
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.pstree")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_psxview(mempath: str) -> dict:
        """
        [Vol3 #120] 跨视图进程检测
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            跨视图检测结果 (发现隐藏进程)
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.psxview")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_cmdline(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #121] 获取命令行参数
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            命令行参数
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.cmdline", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_dlllist(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #122] 获取 DLL 列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            DLL 列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.dlllist", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_handles(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #123] 获取进程句柄
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            句柄列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.handles", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_getsids(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #124] ⭐ 获取进程完整 SID 列表
        
        比 MemProcFS 更详细的 SID 信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            进程 SID 列表 (包括组成员身份)
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.getsids", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_privileges(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #125] 获取进程权限
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            进程权限列表
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.privileges", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_ldrmodules(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [Vol3 #126] LDR 模块检测 (隐藏 DLL)
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
        
        Returns:
            LDR 模块列表 (False 表示可能隐藏)
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = ["--pid", str(pid)] if pid else None
            return runner.run_plugin("windows.ldrmodules", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_vadinfo(mempath: str, pid: int) -> dict:
        """
        [Vol3 #127] 获取 VAD 信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            VAD 信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.vadinfo", extra_args=["--pid", str(pid)])
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_vadwalk(mempath: str, pid: int) -> dict:
        """
        [Vol3 #128] VAD 遍历
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            VAD 遍历结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.vadwalk", extra_args=["--pid", str(pid)])
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_sessions(mempath: str) -> dict:
        """
        [Vol3 #129] 获取登录会话
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            登录会话信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.sessions")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_joblinks(mempath: str) -> dict:
        """
        [Vol3 #130] 获取作业对象
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            作业对象链接
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.joblinks")
        except Exception as e:
            return {"success": False, "error": str(e)}
