"""
Volatility 2 进程分析工具 (12个)
42. vol2_pslist - 进程列表
43. vol2_psscan - 进程扫描
44. vol2_pstree - 进程树
45. vol2_psxview - 隐藏进程检测
46. vol2_cmdline - 命令行参数
47. vol2_cmdscan - CMD历史
48. vol2_consoles - 控制台输出
49. vol2_dlllist - DLL列表
50. vol2_handles - 句柄
51. vol2_getsids - 进程SID
52. vol2_privs - 进程权限
53. vol2_vadinfo - VAD信息
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_process_tools(mcp):
    """注册 Volatility 2 进程分析工具"""
    
    @mcp.tool()
    def vol2_pslist(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #42] 获取进程列表 (通过 EPROCESS 链表)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            进程列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("pslist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_psscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #43] 扫描进程 (包括隐藏/已终止进程)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            进程扫描结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("psscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_pstree(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #44] 获取进程树
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            进程父子关系树
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("pstree", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_psxview(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #45] 多视图隐藏进程检测
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            跨视图进程检测结果 (可发现隐藏进程)
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("psxview")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_cmdline(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #46] 获取进程命令行参数
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选)
        
        Returns:
            命令行参数
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("cmdline", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_cmdscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #47] 扫描 CMD 历史命令
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            CMD 历史命令
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("cmdscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_consoles(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #48] 获取控制台输出内容
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            控制台输出
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("consoles", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_dlllist(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #49] 获取进程加载的 DLL 列表
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选)
        
        Returns:
            DLL 列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("dlllist", output_type="text", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_handles(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None,
                     handle_type: Optional[str] = None) -> dict:
        """
        [Vol2 #50] 获取进程句柄
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选)
            handle_type: 句柄类型过滤 (如 File, Key, Mutant)
        
        Returns:
            句柄列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = []
            if pid:
                extra_args.extend(["-p", str(pid)])
            if handle_type:
                extra_args.extend(["-t", handle_type])
            
            return runner.run_plugin("handles", extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_getsids(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #51] 获取进程 SID (安全标识符)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选)
        
        Returns:
            进程 SID 列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("getsids", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_privs(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #52] 获取进程权限
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选)
        
        Returns:
            进程权限列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("privs", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_vadinfo(mempath: str, profile: Optional[str] = None, pid: int = None) -> dict:
        """
        [Vol2 #53] 获取进程 VAD (虚拟地址描述符) 信息
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID
        
        Returns:
            VAD 信息
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("vadinfo", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
