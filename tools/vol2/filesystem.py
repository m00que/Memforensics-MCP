"""
Volatility 2 文件系统工具 (4个)
56. vol2_filescan - 文件扫描
57. vol2_mftparser - MFT解析
58. vol2_symlinkscan - 符号链接扫描
59. vol2_dumpfiles - 文件导出
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_filesystem_tools(mcp):
    """注册 Volatility 2 文件系统工具"""
    
    @mcp.tool()
    def vol2_filescan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #56] 文件对象扫描
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            文件对象列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("filescan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_mftparser(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #57] MFT (主文件表) 解析
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            MFT 记录
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin_to_file("mftparser", timeout=900)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_symlinkscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #58] 符号链接扫描
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            符号链接列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("symlinkscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_dumpfiles(mempath: str, profile: Optional[str] = None, 
                       offset: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #59] 从内存导出文件
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            offset: 文件对象偏移 (十六进制)
            pid: 进程ID (导出该进程相关文件)
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = []
            if offset:
                extra_args.extend(["-Q", offset])
            if pid:
                extra_args.extend(["-p", str(pid)])
            
            return runner.run_dump_plugin("dumpfiles", extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
