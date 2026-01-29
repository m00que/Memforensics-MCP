"""
Volatility 3 文件系统工具 (2个)
137. vol3_filescan - 文件扫描
138. vol3_dumpfiles - 文件导出
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_filesystem_tools(mcp):
    """注册 Volatility 3 文件系统工具"""
    
    @mcp.tool()
    def vol3_filescan(mempath: str) -> dict:
        """
        [Vol3 #137] 文件对象扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            文件对象列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.filescan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_dumpfiles(mempath: str, physaddr: Optional[str] = None, 
                       virtaddr: Optional[str] = None) -> dict:
        """
        [Vol3 #138] 从内存导出文件
        
        Args:
            mempath: 内存镜像文件路径
            physaddr: 物理地址偏移
            virtaddr: 虚拟地址偏移
        
        Returns:
            导出结果
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = []
            if physaddr:
                extra_args.extend(["--physaddr", physaddr])
            if virtaddr:
                extra_args.extend(["--virtaddr", virtaddr])
            
            return runner.run_dump_plugin("windows.dumpfiles", 
                                         extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
