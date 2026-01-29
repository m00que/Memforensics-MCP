"""
Volatility 3 注册表分析工具 (5个)
139-143
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_registry_tools(mcp):
    """注册 Volatility 3 注册表分析工具"""
    
    @mcp.tool()
    def vol3_hivelist(mempath: str) -> dict:
        """
        [Vol3 #139] 获取注册表 Hive 列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            Hive 列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.registry.hivelist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_hivescan(mempath: str) -> dict:
        """
        [Vol3 #140] 注册表 Hive 扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            Hive 扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.registry.hivescan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_printkey(mempath: str, key: Optional[str] = None, 
                      offset: Optional[str] = None) -> dict:
        """
        [Vol3 #141] 打印注册表键值
        
        Args:
            mempath: 内存镜像文件路径
            key: 键路径 (如 "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            offset: Hive 偏移
        
        Returns:
            键值内容
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = []
            if key:
                extra_args.extend(["--key", key])
            if offset:
                extra_args.extend(["--offset", offset])
            
            return runner.run_plugin("windows.registry.printkey", 
                                    extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_userassist(mempath: str) -> dict:
        """
        [Vol3 #142] 获取 UserAssist 记录
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            程序执行记录
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.registry.userassist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_certificates(mempath: str) -> dict:
        """
        [Vol3 #143] 获取证书信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统证书列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.registry.certificates")
        except Exception as e:
            return {"success": False, "error": str(e)}
