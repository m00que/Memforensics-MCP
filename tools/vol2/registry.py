"""
Volatility 2 注册表分析工具 (8个)
60. vol2_hivelist - Hive列表
61. vol2_printkey - 键值查询
62. vol2_hivedump - Hive结构转储
63. vol2_dumpregistry - 导出注册表
64. vol2_userassist - UserAssist记录
65. vol2_shellbags - ShellBags分析
66. vol2_shimcache - Shimcache
67. vol2_autoruns - 自启动项
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_registry_tools(mcp):
    """注册 Volatility 2 注册表分析工具"""
    
    @mcp.tool()
    def vol2_hivelist(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #60] 获取注册表 Hive 列表
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Hive 列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("hivelist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_printkey(mempath: str, profile: Optional[str] = None, 
                      key_path: Optional[str] = None) -> dict:
        """
        [Vol2 #61] 打印注册表键值
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            key_path: 注册表键路径 (如 "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        
        Returns:
            键值内容
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-K", key_path] if key_path else None
            return runner.run_plugin("printkey", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_hivedump(mempath: str, profile: Optional[str] = None, 
                      hive_offset: Optional[str] = None) -> dict:
        """
        [Vol2 #62] Hive 结构转储
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            hive_offset: Hive 虚拟地址偏移
        
        Returns:
            Hive 结构
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-o", hive_offset] if hive_offset else None
            return runner.run_plugin("hivedump", output_type="text", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_dumpregistry(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #63] 导出全部注册表 Hive 文件
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_dump_plugin("dumpregistry")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_userassist(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #64] 获取 UserAssist 程序执行记录
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            程序执行记录
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("userassist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_shellbags(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #65] ShellBags 分析 (文件夹访问记录)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            ShellBags 记录
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("shellbags")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_shimcache(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #66] 获取 Shimcache (应用程序兼容性缓存)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Shimcache 记录 (程序执行痕迹)
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("shimcache")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_autoruns(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #67] 获取自启动项 (需要社区插件)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            自启动项列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("autoruns")
        except Exception as e:
            return {"success": False, "error": str(e)}
