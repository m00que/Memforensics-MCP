"""
Volatility 2 内核分析工具 (10个)
78. vol2_modules - 内核模块
79. vol2_modscan - 模块扫描
80. vol2_driverscan - 驱动扫描
81. vol2_driverirp - IRP钩子
82. vol2_ssdt - SSDT表
83. vol2_callbacks - 回调函数
84. vol2_timers - 定时器
85. vol2_unloadedmodules - 卸载模块
86. vol2_devicetree - 设备树
87. vol2_getservicesids - 服务SID
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_kernel_tools(mcp):
    """注册 Volatility 2 内核分析工具"""
    
    @mcp.tool()
    def vol2_modules(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #78] 获取内核模块列表
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            内核模块列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("modules")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_modscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #79] 扫描内核模块 (包括已卸载)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            模块扫描结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("modscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_driverscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #80] 扫描驱动对象
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            驱动对象列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("driverscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_driverirp(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #81] 检测驱动 IRP 钩子
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            IRP 钩子检测结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("driverirp")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_ssdt(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #82] 获取 SSDT (系统服务描述符表)
        
        检测 SSDT 钩子
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            SSDT 表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("ssdt")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_callbacks(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #83] 获取内核回调函数
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            内核回调函数列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("callbacks")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_timers(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #84] 获取内核定时器
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            内核定时器列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("timers")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_unloadedmodules(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #85] 获取已卸载的内核模块
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            已卸载模块列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("unloadedmodules")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_devicetree(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #86] 获取设备树
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            设备树结构
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("devicetree", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_getservicesids(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #87] 获取服务 SID
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            服务 SID 列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("getservicesids")
        except Exception as e:
            return {"success": False, "error": str(e)}
