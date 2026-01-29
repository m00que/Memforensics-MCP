"""
Volatility 3 内核分析工具 (9个)
153-161
"""

from core.vol3_runner import Vol3Runner


def register_vol3_kernel_tools(mcp):
    """注册 Volatility 3 内核分析工具"""
    
    @mcp.tool()
    def vol3_modules(mempath: str) -> dict:
        """
        [Vol3 #153] 获取内核模块列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            内核模块列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.modules")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_modscan(mempath: str) -> dict:
        """
        [Vol3 #154] 扫描内核模块
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            模块扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.modscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_driverscan(mempath: str) -> dict:
        """
        [Vol3 #155] 扫描驱动对象
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            驱动对象列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.driverscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_drivermodule(mempath: str) -> dict:
        """
        [Vol3 #156] 获取驱动模块信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            驱动模块详情
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.drivermodule")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_driverirp(mempath: str) -> dict:
        """
        [Vol3 #157] 获取驱动 IRP
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            驱动 IRP 信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.driverirp")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_ssdt(mempath: str) -> dict:
        """
        [Vol3 #158] 获取 SSDT 表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            SSDT 系统服务描述符表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.ssdt")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_callbacks(mempath: str) -> dict:
        """
        [Vol3 #159] 获取内核回调
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            内核回调函数列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.callbacks")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_timers(mempath: str) -> dict:
        """
        [Vol3 #160] 获取内核定时器
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            内核定时器列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.timers")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_devicetree(mempath: str) -> dict:
        """
        [Vol3 #161] 获取设备树
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            设备树结构
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.devicetree")
        except Exception as e:
            return {"success": False, "error": str(e)}
