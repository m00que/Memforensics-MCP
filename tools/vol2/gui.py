"""
Volatility 2 GUI/窗口分析工具 (7个) ⭐独有
88. vol2_svcscan - 服务扫描
89. vol2_windows - 窗口信息
90. vol2_wintree - 窗口树
91. vol2_deskscan - 桌面扫描
92. vol2_screenshot - 截图重建
93. vol2_clipboard - 剪贴板
94. vol2_messagehooks - 消息钩子
95. vol2_eventhooks - 事件钩子
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_gui_tools(mcp):
    """注册 Volatility 2 GUI/窗口分析工具"""
    
    @mcp.tool()
    def vol2_svcscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #88] 服务扫描
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            系统服务列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("svcscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_windows(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #89] ⭐ 获取窗口信息 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            窗口信息
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("windows", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_wintree(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #90] ⭐ 获取窗口树 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            窗口层级结构
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("wintree")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_deskscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #91] ⭐ 桌面扫描 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            桌面对象信息
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("deskscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_screenshot(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #92] ⭐ 截图重建 (Vol2 独有)
        
        从内存中重建窗口截图
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            截图文件路径
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_dump_plugin("screenshot")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_clipboard(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #93] ⭐ 获取剪贴板内容 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            剪贴板内容
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("clipboard", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_messagehooks(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #94] ⭐ 消息钩子检测 (Vol2 独有)
        
        检测 Windows 消息钩子
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            消息钩子列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("messagehooks", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_eventhooks(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #95] ⭐ 事件钩子检测 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            事件钩子列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("eventhooks")
        except Exception as e:
            return {"success": False, "error": str(e)}
