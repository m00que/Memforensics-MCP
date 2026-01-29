"""
Volatility 2 浏览器/应用痕迹工具 (5个) ⭐独有
96. vol2_iehistory - IE历史
97. vol2_chromehistory - Chrome历史
98. vol2_firefoxhistory - Firefox历史
99. vol2_trustrecords - Office信任记录
100. vol2_prefetch - 预读文件
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_browser_tools(mcp):
    """注册 Volatility 2 浏览器/应用痕迹工具"""
    
    @mcp.tool()
    def vol2_iehistory(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #96] ⭐ IE 浏览历史记录 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            IE 浏览历史
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("iehistory", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_chromehistory(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #97] ⭐ Chrome 浏览历史 (Vol2 独有/扩展插件)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Chrome 浏览历史
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("chromehistory", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_firefoxhistory(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #98] ⭐ Firefox 浏览历史 (Vol2 独有/扩展插件)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Firefox 浏览历史
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("firefoxhistory", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_trustrecords(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #99] ⭐ Office 信任记录 (Vol2 独有/扩展插件)
        
        记录用户信任过的文档
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Office 信任记录
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("trustrecords", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_prefetch(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #100] ⭐ 预读文件分析 (Vol2 独有/扩展插件)
        
        分析 Windows 预读缓存
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            预读文件记录
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("prefetch")
        except Exception as e:
            return {"success": False, "error": str(e)}
