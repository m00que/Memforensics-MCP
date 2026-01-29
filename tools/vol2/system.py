"""
Volatility 2 系统信息工具 (6个)
36. vol2_imageinfo - Profile检测
37. vol2_kdbgscan - KDBG扫描
38. vol2_shutdowntime - 关机时间
39. vol2_envars - 环境变量
40. vol2_verinfo - 版本信息
41. vol2_auditpol - 审计策略
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_system_tools(mcp):
    """注册 Volatility 2 系统信息工具"""
    
    @mcp.tool()
    def vol2_imageinfo(mempath: str) -> dict:
        """
        [Vol2 #36] 获取镜像信息并自动检测 Profile
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            镜像信息和建议的 Profile
        """
        try:
            runner = Vol2Runner(mempath)
            result = runner.run_plugin("imageinfo", output_type="text")
            
            # 解析建议的 Profile
            profiles = []
            for line in result.get("output", "").split("\n"):
                if "Suggested Profile(s)" in line:
                    profiles = [p.strip() for p in line.split(":")[1].split(",")]
                    break
            
            result["suggested_profiles"] = profiles
            result["recommended_profile"] = profiles[0] if profiles else None
            
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_kdbgscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #37] 扫描 KDBG 结构
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            KDBG 扫描结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("kdbgscan", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_shutdowntime(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #38] 获取系统关机时间
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            系统关机时间
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("shutdowntime", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_envars(mempath: str, profile: Optional[str] = None, pid: Optional[int] = None) -> dict:
        """
        [Vol2 #39] 获取环境变量
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID (可选，指定则只获取该进程)
        
        Returns:
            环境变量列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_plugin("envars", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_verinfo(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #40] 获取 PE 文件版本信息
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            PE 文件版本信息
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("verinfo")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_auditpol(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #41] 获取审计策略
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            系统审计策略
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("auditpol")
        except Exception as e:
            return {"success": False, "error": str(e)}
