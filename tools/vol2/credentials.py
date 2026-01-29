"""
Volatility 2 凭据提取工具 (4个) ⭐独有 mimikatz
68. vol2_hashdump - SAM哈希
69. vol2_lsadump - LSA Secrets
70. vol2_cachedump - 缓存凭据
71. vol2_mimikatz - Mimikatz凭据 ⭐
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_credentials_tools(mcp):
    """注册 Volatility 2 凭据提取工具"""
    
    @mcp.tool()
    def vol2_hashdump(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #68] 提取 SAM 密码哈希
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            用户密码哈希 (LM/NT Hash)
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("hashdump", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_lsadump(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #69] 提取 LSA Secrets
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            LSA 密钥和机密
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("lsadump", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_cachedump(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #70] 提取域缓存凭据 (DCC/DCC2)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            域缓存哈希
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("cachedump", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_mimikatz(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #71] ⭐ Mimikatz 凭据提取 (Vol2 独有)
        
        从 lsass.exe 进程内存中提取明文密码、哈希、票据
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            Mimikatz 提取的凭据 (可能包含明文密码)
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("mimikatz", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
