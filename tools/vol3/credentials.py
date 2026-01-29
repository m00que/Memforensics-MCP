"""
Volatility 3 凭据提取工具 (3个)
144-146
"""

from core.vol3_runner import Vol3Runner


def register_vol3_credentials_tools(mcp):
    """注册 Volatility 3 凭据提取工具"""
    
    @mcp.tool()
    def vol3_hashdump(mempath: str) -> dict:
        """
        [Vol3 #144] 提取 SAM 密码哈希
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            用户密码哈希
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.hashdump", output_format="quick")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_lsadump(mempath: str) -> dict:
        """
        [Vol3 #145] 提取 LSA Secrets
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            LSA 密钥和机密
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.lsadump", output_format="quick")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_cachedump(mempath: str) -> dict:
        """
        [Vol3 #146] 提取域缓存凭据
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            域缓存哈希 (DCC2)
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.cachedump", output_format="quick")
        except Exception as e:
            return {"success": False, "error": str(e)}
