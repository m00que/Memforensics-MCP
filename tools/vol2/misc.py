"""
Volatility 2 其他分析工具 (12个)
101-103. 加密分析 (BitLocker, TrueCrypt)
104-108. 杂项分析
109-112. 数据导出
"""

from typing import Optional
from core.vol2_runner import Vol2Runner


def register_vol2_misc_tools(mcp):
    """注册 Volatility 2 其他分析工具"""
    
    # ========== 加密分析 (3个) ==========
    
    @mcp.tool()
    def vol2_bitlocker(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #101] ⭐ BitLocker 密钥提取 (Vol2 独有/扩展插件)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            BitLocker 恢复密钥
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("bitlocker", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_truecryptsummary(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #102] ⭐ TrueCrypt 摘要 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            TrueCrypt 信息摘要
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("truecryptsummary", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_truecryptmaster(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #103] ⭐ TrueCrypt 主密钥 (Vol2 独有)
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            TrueCrypt 主密钥
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("truecryptmaster", output_type="text")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== 杂项分析 (5个) ==========
    
    @mcp.tool()
    def vol2_timeliner(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #104] 综合时间线
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            综合时间线
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin_to_file("timeliner", timeout=900)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_mutantscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #105] 互斥对象扫描
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            互斥对象列表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("mutantscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_atomscan(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #106] 原子表扫描
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            原子表
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("atomscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_sessions(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #107] 会话信息
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            登录会话信息
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("sessions")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_bigpools(mempath: str, profile: Optional[str] = None) -> dict:
        """
        [Vol2 #108] 大内存池
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
        
        Returns:
            大内存池分配
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            return runner.run_plugin("bigpools")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== 数据导出 (4个) ==========
    
    @mcp.tool()
    def vol2_procdump(mempath: str, profile: Optional[str] = None, pid: int = None) -> dict:
        """
        [Vol2 #109] 导出进程可执行文件
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_dump_plugin("procdump", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_memdump(mempath: str, profile: Optional[str] = None, pid: int = None) -> dict:
        """
        [Vol2 #110] 导出进程完整内存
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_dump_plugin("memdump", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_dlldump(mempath: str, profile: Optional[str] = None, 
                     pid: Optional[int] = None, base: Optional[str] = None) -> dict:
        """
        [Vol2 #111] 导出 DLL
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID
            base: DLL 基地址 (十六进制)
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = []
            if pid:
                extra_args.extend(["-p", str(pid)])
            if base:
                extra_args.extend(["-b", base])
            
            return runner.run_dump_plugin("dlldump", extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol2_vaddump(mempath: str, profile: Optional[str] = None, pid: int = None) -> dict:
        """
        [Vol2 #112] 导出 VAD 区域
        
        Args:
            mempath: 内存镜像文件路径
            profile: Windows Profile
            pid: 进程ID
        
        Returns:
            导出结果
        """
        try:
            runner = Vol2Runner(mempath, profile)
            if not profile:
                runner.get_profile()
            
            extra_args = ["-p", str(pid)] if pid else None
            return runner.run_dump_plugin("vaddump", extra_args=extra_args)
        except Exception as e:
            return {"success": False, "error": str(e)}
