"""
Volatility 3 其他分析工具 (14个)
162-175
"""

from typing import Optional
from core.vol3_runner import Vol3Runner


def register_vol3_misc_tools(mcp):
    """注册 Volatility 3 其他分析工具"""
    
    # ========== 服务分析 (3个) ==========
    
    @mcp.tool()
    def vol3_getservicesids(mempath: str) -> dict:
        """
        [Vol3 #162] 获取服务 SID
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            服务 SID 列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.getservicesids")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_svclist(mempath: str) -> dict:
        """
        [Vol3 #163] 获取服务列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统服务列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.svclist")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_svcdiff(mempath: str) -> dict:
        """
        [Vol3 #164] 服务差异对比
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            服务差异
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.svcdiff")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== 内存池 (2个) ==========
    
    @mcp.tool()
    def vol3_bigpools(mempath: str) -> dict:
        """
        [Vol3 #165] 获取大内存池
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            大内存池分配
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.bigpools")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_poolscanner(mempath: str) -> dict:
        """
        [Vol3 #166] 池扫描器
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            池扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.poolscanner")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== 其他分析 (6个) ==========
    
    @mcp.tool()
    def vol3_strings(mempath: str, pid: Optional[int] = None, 
                     strings_file: Optional[str] = None) -> dict:
        """
        [Vol3 #167] 字符串搜索
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选)
            strings_file: 预生成的字符串文件
        
        Returns:
            字符串搜索结果
        """
        try:
            runner = Vol3Runner(mempath)
            extra_args = []
            if pid:
                extra_args.extend(["--pid", str(pid)])
            if strings_file:
                extra_args.extend(["--strings-file", strings_file])
            
            return runner.run_plugin("windows.strings", 
                                    extra_args=extra_args if extra_args else None)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_symlinkscan(mempath: str) -> dict:
        """
        [Vol3 #168] 符号链接扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            符号链接列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.symlinkscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_mutantscan(mempath: str) -> dict:
        """
        [Vol3 #169] 互斥对象扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            互斥对象列表
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.mutantscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_mbrscan(mempath: str) -> dict:
        """
        [Vol3 #170] MBR 扫描
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            MBR 扫描结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.mbrscan")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_shimcachemem(mempath: str) -> dict:
        """
        [Vol3 #171] Shimcache 内存分析
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            Shimcache 记录
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.shimcachemem")
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_iat(mempath: str, pid: int) -> dict:
        """
        [Vol3 #172] 导入地址表 (IAT)
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            IAT 信息
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_plugin("windows.iat", extra_args=["--pid", str(pid)])
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ========== 数据导出 (3个) ==========
    
    @mcp.tool()
    def vol3_procdump(mempath: str, pid: int) -> dict:
        """
        [Vol3 #173] 导出进程可执行文件
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            导出结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_dump_plugin("windows.pslist", 
                                         extra_args=["--pid", str(pid), "--dump"])
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_memmap(mempath: str, pid: int) -> dict:
        """
        [Vol3 #174] 导出进程内存映射
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            导出结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_dump_plugin("windows.memmap", 
                                         extra_args=["--pid", str(pid), "--dump"])
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def vol3_pedump(mempath: str, base: str) -> dict:
        """
        [Vol3 #175] PE 文件导出
        
        Args:
            mempath: 内存镜像文件路径
            base: PE 基地址
        
        Returns:
            导出结果
        """
        try:
            runner = Vol3Runner(mempath)
            return runner.run_dump_plugin("windows.pedump", 
                                         extra_args=["--base", base])
        except Exception as e:
            return {"success": False, "error": str(e)}
