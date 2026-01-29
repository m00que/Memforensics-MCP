"""
系统概览模块 - 内存镜像基本信息
"""

from typing import Optional
import os
from datetime import datetime
from core.loader import get_vmm, format_bytes, get_memory_model


def register_system_tools(mcp):
    """注册系统概览相关工具"""
    
    @mcp.tool()
    def memory_info(mempath: str) -> dict:
        """
        获取内存镜像基本信息
        
        Args:
            mempath: 内存镜像文件路径（支持 raw, vmem, dmp 等格式）
        
        Returns:
            包含镜像信息的字典，包括：
            - file: 文件信息（名称、路径、大小）
            - system: 系统信息（OS版本、架构）
            - processes: 进程统计
        """
        try:
            vmm = get_vmm(mempath)
            
            # 文件信息
            file_size = os.path.getsize(mempath)
            
            # 进程统计
            process_list = vmm.process_list()
            
            # 获取系统进程
            try:
                system_proc = vmm.process('System')
                kernel_build = vmm.kernel.build if hasattr(vmm.kernel, 'build') else "Unknown"
            except:
                kernel_build = "Unknown"
            
            return {
                "success": True,
                "tool": "memory_info",
                "data": {
                    "file": {
                        "name": os.path.basename(mempath),
                        "path": os.path.abspath(mempath),
                        "size_bytes": file_size,
                        "size_human": format_bytes(file_size)
                    },
                    "system": {
                        "kernel_build": kernel_build,
                        "memory_model": get_memory_model(vmm),
                        "architecture": "x64" if get_memory_model(vmm) == "x64" else "x86"
                    },
                    "statistics": {
                        "total_processes": len(process_list),
                        "user_processes": len([p for p in process_list if p.is_usermode]),
                        "kernel_processes": len([p for p in process_list if not p.is_usermode])
                    }
                }
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "memory_info",
                "error": str(e)
            }
    
    @mcp.tool()
    def system_info(mempath: str) -> dict:
        """
        获取系统详细信息（计算机名、域、版本等）
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            包含系统详细信息的字典
        """
        try:
            vmm = get_vmm(mempath)
            
            # 尝试从注册表获取系统信息
            system_data = {
                "computer_name": "Unknown",
                "domain": "Unknown",
                "os_version": "Unknown",
                "product_name": "Unknown",
                "install_date": "Unknown"
            }
            
            # 尝试读取计算机名
            try:
                key = vmm.reg_key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName")
                values = key.values()
                for v in values:
                    if v.name == "ComputerName":
                        system_data["computer_name"] = v.value.decode('utf-16-le').rstrip('\x00')
            except:
                pass
            
            # 尝试读取 OS 版本信息
            try:
                key = vmm.reg_key("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                values = key.values()
                for v in values:
                    try:
                        if v.name == "ProductName":
                            system_data["product_name"] = v.value.decode('utf-16-le').rstrip('\x00')
                        elif v.name == "CurrentBuild":
                            system_data["os_version"] = v.value.decode('utf-16-le').rstrip('\x00')
                    except:
                        pass
            except:
                pass
            
            return {
                "success": True,
                "tool": "system_info",
                "data": system_data
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "system_info",
                "error": str(e)
            }
