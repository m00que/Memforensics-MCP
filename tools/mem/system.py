"""
MemProcFS 系统信息工具 (5个)
1. mem_info - 内存镜像基本信息
2. mem_sysinfo - 系统详细信息
3. mem_users - 用户账户列表
4. mem_dtb - 页表基址信息
5. mem_certificates - 系统证书列表
"""

from typing import Optional
import os
from core.loader import get_vmm, get_memory_info, format_bytes


def register_mem_system_tools(mcp):
    """注册 MemProcFS 系统信息工具"""
    
    @mcp.tool()
    def mem_info(mempath: str) -> dict:
        """
        [MemProcFS #1] 获取内存镜像基本信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            包含镜像大小、架构、OS版本等信息
        """
        try:
            vmm = get_vmm(mempath)
            file_size = os.path.getsize(mempath)
            
            # 获取系统进程判断架构
            system_proc = vmm.process('System')
            if system_proc.tp_memorymodel == 1:
                arch = "x86"
            elif system_proc.tp_memorymodel == 2:
                arch = "x86 PAE"
            elif system_proc.tp_memorymodel == 3:
                arch = "x64"
            else:
                arch = "Unknown"
            
            # 获取进程数量
            process_count = len(list(vmm.process_list()))
            
            return {
                "success": True,
                "data": {
                    "file_name": os.path.basename(mempath),
                    "file_path": mempath,
                    "file_size_bytes": file_size,
                    "file_size_human": format_bytes(file_size),
                    "architecture": arch,
                    "kernel_build": getattr(vmm.kernel, 'build', 'Unknown'),
                    "process_count": process_count
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_sysinfo(mempath: str) -> dict:
        """
        [MemProcFS #2] 获取系统详细信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            计算机名、域、OS版本等详细系统信息
        """
        try:
            vmm = get_vmm(mempath)
            
            info = {
                "computer_name": None,
                "domain": None,
                "os_version": None,
                "product_type": None,
                "install_date": None
            }
            
            # 尝试从注册表读取系统信息
            try:
                # 计算机名
                reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"
                info["computer_name"] = vmm.reg_value(reg_path, "ComputerName")
            except:
                pass
            
            try:
                # 产品名称
                reg_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                info["os_version"] = vmm.reg_value(reg_path, "ProductName")
                info["build_number"] = vmm.reg_value(reg_path, "CurrentBuildNumber")
            except:
                pass
            
            # 尝试读取 sysinfo.txt
            try:
                sysinfo_data = vmm.vfs.read("/sys/sysinfo/sysinfo.txt")
                if sysinfo_data:
                    info["raw_sysinfo"] = sysinfo_data.decode('utf-8', errors='replace')
            except:
                pass
            
            return {"success": True, "data": info}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_users(mempath: str) -> dict:
        """
        [MemProcFS #3] 获取用户账户列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统用户账户列表
        """
        try:
            vmm = get_vmm(mempath)
            users = []
            
            # 尝试读取 users.txt
            try:
                users_data = vmm.vfs.read("/sys/users/users.txt")
                if users_data:
                    lines = users_data.decode('utf-8', errors='replace').strip().split('\n')
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                users.append({
                                    "sid": parts[0],
                                    "name": parts[1] if len(parts) > 1 else "",
                                    "raw": line
                                })
            except:
                pass
            
            # 备用方法：从 SAM 读取
            if not users:
                try:
                    sam_users = vmm.vfs.list("/registry/HKLM/SAM/SAM/Domains/Account/Users/Names")
                    for user in sam_users:
                        if user not in ['.', '..']:
                            users.append({"name": user, "source": "SAM"})
                except:
                    pass
            
            return {
                "success": True,
                "count": len(users),
                "data": users
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_dtb(mempath: str) -> dict:
        """
        [MemProcFS #4] 获取页表基址(DTB)信息
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            DTB 信息
        """
        try:
            vmm = get_vmm(mempath)
            dtb_info = []
            
            # 获取每个进程的 DTB
            for proc in vmm.process_list():
                try:
                    dtb_info.append({
                        "pid": proc.pid,
                        "name": proc.name,
                        "dtb": hex(proc.dtb) if hasattr(proc, 'dtb') else "N/A",
                        "dtb_user": hex(proc.dtb_user) if hasattr(proc, 'dtb_user') else "N/A"
                    })
                except:
                    continue
            
            # 也尝试读取 dtb.txt
            try:
                dtb_data = vmm.vfs.read("/misc/procinfo/dtb.txt")
                if dtb_data:
                    raw_dtb = dtb_data.decode('utf-8', errors='replace')
            except:
                raw_dtb = None
            
            return {
                "success": True,
                "count": len(dtb_info),
                "data": dtb_info,
                "raw": raw_dtb
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_certificates(mempath: str) -> dict:
        """
        [MemProcFS #5] 获取系统证书列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统证书信息
        """
        try:
            vmm = get_vmm(mempath)
            certs = []
            
            # 读取证书目录
            try:
                cert_path = "/sys/certificates"
                cert_list = vmm.vfs.list(cert_path)
                
                for cert in cert_list:
                    if cert not in ['.', '..']:
                        cert_info = {"name": cert}
                        
                        # 尝试读取证书详情
                        try:
                            cert_data = vmm.vfs.read(f"{cert_path}/{cert}")
                            if cert_data:
                                cert_info["size"] = len(cert_data)
                        except:
                            pass
                        
                        certs.append(cert_info)
            except:
                pass
            
            # 尝试读取 certificates.txt
            try:
                cert_txt = vmm.vfs.read("/sys/certificates/certificates.txt")
                if cert_txt:
                    raw_certs = cert_txt.decode('utf-8', errors='replace')
                else:
                    raw_certs = None
            except:
                raw_certs = None
            
            return {
                "success": True,
                "count": len(certs),
                "data": certs,
                "raw": raw_certs
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
