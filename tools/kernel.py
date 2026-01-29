"""
内核分析模块 - 驱动、SSDT、内核模块等
"""

from typing import Optional
from core.loader import get_vmm


def register_kernel_tools(mcp):
    """注册内核分析相关工具"""
    
    @mcp.tool()
    def drivers(mempath: str) -> dict:
        """
        获取驱动程序列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            驱动程序列表
        """
        try:
            vmm = get_vmm(mempath)
            
            driver_list = []
            
            # 获取系统进程的模块（内核驱动）
            try:
                system_proc = vmm.process('System')
                for module in system_proc.module_list():
                    try:
                        driver_list.append({
                            "name": module.name,
                            "fullname": module.fullname if hasattr(module, 'fullname') else "",
                            "base": hex(module.base),
                            "size": module.size,
                            "entry": hex(module.entry) if module.entry else None,
                            "suspicious": is_suspicious_driver(module.name, module.fullname if hasattr(module, 'fullname') else "")
                        })
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "drivers",
                    "error": f"无法获取驱动列表: {str(e)}"
                }
            
            suspicious_count = len([d for d in driver_list if d.get("suspicious")])
            
            return {
                "success": True,
                "tool": "drivers",
                "summary": f"发现 {len(driver_list)} 个驱动，{suspicious_count} 个可疑",
                "data": driver_list
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "drivers",
                "error": str(e)
            }
    
    @mcp.tool()
    def modules(mempath: str) -> dict:
        """
        获取内核模块列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            内核模块列表
        """
        try:
            vmm = get_vmm(mempath)
            
            module_list = []
            
            try:
                # 读取内核模块信息
                modules_data = vmm.vfs.read('/sys/modules/modules.txt')
                if modules_data:
                    lines = modules_data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines[1:]:  # 跳过标题
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                module_list.append({
                                    "base": parts[0],
                                    "size": parts[1],
                                    "name": parts[2] if len(parts) > 2 else ""
                                })
            except:
                # 备选方案
                try:
                    system_proc = vmm.process('System')
                    for module in system_proc.module_list():
                        module_list.append({
                            "name": module.name,
                            "base": hex(module.base),
                            "size": module.size
                        })
                except:
                    pass
            
            return {
                "success": True,
                "tool": "modules",
                "summary": f"发现 {len(module_list)} 个内核模块",
                "data": module_list
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "modules",
                "error": str(e)
            }
    
    @mcp.tool()
    def ssdt(mempath: str) -> dict:
        """
        检查系统服务描述符表（SSDT）
        
        SSDT Hook 是 rootkit 常用的隐藏技术。
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            SSDT 分析结果
        """
        try:
            vmm = get_vmm(mempath)
            
            ssdt_info = {
                "hooked_entries": [],
                "total_entries": 0,
                "analysis": ""
            }
            
            try:
                # 尝试读取 SSDT 信息
                ssdt_data = vmm.vfs.read('/sys/ssdt/ssdt.txt')
                if ssdt_data:
                    lines = ssdt_data.decode('utf-8', errors='ignore').split('\n')
                    entries = []
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                entry = {
                                    "index": parts[0],
                                    "address": parts[1],
                                    "name": parts[2] if len(parts) > 2 else ""
                                }
                                entries.append(entry)
                                
                                # 检查是否被 Hook
                                # 正常情况下 SSDT 条目应该指向 ntoskrnl.exe
                                if len(parts) > 3:
                                    module = parts[3]
                                    if "ntoskrnl" not in module.lower() and "win32k" not in module.lower():
                                        entry["hooked"] = True
                                        entry["hook_module"] = module
                                        ssdt_info["hooked_entries"].append(entry)
                    
                    ssdt_info["total_entries"] = len(entries)
            except:
                ssdt_info["analysis"] = "无法读取 SSDT 信息（可能需要符号支持）"
            
            hooked_count = len(ssdt_info["hooked_entries"])
            
            return {
                "success": True,
                "tool": "ssdt",
                "summary": f"SSDT 共 {ssdt_info['total_entries']} 个条目，{hooked_count} 个被 Hook",
                "alerts": [
                    {"level": "high", "message": f"发现 {hooked_count} 个 SSDT Hook"}
                ] if hooked_count > 0 else [],
                "data": ssdt_info
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "ssdt",
                "error": str(e)
            }
    
    @mcp.tool()
    def callbacks(mempath: str) -> dict:
        """
        获取内核回调函数列表
        
        恶意驱动常注册回调函数来拦截系统事件。
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            内核回调列表
        """
        try:
            vmm = get_vmm(mempath)
            
            callbacks_list = []
            
            try:
                # 尝试读取回调信息
                callback_data = vmm.vfs.read('/sys/callbacks/callbacks.txt')
                if callback_data:
                    lines = callback_data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split(None, 3)
                            if len(parts) >= 2:
                                callbacks_list.append({
                                    "type": parts[0],
                                    "address": parts[1],
                                    "module": parts[2] if len(parts) > 2 else "",
                                    "function": parts[3] if len(parts) > 3 else ""
                                })
            except:
                pass
            
            # 检查可疑回调
            suspicious = []
            for cb in callbacks_list:
                module = cb.get("module", "").lower()
                # 非标准模块的回调
                if module and "ntoskrnl" not in module and "win32k" not in module:
                    # 不在常见驱动列表中
                    common_drivers = ["ndis", "tcpip", "disk", "fltmgr", "volmgr", "acpi", "pci"]
                    if not any(cd in module for cd in common_drivers):
                        suspicious.append(cb)
            
            return {
                "success": True,
                "tool": "callbacks",
                "summary": f"发现 {len(callbacks_list)} 个回调，{len(suspicious)} 个来自非标准模块",
                "data": callbacks_list,
                "suspicious": suspicious
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "callbacks",
                "error": str(e)
            }


def is_suspicious_driver(name: str, path: str) -> bool:
    """检查驱动是否可疑"""
    name_lower = name.lower()
    path_lower = path.lower()
    
    # 可疑路径
    if "temp" in path_lower or "tmp" in path_lower:
        return True
    
    # 随机名称（可能是恶意驱动）
    import re
    if re.match(r'^[a-f0-9]{8,}\.sys$', name_lower):
        return True
    
    return False
