"""
注册表模块 - 注册表分析
"""

from typing import Optional, List
from core.loader import get_vmm


def register_registry_tools(mcp):
    """注册注册表相关工具"""
    
    @mcp.tool()
    def hivelist(mempath: str) -> dict:
        """
        获取注册表 Hive 列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            注册表 Hive 列表
        """
        try:
            vmm = get_vmm(mempath)
            
            hives = []
            try:
                for hive in vmm.reg_hive_list():
                    try:
                        hives.append({
                            "name": hive.name,
                            "name_short": hive.name_short if hasattr(hive, 'name_short') else "",
                            "path": hive.path if hasattr(hive, 'path') else "",
                            "size": hive.size if hasattr(hive, 'size') else 0,
                            "address": hex(hive.addr) if hasattr(hive, 'addr') else ""
                        })
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "hivelist",
                    "error": f"无法获取 Hive 列表: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "hivelist",
                "summary": f"发现 {len(hives)} 个注册表 Hive",
                "data": hives
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "hivelist",
                "error": str(e)
            }
    
    @mcp.tool()
    def printkey(mempath: str, key_path: str) -> dict:
        """
        打印注册表键值
        
        Args:
            mempath: 内存镜像文件路径
            key_path: 注册表键路径（如 HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run）
        
        Returns:
            注册表键的子键和值
        """
        try:
            vmm = get_vmm(mempath)
            
            try:
                key = vmm.reg_key(key_path)
            except Exception as e:
                return {
                    "success": False,
                    "tool": "printkey",
                    "error": f"无法找到注册表键: {key_path}"
                }
            
            # 获取子键
            subkeys = []
            try:
                for subkey in key.subkeys():
                    try:
                        subkeys.append({
                            "name": subkey.name,
                            "last_write_time": subkey.time_str if hasattr(subkey, 'time_str') else ""
                        })
                    except:
                        continue
            except:
                pass
            
            # 获取值
            values = []
            try:
                for value in key.values():
                    try:
                        # 解析值数据
                        raw_value = value.value
                        value_str = ""
                        
                        # 尝试解码
                        try:
                            if isinstance(raw_value, bytes):
                                # 尝试 UTF-16 解码
                                value_str = raw_value.decode('utf-16-le', errors='ignore').rstrip('\x00')
                                if not value_str.isprintable():
                                    # 尝试 UTF-8
                                    value_str = raw_value.decode('utf-8', errors='ignore').rstrip('\x00')
                                if not value_str.isprintable():
                                    # 显示十六进制
                                    value_str = raw_value.hex()[:100] + "..." if len(raw_value) > 50 else raw_value.hex()
                            else:
                                value_str = str(raw_value)
                        except:
                            value_str = str(raw_value)[:200]
                        
                        values.append({
                            "name": value.name,
                            "type": value.type if hasattr(value, 'type') else "",
                            "size": value.size if hasattr(value, 'size') else len(raw_value) if isinstance(raw_value, bytes) else 0,
                            "value": value_str
                        })
                    except:
                        continue
            except:
                pass
            
            return {
                "success": True,
                "tool": "printkey",
                "key_path": key_path,
                "last_write_time": key.time_str if hasattr(key, 'time_str') else "",
                "subkeys": subkeys,
                "values": values
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "printkey",
                "error": str(e)
            }
    
    @mcp.tool()
    def autoruns(mempath: str) -> dict:
        """
        分析自启动项（注册表 Run 键等）
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            自启动项列表
        """
        try:
            vmm = get_vmm(mempath)
            
            autoruns = []
            
            # 常见自启动位置
            run_keys = [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]
            
            for key_path in run_keys:
                try:
                    key = vmm.reg_key(key_path)
                    for value in key.values():
                        try:
                            raw_value = value.value
                            if isinstance(raw_value, bytes):
                                value_str = raw_value.decode('utf-16-le', errors='ignore').rstrip('\x00')
                            else:
                                value_str = str(raw_value)
                            
                            autoruns.append({
                                "location": key_path,
                                "name": value.name,
                                "command": value_str,
                                "suspicious": is_suspicious_autorun(value.name, value_str)
                            })
                        except:
                            continue
                except:
                    continue
            
            suspicious_count = len([a for a in autoruns if a.get("suspicious")])
            
            return {
                "success": True,
                "tool": "autoruns",
                "summary": f"发现 {len(autoruns)} 个自启动项，{suspicious_count} 个可疑",
                "data": autoruns
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "autoruns",
                "error": str(e)
            }
    
    @mcp.tool()
    def services(mempath: str) -> dict:
        """
        获取系统服务列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            服务列表
        """
        try:
            vmm = get_vmm(mempath)
            
            services = []
            
            try:
                # 服务注册表路径
                services_key = vmm.reg_key("HKLM\\SYSTEM\\CurrentControlSet\\Services")
                
                for subkey in services_key.subkeys():
                    try:
                        service_info = {
                            "name": subkey.name,
                            "display_name": "",
                            "image_path": "",
                            "start_type": "",
                            "service_type": "",
                            "suspicious": False
                        }
                        
                        # 读取服务属性
                        for value in subkey.values():
                            try:
                                if value.name == "DisplayName":
                                    raw = value.value
                                    if isinstance(raw, bytes):
                                        service_info["display_name"] = raw.decode('utf-16-le', errors='ignore').rstrip('\x00')
                                elif value.name == "ImagePath":
                                    raw = value.value
                                    if isinstance(raw, bytes):
                                        service_info["image_path"] = raw.decode('utf-16-le', errors='ignore').rstrip('\x00')
                                elif value.name == "Start":
                                    raw = value.value
                                    if isinstance(raw, bytes) and len(raw) >= 4:
                                        start_type = int.from_bytes(raw[:4], 'little')
                                        start_types = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
                                        service_info["start_type"] = start_types.get(start_type, str(start_type))
                                elif value.name == "Type":
                                    raw = value.value
                                    if isinstance(raw, bytes) and len(raw) >= 4:
                                        svc_type = int.from_bytes(raw[:4], 'little')
                                        service_info["service_type"] = str(svc_type)
                            except:
                                continue
                        
                        # 检查可疑服务
                        service_info["suspicious"] = is_suspicious_service(service_info)
                        services.append(service_info)
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "services",
                    "error": f"无法读取服务注册表: {str(e)}"
                }
            
            suspicious_count = len([s for s in services if s.get("suspicious")])
            
            return {
                "success": True,
                "tool": "services",
                "summary": f"发现 {len(services)} 个服务，{suspicious_count} 个可疑",
                "data": services
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "services",
                "error": str(e)
            }


def is_suspicious_autorun(name: str, command: str) -> bool:
    """检查自启动项是否可疑"""
    suspicious_patterns = [
        "temp", "tmp", "appdata\\local\\temp",
        "powershell", "cmd.exe /c", "wscript", "cscript",
        "rundll32", "regsvr32", "mshta",
        ".vbs", ".js", ".bat", ".ps1",
        "http://", "https://",
        "base64", "-enc", "-encodedcommand"
    ]
    
    combined = (name + command).lower()
    return any(pattern in combined for pattern in suspicious_patterns)


def is_suspicious_service(service: dict) -> bool:
    """检查服务是否可疑"""
    image_path = service.get("image_path", "").lower()
    
    suspicious_patterns = [
        "temp", "tmp", "appdata\\local\\temp",
        "users\\public", "programdata\\",
        ".tmp", ".dat",
    ]
    
    # 路径可疑
    if any(pattern in image_path for pattern in suspicious_patterns):
        return True
    
    # 没有路径（可能是 rootkit）
    if service.get("start_type") in ["Automatic", "Boot", "System"] and not image_path:
        return True
    
    return False
