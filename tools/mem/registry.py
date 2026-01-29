"""
MemProcFS 注册表分析工具 (6个)
19. mem_hivelist - Hive列表
20. mem_printkey - 读取键值
21. mem_autoruns - 自启动项
22. mem_usb_devices - USB设备历史
23. mem_network_interfaces - 网络接口
24. mem_reg_timeline - 注册表时间线
"""

from typing import Optional
from core.loader import get_vmm
import csv
import io


def register_mem_registry_tools(mcp):
    """注册 MemProcFS 注册表分析工具"""
    
    @mcp.tool()
    def mem_hivelist(mempath: str) -> dict:
        """
        [MemProcFS #19] 获取注册表Hive列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            注册表Hive列表
        """
        try:
            vmm = get_vmm(mempath)
            hives = []
            
            # 列出注册表 hive 文件
            try:
                hive_list = vmm.reg_hive_list()
                for hive in hive_list:
                    hives.append({
                        "name": hive.name,
                        "path": getattr(hive, 'path', ''),
                        "address": hex(hive.va) if hasattr(hive, 'va') else ''
                    })
            except:
                pass
            
            # 备用：列出 hive_files 目录
            if not hives:
                try:
                    hive_files = vmm.vfs.list("/registry/hive_files")
                    for hf in hive_files:
                        if hf not in ['.', '..']:
                            hives.append({"name": hf, "source": "hive_files"})
                except:
                    pass
            
            return {
                "success": True,
                "count": len(hives),
                "data": hives
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_printkey(mempath: str, key_path: str) -> dict:
        """
        [MemProcFS #20] 读取注册表键值
        
        Args:
            mempath: 内存镜像文件路径
            key_path: 注册表路径 (如 "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
        
        Returns:
            键值内容
        """
        try:
            vmm = get_vmm(mempath)
            
            # 转换路径格式
            vfs_path = "/registry/" + key_path.replace("\\", "/")
            
            result = {
                "key_path": key_path,
                "subkeys": [],
                "values": []
            }
            
            # 列出子键
            try:
                items = vmm.vfs.list(vfs_path)
                for item in items:
                    if item not in ['.', '..']:
                        if item.endswith('.txt') or '.' not in item:
                            # 尝试读取值
                            try:
                                value_path = f"{vfs_path}/{item}"
                                value_data = vmm.vfs.read(value_path)
                                if value_data:
                                    result["values"].append({
                                        "name": item.replace('.txt', ''),
                                        "data": value_data.decode('utf-8', errors='replace')[:500]
                                    })
                            except:
                                result["subkeys"].append(item)
                        else:
                            result["subkeys"].append(item)
            except Exception as e:
                result["error"] = str(e)
            
            return {"success": True, "data": result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_autoruns(mempath: str) -> dict:
        """
        [MemProcFS #21] 获取自启动项
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            自启动项列表
        """
        try:
            vmm = get_vmm(mempath)
            autoruns = []
            
            # 检查的自启动路径
            run_paths = [
                "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
                "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce",
                "HKLM/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Run",
            ]
            
            for run_path in run_paths:
                vfs_path = f"/registry/{run_path}"
                try:
                    items = vmm.vfs.list(vfs_path)
                    for item in items:
                        if item not in ['.', '..', '(_Key_).txt']:
                            try:
                                value_data = vmm.vfs.read(f"{vfs_path}/{item}")
                                if value_data:
                                    # 解析值内容
                                    lines = value_data.decode('utf-8', errors='replace').strip().split('\n')
                                    value = lines[2] if len(lines) > 2 else lines[0]
                                    
                                    autoruns.append({
                                        "location": run_path,
                                        "name": item.replace('.txt', ''),
                                        "value": value
                                    })
                            except:
                                continue
                except:
                    continue
            
            # 检查用户自启动
            try:
                users_data = vmm.vfs.read("/sys/users/users.txt")
                if users_data:
                    for line in users_data.decode('utf-8', errors='replace').split('\n'):
                        if line.strip() and line.startswith('0000'):
                            parts = line.split()
                            if len(parts) > 1:
                                username = parts[1]
                                user_run_path = f"/registry/HKU/{username}/SOFTWARE/Microsoft/Windows/CurrentVersion/Run"
                                try:
                                    items = vmm.vfs.list(user_run_path)
                                    for item in items:
                                        if item not in ['.', '..', '(_Key_).txt']:
                                            try:
                                                value_data = vmm.vfs.read(f"{user_run_path}/{item}")
                                                if value_data:
                                                    lines = value_data.decode('utf-8', errors='replace').strip().split('\n')
                                                    value = lines[2] if len(lines) > 2 else lines[0]
                                                    autoruns.append({
                                                        "location": f"HKU\\{username}\\...\\Run",
                                                        "name": item.replace('.txt', ''),
                                                        "value": value,
                                                        "user": username
                                                    })
                                            except:
                                                continue
                                except:
                                    continue
            except:
                pass
            
            return {
                "success": True,
                "count": len(autoruns),
                "data": autoruns
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_usb_devices(mempath: str) -> dict:
        """
        [MemProcFS #22] 获取USB设备历史
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            USB设备连接历史
        """
        try:
            vmm = get_vmm(mempath)
            usb_devices = []
            
            # USBSTOR 路径
            usbstor_path = "/registry/HKLM/SYSTEM/CurrentControlSet/Enum/USBSTOR"
            
            try:
                vendors = vmm.vfs.list(usbstor_path)
                for vendor in vendors:
                    if vendor not in ['.', '..', '(_Key_).txt']:
                        vendor_path = f"{usbstor_path}/{vendor}"
                        try:
                            devices = vmm.vfs.list(vendor_path)
                            for device in devices:
                                if device not in ['.', '..', '(_Key_).txt']:
                                    usb_devices.append({
                                        "vendor_product": vendor,
                                        "serial": device,
                                        "type": "USB Storage"
                                    })
                        except:
                            continue
            except:
                pass
            
            return {
                "success": True,
                "count": len(usb_devices),
                "data": usb_devices
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_network_interfaces(mempath: str) -> dict:
        """
        [MemProcFS #23] 获取网络接口配置
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络接口配置信息
        """
        try:
            vmm = get_vmm(mempath)
            interfaces = []
            
            # TCP/IP 接口路径
            tcpip_path = "/registry/HKLM/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Interfaces"
            
            try:
                iface_list = vmm.vfs.list(tcpip_path)
                for iface in iface_list:
                    if iface not in ['.', '..', '(_Key_).txt']:
                        iface_info = {"guid": iface}
                        
                        # 读取接口配置
                        iface_path = f"{tcpip_path}/{iface}"
                        for config_key in ['IPAddress', 'SubnetMask', 'DefaultGateway', 'NameServer', 'DhcpIPAddress']:
                            try:
                                value_data = vmm.vfs.read(f"{iface_path}/{config_key}.txt")
                                if value_data:
                                    lines = value_data.decode('utf-8', errors='replace').strip().split('\n')
                                    iface_info[config_key] = lines[2] if len(lines) > 2 else lines[0]
                            except:
                                continue
                        
                        interfaces.append(iface_info)
            except:
                pass
            
            return {
                "success": True,
                "count": len(interfaces),
                "data": interfaces
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_reg_timeline(mempath: str) -> dict:
        """
        [MemProcFS #24] 获取注册表修改时间线
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            注册表修改时间线
        """
        try:
            vmm = get_vmm(mempath)
            timeline = []
            
            # 读取注册表时间线
            try:
                timeline_data = vmm.vfs.read("/forensic/csv/timeline_registry.csv")
                if timeline_data:
                    csv_reader = csv.DictReader(io.StringIO(timeline_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        timeline.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(timeline),
                "data": timeline[:1000]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
