"""
MemProcFS 服务与驱动工具 (4个)
25. mem_services - 服务列表
26. mem_drivers - 驱动列表
27. mem_tasks - 计划任务
28. mem_driver_detail - 驱动详情
"""

from core.loader import get_vmm
import csv
import io


def register_mem_services_tools(mcp):
    """注册 MemProcFS 服务与驱动工具"""
    
    @mcp.tool()
    def mem_services(mempath: str) -> dict:
        """
        [MemProcFS #25] 获取系统服务列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            系统服务列表
        """
        try:
            vmm = get_vmm(mempath)
            services = []
            
            # 读取 services.csv
            try:
                services_data = vmm.vfs.read("/forensic/csv/services.csv")
                if services_data:
                    csv_reader = csv.DictReader(io.StringIO(services_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        services.append(row)
            except:
                pass
            
            # 备用方法：从注册表读取
            if not services:
                try:
                    services_path = "/registry/HKLM/SYSTEM/CurrentControlSet/Services"
                    svc_list = vmm.vfs.list(services_path)
                    for svc in svc_list:
                        if svc not in ['.', '..', '(_Key_).txt']:
                            svc_info = {"name": svc}
                            
                            # 读取服务详情
                            for key in ['DisplayName', 'ImagePath', 'Start', 'Type']:
                                try:
                                    value_data = vmm.vfs.read(f"{services_path}/{svc}/{key}.txt")
                                    if value_data:
                                        lines = value_data.decode('utf-8', errors='replace').strip().split('\n')
                                        svc_info[key] = lines[2] if len(lines) > 2 else lines[0]
                                except:
                                    continue
                            
                            services.append(svc_info)
                except:
                    pass
            
            return {
                "success": True,
                "count": len(services),
                "data": services
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_drivers(mempath: str) -> dict:
        """
        [MemProcFS #26] 获取驱动程序列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            驱动程序列表
        """
        try:
            vmm = get_vmm(mempath)
            drivers = []
            
            # 读取 drivers.csv
            try:
                drivers_data = vmm.vfs.read("/forensic/csv/drivers.csv")
                if drivers_data:
                    csv_reader = csv.DictReader(io.StringIO(drivers_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        drivers.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(drivers),
                "data": drivers
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_tasks(mempath: str) -> dict:
        """
        [MemProcFS #27] 获取计划任务
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            计划任务列表
        """
        try:
            vmm = get_vmm(mempath)
            tasks = []
            
            # 读取 tasks.csv
            try:
                tasks_data = vmm.vfs.read("/forensic/csv/tasks.csv")
                if tasks_data:
                    csv_reader = csv.DictReader(io.StringIO(tasks_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        tasks.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(tasks),
                "data": tasks
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_driver_detail(mempath: str, driver_name: str) -> dict:
        """
        [MemProcFS #28] 获取驱动详细信息
        
        Args:
            mempath: 内存镜像文件路径
            driver_name: 驱动名称
        
        Returns:
            驱动详细信息
        """
        try:
            vmm = get_vmm(mempath)
            
            # 从注册表读取驱动信息
            driver_path = f"/registry/HKLM/SYSTEM/CurrentControlSet/Services/{driver_name}"
            
            driver_info = {
                "name": driver_name,
                "properties": {}
            }
            
            # 读取各属性
            properties = ['DisplayName', 'ImagePath', 'Start', 'Type', 'ErrorControl', 'Group', 'Description']
            
            for prop in properties:
                try:
                    value_data = vmm.vfs.read(f"{driver_path}/{prop}.txt")
                    if value_data:
                        lines = value_data.decode('utf-8', errors='replace').strip().split('\n')
                        driver_info["properties"][prop] = lines[2] if len(lines) > 2 else lines[0]
                except:
                    continue
            
            # 检查 Parameters 子键
            try:
                params = vmm.vfs.list(f"{driver_path}/Parameters")
                if params:
                    driver_info["has_parameters"] = True
                    driver_info["parameters"] = [p for p in params if p not in ['.', '..']]
            except:
                driver_info["has_parameters"] = False
            
            return {"success": True, "data": driver_info}
        except Exception as e:
            return {"success": False, "error": str(e)}
