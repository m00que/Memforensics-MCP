"""
MemProcFS 网络分析工具 (2个)
14. mem_netstat - 网络连接状态
15. mem_netstat_timeline - 网络活动时间线
"""

from core.loader import get_vmm
import csv
import io


def register_mem_network_tools(mcp):
    """注册 MemProcFS 网络分析工具"""
    
    @mcp.tool()
    def mem_netstat(mempath: str) -> dict:
        """
        [MemProcFS #14] 获取网络连接状态
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络连接列表 (协议、本地地址、远程地址、状态、进程)
        """
        try:
            vmm = get_vmm(mempath)
            connections = []
            
            # 尝试读取 net.csv
            try:
                net_data = vmm.vfs.read("/forensic/csv/net.csv")
                if net_data:
                    csv_reader = csv.DictReader(io.StringIO(net_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        connections.append(row)
            except:
                pass
            
            # 备用方法：直接从 VMM 获取
            if not connections:
                try:
                    for proc in vmm.process_list():
                        try:
                            for net in proc.maps.net():
                                connections.append({
                                    "pid": proc.pid,
                                    "process_name": proc.name,
                                    "protocol": net.protocol if hasattr(net, 'protocol') else '',
                                    "local_address": f"{net.src_addr}:{net.src_port}" if hasattr(net, 'src_addr') else '',
                                    "remote_address": f"{net.dst_addr}:{net.dst_port}" if hasattr(net, 'dst_addr') else '',
                                    "state": net.state if hasattr(net, 'state') else ''
                                })
                        except:
                            continue
                except:
                    pass
            
            return {
                "success": True,
                "count": len(connections),
                "data": connections
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_netstat_timeline(mempath: str) -> dict:
        """
        [MemProcFS #15] 获取网络活动时间线
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络活动时间线
        """
        try:
            vmm = get_vmm(mempath)
            timeline = []
            
            # 读取网络时间线 CSV
            try:
                timeline_data = vmm.vfs.read("/forensic/csv/timeline_net.csv")
                if timeline_data:
                    csv_reader = csv.DictReader(io.StringIO(timeline_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        timeline.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(timeline),
                "data": timeline
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
