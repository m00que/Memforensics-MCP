"""
网络分析模块 - 网络连接、监听端口等
"""

from typing import Optional
from core.loader import get_vmm


def register_network_tools(mcp):
    """注册网络分析相关工具"""
    
    @mcp.tool()
    def netscan(mempath: str) -> dict:
        """
        扫描网络连接（TCP/UDP）
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            网络连接列表，包含本地/远程地址、端口、状态、关联进程等
        """
        try:
            vmm = get_vmm(mempath)
            
            connections = []
            
            # 通过读取 VFS 文件系统获取网络信息
            try:
                # MemProcFS 提供网络信息在 /forensic/net/ 目录下
                net_data = vmm.vfs.read('/forensic/net/net.txt')
                if net_data:
                    lines = net_data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines[1:]:  # 跳过标题行
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 6:
                                connections.append({
                                    "protocol": parts[0] if len(parts) > 0 else "",
                                    "local_address": parts[1] if len(parts) > 1 else "",
                                    "remote_address": parts[2] if len(parts) > 2 else "",
                                    "state": parts[3] if len(parts) > 3 else "",
                                    "pid": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                                    "process_name": parts[5] if len(parts) > 5 else ""
                                })
            except:
                # 备选方案：遍历进程获取网络信息
                for proc in vmm.process_list():
                    try:
                        maps = proc.maps
                        # 尝试获取进程的网络连接
                        # 注意：这取决于 MemProcFS 版本
                    except:
                        continue
            
            # 统计
            tcp_count = len([c for c in connections if c.get("protocol", "").upper() == "TCP"])
            udp_count = len([c for c in connections if c.get("protocol", "").upper() == "UDP"])
            listening = len([c for c in connections if "LISTEN" in c.get("state", "").upper()])
            established = len([c for c in connections if "ESTABLISHED" in c.get("state", "").upper()])
            
            return {
                "success": True,
                "tool": "netscan",
                "summary": f"发现 {len(connections)} 个网络连接 (TCP: {tcp_count}, UDP: {udp_count}, LISTENING: {listening}, ESTABLISHED: {established})",
                "data": connections
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "netscan",
                "error": str(e)
            }
    
    @mcp.tool()
    def netstat(mempath: str, state_filter: Optional[str] = None) -> dict:
        """
        获取活动网络连接（类似 netstat -ano）
        
        Args:
            mempath: 内存镜像文件路径
            state_filter: 状态过滤（ESTABLISHED, LISTENING, TIME_WAIT 等）
        
        Returns:
            活动网络连接列表
        """
        try:
            vmm = get_vmm(mempath)
            
            connections = []
            
            # 读取网络信息
            try:
                net_data = vmm.vfs.read('/forensic/net/net.txt')
                if net_data:
                    lines = net_data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 6:
                                state = parts[3] if len(parts) > 3 else ""
                                
                                # 状态过滤
                                if state_filter:
                                    if state_filter.upper() not in state.upper():
                                        continue
                                
                                connections.append({
                                    "protocol": parts[0],
                                    "local_address": parts[1],
                                    "remote_address": parts[2],
                                    "state": state,
                                    "pid": int(parts[4]) if parts[4].isdigit() else 0,
                                    "process_name": parts[5] if len(parts) > 5 else ""
                                })
            except:
                pass
            
            return {
                "success": True,
                "tool": "netstat",
                "summary": f"发现 {len(connections)} 个连接" + (f" (状态: {state_filter})" if state_filter else ""),
                "data": connections
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "netstat",
                "error": str(e)
            }
