"""
时间线模块 - 事件时间线分析
"""

from typing import Optional, List
from datetime import datetime
from core.loader import get_vmm


def register_timeline_tools(mcp):
    """注册时间线相关工具"""
    
    @mcp.tool()
    def timeline(mempath: str, timeline_type: str = "all", limit: int = 100) -> dict:
        """
        获取综合时间线
        
        Args:
            mempath: 内存镜像文件路径
            timeline_type: 时间线类型（all, process, network, registry, file）
            limit: 最大返回条目数
        
        Returns:
            时间线事件列表
        """
        try:
            vmm = get_vmm(mempath)
            
            events = []
            
            # 根据类型读取不同的时间线
            timeline_files = {
                "all": ['/forensic/timeline/timeline.txt'],
                "process": ['/forensic/timeline/timeline_process.txt'],
                "network": ['/forensic/timeline/timeline_net.txt'],
                "registry": ['/forensic/timeline/timeline_registry.txt'],
                "file": ['/forensic/timeline/timeline_ntfs.txt']
            }
            
            if timeline_type == "all":
                files_to_read = timeline_files["process"] + timeline_files["network"]
            else:
                files_to_read = timeline_files.get(timeline_type, timeline_files["all"])
            
            for filepath in files_to_read:
                try:
                    data = vmm.vfs.read(filepath)
                    if data:
                        lines = data.decode('utf-8', errors='ignore').split('\n')
                        for line in lines[1:]:  # 跳过标题
                            if line.strip() and len(events) < limit:
                                parts = line.split('\t') if '\t' in line else line.split(None, 4)
                                if len(parts) >= 3:
                                    events.append({
                                        "timestamp": parts[0] if len(parts) > 0 else "",
                                        "action": parts[1] if len(parts) > 1 else "",
                                        "type": parts[2] if len(parts) > 2 else "",
                                        "details": parts[3] if len(parts) > 3 else "",
                                        "source": filepath.split('/')[-1]
                                    })
                except:
                    continue
            
            # 按时间排序
            events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return {
                "success": True,
                "tool": "timeline",
                "summary": f"获取到 {len(events)} 个时间线事件（类型: {timeline_type}）",
                "data": events[:limit]
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "timeline",
                "error": str(e)
            }
    
    @mcp.tool()
    def process_timeline(mempath: str) -> dict:
        """
        获取进程创建/退出时间线
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程事件时间线
        """
        try:
            vmm = get_vmm(mempath)
            
            events = []
            
            # 尝试从时间线文件读取
            try:
                data = vmm.vfs.read('/forensic/timeline/timeline_process.txt')
                if data:
                    lines = data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                events.append({
                                    "timestamp": parts[0] + " " + parts[1] if len(parts) > 1 else parts[0],
                                    "action": parts[2] if len(parts) > 2 else "",
                                    "pid": parts[3] if len(parts) > 3 else "",
                                    "process_name": parts[4] if len(parts) > 4 else "",
                                    "details": " ".join(parts[5:]) if len(parts) > 5 else ""
                                })
            except:
                # 备选：从进程信息构建
                for proc in vmm.process_list():
                    try:
                        events.append({
                            "pid": proc.pid,
                            "process_name": proc.name,
                            "state": "running" if proc.state == 0 else "terminated",
                            "ppid": proc.ppid
                        })
                    except:
                        continue
            
            return {
                "success": True,
                "tool": "process_timeline",
                "summary": f"获取到 {len(events)} 个进程事件",
                "data": events
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "process_timeline",
                "error": str(e)
            }
