"""
MemProcFS 时间线工具 (2个 - 合并简化)
34. mem_timeline_all - 综合时间线
35. mem_timeline_process - 进程时间线
"""

from core.loader import get_vmm
import csv
import io


def register_mem_timeline_tools(mcp):
    """注册 MemProcFS 时间线工具"""
    
    @mcp.tool()
    def mem_timeline_all(mempath: str, limit: int = 1000) -> dict:
        """
        [MemProcFS #34] 获取综合时间线
        
        Args:
            mempath: 内存镜像文件路径
            limit: 返回条目数量限制
        
        Returns:
            综合时间线 (进程、网络、文件、注册表等)
        """
        try:
            vmm = get_vmm(mempath)
            timeline = []
            
            # 尝试读取综合时间线
            try:
                timeline_data = vmm.vfs.read("/forensic/csv/timeline_all.csv")
                if timeline_data:
                    csv_reader = csv.DictReader(io.StringIO(timeline_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        timeline.append(row)
                        if len(timeline) >= limit:
                            break
            except:
                pass
            
            # 如果没有综合时间线，合并各个时间线
            if not timeline:
                timelines = [
                    "/forensic/csv/timeline_process.csv",
                    "/forensic/csv/timeline_net.csv",
                    "/forensic/csv/timeline_registry.csv",
                    "/forensic/csv/timeline_ntfs.csv",
                    "/forensic/csv/timeline_web.csv",
                    "/forensic/csv/timeline_tasks.csv",
                    "/forensic/csv/timeline_prefetch.csv"
                ]
                
                for tl_path in timelines:
                    try:
                        tl_data = vmm.vfs.read(tl_path)
                        if tl_data:
                            csv_reader = csv.DictReader(io.StringIO(tl_data.decode('utf-8', errors='replace')))
                            for row in csv_reader:
                                row['_source'] = tl_path.split('/')[-1].replace('.csv', '')
                                timeline.append(row)
                    except:
                        continue
                
                # 按时间排序
                try:
                    timeline.sort(key=lambda x: x.get('Time', x.get('time', '')), reverse=True)
                except:
                    pass
                
                timeline = timeline[:limit]
            
            return {
                "success": True,
                "count": len(timeline),
                "limit": limit,
                "data": timeline
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_timeline_process(mempath: str) -> dict:
        """
        [MemProcFS #35] 获取进程创建时间线
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程创建/退出时间线
        """
        try:
            vmm = get_vmm(mempath)
            timeline = []
            
            # 读取进程时间线
            try:
                timeline_data = vmm.vfs.read("/forensic/csv/timeline_process.csv")
                if timeline_data:
                    csv_reader = csv.DictReader(io.StringIO(timeline_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        timeline.append(row)
            except:
                pass
            
            # 备用方法：从进程列表构建
            if not timeline:
                for proc in vmm.process_list():
                    try:
                        create_time = getattr(proc, 'time_create', None)
                        if create_time:
                            timeline.append({
                                "Time": str(create_time),
                                "Type": "ProcessCreate",
                                "PID": proc.pid,
                                "Name": proc.name,
                                "PPID": proc.ppid
                            })
                    except:
                        continue
                
                # 按时间排序
                try:
                    timeline.sort(key=lambda x: x.get('Time', ''), reverse=True)
                except:
                    pass
            
            return {
                "success": True,
                "count": len(timeline),
                "data": timeline
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
