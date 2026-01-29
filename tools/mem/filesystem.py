"""
MemProcFS 文件系统工具 (3个)
16. mem_filescan - 文件对象列表
17. mem_ntfs_timeline - NTFS时间线
18. mem_dumpfile - 提取文件
"""

from typing import Optional
from core.loader import get_vmm
import csv
import io
import os
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent.parent / "output"


def register_mem_filesystem_tools(mcp):
    """注册 MemProcFS 文件系统工具"""
    
    @mcp.tool()
    def mem_filescan(mempath: str, filter_pattern: Optional[str] = None) -> dict:
        """
        [MemProcFS #16] 获取内存中的文件对象列表
        
        Args:
            mempath: 内存镜像文件路径
            filter_pattern: 过滤模式 (如 ".exe", ".dll")
        
        Returns:
            文件对象列表
        """
        try:
            vmm = get_vmm(mempath)
            files = []
            
            # 读取 files.csv
            try:
                files_data = vmm.vfs.read("/forensic/csv/files.csv")
                if files_data:
                    csv_reader = csv.DictReader(io.StringIO(files_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        if filter_pattern:
                            file_name = row.get('Name', row.get('name', ''))
                            if filter_pattern.lower() not in file_name.lower():
                                continue
                        files.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(files),
                "filter": filter_pattern,
                "data": files[:500]  # 限制返回数量
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_ntfs_timeline(mempath: str) -> dict:
        """
        [MemProcFS #17] 获取NTFS文件时间线
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            NTFS文件系统时间线
        """
        try:
            vmm = get_vmm(mempath)
            timeline = []
            
            # 读取 NTFS 时间线
            try:
                timeline_data = vmm.vfs.read("/forensic/csv/timeline_ntfs.csv")
                if timeline_data:
                    csv_reader = csv.DictReader(io.StringIO(timeline_data.decode('utf-8', errors='replace')))
                    for row in csv_reader:
                        timeline.append(row)
            except:
                pass
            
            return {
                "success": True,
                "count": len(timeline),
                "data": timeline[:1000]  # 限制返回数量
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_dumpfile(mempath: str, file_path: str, output_name: Optional[str] = None) -> dict:
        """
        [MemProcFS #18] 从内存中提取文件
        
        Args:
            mempath: 内存镜像文件路径
            file_path: 要提取的文件路径 (如 "C:\\Windows\\System32\\cmd.exe")
            output_name: 输出文件名 (可选)
        
        Returns:
            提取结果
        """
        try:
            vmm = get_vmm(mempath)
            
            OUTPUT_DIR.mkdir(exist_ok=True)
            
            # 尝试从 VFS 读取文件
            # 转换路径格式
            vfs_path = file_path.replace("\\", "/")
            if not vfs_path.startswith("/"):
                # 假设是 Windows 路径，转换为 VFS 格式
                if len(vfs_path) >= 2 and vfs_path[1] == ':':
                    drive = vfs_path[0].upper()
                    vfs_path = f"/fs/{drive}/{vfs_path[3:]}"
            
            try:
                file_data = vmm.vfs.read(vfs_path)
                
                if file_data:
                    if output_name is None:
                        output_name = os.path.basename(file_path)
                    
                    output_path = OUTPUT_DIR / output_name
                    with open(output_path, 'wb') as f:
                        f.write(file_data)
                    
                    return {
                        "success": True,
                        "source_path": file_path,
                        "output_path": str(output_path),
                        "size": len(file_data)
                    }
                else:
                    return {"success": False, "error": "文件为空或不存在"}
            except Exception as e:
                return {"success": False, "error": f"无法读取文件: {str(e)}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
