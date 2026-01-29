"""
文件系统模块 - 文件扫描、文件提取等
"""

from typing import Optional
import os
from core.loader import get_vmm


def register_filesystem_tools(mcp):
    """注册文件系统相关工具"""
    
    @mcp.tool()
    def filescan(mempath: str, pattern: Optional[str] = None, limit: int = 100) -> dict:
        """
        扫描内存中的文件对象
        
        Args:
            mempath: 内存镜像文件路径
            pattern: 文件名过滤模式（支持部分匹配）
            limit: 最大返回数量
        
        Returns:
            文件对象列表
        """
        try:
            vmm = get_vmm(mempath)
            
            files = []
            
            # 读取文件扫描结果
            try:
                file_data = vmm.vfs.read('/forensic/files/files.txt')
                if file_data:
                    lines = file_data.decode('utf-8', errors='ignore').split('\n')
                    count = 0
                    for line in lines[1:]:  # 跳过标题行
                        if line.strip() and count < limit:
                            # 解析文件信息
                            # 格式通常是：偏移 大小 文件名
                            parts = line.split(None, 2)  # 最多分割成3部分
                            if len(parts) >= 3:
                                filename = parts[2]
                                
                                # 模式匹配
                                if pattern:
                                    if pattern.lower() not in filename.lower():
                                        continue
                                
                                files.append({
                                    "offset": parts[0],
                                    "size": parts[1],
                                    "filename": filename
                                })
                                count += 1
            except Exception as e:
                # 备选：通过进程句柄获取文件
                seen_files = set()
                for proc in vmm.process_list():
                    try:
                        maps = proc.maps
                        for h in maps.handle():
                            if h.type == "File":
                                filename = h.name if hasattr(h, 'name') else ""
                                if filename and filename not in seen_files:
                                    if pattern is None or pattern.lower() in filename.lower():
                                        files.append({
                                            "pid": proc.pid,
                                            "process": proc.name,
                                            "handle": hex(h.handle),
                                            "filename": filename
                                        })
                                        seen_files.add(filename)
                                        if len(files) >= limit:
                                            break
                    except:
                        continue
                    if len(files) >= limit:
                        break
            
            return {
                "success": True,
                "tool": "filescan",
                "summary": f"发现 {len(files)} 个文件对象" + (f" (匹配: {pattern})" if pattern else ""),
                "data": files
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "filescan",
                "error": str(e)
            }
    
    @mcp.tool()
    def dumpfiles(mempath: str, pid: int, output_dir: str, filename_pattern: Optional[str] = None) -> dict:
        """
        从内存中提取进程相关的文件
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
            output_dir: 输出目录
            filename_pattern: 文件名过滤模式
        
        Returns:
            提取结果
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)
            
            extracted = []
            failed = []
            
            # 遍历进程的内存映射文件
            try:
                maps = proc.maps
                for vad in maps.vad():
                    try:
                        # 检查是否是映射文件
                        if hasattr(vad, 'info') and vad.info:
                            filename = vad.info
                            
                            # 模式匹配
                            if filename_pattern:
                                if filename_pattern.lower() not in filename.lower():
                                    continue
                            
                            # 生成输出文件名
                            safe_name = os.path.basename(filename).replace('\\', '_').replace('/', '_')
                            output_path = os.path.join(output_dir, f"{pid}_{safe_name}")
                            
                            # 尝试读取内存并保存
                            try:
                                size = vad.end - vad.start
                                if size > 0 and size < 100 * 1024 * 1024:  # 限制 100MB
                                    data = proc.memory.read(vad.start, min(size, 1024 * 1024))  # 最多读取 1MB
                                    with open(output_path, 'wb') as f:
                                        f.write(data)
                                    extracted.append({
                                        "source": filename,
                                        "output": output_path,
                                        "size": len(data)
                                    })
                            except:
                                failed.append(filename)
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "dumpfiles",
                    "error": f"无法访问进程内存: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "dumpfiles",
                "summary": f"成功提取 {len(extracted)} 个文件，失败 {len(failed)} 个",
                "extracted": extracted,
                "failed": failed
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "dumpfiles",
                "error": str(e)
            }
