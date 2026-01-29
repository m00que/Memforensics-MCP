"""
辅助工具模块 - 进程导出、内存搜索等
"""

from typing import Optional
import os
import re
from core.loader import get_vmm


def register_utils_tools(mcp):
    """注册辅助工具"""
    
    @mcp.tool()
    def procdump(mempath: str, pid: int, output_dir: str) -> dict:
        """
        导出进程可执行文件
        
        从内存中重建进程的主模块可执行文件。
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
            output_dir: 输出目录
        
        Returns:
            导出结果
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)
            
            result = {
                "pid": pid,
                "process_name": proc.name,
                "output_files": []
            }
            
            try:
                # 获取主模块
                main_module = None
                for module in proc.module_list():
                    if module.name.lower() == proc.name.lower() or \
                       proc.name.lower().startswith(module.name.lower().replace('.exe', '')):
                        main_module = module
                        break
                
                if main_module is None:
                    return {
                        "success": False,
                        "tool": "procdump",
                        "error": f"无法找到进程 {pid} 的主模块"
                    }
                
                # 读取模块内存
                output_path = os.path.join(output_dir, f"{pid}_{proc.name}")
                
                try:
                    # 读取 PE 头获取大小信息
                    header = proc.memory.read(main_module.base, 0x1000)
                    
                    if header[:2] != b'MZ':
                        return {
                            "success": False,
                            "tool": "procdump",
                            "error": "主模块不是有效的 PE 文件"
                        }
                    
                    # 获取 PE 大小
                    e_lfanew = int.from_bytes(header[0x3C:0x40], 'little')
                    if e_lfanew > 0 and e_lfanew < 0x400:
                        size_of_image = int.from_bytes(header[e_lfanew + 0x50:e_lfanew + 0x54], 'little')
                    else:
                        size_of_image = main_module.size
                    
                    # 限制大小（最大 50MB）
                    size_to_read = min(size_of_image, 50 * 1024 * 1024)
                    
                    # 分块读取
                    pe_data = b''
                    chunk_size = 0x10000  # 64KB
                    offset = 0
                    
                    while offset < size_to_read:
                        try:
                            chunk = proc.memory.read(main_module.base + offset, min(chunk_size, size_to_read - offset))
                            pe_data += chunk
                            offset += len(chunk)
                        except:
                            # 无法读取的区域填充零
                            pe_data += b'\x00' * min(chunk_size, size_to_read - offset)
                            offset += chunk_size
                    
                    # 保存文件
                    with open(output_path, 'wb') as f:
                        f.write(pe_data)
                    
                    result["output_files"].append({
                        "path": output_path,
                        "size": len(pe_data),
                        "base": hex(main_module.base)
                    })
                    
                except Exception as e:
                    return {
                        "success": False,
                        "tool": "procdump",
                        "error": f"读取进程内存失败: {str(e)}"
                    }
            except Exception as e:
                return {
                    "success": False,
                    "tool": "procdump",
                    "error": f"无法访问进程模块: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "procdump",
                "summary": f"成功导出进程 {pid} ({proc.name})",
                "data": result
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "procdump",
                "error": str(e)
            }
    
    @mcp.tool()
    def memdump(mempath: str, pid: int, output_dir: str) -> dict:
        """
        导出进程完整内存
        
        导出进程的所有可读内存区域。
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
            output_dir: 输出目录
        
        Returns:
            导出结果
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            # 确保输出目录存在
            os.makedirs(output_dir, exist_ok=True)
            
            output_path = os.path.join(output_dir, f"{pid}_{proc.name}.dmp")
            
            total_size = 0
            regions = 0
            
            try:
                with open(output_path, 'wb') as f:
                    maps = proc.maps
                    for vad in maps.vad():
                        try:
                            size = vad.end - vad.start
                            if size > 0 and size < 100 * 1024 * 1024:  # 限制单区域 100MB
                                data = proc.memory.read(vad.start, min(size, 10 * 1024 * 1024))  # 最多读取 10MB
                                f.write(data)
                                total_size += len(data)
                                regions += 1
                        except:
                            continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "memdump",
                    "error": f"导出内存失败: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "memdump",
                "summary": f"导出进程 {pid} 内存，共 {regions} 个区域，{total_size} 字节",
                "data": {
                    "pid": pid,
                    "process_name": proc.name,
                    "output_path": output_path,
                    "total_size": total_size,
                    "regions": regions
                }
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "memdump",
                "error": str(e)
            }
    
    @mcp.tool()
    def search_memory(mempath: str, pattern: str, pid: Optional[int] = None, 
                      search_type: str = "string", limit: int = 50) -> dict:
        """
        在内存中搜索模式
        
        Args:
            mempath: 内存镜像文件路径
            pattern: 搜索模式（字符串或十六进制）
            pid: 进程 ID（可选，不指定则搜索所有进程）
            search_type: 搜索类型（string 或 hex）
            limit: 最大结果数
        
        Returns:
            搜索结果
        """
        try:
            vmm = get_vmm(mempath)
            
            results = []
            
            # 准备搜索模式
            if search_type == "hex":
                try:
                    search_bytes = bytes.fromhex(pattern.replace(" ", ""))
                except:
                    return {
                        "success": False,
                        "tool": "search_memory",
                        "error": "无效的十六进制模式"
                    }
            else:
                search_bytes = pattern.encode('utf-8')
                # 同时搜索 UTF-16
                search_bytes_wide = pattern.encode('utf-16-le')
            
            # 获取要搜索的进程
            if pid is not None:
                processes = [vmm.process(pid)]
            else:
                processes = vmm.process_list()
            
            for proc in processes:
                try:
                    if not proc.is_usermode:
                        continue
                    
                    maps = proc.maps
                    for vad in maps.vad():
                        try:
                            if len(results) >= limit:
                                break
                            
                            size = vad.end - vad.start
                            if size > 10 * 1024 * 1024:  # 跳过超大区域
                                continue
                            
                            try:
                                data = proc.memory.read(vad.start, min(size, 1024 * 1024))
                                
                                # 搜索 ASCII
                                offset = 0
                                while True:
                                    pos = data.find(search_bytes, offset)
                                    if pos == -1:
                                        break
                                    
                                    # 提取上下文
                                    context_start = max(0, pos - 16)
                                    context_end = min(len(data), pos + len(search_bytes) + 16)
                                    context = data[context_start:context_end]
                                    
                                    results.append({
                                        "pid": proc.pid,
                                        "process_name": proc.name,
                                        "address": hex(vad.start + pos),
                                        "vad_start": hex(vad.start),
                                        "encoding": "ASCII/UTF-8" if search_type == "string" else "HEX",
                                        "context_hex": context.hex(),
                                        "context_ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
                                    })
                                    
                                    if len(results) >= limit:
                                        break
                                    
                                    offset = pos + 1
                                
                                # 搜索 UTF-16（仅字符串模式）
                                if search_type == "string" and len(results) < limit:
                                    offset = 0
                                    while True:
                                        pos = data.find(search_bytes_wide, offset)
                                        if pos == -1:
                                            break
                                        
                                        results.append({
                                            "pid": proc.pid,
                                            "process_name": proc.name,
                                            "address": hex(vad.start + pos),
                                            "vad_start": hex(vad.start),
                                            "encoding": "UTF-16-LE"
                                        })
                                        
                                        if len(results) >= limit:
                                            break
                                        
                                        offset = pos + 1
                            except:
                                continue
                        except:
                            continue
                    
                    if len(results) >= limit:
                        break
                except:
                    continue
            
            return {
                "success": True,
                "tool": "search_memory",
                "summary": f"找到 {len(results)} 个匹配（模式: {pattern}）",
                "data": results
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "search_memory",
                "error": str(e)
            }
    
    @mcp.tool()
    def clear_vmm_cache(mempath: Optional[str] = None) -> dict:
        """
        清理 VMM 缓存
        
        释放内存中缓存的 VMM 实例。
        
        Args:
            mempath: 指定清理的镜像路径（可选，不指定则清理全部）
        
        Returns:
            清理结果
        """
        try:
            from core.loader import clear_cache, VMM_CACHE
            
            before_count = len(VMM_CACHE)
            clear_cache(mempath)
            after_count = len(VMM_CACHE)
            
            return {
                "success": True,
                "tool": "clear_vmm_cache",
                "summary": f"清理了 {before_count - after_count} 个 VMM 缓存",
                "data": {
                    "before": before_count,
                    "after": after_count
                }
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "clear_vmm_cache",
                "error": str(e)
            }
