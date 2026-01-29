"""
MemProcFS 进程分析工具 (8个)
6. mem_pslist - 进程列表
7. mem_pstree - 进程树
8. mem_handles - 进程句柄
9. mem_modules - 进程模块
10. mem_vad - VAD信息
11. mem_threads - 线程列表
12. mem_heap - 堆信息
13. mem_console - 控制台输出
"""

from typing import Optional, List
from core.loader import get_vmm


def register_mem_process_tools(mcp):
    """注册 MemProcFS 进程分析工具"""
    
    @mcp.tool()
    def mem_pslist(mempath: str) -> dict:
        """
        [MemProcFS #6] 获取进程列表
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程列表 (PID, 名称, PPID, 路径, 命令行)
        """
        try:
            vmm = get_vmm(mempath)
            processes = []
            
            for proc in vmm.process_list():
                try:
                    proc_info = {
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "path": getattr(proc, 'fullname', ''),
                        "cmdline": getattr(proc, 'cmdline', ''),
                        "state": proc.state if hasattr(proc, 'state') else 'Unknown',
                        "user": getattr(proc, 'sid', ''),
                        "create_time": str(getattr(proc, 'time_create', ''))
                    }
                    processes.append(proc_info)
                except Exception:
                    continue
            
            # 按 PID 排序
            processes.sort(key=lambda x: x['pid'])
            
            return {
                "success": True,
                "count": len(processes),
                "data": processes
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_pstree(mempath: str) -> dict:
        """
        [MemProcFS #7] 获取进程树结构
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            进程父子关系树
        """
        try:
            vmm = get_vmm(mempath)
            
            # 收集所有进程
            proc_dict = {}
            for proc in vmm.process_list():
                proc_dict[proc.pid] = {
                    "pid": proc.pid,
                    "ppid": proc.ppid,
                    "name": proc.name,
                    "children": []
                }
            
            # 构建树结构
            roots = []
            for pid, proc in proc_dict.items():
                ppid = proc["ppid"]
                if ppid in proc_dict:
                    proc_dict[ppid]["children"].append(proc)
                else:
                    roots.append(proc)
            
            # 生成树形文本
            def build_tree_text(node, prefix="", is_last=True):
                lines = []
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}[{node['pid']}] {node['name']}")
                
                child_prefix = prefix + ("    " if is_last else "│   ")
                children = node.get("children", [])
                for i, child in enumerate(children):
                    lines.extend(build_tree_text(child, child_prefix, i == len(children) - 1))
                
                return lines
            
            tree_text = []
            for i, root in enumerate(roots):
                tree_text.extend(build_tree_text(root, "", i == len(roots) - 1))
            
            return {
                "success": True,
                "tree_text": "\n".join(tree_text),
                "data": roots
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_handles(mempath: str, pid: Optional[int] = None) -> dict:
        """
        [MemProcFS #8] 获取进程句柄列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID (可选，不指定则获取所有)
        
        Returns:
            句柄列表
        """
        try:
            vmm = get_vmm(mempath)
            handles = []
            
            if pid:
                procs = [vmm.process(pid)]
            else:
                procs = list(vmm.process_list())
            
            for proc in procs:
                try:
                    for handle in proc.maps.handle():
                        handles.append({
                            "pid": proc.pid,
                            "process_name": proc.name,
                            "handle": handle.handle,
                            "type": handle.type,
                            "name": handle.name,
                            "access": hex(handle.access) if hasattr(handle, 'access') else ''
                        })
                except:
                    continue
            
            return {
                "success": True,
                "count": len(handles),
                "data": handles[:1000]  # 限制返回数量
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_modules(mempath: str, pid: int) -> dict:
        """
        [MemProcFS #9] 获取进程加载模块/DLL
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            模块列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            modules = []
            
            for module in proc.module_list():
                modules.append({
                    "name": module.name,
                    "base": hex(module.base),
                    "image_size": getattr(module, 'image_size', 0),
                    "file_size": getattr(module, 'file_size', 0),
                    "path": getattr(module, 'fullname', module.name),
                    "entry": hex(module.entry) if hasattr(module, 'entry') else ''
                })
            
            return {
                "success": True,
                "pid": pid,
                "process_name": proc.name,
                "count": len(modules),
                "data": modules
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_vad(mempath: str, pid: int) -> dict:
        """
        [MemProcFS #10] 获取进程VAD信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            VAD (Virtual Address Descriptor) 列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            vads = []
            
            for vad in proc.maps.vad():
                vads.append({
                    "start": hex(vad.start),
                    "end": hex(vad.end),
                    "size": vad.end - vad.start,
                    "protection": vad.protection,
                    "type": vad.type,
                    "tag": getattr(vad, 'tag', ''),
                    "info": getattr(vad, 'info', '')
                })
            
            return {
                "success": True,
                "pid": pid,
                "process_name": proc.name,
                "count": len(vads),
                "data": vads
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_threads(mempath: str, pid: int) -> dict:
        """
        [MemProcFS #11] 获取进程线程列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            线程列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            threads = []
            
            for thread in proc.maps.thread():
                threads.append({
                    "tid": thread.tid,
                    "teb": hex(thread.teb) if hasattr(thread, 'teb') else '',
                    "start_address": hex(thread.start_address) if hasattr(thread, 'start_address') else '',
                    "state": getattr(thread, 'state', ''),
                    "priority": getattr(thread, 'priority', ''),
                    "create_time": str(getattr(thread, 'time_create', ''))
                })
            
            return {
                "success": True,
                "pid": pid,
                "process_name": proc.name,
                "count": len(threads),
                "data": threads
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_heap(mempath: str, pid: int) -> dict:
        """
        [MemProcFS #12] 获取进程堆信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            堆信息
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            heaps = []
            
            try:
                for heap in proc.maps.heap():
                    heaps.append({
                        "base": hex(heap.base) if hasattr(heap, 'base') else '',
                        "size": getattr(heap, 'size', 0),
                        "type": getattr(heap, 'type', ''),
                        "flags": getattr(heap, 'flags', '')
                    })
            except:
                # 某些进程可能没有堆信息
                pass
            
            return {
                "success": True,
                "pid": pid,
                "process_name": proc.name,
                "count": len(heaps),
                "data": heaps
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_console(mempath: str) -> dict:
        """
        [MemProcFS #13] 获取控制台输出内容
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            所有 conhost.exe 进程的控制台输出
        """
        try:
            vmm = get_vmm(mempath)
            consoles = []
            
            # 查找所有 conhost.exe 进程
            for proc in vmm.process_list():
                if 'conhost' in proc.name.lower():
                    try:
                        # 尝试读取控制台内容
                        console_path = f"/name/{proc.name}-{proc.pid}/console/console.txt"
                        console_data = vmm.vfs.read(console_path)
                        
                        if console_data:
                            consoles.append({
                                "pid": proc.pid,
                                "name": proc.name,
                                "content": console_data.decode('utf-8', errors='replace')
                            })
                    except:
                        continue
            
            return {
                "success": True,
                "count": len(consoles),
                "data": consoles
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_procdump_hash(mempath: str, pid: int) -> dict:
        """
        [MemProcFS] 获取进程可执行文件的哈希值
        
        导出进程主模块并计算 MD5, SHA1, SHA256 哈希
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程ID
        
        Returns:
            进程可执行文件的哈希值
        """
        import hashlib
        import memprocfs
        
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            result = {
                "pid": pid,
                "process_name": proc.name,
                "path": getattr(proc, 'fullname', ''),
                "module_info": None,
                "hashes": None
            }
            
            # 找到主模块 (与进程同名的模块)
            main_module = None
            for module in proc.module_list():
                if module.name.lower() == proc.name.lower():
                    main_module = module
                    break
            
            if not main_module:
                # 尝试找 .exe 结尾的模块
                for module in proc.module_list():
                    if module.name.lower().endswith('.exe'):
                        main_module = module
                        break
            
            if not main_module:
                return {"success": False, "error": f"找不到进程 {pid} 的主模块"}
            
            result["module_info"] = {
                "name": main_module.name,
                "base": hex(main_module.base),
                "image_size": main_module.image_size,
                "file_size": main_module.file_size,
                "fullname": getattr(main_module, 'fullname', '')
            }
            
            # 读取模块数据
            try:
                # 使用 file_size 读取实际文件大小
                size_to_read = main_module.file_size if main_module.file_size > 0 else main_module.image_size
                data = proc.memory.read(main_module.base, size_to_read, memprocfs.FLAG_NOCACHE)
                
                # 计算哈希
                result["hashes"] = {
                    "md5": hashlib.md5(data).hexdigest(),
                    "sha1": hashlib.sha1(data).hexdigest(),
                    "sha256": hashlib.sha256(data).hexdigest()
                }
                result["success"] = True
                result["data_size"] = len(data)
                
            except Exception as e:
                result["success"] = False
                result["error"] = f"读取模块数据失败: {str(e)}"
            
            return result
            
        except Exception as e:
            return {"success": False, "error": str(e)}
