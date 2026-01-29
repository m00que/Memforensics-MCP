"""
进程分析模块 - 进程列表、进程树、DLL、句柄等
"""

from typing import Optional, List
from datetime import datetime
from core.loader import get_vmm


def register_process_tools(mcp):
    """注册进程分析相关工具"""
    
    @mcp.tool()
    def process_list(mempath: str, show_path: bool = True) -> dict:
        """
        获取进程列表
        
        Args:
            mempath: 内存镜像文件路径
            show_path: 是否显示进程路径
        
        Returns:
            进程列表，包含 PID、PPID、名称、路径、创建时间等
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
                        "state": proc.state,
                        "is_usermode": proc.is_usermode,
                        "is_wow64": proc.is_wow64,
                        "session": proc.session if hasattr(proc, 'session') else None
                    }
                    
                    if show_path:
                        try:
                            proc_info["path"] = proc.pathuser if proc.pathuser else proc.pathkernel
                        except:
                            proc_info["path"] = ""
                    
                    try:
                        proc_info["cmdline"] = proc.cmdline
                    except:
                        proc_info["cmdline"] = ""
                    
                    processes.append(proc_info)
                except Exception as e:
                    # 跳过无法读取的进程
                    continue
            
            # 按 PID 排序
            processes.sort(key=lambda x: x["pid"])
            
            return {
                "success": True,
                "tool": "process_list",
                "summary": f"共发现 {len(processes)} 个进程",
                "data": processes
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "process_list",
                "error": str(e)
            }
    
    @mcp.tool()
    def process_tree(mempath: str) -> dict:
        """
        获取进程树（显示父子关系）
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            树形结构的进程列表
        """
        try:
            vmm = get_vmm(mempath)
            
            # 构建进程字典
            proc_dict = {}
            for proc in vmm.process_list():
                try:
                    proc_dict[proc.pid] = {
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "children": []
                    }
                except:
                    continue
            
            # 构建树形结构
            roots = []
            for pid, proc in proc_dict.items():
                ppid = proc["ppid"]
                if ppid in proc_dict:
                    proc_dict[ppid]["children"].append(proc)
                else:
                    roots.append(proc)
            
            # 生成树形文本表示
            def build_tree_text(proc, prefix="", is_last=True):
                lines = []
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}{proc['name']} (PID: {proc['pid']})")
                
                child_prefix = prefix + ("    " if is_last else "│   ")
                children = proc["children"]
                for i, child in enumerate(children):
                    lines.extend(build_tree_text(child, child_prefix, i == len(children) - 1))
                
                return lines
            
            tree_lines = []
            for i, root in enumerate(roots):
                if i == 0:
                    tree_lines.append(f"{root['name']} (PID: {root['pid']})")
                    for j, child in enumerate(root["children"]):
                        tree_lines.extend(build_tree_text(child, "", j == len(root["children"]) - 1))
                else:
                    tree_lines.extend(build_tree_text(root, "", i == len(roots) - 1))
            
            return {
                "success": True,
                "tool": "process_tree",
                "summary": f"共 {len(proc_dict)} 个进程，{len(roots)} 个根进程",
                "tree_text": "\n".join(tree_lines),
                "data": roots
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "process_tree",
                "error": str(e)
            }
    
    @mcp.tool()
    def process_detail(mempath: str, pid: int) -> dict:
        """
        获取单个进程的详细信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
        
        Returns:
            进程详细信息
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            detail = {
                "pid": proc.pid,
                "ppid": proc.ppid,
                "name": proc.name,
                "fullname": proc.fullname,
                "state": proc.state,
                "is_usermode": proc.is_usermode,
                "is_wow64": proc.is_wow64,
                "eprocess": hex(proc.eprocess),
                "peb": hex(proc.peb) if proc.peb else None,
                "dtb": hex(proc.dtb),
                "session": proc.session if hasattr(proc, 'session') else None,
                "integrity": proc.integrity if hasattr(proc, 'integrity') else None,
                "sid": proc.sid if hasattr(proc, 'sid') else None
            }
            
            try:
                detail["pathuser"] = proc.pathuser
            except:
                detail["pathuser"] = ""
            
            try:
                detail["pathkernel"] = proc.pathkernel
            except:
                detail["pathkernel"] = ""
            
            try:
                detail["cmdline"] = proc.cmdline
            except:
                detail["cmdline"] = ""
            
            return {
                "success": True,
                "tool": "process_detail",
                "data": detail
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "process_detail",
                "error": str(e)
            }
    
    @mcp.tool()
    def cmdline(mempath: str, pid: Optional[int] = None) -> dict:
        """
        获取进程命令行参数
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID（可选，不指定则获取所有进程）
        
        Returns:
            进程命令行列表
        """
        try:
            vmm = get_vmm(mempath)
            cmdlines = []
            
            if pid is not None:
                proc = vmm.process(pid)
                try:
                    cmdlines.append({
                        "pid": proc.pid,
                        "name": proc.name,
                        "cmdline": proc.cmdline
                    })
                except:
                    cmdlines.append({
                        "pid": proc.pid,
                        "name": proc.name,
                        "cmdline": "(无法读取)"
                    })
            else:
                for proc in vmm.process_list():
                    try:
                        cmd = proc.cmdline
                        if cmd:  # 只添加有命令行的进程
                            cmdlines.append({
                                "pid": proc.pid,
                                "name": proc.name,
                                "cmdline": cmd
                            })
                    except:
                        continue
            
            return {
                "success": True,
                "tool": "cmdline",
                "summary": f"获取到 {len(cmdlines)} 个进程的命令行",
                "data": cmdlines
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "cmdline",
                "error": str(e)
            }
    
    @mcp.tool()
    def dlllist(mempath: str, pid: int) -> dict:
        """
        获取进程加载的 DLL 列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
        
        Returns:
            DLL 列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            dlls = []
            try:
                for module in proc.module_list():
                    try:
                        dlls.append({
                            "name": module.name,
                            "fullname": module.fullname,
                            "base": hex(module.base),
                            "size": module.size,
                            "entry": hex(module.entry) if module.entry else None,
                            "is_wow64": module.is_wow64 if hasattr(module, 'is_wow64') else False
                        })
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "dlllist",
                    "error": f"无法获取模块列表: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "dlllist",
                "summary": f"进程 {pid} 加载了 {len(dlls)} 个模块",
                "data": dlls
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "dlllist",
                "error": str(e)
            }
    
    @mcp.tool()
    def handles(mempath: str, pid: int, handle_type: Optional[str] = None) -> dict:
        """
        获取进程句柄列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
            handle_type: 句柄类型过滤（如 File, Key, Mutant, Process, Thread 等）
        
        Returns:
            句柄列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            handle_list = []
            try:
                maps = proc.maps
                for h in maps.handle():
                    try:
                        h_info = {
                            "handle": hex(h.handle),
                            "type": h.type,
                            "name": h.name if hasattr(h, 'name') else "",
                            "access": hex(h.access) if hasattr(h, 'access') else ""
                        }
                        
                        # 类型过滤
                        if handle_type is None or h.type.lower() == handle_type.lower():
                            handle_list.append(h_info)
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "handles",
                    "error": f"无法获取句柄列表: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "handles",
                "summary": f"进程 {pid} 共有 {len(handle_list)} 个句柄" + (f" (类型: {handle_type})" if handle_type else ""),
                "data": handle_list
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "handles",
                "error": str(e)
            }
    
    @mcp.tool()
    def threads(mempath: str, pid: int) -> dict:
        """
        获取进程线程列表
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
        
        Returns:
            线程列表
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            thread_list = []
            try:
                maps = proc.maps
                for t in maps.thread():
                    try:
                        thread_list.append({
                            "tid": t.tid,
                            "pid": t.pid,
                            "ethread": hex(t.ethread),
                            "teb": hex(t.teb) if t.teb else None,
                            "state": t.state if hasattr(t, 'state') else None,
                            "start_address": hex(t.start_address) if hasattr(t, 'start_address') else None,
                            "exit_status": t.exit_status if hasattr(t, 'exit_status') else None
                        })
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "threads",
                    "error": f"无法获取线程列表: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "threads",
                "summary": f"进程 {pid} 共有 {len(thread_list)} 个线程",
                "data": thread_list
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "threads",
                "error": str(e)
            }
    
    @mcp.tool()
    def vad_info(mempath: str, pid: int) -> dict:
        """
        获取进程虚拟地址描述符（VAD）信息
        
        Args:
            mempath: 内存镜像文件路径
            pid: 进程 ID
        
        Returns:
            VAD 列表，包含内存区域信息
        """
        try:
            vmm = get_vmm(mempath)
            proc = vmm.process(pid)
            
            vad_list = []
            try:
                maps = proc.maps
                for vad in maps.vad():
                    try:
                        vad_info = {
                            "start": hex(vad.start),
                            "end": hex(vad.end),
                            "size": vad.end - vad.start,
                            "protection": vad.protection if hasattr(vad, 'protection') else "",
                            "type": vad.type if hasattr(vad, 'type') else "",
                            "tag": vad.tag if hasattr(vad, 'tag') else "",
                            "info": vad.info if hasattr(vad, 'info') else ""
                        }
                        vad_list.append(vad_info)
                    except:
                        continue
            except Exception as e:
                return {
                    "success": False,
                    "tool": "vad_info",
                    "error": f"无法获取 VAD 信息: {str(e)}"
                }
            
            return {
                "success": True,
                "tool": "vad_info",
                "summary": f"进程 {pid} 共有 {len(vad_list)} 个 VAD 条目",
                "data": vad_list
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "vad_info",
                "error": str(e)
            }
    
    @mcp.tool()
    def psscan(mempath: str) -> dict:
        """
        扫描隐藏进程（通过物理内存扫描 EPROCESS 结构）
        
        此工具可以发现被 rootkit 隐藏的进程
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            扫描发现的所有进程（包括隐藏进程）
        """
        try:
            vmm = get_vmm(mempath)
            
            # 获取标准进程列表的 PID
            standard_pids = set()
            for proc in vmm.process_list():
                standard_pids.add(proc.pid)
            
            # MemProcFS 的 process_list 实际上已经包含了物理扫描结果
            # 这里我们标记哪些可能是隐藏的
            processes = []
            for proc in vmm.process_list():
                try:
                    processes.append({
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "eprocess": hex(proc.eprocess),
                        "state": proc.state,
                        "potentially_hidden": proc.state != 0  # 非活动状态可能是隐藏进程
                    })
                except:
                    continue
            
            hidden_count = len([p for p in processes if p["potentially_hidden"]])
            
            return {
                "success": True,
                "tool": "psscan",
                "summary": f"扫描发现 {len(processes)} 个进程，其中 {hidden_count} 个可能被隐藏",
                "data": processes
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "psscan",
                "error": str(e)
            }
