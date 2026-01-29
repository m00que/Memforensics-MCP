"""
MemProcFS 加载器 - 管理 VMM 实例缓存
"""

import memprocfs
from typing import Optional, Dict
from datetime import datetime
import os

# VMM 实例缓存（避免重复加载同一个镜像）
VMM_CACHE: Dict[str, tuple] = {}  # {mempath: (vmm, load_time)}

# 缓存过期时间（秒）
CACHE_EXPIRE_SECONDS = 3600  # 1小时


def get_vmm(mempath: str, force_reload: bool = False) -> memprocfs.Vmm:
    """
    获取 VMM 实例，带缓存支持
    
    Args:
        mempath: 内存镜像文件路径
        force_reload: 是否强制重新加载
    
    Returns:
        memprocfs.Vmm 实例
    """
    global VMM_CACHE
    
    # 规范化路径
    mempath = os.path.abspath(mempath)
    
    # 检查文件是否存在
    if not os.path.exists(mempath):
        raise FileNotFoundError(f"内存镜像文件不存在: {mempath}")
    
    # 检查缓存
    if mempath in VMM_CACHE and not force_reload:
        vmm, load_time = VMM_CACHE[mempath]
        # 检查是否过期
        if (datetime.now() - load_time).total_seconds() < CACHE_EXPIRE_SECONDS:
            return vmm
    
    # 加载新实例
    try:
        vmm = memprocfs.Vmm(['-device', mempath])
        VMM_CACHE[mempath] = (vmm, datetime.now())
        return vmm
    except Exception as e:
        raise RuntimeError(f"加载内存镜像失败: {str(e)}")


def clear_cache(mempath: Optional[str] = None):
    """
    清理 VMM 缓存
    
    Args:
        mempath: 指定清理的镜像路径，为 None 则清理全部
    """
    global VMM_CACHE
    
    if mempath is None:
        # 关闭所有 VMM 实例
        for path, (vmm, _) in VMM_CACHE.items():
            try:
                vmm.close()
            except:
                pass
        VMM_CACHE.clear()
    elif mempath in VMM_CACHE:
        try:
            VMM_CACHE[mempath][0].close()
        except:
            pass
        del VMM_CACHE[mempath]


def get_memory_info(mempath: str) -> dict:
    """
    获取内存镜像基本信息
    
    Args:
        mempath: 内存镜像文件路径
    
    Returns:
        包含镜像信息的字典
    """
    vmm = get_vmm(mempath)
    
    # 获取文件信息
    file_size = os.path.getsize(mempath)
    file_name = os.path.basename(mempath)
    
    # 获取系统信息
    info = {
        "file": {
            "name": file_name,
            "path": mempath,
            "size_bytes": file_size,
            "size_human": format_bytes(file_size)
        },
        "system": {
            "build": vmm.kernel.build if hasattr(vmm.kernel, 'build') else "Unknown",
            "memory_model": get_memory_model(vmm)
        }
    }
    
    return info


def format_bytes(size: int) -> str:
    """格式化字节数为人类可读形式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def get_memory_model(vmm) -> str:
    """获取内存模型类型"""
    try:
        # 通过系统进程判断架构
        system_process = vmm.process('System')
        if system_process.tp_memorymodel == 1:
            return "x86"
        elif system_process.tp_memorymodel == 2:
            return "x86 PAE"
        elif system_process.tp_memorymodel == 3:
            return "x64"
        else:
            return "Unknown"
    except:
        return "Unknown"
