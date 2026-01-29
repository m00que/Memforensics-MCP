"""
Volatility 3 命令执行器
基于 toolkit/volatility3/ 和 python3 环境
"""

import subprocess
import os
import csv
import io
from typing import Optional, Dict, List, Any
from pathlib import Path

# 获取工具路径
TOOLKIT_PATH = Path(__file__).parent.parent / "toolkit"
PYTHON3_PATH = TOOLKIT_PATH / "python3" / "python.exe"
VOL3_PATH = TOOLKIT_PATH / "volatility3"
VOL3_SCRIPT = VOL3_PATH / "vol.py"

# 如果 vol.py 不存在，尝试使用 volshell.py 或直接调用模块
if not VOL3_SCRIPT.exists():
    VOL3_SCRIPT = VOL3_PATH / "volshell.py"

# 输出目录
OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


class Vol3Runner:
    """Volatility 3 命令执行器"""
    
    def __init__(self, mempath: str):
        """
        初始化 Vol3 执行器
        
        Args:
            mempath: 内存镜像路径
        """
        self.mempath = os.path.abspath(mempath)
        self._validate_environment()
        
    def _validate_environment(self):
        """验证运行环境"""
        if not PYTHON3_PATH.exists():
            raise FileNotFoundError(f"Python 3 不存在: {PYTHON3_PATH}")
        if not VOL3_PATH.exists():
            raise FileNotFoundError(f"Volatility 3 目录不存在: {VOL3_PATH}")
        if not os.path.exists(self.mempath):
            raise FileNotFoundError(f"内存镜像不存在: {self.mempath}")
    
    def build_command(self, plugin: str, output_format: str = "csv",
                      extra_args: Optional[List[str]] = None,
                      output_dir: Optional[str] = None,
                      offline: bool = False) -> List[str]:
        """
        构建 Vol3 命令
        
        Args:
            plugin: 插件名称 (如 windows.pslist)
            output_format: 输出格式 (csv/quick/json)
            extra_args: 额外参数
            output_dir: 输出目录（用于 dump 操作）
            offline: 是否离线模式
        
        Returns:
            命令列表
        """
        cmd = [
            str(PYTHON3_PATH),
            str(VOL3_SCRIPT),  # 使用 vol.py 脚本而不是 -m volatility3.cli
            "-f", self.mempath,
        ]
        
        # 添加离线模式
        if offline:
            cmd.append("--offline")
        
        # 添加输出格式
        cmd.extend(["-r", output_format])
        
        # 添加输出目录
        if output_dir:
            cmd.extend(["-o", output_dir])
        
        # 添加插件
        cmd.append(plugin)
        
        # 添加额外参数
        if extra_args:
            cmd.extend(extra_args)
        
        return cmd
    
    def run_plugin(self, plugin: str, output_format: str = "csv",
                   extra_args: Optional[List[str]] = None,
                   timeout: int = 300,
                   offline: bool = False) -> Dict[str, Any]:
        """
        运行 Vol3 插件
        
        Args:
            plugin: 插件名称 (如 windows.pslist)
            output_format: 输出格式 (csv/quick/json)
            extra_args: 额外参数
            timeout: 超时时间（秒）
            offline: 是否离线模式
        
        Returns:
            结果字典 {success, output, error, data}
        """
        cmd = self.build_command(plugin, output_format, extra_args, offline=offline)
        
        # 设置环境变量
        env = os.environ.copy()
        env['PYTHONPATH'] = str(VOL3_PATH)
        env['PYTHONIOENCODING'] = 'utf-8'
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(VOL3_PATH)
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            # 解码输出
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            result = {
                "success": process.returncode == 0,
                "output": stdout_str,
                "error": stderr_str,
                "command": " ".join(cmd),
                "plugin": plugin
            }
            
            # 解析 CSV 输出
            if output_format == "csv" and stdout_str:
                result["data"] = self._parse_csv_output(stdout_str)
            
            return result
            
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "success": False,
                "output": "",
                "error": f"命令超时 ({timeout}秒)",
                "command": " ".join(cmd),
                "plugin": plugin
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd),
                "plugin": plugin
            }
    
    def run_plugin_to_file(self, plugin: str, output_format: str = "csv",
                           extra_args: Optional[List[str]] = None,
                           output_file: Optional[str] = None,
                           timeout: int = 600,
                           offline: bool = False) -> Dict[str, Any]:
        """
        运行 Vol3 插件并保存到文件
        
        Args:
            plugin: 插件名称
            output_format: 输出格式
            extra_args: 额外参数
            output_file: 输出文件路径
            timeout: 超时时间（秒）
            offline: 是否离线模式
        
        Returns:
            结果字典
        """
        result = self.run_plugin(plugin, output_format, extra_args, timeout, offline)
        
        if result["success"] and result.get("output"):
            if output_file is None:
                ext = "txt" if output_format == "quick" else output_format
                output_file = OUTPUT_DIR / f"vol3_{plugin.replace('.', '_')}.{ext}"
            else:
                output_file = Path(output_file)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result["output"])
            
            result["output_file"] = str(output_file)
        
        return result
    
    def run_dump_plugin(self, plugin: str, dump_dir: Optional[str] = None,
                        extra_args: Optional[List[str]] = None,
                        timeout: int = 600) -> Dict[str, Any]:
        """
        运行导出类插件
        
        Args:
            plugin: 插件名称
            dump_dir: 导出目录
            extra_args: 额外参数
            timeout: 超时时间
        
        Returns:
            结果字典
        """
        if dump_dir is None:
            dump_dir = OUTPUT_DIR / f"vol3_{plugin.replace('.', '_')}_dump"
        else:
            dump_dir = Path(dump_dir)
        
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        # Vol3 dump 使用 -o 参数指定输出目录
        cmd = self.build_command(plugin, "csv", extra_args, output_dir=str(dump_dir))
        
        # 添加 --dump 参数（某些插件需要）
        if extra_args is None or "--dump" not in extra_args:
            cmd.append("--dump")
        
        env = os.environ.copy()
        env['PYTHONPATH'] = str(VOL3_PATH)
        env['PYTHONIOENCODING'] = 'utf-8'
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(VOL3_PATH)
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode('utf-8', errors='replace'),
                "error": stderr.decode('utf-8', errors='replace'),
                "command": " ".join(cmd),
                "plugin": plugin,
                "dump_dir": str(dump_dir)
            }
            
        except subprocess.TimeoutExpired:
            process.kill()
            return {
                "success": False,
                "error": f"命令超时 ({timeout}秒)",
                "dump_dir": str(dump_dir)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "dump_dir": str(dump_dir)
            }
    
    def _parse_csv_output(self, csv_str: str) -> List[Dict[str, Any]]:
        """解析 CSV 格式输出"""
        records = []
        try:
            reader = csv.DictReader(io.StringIO(csv_str))
            for row in reader:
                # 清理空值
                cleaned = {k: v for k, v in row.items() if v}
                records.append(cleaned)
        except Exception:
            pass
        return records
    
    def get_available_plugins(self) -> List[str]:
        """获取可用的 Vol3 插件列表"""
        cmd = [
            str(PYTHON3_PATH),
            str(VOL3_SCRIPT),
            "-h"
        ]
        
        env = os.environ.copy()
        env['PYTHONPATH'] = str(VOL3_PATH)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                env=env,
                cwd=str(VOL3_PATH),
                timeout=30
            )
            
            output = result.stdout.decode('utf-8', errors='replace')
            plugins = []
            
            # 解析帮助输出中的插件列表
            in_plugins = False
            for line in output.split('\n'):
                if 'Plugins' in line:
                    in_plugins = True
                    continue
                if in_plugins and line.strip().startswith('windows.'):
                    plugin_name = line.strip().split()[0]
                    plugins.append(plugin_name)
            
            return plugins
        except Exception:
            return []


# 快捷函数
def run_vol3(mempath: str, plugin: str, output_format: str = "csv",
             extra_args: Optional[List[str]] = None,
             offline: bool = False) -> Dict[str, Any]:
    """
    快捷运行 Vol3 插件
    
    Args:
        mempath: 内存镜像路径
        plugin: 插件名称 (如 windows.pslist)
        output_format: 输出格式
        extra_args: 额外参数
        offline: 是否离线模式
    
    Returns:
        结果字典
    """
    runner = Vol3Runner(mempath)
    return runner.run_plugin(plugin, output_format, extra_args, offline=offline)
