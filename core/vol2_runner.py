"""
Volatility 2 命令执行器
基于 toolkit/volatility2_python/vol.py 和 python27 环境
"""

import subprocess
import os
import json
import csv
import io
from typing import Optional, Dict, List, Any
from pathlib import Path

# 获取工具路径
TOOLKIT_PATH = Path(__file__).parent.parent / "toolkit"
PYTHON27_PATH = TOOLKIT_PATH / "python27" / "python.exe"
VOL2_SCRIPT = TOOLKIT_PATH / "volatility2_python" / "vol.py"
VOL2_PLUGIN_PATH = TOOLKIT_PATH / "volatility2_plugin"
VOL2_COMMUNITY_PLUGIN = TOOLKIT_PATH / "vol2plugin"

# 输出目录
OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


class Vol2Runner:
    """Volatility 2 命令执行器"""
    
    def __init__(self, mempath: str, profile: Optional[str] = None):
        """
        初始化 Vol2 执行器
        
        Args:
            mempath: 内存镜像路径
            profile: Windows Profile (如 Win7SP1x64)，为 None 则自动检测
        """
        self.mempath = os.path.abspath(mempath)
        self.profile = profile
        self._validate_environment()
        
    def _validate_environment(self):
        """验证运行环境"""
        if not PYTHON27_PATH.exists():
            raise FileNotFoundError(f"Python 2.7 不存在: {PYTHON27_PATH}")
        if not VOL2_SCRIPT.exists():
            raise FileNotFoundError(f"Volatility 2 脚本不存在: {VOL2_SCRIPT}")
        if not os.path.exists(self.mempath):
            raise FileNotFoundError(f"内存镜像不存在: {self.mempath}")
    
    def get_profile(self) -> str:
        """
        获取或检测 Profile
        
        Returns:
            Profile 字符串
        """
        if self.profile:
            return self.profile
        
        # 运行 imageinfo 自动检测
        result = self.run_plugin("imageinfo", output_type="text")
        
        # 解析 Suggested Profile
        for line in result.get("output", "").split("\n"):
            if "Suggested Profile(s)" in line:
                profiles = line.split(":")[1].strip()
                suggested = profiles.split(",")[0].strip()
                self.profile = suggested
                return suggested
        
        raise RuntimeError("无法自动检测 Profile，请手动指定")
    
    def build_command(self, plugin: str, output_type: str = "json", 
                      extra_args: Optional[List[str]] = None,
                      use_plugin_dir: bool = True) -> List[str]:
        """
        构建 Vol2 命令
        
        Args:
            plugin: 插件名称
            output_type: 输出类型 (json/text/csv)
            extra_args: 额外参数
            use_plugin_dir: 是否使用插件目录
        
        Returns:
            命令列表
        """
        cmd = [
            str(PYTHON27_PATH),
            str(VOL2_SCRIPT),
        ]
        
        # 添加插件目录
        if use_plugin_dir:
            if VOL2_PLUGIN_PATH.exists():
                cmd.extend([f"--plugins={VOL2_PLUGIN_PATH}"])
            if VOL2_COMMUNITY_PLUGIN.exists():
                cmd.extend([f"--plugins={VOL2_COMMUNITY_PLUGIN}"])
        
        # 添加镜像路径
        cmd.extend(["-f", self.mempath])
        
        # 添加 Profile
        if self.profile:
            cmd.extend([f"--profile={self.profile}"])
        
        # 添加插件
        cmd.append(plugin)
        
        # 添加输出格式
        if output_type in ["json", "csv"]:
            cmd.extend([f"--output={output_type}"])
        
        # 添加额外参数
        if extra_args:
            cmd.extend(extra_args)
        
        return cmd
    
    def run_plugin(self, plugin: str, output_type: str = "json",
                   extra_args: Optional[List[str]] = None,
                   timeout: int = 300) -> Dict[str, Any]:
        """
        运行 Vol2 插件
        
        Args:
            plugin: 插件名称
            output_type: 输出类型 (json/text/csv)
            extra_args: 额外参数
            timeout: 超时时间（秒）
        
        Returns:
            结果字典 {success, output, error, data}
        """
        cmd = self.build_command(plugin, output_type, extra_args)
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace'
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            result = {
                "success": process.returncode == 0,
                "output": stdout,
                "error": stderr,
                "command": " ".join(cmd),
                "plugin": plugin
            }
            
            # 解析 JSON 输出
            if output_type == "json" and stdout:
                try:
                    data = json.loads(stdout)
                    if "rows" in data and "columns" in data:
                        result["data"] = self._json_to_records(data)
                    else:
                        result["data"] = data
                except json.JSONDecodeError:
                    result["data"] = None
            
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
    
    def run_plugin_to_file(self, plugin: str, output_type: str = "json",
                           extra_args: Optional[List[str]] = None,
                           output_file: Optional[str] = None,
                           timeout: int = 600) -> Dict[str, Any]:
        """
        运行 Vol2 插件并保存到文件
        
        Args:
            plugin: 插件名称
            output_type: 输出类型 (json/text/csv)
            extra_args: 额外参数
            output_file: 输出文件路径
            timeout: 超时时间（秒）
        
        Returns:
            结果字典
        """
        if output_file is None:
            ext = "txt" if output_type == "text" else output_type
            output_file = OUTPUT_DIR / f"vol2_{plugin}.{ext}"
        else:
            output_file = Path(output_file)
        
        # 添加输出文件参数
        args = list(extra_args or [])
        args.extend([f"--output-file={output_file}"])
        
        result = self.run_plugin(plugin, output_type, args, timeout)
        result["output_file"] = str(output_file)
        
        # 如果 JSON 输出成功，转换为 CSV
        if result["success"] and output_type == "json" and output_file.exists():
            csv_file = output_file.with_suffix(".csv")
            self._json_file_to_csv(output_file, csv_file)
            result["csv_file"] = str(csv_file)
        
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
            dump_dir = OUTPUT_DIR / f"vol2_{plugin}_dump"
        else:
            dump_dir = Path(dump_dir)
        
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        args = list(extra_args or [])
        args.extend([f"--dump-dir={dump_dir}"])
        
        result = self.run_plugin(plugin, "text", args, timeout)
        result["dump_dir"] = str(dump_dir)
        
        return result
    
    def _json_to_records(self, data: dict) -> List[dict]:
        """将 Vol2 JSON 输出转换为记录列表"""
        if "rows" not in data or "columns" not in data:
            return []
        
        columns = data["columns"]
        records = []
        for row in data["rows"]:
            record = dict(zip(columns, row))
            records.append(record)
        return records
    
    def _json_file_to_csv(self, json_path: Path, csv_path: Path):
        """将 JSON 文件转换为 CSV"""
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "rows" in data and "columns" in data:
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(data["columns"])
                    writer.writerows(data["rows"])
        except Exception:
            pass


# 快捷函数
def run_vol2(mempath: str, plugin: str, profile: Optional[str] = None,
             output_type: str = "json", extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    快捷运行 Vol2 插件
    
    Args:
        mempath: 内存镜像路径
        plugin: 插件名称
        profile: Profile
        output_type: 输出类型
        extra_args: 额外参数
    
    Returns:
        结果字典
    """
    runner = Vol2Runner(mempath, profile)
    if not profile:
        runner.get_profile()
    return runner.run_plugin(plugin, output_type, extra_args)
