"""
凭据提取模块 - 密码哈希、LSA Secrets 等
"""

from typing import Optional
from core.loader import get_vmm


def register_credentials_tools(mcp):
    """注册凭据提取相关工具"""
    
    @mcp.tool()
    def hashdump(mempath: str) -> dict:
        """
        提取用户密码哈希（SAM）
        
        从内存中提取 Windows 用户的 NTLM 密码哈希，
        可用于离线破解或 Pass-the-Hash 攻击检测。
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            用户密码哈希列表
        """
        try:
            vmm = get_vmm(mempath)
            
            hashes = []
            
            # 尝试从 VFS 读取密码哈希
            try:
                # MemProcFS 在 /forensic/cred/ 目录下存储凭据信息
                cred_data = vmm.vfs.read('/forensic/sam/sam.txt')
                if cred_data:
                    lines = cred_data.decode('utf-8', errors='ignore').split('\n')
                    for line in lines:
                        if line.strip() and ':' in line:
                            parts = line.strip().split(':')
                            if len(parts) >= 4:
                                hashes.append({
                                    "username": parts[0],
                                    "rid": parts[1],
                                    "lm_hash": parts[2] if len(parts[2]) == 32 else "aad3b435b51404eeaad3b435b51404ee",
                                    "ntlm_hash": parts[3] if len(parts) > 3 else "",
                                    "format": f"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}" if len(parts) >= 4 else line
                                })
            except:
                pass
            
            # 备选：尝试从注册表提取
            if not hashes:
                try:
                    # 读取 SAM 注册表
                    sam_key = vmm.reg_key("HKLM\\SAM\\SAM\\Domains\\Account\\Users")
                    
                    for subkey in sam_key.subkeys():
                        try:
                            if subkey.name != "Names":
                                rid = subkey.name
                                hashes.append({
                                    "rid": rid,
                                    "username": f"User_{rid}",
                                    "note": "需要进一步解析 V 值获取哈希"
                                })
                        except:
                            continue
                except:
                    pass
            
            return {
                "success": True,
                "tool": "hashdump",
                "summary": f"提取到 {len(hashes)} 个用户哈希",
                "data": hashes,
                "note": "哈希格式: username:rid:lm_hash:ntlm_hash，可使用 hashcat 或 john 破解"
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "hashdump",
                "error": str(e)
            }
    
    @mcp.tool()
    def lsadump(mempath: str) -> dict:
        """
        提取 LSA Secrets
        
        LSA Secrets 包含服务账户密码、自动登录密码、VPN 密码等敏感信息。
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            LSA Secrets 内容
        """
        try:
            vmm = get_vmm(mempath)
            
            secrets = []
            
            # 尝试从 VFS 读取
            try:
                lsa_data = vmm.vfs.read('/forensic/secrets/secrets.txt')
                if lsa_data:
                    lines = lsa_data.decode('utf-8', errors='ignore').split('\n')
                    current_secret = None
                    for line in lines:
                        if line.strip():
                            if ':' in line and not line.startswith(' '):
                                if current_secret:
                                    secrets.append(current_secret)
                                parts = line.split(':', 1)
                                current_secret = {
                                    "name": parts[0].strip(),
                                    "value": parts[1].strip() if len(parts) > 1 else ""
                                }
                            elif current_secret:
                                current_secret["value"] += " " + line.strip()
                    if current_secret:
                        secrets.append(current_secret)
            except:
                pass
            
            # 尝试从注册表读取 LSA 配置
            if not secrets:
                try:
                    lsa_key = vmm.reg_key("HKLM\\SECURITY\\Policy\\Secrets")
                    for subkey in lsa_key.subkeys():
                        secrets.append({
                            "name": subkey.name,
                            "note": "加密数据，需要 LSA 密钥解密"
                        })
                except:
                    pass
            
            return {
                "success": True,
                "tool": "lsadump",
                "summary": f"发现 {len(secrets)} 个 LSA Secret",
                "data": secrets
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "lsadump",
                "error": str(e)
            }
    
    @mcp.tool()
    def cached_creds(mempath: str) -> dict:
        """
        提取域缓存凭据（DCC2）
        
        Windows 缓存的域登录凭据，用于离线登录验证。
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            缓存凭据列表
        """
        try:
            vmm = get_vmm(mempath)
            
            cached = []
            
            try:
                # 尝试读取缓存凭据
                cache_key = vmm.reg_key("HKLM\\SECURITY\\Cache")
                
                for value in cache_key.values():
                    if value.name.startswith("NL$"):
                        cached.append({
                            "name": value.name,
                            "size": value.size if hasattr(value, 'size') else 0,
                            "note": "DCC2 格式，可使用 hashcat mode 2100 破解"
                        })
            except:
                pass
            
            return {
                "success": True,
                "tool": "cached_creds",
                "summary": f"发现 {len(cached)} 个缓存凭据",
                "data": cached
            }
        except Exception as e:
            return {
                "success": False,
                "tool": "cached_creds",
                "error": str(e)
            }
