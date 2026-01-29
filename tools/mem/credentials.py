"""
MemProcFS 凭据提取工具 (3个)
29. mem_pypykatz - lsass凭据提取
30. mem_regsecrets - 注册表凭据
31. mem_kerberos_tickets - Kerberos票据
"""

from core.loader import get_vmm
import json


def register_mem_credentials_tools(mcp):
    """注册 MemProcFS 凭据提取工具"""
    
    @mcp.tool()
    def mem_pypykatz(mempath: str) -> dict:
        """
        [MemProcFS #29] 使用 pypykatz 提取 lsass 凭据
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            提取的凭据信息（密码、哈希、票据）
        """
        try:
            vmm = get_vmm(mempath)
            
            result = {
                "credentials": [],
                "raw_json": None,
                "by_domain": {},
                "errors": []
            }
            
            # 尝试读取 pypykatz 插件输出
            try:
                # 读取所有结果
                all_results = vmm.vfs.read("/py/secrets/all_results.json")
                if all_results:
                    result["raw_json"] = all_results.decode('utf-8', errors='replace')
                    
                    # 解析 JSON
                    try:
                        data = json.loads(result["raw_json"])
                        
                        # 提取登录会话信息
                        if "logon_sessions" in data:
                            for luid, session in data["logon_sessions"].items():
                                cred = {
                                    "luid": luid,
                                    "username": session.get("username", ""),
                                    "domain": session.get("domainname", ""),
                                    "logon_type": session.get("logon_type", ""),
                                    "msv_creds": [],
                                    "kerberos_creds": [],
                                    "wdigest_creds": []
                                }
                                
                                # MSV 凭据 (NT/LM Hash)
                                if "msv_creds" in session:
                                    for msv in session["msv_creds"]:
                                        cred["msv_creds"].append({
                                            "username": msv.get("username", ""),
                                            "domain": msv.get("domainname", ""),
                                            "nt_hash": msv.get("NThash", ""),
                                            "lm_hash": msv.get("LMhash", ""),
                                            "sha1": msv.get("SHAHash", "")
                                        })
                                
                                # Kerberos 凭据
                                if "kerberos_creds" in session:
                                    for krb in session["kerberos_creds"]:
                                        cred["kerberos_creds"].append({
                                            "username": krb.get("username", ""),
                                            "domain": krb.get("domain", ""),
                                            "password": krb.get("password", "")
                                        })
                                
                                # WDigest
                                if "wdigest_creds" in session:
                                    for wd in session["wdigest_creds"]:
                                        cred["wdigest_creds"].append({
                                            "username": wd.get("username", ""),
                                            "domain": wd.get("domainname", ""),
                                            "password": wd.get("password", "")
                                        })
                                
                                result["credentials"].append(cred)
                    except json.JSONDecodeError:
                        result["errors"].append("JSON 解析失败")
            except Exception as e:
                result["errors"].append(f"读取 pypykatz 输出失败: {str(e)}")
            
            # 检查是否有错误文件
            try:
                import_error = vmm.vfs.read("/py/secrets/import_error.txt")
                if import_error:
                    result["errors"].append(import_error.decode('utf-8', errors='replace'))
            except:
                pass
            
            try:
                parsing_error = vmm.vfs.read("/py/secrets/parsing_error.txt")
                if parsing_error:
                    result["errors"].append(parsing_error.decode('utf-8', errors='replace'))
            except:
                pass
            
            return {
                "success": len(result["credentials"]) > 0 or result["raw_json"] is not None,
                "credential_count": len(result["credentials"]),
                "data": result
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_regsecrets(mempath: str) -> dict:
        """
        [MemProcFS #30] 从注册表提取凭据 (SAM/LSA/SECURITY)
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            注册表中的凭据信息
        """
        try:
            vmm = get_vmm(mempath)
            
            result = {
                "sam": None,
                "security": None,
                "software": None,
                "all": None,
                "errors": []
            }
            
            # 尝试读取 regsecrets 插件输出
            secrets_path = "/py/regsecrets"
            
            for key in ["sam.txt", "security.txt", "software.txt", "all.txt"]:
                try:
                    data = vmm.vfs.read(f"{secrets_path}/{key}")
                    if data:
                        result[key.replace('.txt', '')] = data.decode('utf-8', errors='replace')
                except:
                    continue
            
            # 检查错误
            try:
                import_error = vmm.vfs.read(f"{secrets_path}/import_error.txt")
                if import_error:
                    result["errors"].append(import_error.decode('utf-8', errors='replace'))
            except:
                pass
            
            try:
                parsing_error = vmm.vfs.read(f"{secrets_path}/parsing_error.txt")
                if parsing_error:
                    result["errors"].append(parsing_error.decode('utf-8', errors='replace'))
            except:
                pass
            
            has_data = any([result["sam"], result["security"], result["software"], result["all"]])
            
            return {
                "success": has_data,
                "data": result
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @mcp.tool()
    def mem_kerberos_tickets(mempath: str) -> dict:
        """
        [MemProcFS #31] 导出 Kerberos 票据
        
        Args:
            mempath: 内存镜像文件路径
        
        Returns:
            Kerberos 票据列表
        """
        try:
            vmm = get_vmm(mempath)
            tickets = []
            
            # 尝试列出 Kerberos 目录
            kerberos_path = "/py/secrets/kerberos"
            
            try:
                luids = vmm.vfs.list(kerberos_path)
                for luid in luids:
                    if luid not in ['.', '..']:
                        luid_path = f"{kerberos_path}/{luid}"
                        try:
                            ticket_files = vmm.vfs.list(luid_path)
                            for tf in ticket_files:
                                if tf.endswith('.kirbi'):
                                    tickets.append({
                                        "luid": luid,
                                        "filename": tf,
                                        "path": f"{luid_path}/{tf}"
                                    })
                        except:
                            continue
            except:
                pass
            
            return {
                "success": True,
                "count": len(tickets),
                "data": tickets
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
