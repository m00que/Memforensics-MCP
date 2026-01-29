# 内存取证 MCP 工具清单 (182个)

## 工具总览

| 引擎 | 工具数量 | 底层 | 运行环境 |
|------|---------|------|----------|
| **搜索工具** | 6 个 | `tools_index.json` | Python |
| **MemProcFS** | 36 个 | `vmmpyc.pyd` API | `toolkit/python3/` |
| **Volatility 2** | 77 个 | `vol.py` / `vol.exe` | `toolkit/python27/` |
| **Volatility 3** | 63 个 | `volatility3/` 框架 | `toolkit/python3/` |

---

## 零、搜索工具 (6个) - AI入口点

| # | 工具名 | 功能 | 状态 |
|---|--------|------|------|
| 0 | `search_tools` | 🔍 关键词搜索工具 (AI应首先调用) | ✅ |
| 0 | `list_tools_by_category` | 按分类列出工具 | ✅ |
| 0 | `list_tools_by_engine` | 按引擎列出工具 | ✅ |
| 0 | `get_tool_info` | 获取单个工具详情 | ✅ |
| 0 | `get_unique_features` | 获取各引擎独有功能 | ✅ |
| 0 | `forensics_help` | 获取内存取证 MCP 服务帮助信息 | ✅ |

---

## 一、MemProcFS 工具 (36个)

### 1.1 系统信息 (System) - 5个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 1 | `mem_info` | 内存镜像基本信息 | VMM API | ⬜ |
| 2 | `mem_sysinfo` | 系统详细信息 | `/sys/sysinfo/` | ⬜ |
| 3 | `mem_users` | 用户账户列表 | `/sys/users/` | ⬜ |
| 4 | `mem_dtb` | 页表基址信息 | `/misc/procinfo/dtb.txt` | ⬜ |
| 5 | `mem_certificates` | 系统证书列表 | `/sys/certificates/` | ⬜ |

### 1.2 进程分析 (Process) - 8个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 6 | `mem_pslist` | 进程列表 | `/forensic/csv/process.csv` | ⬜ |
| 7 | `mem_pstree` | 进程父子关系树 | VMM API | ⬜ |
| 8 | `mem_handles` | 进程句柄列表 | `/forensic/csv/handles.csv` | ⬜ |
| 9 | `mem_modules` | 进程加载模块 | `/name/{pid}/modules/` | ⬜ |
| 10 | `mem_vad` | 虚拟地址描述符 | `/name/{pid}/vad/` | ⬜ |
| 11 | `mem_threads` | 进程线程列表 | `/name/{pid}/threads/` | ⬜ |
| 12 | `mem_heap` | 进程堆信息 | `/name/{pid}/heaps/` | ⬜ |
| 13 | `mem_console` | 控制台输出 | `/name/*conhost*/console/` | ⬜ |

### 1.3 网络分析 (Network) - 2个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 14 | `mem_netstat` | 网络连接状态 | `/forensic/csv/net.csv` | ⬜ |
| 15 | `mem_netstat_timeline` | 网络活动时间线 | `/forensic/csv/timeline_net.csv` | ⬜ |

### 1.4 文件系统 (Filesystem) - 3个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 16 | `mem_filescan` | 文件对象列表 | `/forensic/csv/files.csv` | ⬜ |
| 17 | `mem_ntfs_timeline` | NTFS时间线 | `/forensic/csv/timeline_ntfs.csv` | ⬜ |
| 18 | `mem_dumpfile` | 提取文件 | VMM API | ⬜ |

### 1.5 注册表分析 (Registry) - 6个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 19 | `mem_hivelist` | Hive列表 | `/registry/hive_files/` | ⬜ |
| 20 | `mem_printkey` | 读取键值 | `/registry/` | ⬜ |
| 21 | `mem_autoruns` | 自启动项 | Run/RunOnce 键 | ⬜ |
| 22 | `mem_usb_devices` | USB设备历史 | 插件 | ⬜ |
| 23 | `mem_network_interfaces` | 网络接口 | 插件 | ⬜ |
| 24 | `mem_reg_timeline` | 注册表时间线 | `/forensic/csv/timeline_registry.csv` | ⬜ |

### 1.6 服务与驱动 (Services) - 4个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 25 | `mem_services` | 服务列表 | `/forensic/csv/services.csv` | ⬜ |
| 26 | `mem_drivers` | 驱动列表 | `/forensic/csv/drivers.csv` | ⬜ |
| 27 | `mem_tasks` | 计划任务 | `/forensic/csv/tasks.csv` | ⬜ |
| 28 | `mem_driver_detail` | 驱动详情 | `/sys/drivers/` | ⬜ |

### 1.7 凭据提取 (Credentials) - 3个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 29 | `mem_pypykatz` | lsass凭据提取 | 插件 `pym_pypykatz` | ⬜ |
| 30 | `mem_regsecrets` | 注册表凭据 | 插件 `pym_regsecrets` | ⬜ |
| 31 | `mem_kerberos_tickets` | Kerberos票据 | `pym_pypykatz/kerberos/` | ⬜ |

### 1.8 恶意检测 (Malware) - 2个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 32 | `mem_findevil` | 综合恶意检测 | `/forensic/csv/findevil.csv` | ⬜ |
| 33 | `mem_yara` | YARA扫描 | `/forensic/csv/yara.csv` | ⬜ |

### 1.9 时间线 (Timeline) - 2个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 34 | `mem_timeline_all` | 综合时间线 | `/forensic/csv/timeline_all.csv` | ⬜ |
| 35 | `mem_timeline_process` | 进程时间线 | `/forensic/csv/timeline_process.csv` | ⬜ |

### 1.10 数据导出 (Dump) - 1个
| # | 工具名 | 功能 | 数据源 | 状态 |
|---|--------|------|--------|------|
| 36 | `mem_procdump_hash` | 进程可执行文件哈希 (MD5/SHA1/SHA256) | VMM API | ⬜ |

---

## 二、Volatility 2 工具 (77个)

### 2.1 系统信息 (System) - 6个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 36 | `vol2_imageinfo` | `imageinfo` | Profile检测 | text | ⬜ |
| 37 | `vol2_kdbgscan` | `kdbgscan` | KDBG扫描 | text | ⬜ |
| 38 | `vol2_shutdowntime` | `shutdowntime` | 关机时间 | text | ⬜ |
| 39 | `vol2_envars` | `envars` | 环境变量 | csv | ⬜ |
| 40 | `vol2_verinfo` | `verinfo` | 版本信息 | csv | ⬜ |
| 41 | `vol2_auditpol` | `auditpol` | 审计策略 | csv | ⬜ |

### 2.2 进程分析 (Process) - 12个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 42 | `vol2_pslist` | `pslist` | 进程列表 | csv | ⬜ |
| 43 | `vol2_psscan` | `psscan` | 进程扫描 | csv | ⬜ |
| 44 | `vol2_pstree` | `pstree` | 进程树 | text | ⬜ |
| 45 | `vol2_psxview` | `psxview` | 隐藏进程 | csv | ⬜ |
| 46 | `vol2_cmdline` | `cmdline` | 命令行 | csv | ⬜ |
| 47 | `vol2_cmdscan` | `cmdscan` | CMD历史 | csv | ⬜ |
| 48 | `vol2_consoles` | `consoles` | 控制台 | text | ⬜ |
| 49 | `vol2_dlllist` | `dlllist` | DLL列表 | text | ⬜ |
| 50 | `vol2_handles` | `handles` | 句柄 | csv | ⬜ |
| 51 | `vol2_getsids` | `getsids` | 进程SID | csv | ⬜ |
| 52 | `vol2_privs` | `privs` | 权限 | csv | ⬜ |
| 53 | `vol2_vadinfo` | `vadinfo` | VAD信息 | csv | ⬜ |

### 2.3 网络分析 (Network) - 2个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 54 | `vol2_netscan` | `netscan` | 网络连接 | csv | ⬜ |
| 55 | `vol2_connections` | `connections` | 连接(XP) | csv | ⬜ |

### 2.4 文件系统 (Filesystem) - 4个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 56 | `vol2_filescan` | `filescan` | 文件扫描 | csv | ⬜ |
| 57 | `vol2_mftparser` | `mftparser` | MFT解析 | csv | ⬜ |
| 58 | `vol2_symlinkscan` | `symlinkscan` | 符号链接 | csv | ⬜ |
| 59 | `vol2_dumpfiles` | `dumpfiles` | 文件导出 | dump | ⬜ |

### 2.5 注册表分析 (Registry) - 8个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 60 | `vol2_hivelist` | `hivelist` | Hive列表 | csv | ⬜ |
| 61 | `vol2_printkey` | `printkey` | 键值 | csv | ⬜ |
| 62 | `vol2_hivedump` | `hivedump` | Hive转储 | text | ⬜ |
| 63 | `vol2_dumpregistry` | `dumpregistry` | 导出注册表 | dump | ⬜ |
| 64 | `vol2_userassist` | `userassist` | 执行记录 | csv | ⬜ |
| 65 | `vol2_shellbags` | `shellbags` | ShellBags | csv | ⬜ |
| 66 | `vol2_shimcache` | `shimcache` | Shimcache | csv | ⬜ |
| 67 | `vol2_autoruns` | `autoruns` | 自启动项 | csv | ⬜ |

### 2.6 凭据提取 (Credentials) - 4个 ⭐独有mimikatz
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 68 | `vol2_hashdump` | `hashdump` | SAM哈希 | text | ⬜ |
| 69 | `vol2_lsadump` | `lsadump` | LSA Secrets | text | ⬜ |
| 70 | `vol2_cachedump` | `cachedump` | 缓存凭据 | text | ⬜ |
| 71 | `vol2_mimikatz` | `mimikatz` | Mimikatz⭐ | text | ⬜ |

### 2.7 恶意检测 (Malware) - 6个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 72 | `vol2_malfind` | `malfind` | 代码注入 | csv | ⬜ |
| 73 | `vol2_malfinddeep` | `malfinddeep` | 深度检测 | csv | ⬜ |
| 74 | `vol2_apihooks` | `apihooks` | API钩子 | csv | ⬜ |
| 75 | `vol2_apihooksdeep` | `apihooksdeep` | 深度钩子 | csv | ⬜ |
| 76 | `vol2_ldrmodules` | `ldrmodules` | 隐藏DLL | csv | ⬜ |
| 77 | `vol2_hollowfind` | `hollowfind` | 进程镂空 | csv | ⬜ |

### 2.8 内核分析 (Kernel) - 10个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 78 | `vol2_modules` | `modules` | 内核模块 | csv | ⬜ |
| 79 | `vol2_modscan` | `modscan` | 模块扫描 | csv | ⬜ |
| 80 | `vol2_driverscan` | `driverscan` | 驱动扫描 | csv | ⬜ |
| 81 | `vol2_driverirp` | `driverirp` | IRP钩子 | csv | ⬜ |
| 82 | `vol2_ssdt` | `ssdt` | SSDT表 | csv | ⬜ |
| 83 | `vol2_callbacks` | `callbacks` | 回调函数 | csv | ⬜ |
| 84 | `vol2_timers` | `timers` | 定时器 | csv | ⬜ |
| 85 | `vol2_unloadedmodules` | `unloadedmodules` | 卸载模块 | csv | ⬜ |
| 86 | `vol2_devicetree` | `devicetree` | 设备树 | text | ⬜ |
| 87 | `vol2_getservicesids` | `getservicesids` | 服务SID | csv | ⬜ |

### 2.9 服务分析 (Services) - 1个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 88 | `vol2_svcscan` | `svcscan` | 服务扫描 | csv | ⬜ |

### 2.10 GUI/窗口分析 (GUI) - 7个 ⭐独有
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 89 | `vol2_windows` | `windows` | 窗口信息 | text | ⬜ |
| 90 | `vol2_wintree` | `wintree` | 窗口树 | csv | ⬜ |
| 91 | `vol2_deskscan` | `deskscan` | 桌面扫描 | csv | ⬜ |
| 92 | `vol2_screenshot` | `screenshot` | 截图重建 | dump | ⬜ |
| 93 | `vol2_clipboard` | `clipboard` | 剪贴板 | text | ⬜ |
| 94 | `vol2_messagehooks` | `messagehooks` | 消息钩子 | text | ⬜ |
| 95 | `vol2_eventhooks` | `eventhooks` | 事件钩子 | csv | ⬜ |

### 2.11 浏览器痕迹 (Browser) - 5个 ⭐独有
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 96 | `vol2_iehistory` | `iehistory` | IE历史 | text | ⬜ |
| 97 | `vol2_chromehistory` | `chromehistory` | Chrome历史 | text | ⬜ |
| 98 | `vol2_firefoxhistory` | `firefoxhistory` | Firefox历史 | text | ⬜ |
| 99 | `vol2_trustrecords` | `trustrecords` | Office信任 | text | ⬜ |
| 100 | `vol2_prefetch` | `prefetch` | 预读文件 | csv | ⬜ |

### 2.12 加密分析 (Encryption) - 3个 ⭐独有
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 101 | `vol2_bitlocker` | `bitlocker` | BitLocker密钥 | text | ⬜ |
| 102 | `vol2_truecryptsummary` | `truecryptsummary` | TrueCrypt摘要 | text | ⬜ |
| 103 | `vol2_truecryptmaster` | `truecryptmaster` | TrueCrypt主密钥 | text | ⬜ |

### 2.13 其他分析 (Misc) - 5个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 104 | `vol2_timeliner` | `timeliner` | 时间线 | csv | ⬜ |
| 105 | `vol2_mutantscan` | `mutantscan` | 互斥对象 | csv | ⬜ |
| 106 | `vol2_atomscan` | `atomscan` | 原子表 | csv | ⬜ |
| 107 | `vol2_sessions` | `sessions` | 会话 | csv | ⬜ |
| 108 | `vol2_bigpools` | `bigpools` | 大内存池 | csv | ⬜ |

### 2.14 数据导出 (Dump) - 4个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 109 | `vol2_procdump` | `procdump` | 进程导出 | dump | ⬜ |
| 110 | `vol2_memdump` | `memdump` | 内存导出 | dump | ⬜ |
| 111 | `vol2_dlldump` | `dlldump` | DLL导出 | dump | ⬜ |
| 112 | `vol2_vaddump` | `vaddump` | VAD导出 | dump | ⬜ |

---

## 三、Volatility 3 工具 (63个)

### 3.1 系统信息 (System) - 4个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 113 | `vol3_info` | `windows.info` | 系统信息 | csv | ⬜ |
| 114 | `vol3_crashinfo` | `windows.crashinfo` | 崩溃信息 | text | ⬜ |
| 115 | `vol3_verinfo` | `windows.verinfo` | 版本信息 | csv | ⬜ |
| 116 | `vol3_envars` | `windows.envars` | 环境变量 | csv | ⬜ |

### 3.2 进程分析 (Process) - 14个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 117 | `vol3_pslist` | `windows.pslist` | 进程列表 | csv | ⬜ |
| 118 | `vol3_psscan` | `windows.psscan` | 进程扫描 | csv | ⬜ |
| 119 | `vol3_pstree` | `windows.pstree` | 进程树 | csv | ⬜ |
| 120 | `vol3_psxview` | `windows.psxview` | 跨视图检测 | csv | ⬜ |
| 121 | `vol3_cmdline` | `windows.cmdline` | 命令行 | csv | ⬜ |
| 122 | `vol3_dlllist` | `windows.dlllist` | DLL列表 | csv | ⬜ |
| 123 | `vol3_handles` | `windows.handles` | 句柄 | csv | ⬜ |
| 124 | `vol3_getsids` | `windows.getsids` | SID列表⭐ | csv | ⬜ |
| 125 | `vol3_privileges` | `windows.privileges` | 权限 | csv | ⬜ |
| 126 | `vol3_ldrmodules` | `windows.ldrmodules` | LDR模块 | csv | ⬜ |
| 127 | `vol3_vadinfo` | `windows.vadinfo` | VAD信息 | csv | ⬜ |
| 128 | `vol3_vadwalk` | `windows.vadwalk` | VAD遍历 | csv | ⬜ |
| 129 | `vol3_sessions` | `windows.sessions` | 会话 | csv | ⬜ |
| 130 | `vol3_joblinks` | `windows.joblinks` | 作业对象 | csv | ⬜ |

### 3.3 线程分析 (Threads) - 4个 ⭐独有
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 131 | `vol3_threads` | `windows.threads` | 线程列表 | csv | ⬜ |
| 132 | `vol3_thrdscan` | `windows.thrdscan` | 线程扫描 | csv | ⬜ |
| 133 | `vol3_suspicious_threads` | `windows.suspicious_threads` | 可疑线程 | csv | ⬜ |
| 134 | `vol3_suspended_threads` | `windows.suspended_threads` | 挂起线程 | csv | ⬜ |

### 3.4 网络分析 (Network) - 2个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 135 | `vol3_netscan` | `windows.netscan` | 网络扫描 | csv | ⬜ |
| 136 | `vol3_netstat` | `windows.netstat` | 网络状态 | csv | ⬜ |

### 3.5 文件系统 (Filesystem) - 2个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 137 | `vol3_filescan` | `windows.filescan` | 文件扫描 | csv | ⬜ |
| 138 | `vol3_dumpfiles` | `windows.dumpfiles` | 文件导出 | dump | ⬜ |

### 3.6 注册表分析 (Registry) - 5个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 139 | `vol3_hivelist` | `windows.registry.hivelist` | Hive列表 | csv | ⬜ |
| 140 | `vol3_hivescan` | `windows.registry.hivescan` | Hive扫描 | csv | ⬜ |
| 141 | `vol3_printkey` | `windows.registry.printkey` | 键值 | csv | ⬜ |
| 142 | `vol3_userassist` | `windows.registry.userassist` | UserAssist | csv | ⬜ |
| 143 | `vol3_certificates` | `windows.registry.certificates` | 证书 | csv | ⬜ |

### 3.7 凭据提取 (Credentials) - 3个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 144 | `vol3_hashdump` | `windows.hashdump` | SAM哈希 | text | ⬜ |
| 145 | `vol3_lsadump` | `windows.lsadump` | LSA | text | ⬜ |
| 146 | `vol3_cachedump` | `windows.cachedump` | 缓存凭据 | text | ⬜ |

### 3.8 恶意检测 (Malware) - 6个 ⭐最强
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 147 | `vol3_malfind` | `windows.malfind` | 代码注入 | csv | ⬜ |
| 148 | `vol3_hollowprocesses` | `windows.hollowprocesses` | 进程镂空⭐ | csv | ⬜ |
| 149 | `vol3_processghosting` | `windows.processghosting` | 进程幽灵⭐ | csv | ⬜ |
| 150 | `vol3_skeleton_key` | `windows.skeleton_key_check` | 骨架密钥 | csv | ⬜ |
| 151 | `vol3_direct_syscalls` | `windows.direct_system_calls` | 直接调用⭐ | csv | ⬜ |
| 152 | `vol3_indirect_syscalls` | `windows.indirect_system_calls` | 间接调用⭐ | csv | ⬜ |

### 3.9 内核分析 (Kernel) - 9个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 153 | `vol3_modules` | `windows.modules` | 内核模块 | csv | ⬜ |
| 154 | `vol3_modscan` | `windows.modscan` | 模块扫描 | csv | ⬜ |
| 155 | `vol3_driverscan` | `windows.driverscan` | 驱动扫描 | csv | ⬜ |
| 156 | `vol3_drivermodule` | `windows.drivermodule` | 驱动模块 | csv | ⬜ |
| 157 | `vol3_driverirp` | `windows.driverirp` | IRP | csv | ⬜ |
| 158 | `vol3_ssdt` | `windows.ssdt` | SSDT表 | csv | ⬜ |
| 159 | `vol3_callbacks` | `windows.callbacks` | 回调 | csv | ⬜ |
| 160 | `vol3_timers` | `windows.timers` | 定时器 | csv | ⬜ |
| 161 | `vol3_devicetree` | `windows.devicetree` | 设备树 | csv | ⬜ |

### 3.10 服务分析 (Services) - 3个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 162 | `vol3_getservicesids` | `windows.getservicesids` | 服务SID | csv | ⬜ |
| 163 | `vol3_svclist` | `windows.svclist` | 服务列表 | csv | ⬜ |
| 164 | `vol3_svcdiff` | `windows.svcdiff` | 服务差异 | csv | ⬜ |

### 3.11 内存池 (Pools) - 2个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 165 | `vol3_bigpools` | `windows.bigpools` | 大内存池 | csv | ⬜ |
| 166 | `vol3_poolscanner` | `windows.poolscanner` | 池扫描 | csv | ⬜ |

### 3.12 其他分析 (Misc) - 6个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 167 | `vol3_strings` | `windows.strings` | 字符串 | csv | ⬜ |
| 168 | `vol3_symlinkscan` | `windows.symlinkscan` | 符号链接 | csv | ⬜ |
| 169 | `vol3_mutantscan` | `windows.mutantscan` | 互斥对象 | csv | ⬜ |
| 170 | `vol3_mbrscan` | `windows.mbrscan` | MBR扫描 | csv | ⬜ |
| 171 | `vol3_shimcachemem` | `windows.shimcachemem` | Shimcache | csv | ⬜ |
| 172 | `vol3_iat` | `windows.iat` | 导入表 | csv | ⬜ |

### 3.13 数据导出 (Dump) - 3个
| # | 工具名 | 插件 | 功能 | 输出 | 状态 |
|---|--------|------|------|------|------|
| 173 | `vol3_procdump` | `windows.pslist --dump` | 进程导出 | dump | ⬜ |
| 174 | `vol3_memmap` | `windows.memmap --dump` | 内存映射 | dump | ⬜ |
| 175 | `vol3_pedump` | `windows.pedump` | PE导出 | dump | ⬜ |

---

## 四、实现进度

| 引擎 | 总数 | 已完成 | 进度 |
|------|------|--------|------|
| 搜索工具 | 6 | 6 | ✅ 100% |
| MemProcFS | 36 | 36 | ✅ 100% |
| Volatility 2 | 77 | 77 | ✅ 100% |
| Volatility 3 | 63 | 63 | ✅ 100% |
| **总计** | **182** | **182** | **✅ 100%** |

---

## 五、构建顺序

### Phase 1: 核心基础 (优先)
1. MemProcFS 加载器 + 基础工具
2. Vol2/Vol3 命令执行器
3. 进程分析工具
4. 网络分析工具

### Phase 2: 取证分析
5. 注册表分析
6. 文件系统分析
7. 凭据提取
8. 恶意检测

### Phase 3: 高级功能
9. 时间线分析
10. 内核分析
11. GUI/浏览器分析 (Vol2独有)
12. 数据导出

---

*最后更新: 2026-01-29*
