# 密码喷洒工具 Password Spray

**仅限授权的渗透测试使用。**

用小量密码对大量用户进行喷洒式认证测试，避免触发账户锁定策略。
与传统暴力破解相反——一个密码试所有用户，而不是对一个用户试所有密码。

## 支持的协议（16 种）

### 网络服务
| 协议     | 默认端口 | 依赖库          | 说明                |
| -------- | -------- | --------------- | ------------------- |
| SMB      | 445      | impacket        | Windows 文件共享    |
| LDAP(S)  | 389/636  | ldap3           | 目录服务            |
| HTTP(S)  | 80/443   | requests(+ntlm) | Web 认证(Basic/NTLM/Digest/Form) |
| SSH      | 22       | paramiko        | 远程 shell          |
| WinRM    | 5985/5986| requests        | Windows 远程管理    |
| Telnet   | 23       | telnetlib(内置) | 远程终端            |
| FTP      | 21       | ftplib(内置)    | 文件传输            |
| VNC      | 5900     | vncdotool       | 远程桌面            |

### 数据库
| 协议       | 默认端口 | 依赖库    | 说明        |
| ---------- | -------- | --------- | ----------- |
| MySQL      | 3306     | pymysql   | MySQL 数据库 |
| PostgreSQL | 5432     | pg8000    | PostgreSQL 数据库 |
| MSSQL      | 1433     | pymssql   | SQL Server 数据库 |
| Oracle     | 1521     | oracledb  | Oracle 数据库 |
| MongoDB    | 27017    | pymongo   | MongoDB 数据库 |
| Redis      | 6379     | redis-py  | Redis 缓存数据库 |

### 邮件服务
| 协议 | 默认端口 | 依赖库              | 说明 |
| ---- | -------- | ------------------- | ---- |
| IMAP | 143/993  | imaplib(内置) | 邮件检索 |
| POP3 | 110/995  | poplib(内置)  | 邮件接收 |

## 安装

```bash
git clone <本仓库地址>
cd password-spray

# 基础安装（仅核心协议）
pip install -r requirements.txt

# 或按需安装部分依赖
pip install colorama requests   # HTTP 基础
pip install impacket            # SMB
pip install ldap3               # LDAP
pip install paramiko            # SSH
pip install pymysql pg8000 pymssql oracledb pymongo redis  # 数据库
pip install vncdotool           # VNC
```

## 快速开始

```bash
# 网络服务
python spray.py smb   -t 192.168.1.10 -U users.txt -P passwords.txt -d corp.local
python spray.py ldap  -t dc.corp.local -U users.txt -P passwords.txt --ssl
python spray.py http  -t https://mail.corp.com -U users.txt --http-method basic
python spray.py ssh   -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py winrm -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py telnet -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py ftp   -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py vnc   -t 192.168.1.10 -P passwords.txt

# 数据库
python spray.py mysql     -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py postgresql -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py mssql     -t 192.168.1.10 -U users.txt -P passwords.txt
python spray.py oracle    -t 192.168.1.10 -U users.txt -P passwords.txt --sid ORCL
python spray.py mongodb   -t 192.168.1.10 -U users.txt -P passwords.txt --auth-db admin
python spray.py redis     -t 192.168.1.10 -P passwords.txt

# 邮件服务
python spray.py imap -t mail.corp.com -U users.txt -P passwords.txt --ssl
python spray.py pop3 -t mail.corp.com -U users.txt -P passwords.txt --ssl
```

## 密码来源（三种方式可同时使用）

### 1. 密码文件 `-P`

```
python spray.py smb -t 10.0.0.1 -U users.txt -P passwords.txt
```

### 2. 命令行指定 `-p`

```
# 单个或重复使用
python spray.py smb -t 10.0.0.1 -U users.txt -p "Spring2026!" -p "P@ssw0rd"

# Redis 空密码
python spray.py redis -t 10.0.0.1 -p ""
```

### 3. 模板生成 `--generate`

```
python spray.py smb -t 10.0.0.1 -U users.txt \
  --generate "{Season}{Year}{Special}" \
  --generate "{Company}{Number}!" \
  --company "Acme"
```

#### 模板变量

| 变量            | 展开结果                                    |
| --------------- | ------------------------------------------- |
| `{Season}`      | Spring, Summer, Fall, Winter                 |
| `{season}`      | spring, summer, fall, winter                 |
| `{Month}`       | January - December                           |
| `{month}`       | january - december                           |
| `{Mon}`         | Jan - Dec                                    |
| `{mon}`         | jan - dec                                    |
| `{Day}`         | 01 - 31                                      |
| `{day}`         | 1 - 31                                       |
| `{Year}`        | 当前年份 ± 1（如 2025, 2026, 2027）          |
| `{Year2024}`    | 指定年份 2024                                 |
| `{Special}`     | !, @, #, !!, 123, 123!, 123456 ...           |
| `{Number}`      | 0 - 99                                       |
| `{Number999}`   | 0 - 999                                      |
| `{Company}`     | 自定义公司名（需 `--company`）                |
| `{company}`     | 小写公司名                                    |
| `{City}`        | London, Paris, Berlin, Tokyo ...             |
| `{city}`        | london, paris, berlin ...                    |
| `{Word}`        | Password, Welcome, Admin, Company ...        |
| `{word}`        | password, welcome, admin ...                 |

## 通用参数

| 参数                | 默认值 | 说明                          |
| ------------------- | ------ | ----------------------------- |
| `-t, --target`      | 必填   | 目标 IP 或主机名               |
| `-U, --users`       | 必填¹  | 用户名文件，每行一个            |
| `-P, --passwords`   | —      | 密码字典文件                   |
| `-p, --password`    | —      | 直接指定密码（可多次使用）       |
| `--generate`        | —      | 密码生成模板（可多次使用）       |
| `--company`         | —      | 模板中 `{Company}` 的替换值    |
| `--year`            | 当前年  | 模板中 `{Year}` 的基准年份     |
| `--threads N`       | 5      | 并发线程数                     |
| `--delay S`         | 1.0    | 每轮内尝试间隔（秒）            |
| `--round-delay S`   | 300    | 每轮之间冷却时间（秒）           |
| `-o, --output`      | —      | 结果输出文件 (.csv 或 .json)   |
| `--state-file`      | —      | 进度保存文件，支持断点续传       |
| `--resume`          | —      | 从状态文件恢复上次中断的喷洒      |
| `--dry-run`         | —      | 试运行，验证输入但不实际认证      |

> ¹ `redis` 不需要 `-U`，但为了接口统一也接受用户文件，留空即可。

## 各协议专属参数

| 协议 | 参数 | 说明 |
|------|------|------|
| smb | `-d, --domain` | Windows 域名 |
| ldap | `--ssl`, `--port` | LDAPS / 自定义端口 |
| http | `--http-method` | basic\|ntlm\|digest\|form |
| http | `--form-*` | 表单认证参数 |
| http | `--no-ssl-verify` | 跳过 TLS 验证 |
| ssh | `--port` | 自定义端口（默认 22） |
| winrm | `--ssl / --no-ssl`, `--port` | 切换 HTTP/HTTPS |
| telnet | `--port` | 自定义端口（默认 23） |
| ftp | `--port` | 自定义端口（默认 21） |
| mysql | `--port` | 默认 3306 |
| postgresql | `--port` | 默认 5432 |
| mssql | `--port` | 默认 1433 |
| oracle | `--port`, `--sid` | 默认 1521，SID 默认 XE |
| mongodb | `--port`, `--auth-db` | 默认 27017，认证库默认 admin |
| redis | `--port` | 默认 6379 |
| imap | `--ssl`, `--port` | IMAPS (993) |
| pop3 | `--ssl`, `--port` | POP3S (995) |
| vnc | `--port` | 默认 5900 |

## 断点续传

```bash
# 第一次运行 — 每轮自动保存进度
python spray.py smb -t 10.0.0.5 -U users.txt -P passwords.txt --state-file spray.json

# 按 Ctrl+C 中断后恢复:
python spray.py smb -t 10.0.0.5 -U users.txt -P passwords.txt --state-file spray.json --resume
```

## 特性

- **16 种协议** — 覆盖网络服务、数据库、邮件、远程桌面
- **三源密码** — 文件 + 命令行 + 模板生成，自动去重合并
- **保守默认值** — 5 线程、1 秒间隔、5 分钟轮间冷却
- **试运行模式** — `--dry-run` 先验证所有输入再执行
- **锁定检测** — 自动识别账户锁定状态
- **断点续传** — 中断后可恢复，不丢失已完成轮次的进度
- **彩色输出** — 实时进度条 + 成功/失败高亮
- **CSV/JSON 输出** — 结果可导出用于报告

## 免责声明

本工具仅供**授权的安全评估**使用。
在未获得系统所有者书面授权的情况下使用本工具是非法的。
作者对任何滥用行为不承担责任。
