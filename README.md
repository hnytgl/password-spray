# 密码喷洒工具 Password Spray

**仅限授权的渗透测试使用。**

用小量密码对大量用户进行喷洒式认证测试，避免触发账户锁定策略。
与传统暴力破解相反——**一个密码试所有用户**，而不是对一个用户试所有密码。

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
| MySQL      | 3306     | pymysql   | MySQL       |
| PostgreSQL | 5432     | pg8000    | PostgreSQL  |
| MSSQL      | 1433     | pymssql   | SQL Server  |
| Oracle     | 1521     | oracledb  | Oracle      |
| MongoDB    | 27017    | pymongo   | MongoDB     |
| Redis      | 6379     | redis-py  | Redis 缓存  |

### 邮件服务
| 协议 | 默认端口 | 依赖库              | 说明 |
| ---- | -------- | ------------------- | ---- |
| IMAP | 143/993  | imaplib(内置) | 邮件检索 |
| POP3 | 110/995  | poplib(内置)  | 邮件接收 |

## 安装

```bash
git clone <本仓库地址>
cd password-spray
pip install -r requirements.txt
```

按需安装部分依赖：

```bash
pip install colorama requests   # HTTP 基础
pip install impacket            # SMB
pip install ldap3               # LDAP
pip install paramiko            # SSH
pip install pymysql pg8000 pymssql oracledb pymongo redis  # 数据库
pip install vncdotool           # VNC
```

## 快速开始

```bash
# 一个密码喷洒所有 SMB 用户
python spray.py smb -t 192.168.1.10 -U users.txt -p 'Spring2026!' -d corp

# 多个密码逐个喷洒 LDAP 用户
python spray.py ldap -t dc.corp.local -U users.txt -p 'P@ssw0rd' -p 'Welcome1' --ssl

# SSH
python spray.py ssh -t 192.168.1.10 -U users.txt -p 'Welcome1'

# MySQL
python spray.py mysql -t 192.168.1.10 -U users.txt -p 'root'

# Redis（空密码）
python spray.py redis -t 192.168.1.10 -U users.txt -p ''

# 邮件
python spray.py imap -t mail.corp.com -U users.txt -p 'Spring2026!' --ssl
```

## 密码来源（两种方式可混用）

### 1. 命令行指定 `-p`（核心方式）

```
# 单个密码喷洒所有用户 ← 标准喷洒模式
python spray.py smb -t 10.0.0.1 -U users.txt -p 'Spring2026!' -d corp

# 多个密码（每个密码一轮，间互有冷静期）
python spray.py smb -t 10.0.0.1 -U users.txt -p 'Spring2026!' -p 'P@ssw0rd' -p 'Welcome1' -d corp

# 空密码（Redis/lDAP 等常见场景）
python spray.py redis -t 10.0.0.1 -U users.txt -p ''
```

### 2. 模板生成 `--generate`

```
# 生成 Spring2026! Summer2026! 等（每个密码一轮）
python spray.py smb -t 10.0.0.1 -U users.txt --generate '{Season}{Year}{Special}' -d corp

# 混用 -p 和 --generate
python spray.py smb -t 10.0.0.1 -U users.txt \
  -p 'P@ssw0rd' \
  --generate '{Season}{Year}{Special}' \
  --company 'Acme' -d corp
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
| `{Company}`     | 自定义公司名（`--company` 指定）              |
| `{company}`     | 小写公司名                                    |
| `{City}`        | London, Paris, Berlin, Tokyo ...             |
| `{city}`        | london, paris, berlin ...                    |
| `{Word}`        | Password, Welcome, Admin, Company ...        |
| `{word}`        | password, welcome, admin ...                 |

## 参数

| 参数                | 默认值 | 说明                          |
| ------------------- | ------ | ----------------------------- |
| `-t, --target`      | 必填   | 目标 IP 或主机名               |
| `-U, --users`       | 必填   | 用户列表文件，每行一个用户名    |
| `-p, --password`    | 必填   | 要喷洒的密码（可多次使用）      |
| `--generate`        | —      | 密码生成模板（可多次使用）      |
| `--company`         | —      | 模板 `{Company}` 的替换值      |
| `--year`            | 当前年  | 模板 `{Year}` 的基准年份       |
| `--threads N`       | 5      | 并发线程数                     |
| `--delay S`         | 1.0    | 每轮内尝试间隔（秒）            |
| `--round-delay S`   | 300    | 每轮之间冷却时间（秒）           |
| `-o, --output`      | —      | 结果输出文件 (.csv 或 .json)   |
| `--state-file`      | —      | 进度保存文件，支持断点续传       |
| `--resume`          | —      | 从状态文件恢复上次中断的喷洒      |
| `--dry-run`         | —      | 试运行，验证输入但不实际认证      |

## 各协议专属参数

| 协议 | 参数 | 说明 |
|------|------|------|
| smb | `-d, --domain` | Windows 域名 |
| ldap | `--ssl`, `--port` | LDAPS / 自定义端口 |
| http | `--http-method` | basic\|ntlm\|digest\|form |
| http | `--form-*` | 表单认证参数 |
| http | `--no-ssl-verify` | 跳过 TLS 验证 |
| ssh/winrm/telnet/ftp | `--port` | 自定义端口 |
| oracle | `--sid` | SID（默认 XE） |
| mongodb | `--auth-db` | 认证数据库（默认 admin） |
| imap/pop3 | `--ssl`, `--port` | 加密连接 / 自定义端口 |
| vnc | `--port` | 默认 5900 |

## 断点续传

```bash
# 第一轮运行 — 每轮自动保存进度
python spray.py smb -t 10.0.0.5 -U users.txt -p 'Spring2026!' --state-file spray.json

# Ctrl+C 中断后恢复:
python spray.py smb -t 10.0.0.5 -U users.txt -p 'Spring2026!' --state-file spray.json --resume
```

## 特性

- **16 种协议** — 网络服务、数据库、邮件、远程桌面全覆盖
- **喷洒模式** — 一个密码试所有用户，轮间有冷却避免锁定
- **模板生成** — 内置常用密码模式，无需外挂字典
- **断点续传** — 中断不丢失进度
- **锁定检测** — 自动识别并报告账户锁定
- **彩色输出** — 实时进度 + 成功/失败/锁定高亮
- **CSV/JSON 输出** — 结果导出

## 免责声明

本工具仅供**授权的安全评估**使用。
在未获得系统所有者书面授权的情况下使用本工具是非法的。
作者对任何滥用行为不承担责任。
