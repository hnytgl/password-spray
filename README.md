# 密码喷洒工具 Password Spray

**仅限授权的渗透测试使用。**

用小量密码对大量用户进行喷洒式认证测试，避免触发账户锁定策略。
与传统暴力破解相反——一个密码试所有用户，而不是对一个用户试所有密码。

## 支持的协议

| 协议   | 默认端口   | 依赖库            |
| ------ | ---------- | ----------------- |
| SMB    | 445        | impacket          |
| LDAP(S)| 389 / 636  | ldap3             |
| HTTP(S)| 80 / 443   | requests (+ ntlm) |
| SSH    | 22         | paramiko          |
| WinRM  | 5985 / 5986| requests          |

## 安装

```bash
git clone <本仓库地址>
cd password-spray
pip install -r requirements.txt
```

## 快速开始

```bash
# SMB 喷洒（域控制器）
python spray.py smb -t 192.168.1.10 -U users.txt -P passwords.txt -d corp.local

# LDAPS 喷洒
python spray.py ldap -t dc.corp.local -U users.txt -P passwords.txt --ssl

# HTTP Basic 认证喷洒
python spray.py http -t https://mail.corp.com/owa -U users.txt -P passwords.txt --http-method basic

# SSH 喷洒
python spray.py ssh -t 192.168.1.10 -U users.txt -P passwords.txt

# WinRM 喷洒
python spray.py winrm -t 192.168.1.10 -U users.txt -P passwords.txt
```

## 密码来源（三种方式可同时使用）

### 1. 密码文件 `-P`

```bash
python spray.py smb -t 10.0.0.1 -U users.txt -P passwords.txt -d corp
```

文件格式（每行一个密码，`#` 开头为注释）：
```
# 常见季节性密码
Spring2026!
Summer2026!
P@ssw0rd
```

### 2. 命令行指定 `-p`

```bash
# 单个密码
python spray.py smb -t 10.0.0.1 -U users.txt -p "Spring2026!" -d corp

# 多个密码（可重复使用 -p）
python spray.py smb -t 10.0.0.1 -U users.txt \
  -p "Spring2026!" -p "Summer2026!" -p "P@ssw0rd" -d corp
```

### 3. 模板生成 `--generate`

```bash
# 生成: Spring2024!, Summer2024!, ..., Winter2026!
python spray.py smb -t 10.0.0.1 -U users.txt \
  --generate "{Season}{Year}{Special}" -d corp

# 多个模板同时使用
python spray.py smb -t 10.0.0.1 -U users.txt \
  --generate "{Season}{Year}{Special}" \
  --generate "{Company}{Number}!" \
  --company "Acme" -d corp
```

#### 模板变量

| 变量              | 展开结果                                              |
| ----------------- | ----------------------------------------------------- |
| `{Season}`        | Spring, Summer, Fall, Winter                          |
| `{season}`        | spring, summer, fall, winter                          |
| `{Month}`         | January - December                                    |
| `{month}`         | january - december                                    |
| `{Mon}`           | Jan - Dec                                             |
| `{mon}`           | jan - dec                                             |
| `{Day}`           | 01 - 31                                               |
| `{day}`           | 1 - 31                                                |
| `{Year}`          | 当前年份 ± 1（如 2025, 2026, 2027）                    |
| `{Year2024}`      | 指定年份 2024                                          |
| `{Special}`       | !, @, #, !!, 123, 123!, 123456, ...                   |
| `{Number}`        | 0 - 99                                                |
| `{Number999}`     | 0 - 999                                               |
| `{Company}`       | 自定义公司名（需 `--company`）                          |
| `{company}`       | 小写公司名                                             |
| `{City}`          | London, Paris, Berlin, Tokyo, ...                     |
| `{city}`          | london, paris, berlin, ...                            |
| `{Word}`          | Password, Welcome, Admin, Company, ...                |
| `{word}`          | password, welcome, admin, ...                         |

#### 模板示例

```bash
# 季节性密码: Spring2026!, Summer2026!, Fall2026!, ...
--generate "{Season}{Year}{Special}"

# 公司名+数字+特殊符: Acme1!, Acme2!, ...
--generate "{Company}{Number}!" --company "Acme"

# 月份+年份: January2026, February2026, ...
--generate "{Month}{Year}"

# 城市+数字: London1, London2, ... London99
--generate "{City}{Number}"

# 常见词+特殊符: Password!, Welcome!, Admin!, ...
--generate "{Word}{Special}"

# 组合：文件 + 自定义 + 模板
python spray.py smb -t 10.0.0.1 -U users.txt \
  -P common.txt \
  -p "MyCustomP@ss1" \
  --generate "{Season}{Year}!" \
  --company "Contoso" -d corp
```

## 常用参数

| 参数                | 默认值 | 说明                          |
| ------------------- | ------ | ----------------------------- |
| `-t, --target`      | 必填   | 目标 IP 或主机名               |
| `-U, --users`       | 必填   | 用户名文件，每行一个            |
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

## 各协议专属参数

### SMB
```
-d, --domain     域名 (如 CORP)
```

### LDAP
```
--ssl            使用 LDAPS (端口 636)
--port PORT      自定义端口
```

### HTTP
```
--http-method    basic | ntlm | digest | form
-d, --domain     域名 (NTLM 认证时使用)
--form-url       POST 登录地址 (表单认证)
--form-success   登录成功标记字符串
--form-extra     额外表单字段: key=val,key=val
--no-ssl-verify  跳过 TLS 证书验证
```

### SSH
```
--port PORT      SSH 端口 (默认 22)
```

### WinRM
```
--ssl / --no-ssl 使用 HTTPS (5986) 或 HTTP (5985)
--port PORT      自定义端口
```

## 断点续传

```bash
# 第一次运行 — 每轮自动保存进度
python spray.py smb -t 10.0.0.5 -U users.txt -P passwords.txt --state-file spray.json

# 按 Ctrl+C 中断后，下次恢复:
python spray.py smb -t 10.0.0.5 -U users.txt -P passwords.txt --state-file spray.json --resume
```

## 输出示例

终端实时显示：

```
  [+] alice : Spring2026!        ← 成功
  [!] 账户已锁定: bob             ← 锁定

  [*] 487/1000 (49%)  |  2 成功  |  1 锁定   ← 进度条
```

完成后显示汇总，如果指定了 `--output` 则导出 CSV 或 JSON。

## 安全特性

- **保守默认值** — 5 线程、1 秒间隔、5 分钟轮间冷却
- **试运行模式** — `--dry-run` 先验证所有输入再执行
- **锁定检测** — SMB 和 LDAP 协议会自动识别账户锁定
- **断点续传** — 中断后可恢复，不丢失已完成轮次的进度
- **单目标设计** — 只对一个目标喷洒多个用户，不是网络扫描器

## 免责声明

本工具仅供**授权的安全评估**使用。
在未获得系统所有者书面授权的情况下使用本工具是非法的。
作者对任何滥用行为不承担责任。
