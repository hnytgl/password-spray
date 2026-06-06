import socket

from protocols.base import AuthResult, BaseProtocol, Result


class SMBProtocol(BaseProtocol):
    name = "smb"

    def authenticate(
        self, target, user, password, domain="", port=445, timeout=10, **kwargs
    ):
        _user = user
        _domain = domain
        if "\\" in _user:
            _domain, _user = _user.split("\\", 1)
        elif "@" in _user and not _domain:
            _user, _domain = _user.split("@", 1)

        try:
            from impacket.smbconnection import SMBConnection, SessionError

            conn = SMBConnection(target, target, timeout=timeout)
            conn.login(_user, password, domain=_domain)
            conn.logoff()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "SMB authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "impacket not installed. Run: pip install impacket")
        except SessionError as e:
            msg = str(e)
            if "STATUS_LOGON_FAILURE" in msg or "STATUS_LOGON_TYPE_NOT_GRANTED" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Invalid credentials")
            if "STATUS_ACCOUNT_LOCKED_OUT" in msg:
                return AuthResult(Result.LOCKOUT, target, user, password,
                                  "Account locked out")
            if "STATUS_PASSWORD_EXPIRED" in msg:
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "Auth succeeded (password expired)")
            if "STATUS_ACCOUNT_DISABLED" in msg or "STATUS_ACCOUNT_EXPIRED" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Account disabled/expired")
            if "STATUS_PASSWORD_MUST_CHANGE" in msg:
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "Auth succeeded (password must change)")
            return AuthResult(Result.ERROR, target, user, password, msg)
        except socket.timeout:
            return AuthResult(Result.TIMEOUT, target, user, password,
                              "Connection timed out")
        except ConnectionRefusedError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection refused")
        except OSError as e:
            return AuthResult(Result.ERROR, target, user, password,
                              f"Network error: {e}")
