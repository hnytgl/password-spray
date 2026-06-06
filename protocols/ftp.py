import socket

from protocols.base import AuthResult, BaseProtocol, Result


class FTPProtocol(BaseProtocol):
    name = "ftp"

    def authenticate(
        self, target, user, password, port=21, timeout=10, **kwargs
    ):
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=timeout)
            ftp.connect(target, port, timeout=timeout)
            ftp.login(user, password)
            ftp.quit()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "FTP login successful")
        except ImportError:
            # ftplib is built-in, but just in case
            return AuthResult(Result.ERROR, target, user, password,
                              "ftplib not available")
        except ftplib.error_perm as e:
            msg = str(e)
            if "530" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Login incorrect")
            if "530 User" in msg and "cannot log in" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "User cannot log in")
            return AuthResult(Result.FAILURE, target, user, password, msg)
        except socket.timeout:
            return AuthResult(Result.TIMEOUT, target, user, password,
                              "Connection timed out")
        except ConnectionRefusedError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection refused")
        except OSError as e:
            return AuthResult(Result.ERROR, target, user, password,
                              f"Network error: {e}")
        except Exception as e:
            return AuthResult(Result.ERROR, target, user, password, str(e))
