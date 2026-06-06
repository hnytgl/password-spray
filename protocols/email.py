import socket

from protocols.base import AuthResult, BaseProtocol, Result


class IMAPProtocol(BaseProtocol):
    name = "imap"

    def authenticate(
        self, target, user, password, port=143, use_ssl=False,
        timeout=10, **kwargs
    ):
        try:
            import imaplib
            if use_ssl:
                conn = imaplib.IMAP4_SSL(
                    target, port if port != 143 else 993,
                    timeout=timeout,
                )
            else:
                conn = imaplib.IMAP4(target, port, timeout=timeout)

            conn.login(user, password)
            conn.logout()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "IMAP login successful")

        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "imaplib not available")
        except imaplib.IMAP4.error as e:
            msg = str(e)
            if "authentication failed" in msg.lower():
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Authentication failed")
            if "LOGIN failed" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "LOGIN failed")
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


class POP3Protocol(BaseProtocol):
    name = "pop3"

    def authenticate(
        self, target, user, password, port=110, use_ssl=False,
        timeout=10, **kwargs
    ):
        try:
            import poplib
            if use_ssl:
                conn = poplib.POP3_SSL(
                    target, port if port != 110 else 995,
                    timeout=timeout,
                )
            else:
                conn = poplib.POP3(target, port, timeout=timeout)

            conn.user(user)
            conn.pass_(password)
            conn.quit()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "POP3 login successful")

        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "poplib not available")
        except poplib.error_proto as e:
            msg = str(e)
            if "-ERR" in msg:
                if "log" in msg.lower() or "auth" in msg.lower():
                    return AuthResult(Result.FAILURE, target, user, password,
                                      "Authentication failed")
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
