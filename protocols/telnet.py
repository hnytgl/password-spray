import socket
import telnetlib

from protocols.base import AuthResult, BaseProtocol, Result


class TelnetProtocol(BaseProtocol):
    name = "telnet"

    def authenticate(
        self, target, user, password, port=23, timeout=10, **kwargs
    ):
        try:
            tn = telnetlib.Telnet(target, port, timeout=timeout)
            tn.read_until(b"login: ", timeout=timeout)
            tn.write(user.encode("ascii", errors="ignore") + b"\n")
            tn.read_until(b"Password: ", timeout=timeout)
            tn.write(password.encode("ascii", errors="ignore") + b"\n")

            idx, _, _ = tn.expect(
                [b"login failed", b"incorrect", b"Login incorrect",
                 b"#", b"$", b">"],
                timeout=timeout,
            )
            tn.write(b"exit\n")
            tn.close()

            if idx == 3 or idx == 4 or idx == 5:
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "Telnet login successful")
            else:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Invalid credentials")
        except EOFError:
            return AuthResult(Result.FAILURE, target, user, password,
                              "Connection closed")
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
