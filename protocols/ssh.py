import socket

from protocols.base import AuthResult, BaseProtocol, Result


class SSHProtocol(BaseProtocol):
    name = "ssh"

    def authenticate(
        self, target, user, password, port=22, timeout=10, **kwargs
    ):
        try:
            import paramiko
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "paramiko not installed. Run: pip install paramiko")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                target, port=port, username=user, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False,
                banner_timeout=timeout, auth_timeout=timeout,
            )
            client.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "SSH authentication successful")
        except paramiko.AuthenticationException:
            return AuthResult(Result.FAILURE, target, user, password,
                              "Invalid credentials")
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
