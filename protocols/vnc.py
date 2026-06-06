import socket

from protocols.base import AuthResult, BaseProtocol, Result


class VNCProtocol(BaseProtocol):
    name = "vnc"

    def authenticate(
        self, target, user, password, port=5900, timeout=10, **kwargs
    ):
        try:
            import vncdotool.api
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "vncdotool not installed. Run: pip install vncdotool")

        try:
            client = vncdotool.api.connect(
                f"{target}::{port}",
                password=password,
                timeout=timeout,
            )
            client.disconnect()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "VNC authentication successful")
        except vncdotool.command.VNCDoError as e:
            msg = str(e)
            if "Authentication" in msg or "auth" in msg.lower():
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Authentication failed")
            if "timeout" in msg.lower():
                return AuthResult(Result.TIMEOUT, target, user, password,
                                  "Connection timed out")
            return AuthResult(Result.FAILURE, target, user, password, msg)
        except socket.timeout:
            return AuthResult(Result.TIMEOUT, target, user, password,
                              "Connection timed out")
        except ConnectionRefusedError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection refused")
        except ConnectionResetError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection reset")
        except OSError as e:
            return AuthResult(Result.ERROR, target, user, password,
                              f"Network error: {e}")
        except Exception as e:
            return AuthResult(Result.ERROR, target, user, password, str(e))
