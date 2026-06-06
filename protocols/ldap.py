import socket

from protocols.base import AuthResult, BaseProtocol, Result


class LDAPProtocol(BaseProtocol):
    name = "ldap"

    def authenticate(
        self, target, user, password, use_ssl=False, port=None, timeout=10, **kwargs
    ):
        if port is None:
            port = 636 if use_ssl else 389

        try:
            from ldap3 import ALL, Connection, Server

            server = Server(
                target, port=port, use_ssl=use_ssl,
                get_info=ALL, connect_timeout=timeout
            )
            conn = Connection(
                server, user=user, password=password,
                authentication="SIMPLE", receive_timeout=timeout,
                raise_exceptions=False,
            )

            bound = conn.bind()
            result_desc = conn.result.get("description", "")

            if bound:
                conn.unbind()
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "LDAP bind successful")

            conn.unbind()

            if result_desc == "invalidCredentials":
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Invalid credentials")
            if "locked" in result_desc.lower():
                return AuthResult(Result.LOCKOUT, target, user, password,
                                  "Account locked out")

            return AuthResult(Result.FAILURE, target, user, password,
                              f"Bind failed: {result_desc}")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "ldap3 not installed. Run: pip install ldap3")
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
