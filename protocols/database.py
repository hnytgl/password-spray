import socket

from protocols.base import AuthResult, BaseProtocol, Result


class MySQLProtocol(BaseProtocol):
    name = "mysql"

    def authenticate(
        self, target, user, password, port=3306, timeout=10, **kwargs
    ):
        try:
            import pymysql
            conn = pymysql.connect(
                host=target, port=port, user=user, password=password,
                connect_timeout=timeout, read_timeout=timeout,
            )
            conn.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "MySQL authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "pymysql not installed. Run: pip install pymysql")
        except pymysql.err.OperationalError as e:
            code, msg = e.args
            if code == 1045:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Access denied for user")
            if code in (1130, 1129):
                return AuthResult(Result.ERROR, target, user, password,
                                  f"Host blocked: {msg}")
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


class PostgreSQLProtocol(BaseProtocol):
    name = "postgresql"

    def authenticate(
        self, target, user, password, port=5432, timeout=10, **kwargs
    ):
        try:
            import pg8000
            conn = pg8000.connect(
                host=target, port=port, user=user, password=password,
                timeout=timeout,
            )
            conn.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "PostgreSQL authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "pg8000 not installed. Run: pip install pg8000")
        except pg8000.exceptions.InterfaceError as e:
            msg = str(e)
            if "Authentication failed" in msg or "password" in msg.lower():
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Invalid credentials")
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


class MSSQLProtocol(BaseProtocol):
    name = "mssql"

    def authenticate(
        self, target, user, password, port=1433, timeout=10, **kwargs
    ):
        try:
            import pymssql
            conn = pymssql.connect(
                server=target, port=port, user=user, password=password,
                timeout=timeout, login_timeout=timeout,
            )
            conn.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "MSSQL authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "pymssql not installed. Run: pip install pymssql")
        except pymssql.OperationalError as e:
            msg = str(e)
            if "Login failed" in msg or "18456" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Login failed")
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
        except OSError as e:
            return AuthResult(Result.ERROR, target, user, password,
                              f"Network error: {e}")
        except Exception as e:
            return AuthResult(Result.ERROR, target, user, password, str(e))


class OracleProtocol(BaseProtocol):
    name = "oracle"

    def authenticate(
        self, target, user, password, port=1521, sid="XE",
        timeout=10, **kwargs
    ):
        try:
            import oracledb
            oracledb.defaults.config_dir = ""
            conn = oracledb.connect(
                user=user, password=password,
                dsn=f"{target}:{port}/{sid}",
                timeout=timeout,
            )
            conn.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "Oracle authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "oracledb not installed. Run: pip install oracledb")
        except oracledb.DatabaseError as e:
            err_obj = e.args[0] if e.args else None
            code = err_obj.code if err_obj else 0
            if code in (1017,):  # ORA-01017: invalid username/password
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Invalid credentials")
            if code in (28000, 28001, 28002):  # account locked/expired
                return AuthResult(Result.LOCKOUT, target, user, password,
                                  "Account locked/expired")
            return AuthResult(Result.FAILURE, target, user, password,
                              f"ORA-{code}: {err_obj.message if err_obj else e}")
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


class MongoDBProtocol(BaseProtocol):
    name = "mongodb"

    def authenticate(
        self, target, user, password, port=27017, auth_db="admin",
        timeout=10, **kwargs
    ):
        try:
            from pymongo import MongoClient
            uri = (
                f"mongodb://{user}:{password}@{target}:{port}/"
                f"{auth_db}?authSource={auth_db}"
                f"&connectTimeoutMS={int(timeout * 1000)}"
                f"&serverSelectionTimeoutMS={int(timeout * 1000)}"
            )
            client = MongoClient(uri)
            client.admin.command("ping")
            client.close()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "MongoDB authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "pymongo not installed. Run: pip install pymongo")
        except Exception as e:
            msg = str(e)
            if "Authentication failed" in msg:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "Authentication failed")
            if "timed out" in msg.lower() or "timeout" in msg.lower():
                return AuthResult(Result.TIMEOUT, target, user, password,
                                  "Connection timed out")
            if "connection refused" in msg.lower():
                return AuthResult(Result.ERROR, target, user, password,
                                  "Connection refused")
            return AuthResult(Result.FAILURE, target, user, password, msg)


class RedisProtocol(BaseProtocol):
    name = "redis"

    def authenticate(
        self, target, user, password, port=6379, timeout=10, **kwargs
    ):
        try:
            import redis as redis_py
            pool = redis_py.ConnectionPool(
                host=target, port=port, password=password,
                socket_connect_timeout=timeout,
                socket_timeout=timeout,
            )
            client = redis_py.Redis(connection_pool=pool)
            info = client.ping()
            client.close()
            pool.disconnect()
            return AuthResult(Result.SUCCESS, target, user, password,
                              "Redis authentication successful")
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "redis not installed. Run: pip install redis")
        except redis_py.AuthenticationError:
            return AuthResult(Result.FAILURE, target, user, password,
                              "Invalid credentials")
        except redis_py.TimeoutError:
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
