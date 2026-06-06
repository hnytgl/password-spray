from protocols.base import AuthResult, BaseProtocol, Result


class WinRMProtocol(BaseProtocol):
    name = "winrm"

    def authenticate(
        self, target, user, password, use_ssl=True, port=None,
        timeout=15, **kwargs
    ):
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            from urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "requests not installed. Run: pip install requests")

        if port is None:
            port = 5986 if use_ssl else 5985

        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{target}:{port}/wsman"

        try:
            r = requests.get(url, auth=HTTPBasicAuth(user, password),
                             timeout=timeout, verify=False)
            if r.status_code == 200:
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "WinRM authentication successful")
            elif r.status_code == 401:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "HTTP 401 Unauthorized")
            elif r.status_code == 403:
                return AuthResult(Result.FAILURE, target, user, password,
                                  "HTTP 403 Forbidden")
            else:
                return AuthResult(Result.FAILURE, target, user, password,
                                  f"HTTP {r.status_code}")
        except requests.exceptions.Timeout:
            return AuthResult(Result.TIMEOUT, target, user, password,
                              "Request timed out")
        except requests.exceptions.ConnectionError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection error")
        except Exception as e:
            return AuthResult(Result.ERROR, target, user, password, str(e))
