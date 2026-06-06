import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from protocols.base import AuthResult, BaseProtocol, Result


class HTTPProtocol(BaseProtocol):
    name = "http"

    def authenticate(
        self, target, user, password,
        method="basic", domain="",
        form_url=None, form_user_field="username", form_pass_field="password",
        form_success=None, form_extra=None,
        timeout=15, verify_ssl=False, **kwargs
    ):
        try:
            if method == "basic":
                return self._try_basic(target, user, password, timeout, verify_ssl)
            elif method == "ntlm":
                return self._try_ntlm(target, user, password, domain, timeout,
                                      verify_ssl)
            elif method == "digest":
                return self._try_digest(target, user, password, timeout, verify_ssl)
            elif method == "form":
                return self._try_form(target, user, password, form_url,
                                      form_user_field, form_pass_field,
                                      form_success, form_extra,
                                      timeout, verify_ssl)
            else:
                return AuthResult(Result.ERROR, target, user, password,
                                  f"Unknown HTTP auth method: {method}")
        except requests.exceptions.Timeout:
            return AuthResult(Result.TIMEOUT, target, user, password,
                              "Request timed out")
        except requests.exceptions.ConnectionError:
            return AuthResult(Result.ERROR, target, user, password,
                              "Connection error")
        except requests.exceptions.SSLError:
            return AuthResult(Result.ERROR, target, user, password,
                              "SSL verification failed (use --no-ssl-verify to skip)")

    def _try_basic(self, target, user, password, timeout, verify_ssl):
        r = requests.get(target, auth=HTTPBasicAuth(user, password),
                         timeout=timeout, verify=verify_ssl,
                         allow_redirects=False)
        if r.status_code in (200, 301, 302):
            return AuthResult(Result.SUCCESS, target, user, password,
                              f"HTTP {r.status_code}")
        elif r.status_code == 401:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 401 Unauthorized")
        elif r.status_code == 403:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 403 Forbidden")
        else:
            return AuthResult(Result.FAILURE, target, user, password,
                              f"HTTP {r.status_code}")

    def _try_ntlm(self, target, user, password, domain, timeout, verify_ssl):
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            return AuthResult(Result.ERROR, target, user, password,
                              "requests-ntlm not installed. "
                              "Run: pip install requests-ntlm")

        ntlm_user = user
        if domain and "\\" not in ntlm_user:
            ntlm_user = f"{domain}\\{user}"

        r = requests.get(target, auth=HttpNtlmAuth(ntlm_user, password),
                         timeout=timeout, verify=verify_ssl,
                         allow_redirects=False)
        if r.status_code in (200, 301, 302):
            return AuthResult(Result.SUCCESS, target, user, password,
                              f"HTTP {r.status_code}")
        elif r.status_code == 401:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 401 Unauthorized")
        elif r.status_code == 403:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 403 Forbidden")
        else:
            return AuthResult(Result.FAILURE, target, user, password,
                              f"HTTP {r.status_code}")

    def _try_digest(self, target, user, password, timeout, verify_ssl):
        r = requests.get(target, auth=HTTPDigestAuth(user, password),
                         timeout=timeout, verify=verify_ssl,
                         allow_redirects=False)
        if r.status_code in (200, 301, 302):
            return AuthResult(Result.SUCCESS, target, user, password,
                              f"HTTP {r.status_code}")
        elif r.status_code == 401:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 401 Unauthorized")
        elif r.status_code == 403:
            return AuthResult(Result.FAILURE, target, user, password,
                              "HTTP 403 Forbidden")
        else:
            return AuthResult(Result.FAILURE, target, user, password,
                              f"HTTP {r.status_code}")

    def _try_form(self, target, user, password, form_url, user_field, pass_field,
                  success_indicator, extra, timeout, verify_ssl):
        login_url = form_url or target
        data = {user_field: user, pass_field: password}
        if extra:
            for pair in extra.split(","):
                k, _, v = pair.partition("=")
                data[k.strip()] = v.strip()

        r = requests.post(login_url, data=data, timeout=timeout,
                          verify=verify_ssl, allow_redirects=True)

        if success_indicator:
            if success_indicator.lower() in r.text.lower():
                return AuthResult(Result.SUCCESS, target, user, password,
                                  "Success indicator found in response")
            return AuthResult(Result.FAILURE, target, user, password,
                              "Success indicator not found")

        if r.status_code == 200 and len(r.history) > 0:
            return AuthResult(Result.SUCCESS, target, user, password,
                              "HTTP 200 after redirect")
        elif r.status_code in (200, 302):
            return AuthResult(Result.SUCCESS, target, user, password,
                              f"HTTP {r.status_code}")
        else:
            return AuthResult(Result.FAILURE, target, user, password,
                              f"HTTP {r.status_code}")
