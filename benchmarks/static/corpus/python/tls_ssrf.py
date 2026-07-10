# Feature gaps closed: insecure TLS (CWE-295, GF-426) and SSRF (CWE-918, GF-427).
import requests


def vuln_tls():
    requests.get("https://api.example.com", verify=False)  # EXPECT GF-426


def vuln_ssrf(user_url):
    requests.get(user_url)  # EXPECT GF-427


def safe_request():
    requests.get("https://api.example.com", verify=True)  # safe: literal + verify


def safe_kwarg_suffix(item):
    # `delete_after_verify=False` must NOT match the `verify=False` TLS marker.
    item.delete(delete_after_verify=False)
