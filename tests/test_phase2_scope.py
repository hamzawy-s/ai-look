import pytest

from adapters.adapter2.scope import ScopeEngine


def make_scope(**kwargs):
    kwargs.setdefault("allowed_hosts", {"t.local"})
    kwargs.setdefault("allowed_schemes", {"https"})
    return ScopeEngine(**kwargs)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api", True),
        ("/api/users", True),
        ("/apifoo", False),
        ("/api2", False),
        ("/", False),
    ],
)
def test_path_prefix_boundary(path, expected):
    scope = make_scope(allowed_path_prefixes=("/api",))
    assert scope.is_authorized(f"https://t.local{path}") is expected


def test_admin_prefix_rejects_api_target():
    scope = make_scope(allowed_path_prefixes=("/admin",))
    assert scope.is_authorized("https://t.local/api/users") is False


def test_out_of_scope_host_rejected():
    scope = make_scope()
    assert scope.is_authorized("https://evil.local/api") is False


def test_disallowed_scheme_rejected():
    scope = make_scope()
    assert scope.is_authorized("http://t.local/api") is False


def test_userinfo_rejected():
    scope = make_scope()
    assert scope.is_authorized("https://user:pw@t.local/api") is False


def test_method_enforced():
    scope = make_scope(allowed_methods={"GET"})
    assert scope.is_authorized("https://t.local/api", "DELETE") is False
    assert scope.is_authorized("https://t.local/api", "GET") is True


def test_port_enforced():
    scope = make_scope(allowed_ports={8443})
    assert scope.is_authorized("https://t.local:8443/api") is True
    assert scope.is_authorized("https://t.local/api") is False


def test_malformed_url_rejected():
    scope = make_scope()
    assert scope.is_authorized("https://t.local:99999/api") is False
    assert scope.is_authorized("not a url") is False


def test_empty_allowlist_denies_everything():
    scope = ScopeEngine()
    assert scope.is_authorized("https://t.local/api") is False


def test_trailing_dot_host_normalized():
    scope = make_scope()
    assert scope.is_authorized("https://t.local./api") is True


def test_port_zero_rejected():
    scope = make_scope()
    assert scope.is_authorized("https://t.local:0/api") is False
    assert scope.is_authorized("http://t.local:0/api") is False


def test_empty_userinfo_rejected():
    scope = make_scope()
    assert scope.is_authorized("https://@t.local/api") is False


@pytest.mark.parametrize(
    "path",
    [
        "/api/../admin",
        "/api/./users",
        "/api/%2e%2e/admin",
        "/api/%2e./x",
        "/api/..%2fadmin",
        "/api//users",
        "/api/%2fusers",
    ],
)
def test_path_canonicalization_rejects_traversal(path):
    scope = make_scope(allowed_path_prefixes=("/api",))
    assert scope.is_authorized(f"https://t.local{path}") is False


def test_path_canonicalization_keeps_legitimate_paths():
    scope = make_scope(allowed_path_prefixes=("/api",))
    assert scope.is_authorized("https://t.local/api/v2/users") is True
    assert scope.is_authorized("https://t.local/api/user-profile") is True


@pytest.mark.parametrize(
    "address,allowed",
    [
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("fc00::1", True),
        ("100.64.0.1", False),
        ("192.0.2.1", False),
        ("224.0.0.1", False),
    ],
)
def test_validate_ip_lab_policy(address, allowed):
    assert make_scope().validate_ip(address, allow_private=True) is allowed


def test_path_canonicalization_rejects_backslashes():
    scope = make_scope(allowed_path_prefixes=("/api",))
    assert scope.is_authorized(r"https://t.local/api\..\admin") is False
    assert scope.is_authorized("https://t.local/api/%5cadmin") is False