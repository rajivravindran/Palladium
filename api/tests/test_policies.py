"""Policy profiles: validation that mirrors the engine, versioned edits, the controller bundle."""
import pytest

from conftest import ADMIN, CONTAIN, NIGHT, POLICY, SENSOR, VIEWER

from river3_api import profiles


def _profile(name="pol-agent", **over):
    p = {
        "name": name, "kind": "ai_worker", "description": "test", "mode": "SHADOW_MODE",
        "decoys": ["/opt/config/.db_recovery_creds"], "protected_read": ["/root/.aws/**"],
        "read_allowed": ["/data/**"], "write_allowed": ["/out/**"],
        "exec_allowed_classes": ["INTERPRETER"], "exec_denied_classes": ["NET_CLIENT"],
        "egress_allowed": ["10.0.0.0/8"], "response": {"on_violation": "PAUSE_CONTAINER", "on_structural_guard": "ALERT"},
    }
    p.update(over)
    return p


def _save(c, body, base=0, who=ADMIN, comment="testing policy edits"):
    return c.put(f"/api/v1/policies/{body['name']}", headers=who,
                 json={"profile": body, "base_version": base, "comment": comment})


# --------------------------------------------------------------------- validation (mirrors policy/profile.go)

@pytest.mark.parametrize("pattern", ["/app/**", "/**", "/etc/shadow", "/var/log/*.log", "/a/[ab]c"])
def test_valid_patterns(pattern):
    assert profiles.check_pattern(pattern) == pattern


@pytest.mark.parametrize("pattern", ["app/x", "/app/", "/a/../b", "//a", "/a/./b", "/a*/**", "/a/**/b", "/a\\b",
                                     "/a/[bc", "/x (deleted)", ""])
def test_invalid_patterns(pattern):
    with pytest.raises(ValueError):
        profiles.check_pattern(pattern)


@pytest.mark.parametrize("cidr,ok", [("10.0.0.0/8", True), ("192.0.2.7/32", True), ("2001:db8::/32", True),
                                      ("10.0.0.1/8", False), ("10.0.0.1", False), ("::ffff:10.0.0.0/104", False),
                                      ("10.0.0.0/255.0.0.0", False), ("nope/8", False)])
def test_cidrs(cidr, ok):
    if ok:
        assert profiles.check_cidr(cidr) == cidr
    else:
        with pytest.raises(ValueError):
            profiles.check_cidr(cidr)


@pytest.mark.parametrize("rule", [
    "10.0.0.0/8",                  # cidr
    "10.0.0.0/8:443",              # cidr:port
    "10.0.0.0/8:8000-8100",        # cidr:range
    "2001:db8::/32",               # ipv6 cidr, any port
    "[2001:db8::/32]:443",         # ipv6 cidr with port
    "[2001:db8::1/128]:8000-8100",
    "api.openai.com",              # host
    "api.openai.com:443",          # host:port
    "api.openai.com:8000-8100",
    "*.github.com",                # wildcard host
    "*.github.com:443",
])
def test_valid_egress_rules(rule):
    assert profiles.check_egress_rule(rule) == rule
    clean, errors = profiles.validate(_profile(egress_allowed=[rule]))
    assert errors == [] and clean["egress_allowed"] == [rule]


@pytest.mark.parametrize("rule,reason", [
    ("https://api.openai.com", "schemes are not allowed"),
    ("http://api.openai.com:443", "schemes are not allowed"),
    ("api.openai.com:0", "port must be 1-65535"),
    ("api.openai.com:70000", "port must be 1-65535"),
    ("10.0.0.0/8:0", "port must be 1-65535"),
    ("10.0.0.0/8:70000", "port must be 1-65535"),
    ("10.0.0.0/8:0443", "no leading zeros"),
    ("10.0.0.0/8:8100-8000", "reversed; write 8000-8100"),
    ("api.openai.com:8100-8000", "reversed"),
    ("10.0.0.0/8:443-443", "single port, 443"),
    ("10.0.0.1", "CIDR form, e.g. 10.0.0.1/32"),           # IP in host form
    ("10.0.0.1:443", "CIDR form, e.g. 10.0.0.1/32"),
    ("2001:db8::1", "IPv6 address goes in CIDR form"),
    ("2001:db8::/32:443", "bracket an IPv6 CIDR before adding a port: [2001:db8::/32]:443"),
    ("[2001:db8::/32]", "brackets are only needed to add a port"),
    ("[10.0.0.0/8]:443", "brackets must contain an IPv6 CIDR"),
    ("*.", "wildcard needs a hostname after '*.'"),         # *. alone
    ("*", "'*' is only allowed as the leading '*.' label"),
    ("*example.com", "'*' is only allowed as the leading '*.' label"),
    ("a.*.example.com", "'*' is only allowed as the leading '*.' label"),
    ("*.com", "at least two labels"),
    ("localhost", "at least two labels"),
    ("Api.OpenAI.com", "must be lowercase"),
    ("api.openai.com.", "trailing dot"),
    ("api.openai.com/v1", "paths and prefix lengths are not allowed on hostnames"),
    ("example.123", "last label cannot be numeric"),
    ("10.2.3.4/8", "host bits; did you mean 10.0.0.0/8"),
    ("10.0.0.0/08", "not a valid CIDR"),
    ("::ffff:10.0.0.0/104", "IPv4-mapped"),
    ("", "empty"),
    ("api.openai.com :443", "whitespace"),
])
def test_invalid_egress_rules(rule, reason):
    with pytest.raises(ValueError) as exc:
        profiles.check_egress_rule(rule)
    assert str(exc.value).startswith("invalid egress rule") and reason in str(exc.value)
    _, errors = profiles.validate(_profile(egress_allowed=["10.0.0.0/8", rule]))
    assert errors[0]["field"].startswith("egress_allowed") and reason in errors[0]["message"]


def test_egress_rule_limit():
    assert profiles.validate(_profile(egress_allowed=["10.0.0.0/8"] * 128))[1] == []
    _, errors = profiles.validate(_profile(egress_allowed=["10.0.0.0/8"] * 129))
    assert errors[0]["field"] == "egress_allowed"


def test_validate_rules():
    clean, errors = profiles.validate(_profile())
    assert errors == [] and clean["read_allowed"] == ["/data/**"]
    # read_allowed absent stays null: the engine treats null (no restriction) differently from []
    p = _profile()
    del p["read_allowed"]
    assert profiles.validate(p)[0]["read_allowed"] is None
    assert profiles.validate(_profile(read_allowed=[]))[0]["read_allowed"] == []

    _, errors = profiles.validate(_profile(kind="shared_service"))
    assert "can't be paused" in errors[0]["message"]
    # a model verdict (on_structural_guard) may pause but never revoke; on_violation may still revoke
    _, errors = profiles.validate(_profile(response={"on_violation": "PAUSE_CONTAINER", "on_structural_guard": "REVOKE_SESSION"}))
    assert "session revocation needs a deterministic violation" in errors[0]["message"]
    assert profiles.validate(_profile(response={"on_violation": "REVOKE_SESSION", "on_structural_guard": "PAUSE_CONTAINER"}))[1] == []
    _, errors = profiles.validate(_profile(surprise=True))
    assert errors[0]["field"] == "surprise"
    _, errors = profiles.validate(_profile(exec_allowed_classes=["ROOTKIT"]))
    assert errors[0]["field"].startswith("exec_allowed_classes")
    _, errors = profiles.validate(_profile(name="bad name"))
    assert errors[0]["field"] == "name"
    _, errors = profiles.validate(_profile(egress_allowed=["10.0.0.1/8"]))
    assert "10.0.0.0/8" in errors[0]["message"]


def test_revision_is_order_independent():
    a, b = profiles.validate(_profile("a"))[0], profiles.validate(_profile("b"))[0]
    assert profiles.revision([a, b]) == profiles.revision([b, a]) != profiles.revision([a])


# --------------------------------------------------------------------- API

def test_create_edit_history_and_audit(c):
    r = _save(c, _profile("pol-1"))
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 1 and r.json()["body"]["version"] == 1

    # stale or duplicate creates are refused
    assert _save(c, _profile("pol-1")).status_code == 409
    assert _save(c, _profile("pol-1", mode="ACTIVE_FREEZE_MODE"), base=7).status_code == 409
    assert _save(c, _profile("pol-1"), base=1).status_code == 409  # nothing changed

    r = _save(c, _profile("pol-1", mode="ACTIVE_FREEZE_MODE"), base=1, comment="go active after shadow week")
    assert r.status_code == 200 and r.json()["version"] == 2

    d = c.get("/api/v1/policies/pol-1", headers=VIEWER).json()
    assert [v["version"] for v in d["history"]] == [2, 1]
    assert d["history"][0]["comment"] == "go active after shadow week"

    audit = c.get("/api/v1/audit", headers=ADMIN).json()
    upd = next(a for a in audit if a["action"] == "policy.update" and a["target"] == "pol-1")
    assert upd["detail"]["changed"] == ["mode"] and upd["detail"]["version"] == 2


def test_save_rejects_invalid_and_renames(c):
    r = _save(c, _profile("pol-bad", egress_allowed=["300.0.0.0/8"]))
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["field"].startswith("egress_allowed")
    r = c.put("/api/v1/policies/other-name", headers=ADMIN,
              json={"profile": _profile("pol-x"), "base_version": 0, "comment": "rename attempt"})
    assert r.status_code == 422
    r = c.put("/api/v1/policies/pol-x", headers=ADMIN, json={"profile": _profile("pol-x"), "base_version": 0, "comment": "short"})
    assert r.status_code == 422  # a reason is required


def test_permissions(c):
    assert _save(c, _profile("pol-perm"), who=VIEWER).status_code == 403
    assert _save(c, _profile("pol-perm"), who=NIGHT).status_code == 403
    assert _save(c, _profile("pol-perm"), who=POLICY).status_code == 403  # machines never edit policy
    assert c.get("/api/v1/policies", headers=VIEWER).status_code == 200
    assert c.get("/api/v1/policy/bundle", headers=ADMIN).status_code == 403
    assert c.get("/api/v1/policy/bundle", headers=SENSOR).status_code == 403
    assert c.get("/api/v1/policy/bundle", headers=CONTAIN).status_code == 403
    assert c.get("/api/v1/policy/bundle", headers=POLICY).status_code == 200


def test_validate_endpoint(c):
    r = c.post("/api/v1/policies/validate", headers=ADMIN, json=_profile(kind="shared_service"))
    assert r.status_code == 200 and r.json()["ok"] is False
    assert c.post("/api/v1/policies/validate", headers=VIEWER, json=_profile()).status_code == 403


def test_delete_refused_while_assigned(c):
    assert _save(c, _profile("pol-used")).status_code == 200
    assert c.post("/api/v1/workloads", headers=POLICY,
                  json={"id": "pw-1", "name": "uses pol-used", "profile": "pol-used", "kind": "ai_worker"}).status_code == 201
    r = c.request("DELETE", "/api/v1/policies/pol-used", headers=ADMIN, json={"base_version": 1, "comment": "cleanup old one"})
    assert r.status_code == 409 and "pw-1" in r.json()["detail"]

    assert _save(c, _profile("pol-free")).status_code == 200
    r = c.request("DELETE", "/api/v1/policies/pol-free", headers=ADMIN, json={"base_version": 1, "comment": "cleanup old one"})
    assert r.status_code == 200
    d = c.get("/api/v1/policies/pol-free", headers=VIEWER).json()
    assert d["profile"] is None and d["history"][0]["deleted"] is True
    # re-creating continues the version sequence, so a controller never sees a version reused
    r = _save(c, _profile("pol-free"))
    assert r.status_code == 200 and r.json()["version"] == 2


def test_bundle_and_sync(c):
    assert _save(c, _profile("pol-sync")).status_code == 200
    b = c.get("/api/v1/policy/bundle", headers=POLICY).json()
    assert any(p["name"] == "pol-sync" for p in b["profiles"]) and len(b["revision"]) == 64

    r = c.post("/api/v1/policy/sync", headers=POLICY,
               json={"seen_revision": b["revision"], "active_revision": b["revision"], "profiles": len(b["profiles"])})
    assert r.status_code == 200
    ctl = next(x for x in c.get("/api/v1/policies", headers=VIEWER).json()["controllers"] if x["controller"] == "policy-1")
    assert ctl["current"] is True

    # an edit makes the controller stale until it reports the new revision
    assert _save(c, _profile("pol-sync", description="edited"), base=1).status_code == 200
    ctl = next(x for x in c.get("/api/v1/policies", headers=VIEWER).json()["controllers"] if x["controller"] == "policy-1")
    assert ctl["current"] is False

    r = c.post("/api/v1/policy/sync", headers=POLICY,
               json={"seen_revision": "f" * 64, "active_revision": b["revision"], "profiles": 1, "error": "profile x: bad"})
    assert r.status_code == 200
    audit = c.get("/api/v1/audit", headers=ADMIN).json()
    assert any(a["action"] == "policy.rejected" for a in audit)
    assert c.post("/api/v1/policy/sync", headers=CONTAIN,
                  json={"seen_revision": "", "active_revision": "", "profiles": 0}).status_code == 403
