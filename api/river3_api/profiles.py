"""Policy profiles edited from the console.

A profile says what one kind of workload may do (files, programs, egress) and what River3
does when it steps outside that (alert, pause, revoke). The policy engine (policy/profile.go)
is the authority: it loads the same JSON and rejects anything invalid. These checks mirror
its compile() rules so the console can explain a mistake before a controller refuses it.

The stored body is exactly what the engine loads. `version` is assigned by the API on every
save, never taken from the editor.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

MAX_PROFILE_BYTES = 256 * 1024
MAX_PATTERNS = 128
MAX_CIDRS = 128
MAX_PROFILES = 256  # the engine loads at most this many

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
CLASSES = ("DIAGNOSTIC", "INTERPRETER", "NET_CLIENT", "PRIVILEGED_TOOL", "OTHER")

Mode = Literal["SHADOW_MODE", "ACTIVE_FREEZE_MODE"]
Response = Literal["ALERT", "PAUSE_CONTAINER", "REVOKE_SESSION"]
ExecClass = Literal["DIAGNOSTIC", "INTERPRETER", "NET_CLIENT", "PRIVILEGED_TOOL", "OTHER"]


def _canonical(s: str) -> bool:
    if not s or len(s) > 4096 or not s.startswith("/") or "\\" in s or s.endswith(" (deleted)"):
        return False
    if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in s):
        return False
    # Go's path.Clean also folds a leading "//", which posixpath.normpath keeps
    return not s.startswith("//") and posixpath.normpath(s) == s


def _glob_ok(pattern: str) -> bool:
    """True when Go's path.Match would accept the pattern (balanced, non-empty [...] classes)."""
    i = 0
    while i < len(pattern):
        if pattern[i] == "[":
            j = i + 1
            if j < len(pattern) and pattern[j] == "^":
                j += 1
            start = j
            while j < len(pattern) and pattern[j] != "]":
                j += 1
            if j >= len(pattern) or j == start:
                return False
            i = j
        i += 1
    return True


def check_pattern(s: str) -> str:
    if not _canonical(s):
        raise ValueError(f"{s!r} is not a canonical absolute path (start with /, no //, ./, ../ or trailing /)")
    base = s
    if s.endswith("/**"):
        base = s[:-3]
        if base and any(c in base for c in "*?["):
            raise ValueError(f"{s!r}: the part before /** must be a literal path")
    if "**" in base:
        raise ValueError(f"{s!r}: ** is only allowed as a final /** (whole subtree)")
    if not _glob_ok(base):
        raise ValueError(f"{s!r}: unbalanced [ ] in pattern")
    return s


def check_cidr(s: str) -> str:
    if "/" not in s or not s.rsplit("/", 1)[1].isdigit():
        raise ValueError(f"{s!r}: write a CIDR with a prefix length, e.g. 10.0.0.0/8 or 192.0.2.7/32")
    try:
        net = ipaddress.ip_network(s, strict=True)
    except ValueError:
        try:
            masked = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise ValueError(f"{s!r} is not a valid IP range") from None
        raise ValueError(f"{s!r} has host bits set; did you mean {masked.with_prefixlen}?") from None
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped:
        raise ValueError(f"{s!r}: write IPv4 ranges in IPv4 form, not ::ffff:")
    return s


MAX_DOMAINS = 128
MAX_DOMAIN_LEN = 253
# One RFC 1123 hostname label: letters, digits and hyphens, no leading or trailing hyphen, 1-63 chars.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


# --------------------------------------------------------------------- egress_allowed (mirrors policy/egress.go)
#
# One entry is one of (CONTRACTS section 4):
#   10.0.0.0/8                 CIDR, any port
#   10.0.0.0/8:443             CIDR, one port
#   10.0.0.0/8:8000-8100       CIDR, port range (low < high)
#   2001:db8::/32              IPv6 CIDR, any port
#   [2001:db8::/32]:443        IPv6 CIDR with a port must be bracketed
#   api.example.com[:443]      exact hostname, optional port or range
#   *.example.com[:443]        any subdomain of example.com (one or more labels), not the apex
# Hostnames are lowercase, at least two labels, no IP literal (an address goes in CIDR form).
# The reasons below are the engine's, so the console shows the same text the controller would.

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _hostname_reason(host: str) -> str | None:
    """Mirror of checkHostname in policy/egress.go: None when valid, else the engine's reason."""
    if not host:
        return "empty hostname"
    if any(c in host for c in "/?#"):
        return "paths are not allowed"
    if host[0] == "[" or host[-1] == "]":
        return "IP literals are not allowed"
    if ":" in host:
        return "ports and IPv6 literals are not allowed"
    if host.endswith("."):
        return "trailing dot is not allowed"
    if any("A" <= c <= "Z" for c in host):
        return "must be lowercase"
    if len(host) > MAX_DOMAIN_LEN:
        return "hostname longer than 253 characters"
    labels = host.split(".")
    for lb in labels:
        if not 1 <= len(lb) <= 63:
            return "each label must be 1–63 characters"
        if lb[0] == "-" or lb[-1] == "-":
            return "a label cannot start or end with '-'"
        if not re.fullmatch(r"[a-z0-9-]+", lb):
            return "only a-z, 0-9, '-' and '.' are allowed"
    if labels[-1].isdigit():
        return "IP addresses belong in CIDR form (the last label cannot be numeric)"
    return None


def _port(s: str) -> int | None:
    if not s or len(s) > 5 or s[0] == "0" or not s.isdigit() or not s.isascii():
        return None
    n = int(s)
    return n if 1 <= n <= 65535 else None


def _ports(spec: str, bad) -> tuple[int, int]:
    if spec == "":
        bad("missing port after ':'")
    lo, dash, hi = spec.partition("-")
    low = _port(lo)
    if low is None:
        bad("port must be 1-65535 with no leading zeros")
    if not dash:
        return low, low
    high = _port(hi)
    if high is None:
        bad("port range must be low-high, each 1-65535 with no leading zeros")
    if low > high:
        bad(f"port range is reversed; write {hi}-{lo}")
    if low == high:
        bad(f"write a single port, {lo}, instead of a one-port range")
    return low, high


def _prefix(cidr: str, bad) -> None:
    # Go's netip.ParsePrefix is stricter than ipaddress.ip_network: no zone, and the prefix
    # length is plain decimal without a leading zero.
    addr, slash, plen = cidr.partition("/")
    if not slash or "%" in addr or not re.fullmatch(r"0|[1-9][0-9]*", plen):
        bad("not a valid CIDR")
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        try:
            masked = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            bad("not a valid CIDR")
        bad(f"CIDR contains host bits; did you mean {masked.with_prefixlen}")
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped:
        bad("IPv4-mapped IPv6 prefixes are not allowed; write the IPv4 range")


def check_egress_rule(s: str) -> str:
    """Accepts exactly what policy.ParseEgressRule accepts, with its error reasons."""
    def bad(reason: str):
        raise ValueError(f"invalid egress rule {s!r}: {reason}")

    if s == "":
        bad("empty")
    if len(s) > 300:
        bad("too long")
    if "://" in s:
        bad("schemes are not allowed; write the hostname only")
    if any(c in s for c in " \t\r\n"):
        bad("whitespace is not allowed")

    if s.startswith("["):  # [IPv6 CIDR]:port
        end = s.find("]")
        if end < 0:
            bad("missing ']' after the IPv6 CIDR")
        inner, rest = s[1:end], s[end + 1:]
        if "/" not in inner or ":" not in inner:
            bad("brackets must contain an IPv6 CIDR, e.g. [2001:db8::/32]:443")
        if rest == "":
            bad(f"brackets are only needed to add a port; write {inner} or [{inner}]:443")
        if rest[0] != ":":
            bad("expected ':port' after ']'")
        _prefix(inner, bad)
        _ports(rest[1:], bad)
        return s
    if s.endswith("]"):
        bad("brackets must open with '['")

    if "/" in s:  # CIDR[:port]
        left, right = s.split("/", 1)
        if ":" in left:  # IPv6
            if ":" in right:
                bad(f"bracket an IPv6 CIDR before adding a port: [{left}/{right.split(':', 1)[0]}]:443")
            _prefix(s, bad)
            return s
        if not _is_ip(left):
            if "*" in left or any(c.isalpha() for c in left):
                bad("paths and prefix lengths are not allowed on hostnames")
            bad("not a valid CIDR; write an IPv4 range like 10.0.0.0/8 or 192.0.2.7/32")
        plen, colon, ports = right.partition(":")
        _prefix(f"{left}/{plen}", bad)
        if colon:
            _ports(ports, bad)
        return s

    # hostname[:port]
    if _is_ip(s):
        if ":" in s:
            bad(f"an IPv6 address goes in CIDR form, e.g. {s}/128, bracketed to add a port: [{s}/128]:443")
        bad(f"an IP address goes in CIDR form, e.g. {s}/32")
    host, colon, ports = s.partition(":")
    if ":" in ports:
        bad("only one ':' is allowed, as host:port; an IPv6 address goes in CIDR form, bracketed to add a port: [2001:db8::1/128]:443")
    if _is_ip(host):
        bad(f"an IP address goes in CIDR form, e.g. {host}/32")
    pattern = host
    if pattern.startswith("*."):
        host = pattern[2:]
        if host == "":
            bad("wildcard needs a hostname after '*.', e.g. *.example.com")
    if "*" in host:
        bad("'*' is only allowed as the leading '*.' label")
    reason = _hostname_reason(host)
    if reason:
        bad(reason)
    if "." not in host:
        bad("a hostname needs at least two labels, e.g. api.example.com; for a single-label name use its address in CIDR form")
    if colon:
        _ports(ports, bad)
    return s


def check_domain(s: str) -> str:
    """A hostname the controller will resolve (CONTRACTS §5), optionally `*.` for the apex plus any
    subdomain. Lowercase is required rather than applied: the stored body must be byte-identical to what
    the policy engine validates, and the engine does not normalise. Trailing dots and IP literals are
    refused because the engine resolves names: an address belongs in egress_allowed."""
    if not s or len(s) > MAX_DOMAIN_LEN:
        raise ValueError(f"{s!r}: a domain is 1-{MAX_DOMAIN_LEN} characters")
    if s != s.lower():
        raise ValueError(f"{s!r}: write domains in lowercase")
    host = s[2:] if s.startswith("*.") else s
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        raise ValueError(f"{s!r} is not a valid hostname (e.g. api.example.com or *.example.com)")
    if labels[-1].isdigit():
        raise ValueError(f"{s!r}: IP addresses go in egress_allowed as a CIDR, not here")
    return s


class ResponsePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    on_violation: Response = "ALERT"
    on_structural_guard: Response = "ALERT"


Paths = list[str]


class ProfileBody(BaseModel):
    """Same keys as policy.Profile. Unknown keys are rejected, as the engine does."""
    model_config = ConfigDict(extra="forbid")
    name: str
    kind: Literal["ai_worker", "shared_service"]
    description: str = Field("", max_length=2048)
    version: int | None = None  # assigned by the API
    mode: Mode = "SHADOW_MODE"
    decoys: Paths = Field(default_factory=list, max_length=MAX_PATTERNS)
    protected_read: Paths = Field(default_factory=list, max_length=MAX_PATTERNS)
    # None (absent) = reads are not restricted; [] = every read outside decoys/protected is out of scope
    read_allowed: Paths | None = Field(None, max_length=MAX_PATTERNS)
    write_allowed: Paths = Field(default_factory=list, max_length=MAX_PATTERNS)
    exec_allowed_classes: list[ExecClass] = Field(default_factory=list, max_length=len(CLASSES))
    exec_denied_classes: list[ExecClass] = Field(default_factory=list, max_length=len(CLASSES))
    # CIDR, CIDR:port, CIDR:low-high, [v6-cidr]:port, hostname[:port], *.wildcard[:port] (see check_egress_rule)
    egress_allowed: list[str] = Field(default_factory=list, max_length=MAX_CIDRS)
    # Names the controller resolves to /32 and /128 CIDRs every -egress-refresh (60 s); the engine itself
    # matches IPs only. Kept here so the console can edit it and the bundle carries it unchanged.
    egress_allowed_domains: list[str] = Field(default_factory=list, max_length=MAX_DOMAINS)
    response: ResponsePolicy = Field(default_factory=ResponsePolicy)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME.match(v):
            raise ValueError("use 1-128 letters, digits, . _ : - (starting with a letter or digit)")
        return v

    @field_validator("decoys", "protected_read", "read_allowed", "write_allowed")
    @classmethod
    def _paths(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else [check_pattern(p) for p in v]

    @field_validator("egress_allowed")
    @classmethod
    def _egress(cls, v: list[str]) -> list[str]:
        return [check_egress_rule(c) for c in v]

    @field_validator("egress_allowed_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        return [check_domain(d) for d in v]

    @model_validator(mode="after")
    def _shared_no_pause(self):
        if self.kind == "shared_service" and "PAUSE_CONTAINER" in (self.response.on_violation,
                                                                   self.response.on_structural_guard):
            raise ValueError("a shared service can't be paused (other users depend on it); use ALERT or REVOKE_SESSION")
        return self

    @model_validator(mode="after")
    def _structural_guard_never_revokes(self):
        # Mirrors policy/profile.go: on_structural_guard is the only place a verified Channel A model
        # verdict can lead to an action, and its ceiling is a container pause. Revocation is reserved
        # for deterministic violations (on_violation).
        if self.response.on_structural_guard == "REVOKE_SESSION":
            raise ValueError("on_structural_guard: a model verdict may at most pause a dedicated AI worker; "
                             "session revocation needs a deterministic violation")
        return self


def validate(raw: Any) -> tuple[dict | None, list[dict]]:
    """Returns (normalized body, []) or (None, [{"field", "message"}, ...])."""
    if not isinstance(raw, dict):
        return None, [{"field": "", "message": "a profile is a JSON object"}]
    if len(json.dumps(raw, default=str)) > MAX_PROFILE_BYTES:
        return None, [{"field": "", "message": f"profile is larger than {MAX_PROFILE_BYTES} bytes"}]
    try:
        p = ProfileBody.model_validate(raw)
    except ValidationError as exc:
        return None, [{"field": ".".join(str(x) for x in e["loc"]), "message": e["msg"].removeprefix("Value error, ")}
                      for e in exc.errors()]
    return p.model_dump(mode="json"), []


def changed_fields(old: dict | None, new: dict) -> list[str]:
    old = old or {}
    return sorted(k for k in set(old) | set(new) if k != "version" and old.get(k) != new.get(k))


def revision(bodies: list[dict]) -> str:
    """Content hash of the whole set; a controller applies a set only when this changes."""
    canon = json.dumps(sorted(bodies, key=lambda b: b["name"]), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()
