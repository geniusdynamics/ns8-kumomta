#
# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Shared code of the ns8-kumomta actions.

The settings live in state/settings.json (no secrets). configure-module
renders them into the KumoMTA policy directory (state/kumomta, mounted on
/opt/kumomta/etc/policy): init.lua and the TOML data files read by it.
Secrets live in 0600 files under state/secrets and state/openbao.env.
"""

import base64
import copy
import datetime
import fcntl
import hmac
import hashlib
import ipaddress
import json
import os
import re
import secrets
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from fractions import Fraction

import agent

# Paths, relative to the state directory (the working directory of the
# actions and of the systemd units)
SETTINGS_FILE = "settings.json"
CONFIG_DIR = "kumomta"          # -> /opt/kumomta/etc/policy
SECRETS_DIR = "secrets"         # -> /opt/kumomta/etc/secrets
DKIM_DIR = "dkim"               # -> /opt/kumomta/etc/dkim
TLS_DIR = "tls"                 # -> /opt/kumomta/etc/tls
OPENBAO_ENV = "openbao.env"     # EnvironmentFile of kumomta.service
API_ENV = "secrets/api.env"     # credentials of the local HTTP API
RESTART_STAMP = ".init-hash"    # hash of the settings read only at startup
WARNINGS_FILE = ".configure-warnings.json"  # configure-module output
CLUSTER_DIR = "cluster"         # cluster state, no secrets
CLUSTER_STATE = "cluster/state.json"        # mode, reason, endpoints
CLUSTER_STORE = "cluster/store.json"        # store endpoint and user name
CLUSTER_PASSWORD = "cluster_redis_password"  # under state/secrets, 0600
TSA_STAMP = ".tsa-hash"         # hash of tsa_init.lua: a change restarts tsa-daemon

# Paths inside the container
C_POLICY = "/opt/kumomta/etc/policy"
C_SECRETS = "/opt/kumomta/etc/secrets"
C_DKIM = "/opt/kumomta/etc/dkim"
C_TLS = "/opt/kumomta/etc/tls"

API_USER = "ns8-admin"
METRICS_USER = "metrics"
RESERVED_NAMES = [API_USER, METRICS_USER]
SETTINGS_LOCK = ".settings.lock"
INTEGRATION_SCOPES = ["inject", "smtp", "domains"]
DOMAIN_STATUSES = ["pending", "verified", "failed"]
RETURN_PATH_PREFIX = "bounces"   # <prefix>.<domain> CNAME <bounce_domain>

SMARTHOST_TLS = {
    "required": "Required",
    "required_insecure": "RequiredInsecure",
    "opportunistic": "OpportunisticInsecure",
    "disabled": "Disabled",
}

WEBHOOK_RECORD_TYPES = ["Reception", "Delivery", "Bounce", "TransientFailure",
                        "Expiration", "AdminBounce", "OOB", "Feedback", "Rejection"]

# Ports of the other mail modules of NS8: kumomta refuses to share them
MAIL_MODULE_PORTS = {
    "mail": [25, 110, 143, 465, 587, 993, 995, 4190],
    "mailcow": [25, 110, 143, 465, 587, 993, 995, 4190],
    "postal": [2525, 2143],
}

DEFAULTS = {
    "hostname": "",
    "lets_encrypt": False,
    "inbound_enabled": True,
    "inbound_port": 25,
    "submission_enabled": True,
    "submission_port": 587,
    "max_message_size": 25,           # MiB
    "relay_networks": [],
    "cluster_relay": False,
    "smtp_users": [],                 # names only, hashes in secrets
    "domains": [],                    # [{domain, selector}]
    "inbound_routes": [],             # [{domain, host, port}]
    "smarthost_enabled": False,
    "smarthost_host": "",
    "smarthost_port": 587,
    "smarthost_tls": "required",
    "smarthost_username": "",
    "shaping": [],                    # [{domain, connection_limit, max_message_rate, max_deliveries_per_connection}]
    "retry_interval": "20m",
    "max_age": "5d",
    "webhook_enabled": False,
    "webhook_url": "",
    "webhook_record_types": ["Delivery", "Bounce", "TransientFailure", "Expiration", "OOB", "Feedback"],
    "vault_enabled": False,
    "vault_address": "",
    "vault_mount": "secret",
    "vault_path": "kumomta",
    "vault_key": "",
    "metrics_host": "",
    "metrics_allowlist": [],
    # Testing: accept and discard every outbound message (no delivery)
    "sink_enabled": False,
    # Sending platforms: integration credentials (hashes in secrets),
    # HTTPS API host name, sending domain policy
    "integrations": [],               # [{name, tenant, scopes, max_message_rate}]
    "api_host": "",
    "api_allowlist": [],
    "require_verified_domains": True,
    "spf_include": "",                # SPF mechanism to suggest, default a:<hostname>
    "bounce_domain": "",              # return path / OOB / FBL domain, empty disables
    # Multi-node cluster (docs/cluster.md): every instance is a peer. A
    # shared throttle store makes the throttles and connection limits
    # global: "none" (standalone, default), "valkey" (an ns8-valkey
    # instance, credentials from its grant-client action) or "manual" (any
    # Redis or Valkey, single node or Redis Cluster)
    "cluster_store": "none",
    "cluster_valkey": "",
    "cluster_redis_nodes": [],        # manual: redis:// or rediss:// URLs, no password
    "cluster_redis_username": "",
    "cluster_redis_cluster": False,   # manual: Redis Cluster protocol with one URL
    # Traffic shaping automation daemon (tsa-daemon) of this instance; in a
    # cluster: this instance is a designated TSA host
    "tsa_enabled": False,
    # Sending IPs (egress sources of the default pool) with their limits,
    # see SENDING_IP_FIELDS. Empty: the address of the default route, no
    # per-IP limits (as before)
    "sending_ips": [],
    # Non-secret markers of the write-only secrets
    "smarthost_password_set": False,
    "webhook_token_set": False,
    "metrics_password_set": False,
    "webhook_signing_secret_set": False,
    "cluster_redis_password_set": False,
}

# configure-module fields that are secrets: written to state/secrets or
# OpenBao, never returned
SECRET_FIELDS = ["smarthost_password", "webhook_token", "vault_token", "metrics_password",
                 "webhook_signing_secret", "cluster_redis_password"]

# Destination providers of the per-IP overrides: the provider blocks of the
# KumoMTA default shaping.toml (policy-extras), matched by their MX names
PROVIDER_PRESETS = {
    "google": "Gmail and Google Workspace",
    "outlook": "Outlook.com and Hotmail",
    "office365": "Microsoft 365",
    "yahoo": "Yahoo and AOL",
    "apple": "iCloud",
}
LIMIT_FIELDS = ["per_minute", "per_hour", "per_day", "max_connections"]
PERIODS = {"per_minute": "min", "per_hour": "h", "per_day": "d"}

RATE_RE = re.compile(r"^[0-9]+/(s|sec|second|m|min|minute|h|hr|hour|d|day)$")
DURATION_RE = re.compile(r"^[0-9]+ ?(s|sec|secs|seconds|m|min|mins|minutes|h|hr|hrs|hours|d|day|days|w|week|weeks)$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SELECTOR_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")
INTEGRATION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*[0-9]+$")
# A store URL never carries credentials: the password is a 0600 file
REDIS_URL_RE = re.compile(r"^rediss?://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?(/[0-9]{0,2})?$")
TENANT_RE = re.compile(r"^[A-Za-z0-9._-]{0,64}$")


def log(message):
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# Settings and secrets
# --------------------------------------------------------------------------

def load_settings():
    settings = copy.deepcopy(DEFAULTS)
    try:
        with open(SETTINGS_FILE) as fp:
            settings.update(json.load(fp))
    except FileNotFoundError:
        pass
    return settings


def save_settings(settings):
    write_file(SETTINGS_FILE, json.dumps(settings, indent=2, sort_keys=True) + "\n", 0o644)


def settings_lock():
    """Exclusive lock of the settings (configure-module, the domain actions
    and the API daemon): keep the returned file open while modifying"""
    fp = open(SETTINGS_LOCK, "a")
    fcntl.flock(fp, fcntl.LOCK_EX)
    return fp


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_file(path, content, mode=0o644):
    """Atomic write; returns True if the content changed"""
    if isinstance(content, str):
        content = content.encode()
    try:
        with open(path, "rb") as fp:
            if fp.read() == content:
                if (os.stat(path).st_mode & 0o777) != mode:
                    os.chmod(path, mode)
                return False
    except FileNotFoundError:
        pass
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(content)
            os.fchmod(fp.fileno(), mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return True


def write_secret(name, value):
    """A secret file under state/secrets, 0600, without trailing newline:
    KumoMTA reads the whole file as the key value"""
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    return write_file(os.path.join(SECRETS_DIR, name), value, 0o600)


def read_secret(name, default=""):
    try:
        with open(os.path.join(SECRETS_DIR, name)) as fp:
            return fp.read()
    except FileNotFoundError:
        return default


def remove_secret(name):
    try:
        os.unlink(os.path.join(SECRETS_DIR, name))
        return True
    except FileNotFoundError:
        return False


def genpw(length=32):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_api_credentials():
    """Credentials of the local HTTP API, used by the module actions"""
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    if not read_secret("api_password"):
        write_secret("api_password", genpw())
    password = read_secret("api_password")
    write_file(API_ENV, f"KUMO_API_USER={API_USER}\nKUMO_API_PASSWORD={password}\n", 0o600)


# scrypt uses about 32 MiB per calculation. Limit concurrent verifications
# in the API daemon and cache only successful results with a bounded LRU.
_verification_slots = threading.BoundedSemaphore(2)
_password_cache_lock = threading.Lock()
_password_cache = {}
_password_cache_key = secrets.token_bytes(32)


def _scrypt(value, salt):
    return hashlib.scrypt(value, salt=bytes.fromhex(salt), n=32768, r=8, p=3,
                          maxmem=64 * 1024**2).hex()


def hash_password(password):
    salt = secrets.token_hex(16)
    return {"salt": salt, "scrypt": _scrypt(password.encode(), salt)}


def _upgrade_password_hash(cred):
    if "scrypt" in cred:
        return cred
    # Strengthen existing verifiers using the old digest as the input.
    # Verification can derive that same digest from the original password.
    salt = secrets.token_hex(16)
    return {"salt": salt, "scrypt": _scrypt(bytes.fromhex(cred["sha256"]), salt),
            "legacy_salt": cred["salt"]}


class PasswordVerifierBusy(Exception):
    pass


def check_password(cred, password):
    if not cred or not password:
        return False
    value = password.encode()
    if "scrypt" not in cred:
        # A legacy backup can be read before its first configure or upgrade.
        digest = hashlib.sha256(cred["salt"].encode() + value).hexdigest()
        return hmac.compare_digest(digest, cred["sha256"])
    if "legacy_salt" in cred:
        value = hashlib.sha256(cred["legacy_salt"].encode() + value).digest()
    cache_key = (cred["salt"], cred["scrypt"], hmac.digest(_password_cache_key, value, "sha256"))
    with _password_cache_lock:
        if _password_cache.pop(cache_key, None):
            _password_cache[cache_key] = True
            return True
    if not _verification_slots.acquire(timeout=0.5):
        raise PasswordVerifierBusy
    try:
        valid = hmac.compare_digest(_scrypt(value, cred["salt"]), cred["scrypt"])
    finally:
        _verification_slots.release()
    if valid:
        with _password_cache_lock:
            _password_cache[cache_key] = True
            if len(_password_cache) > 128:
                del _password_cache[next(iter(_password_cache))]
    return valid


def read_smtp_users():
    """SMTP verifiers from the 0600 secrets file."""
    try:
        with open(os.path.join(SECRETS_DIR, "smtp_users.json")) as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}


def write_smtp_users(users):
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    upgraded = {name: _upgrade_password_hash(cred) for name, cred in users.items()}
    changed = write_file(os.path.join(SECRETS_DIR, "smtp_users.json"),
                         json.dumps(upgraded, indent=1, sort_keys=True), 0o600)
    # Lua only needs to distinguish SMTP users from integration identities.
    changed |= write_file(os.path.join(SECRETS_DIR, "smtp_users.toml"),
                          toml_dumps({"user": {name: True for name in sorted(users)}}), 0o600)
    return changed


def read_integrations_secrets():
    """Integration verifiers from the 0600 secrets file."""
    try:
        with open(os.path.join(SECRETS_DIR, "integrations.json")) as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}


def write_integrations(settings, hashes):
    """Write the credential verifiers and the policy used by KumoMTA."""
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    upgraded = {name: _upgrade_password_hash(cred) for name, cred in hashes.items()}
    changed = write_file(os.path.join(SECRETS_DIR, "integrations.json"),
                         json.dumps(upgraded, indent=1, sort_keys=True), 0o600)
    table = {}
    for integ in settings["integrations"]:
        if integ["name"] not in hashes:
            continue
        table[integ["name"]] = {
            "tenant": integ.get("tenant") or "",
            "scopes": list(integ.get("scopes") or []),
            "max_message_rate": integ.get("max_message_rate") or "",
        }
    changed |= write_file(os.path.join(SECRETS_DIR, "integrations.toml"),
                          toml_dumps({"integration": table}), 0o600)
    return changed


def read_openbao_env():
    try:
        return agent.read_envfile(OPENBAO_ENV)
    except FileNotFoundError:
        return {}


def write_openbao_env(address, token):
    return write_file(OPENBAO_ENV, f"VAULT_ADDR={address}\nVAULT_TOKEN={token}\n", 0o600)


def remove_openbao_env():
    try:
        os.unlink(OPENBAO_ENV)
        return True
    except FileNotFoundError:
        return False


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------

def toml_key(key):
    return json.dumps(str(key))


def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        # JSON string escapes are valid TOML basic string escapes
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{toml_key(k)} = {toml_value(v)}" for k, v in value.items()) + " }"
    raise TypeError(f"unsupported TOML value {value!r}")


def toml_dumps(data, prefix=None, header=""):
    """Minimal TOML writer: nested dicts become tables, everything else
    becomes key = value lines"""
    lines = []
    if header:
        lines += ["# " + line if line else "#" for line in header.splitlines()]
        lines.append("")
    tables = []
    for key, value in data.items():
        if isinstance(value, dict):
            tables.append((key, value))
        else:
            lines.append(f"{toml_key(key)} = {toml_value(value)}")
    for key, value in tables:
        name = (prefix + [toml_key(key)]) if prefix else [toml_key(key)]
        lines.append("")
        lines.append("[" + ".".join(name) + "]")
        sub = toml_dumps(value, name)
        if sub:
            lines.append(sub)
    return "\n".join(lines).strip("\n") + ("\n" if prefix is None else "")


def lua_value(value, indent=0):
    pad = "  " * (indent + 1)
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        out = []
        for ch in value:
            code = ord(ch)
            if ch == "\\":
                out.append("\\\\")
            elif ch == '"':
                out.append('\\"')
            elif code < 32 or code == 127:
                out.append("\\%03d" % code)
            else:
                out.append(ch)
        return '"' + "".join(out) + '"'
    if isinstance(value, (list, tuple)):
        if not value:
            return "{}"
        return "{\n" + "".join(f"{pad}{lua_value(v, indent + 1)},\n" for v in value) + "  " * indent + "}"
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = []
        for key, val in value.items():
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(key)):
                lkey = str(key)
            else:
                lkey = "[" + lua_value(str(key)) + "]"
            items.append(f"{pad}{lkey} = {lua_value(val, indent + 1)},\n")
        return "{\n" + "".join(items) + "  " * indent + "}"
    raise TypeError(f"unsupported Lua value {value!r}")


# --------------------------------------------------------------------------
# Networks, cluster
# --------------------------------------------------------------------------

def normalize_network(value):
    """Return the canonical CIDR string or raise ValueError"""
    value = value.strip()
    return str(ipaddress.ip_network(value, strict=False))


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def cluster_info():
    """(cluster network CIDR, node VPN address) from Redis; None on errors"""
    try:
        rdb = agent.redis_connect(use_replica=True)
        network = rdb.get("cluster/network") or None
        address = rdb.hget(f"node/{os.environ['NODE_ID']}/vpn", "ip_address") or None
        return network, address
    except Exception as ex:
        log(agent.SD_WARNING + f"Cannot read the cluster network: {ex}")
        return None, None


def mail_modules_on_node():
    """{module_id: image_name} of the other NS8 mail modules on this node"""
    node_id = os.environ["NODE_ID"]
    rdb = agent.redis_connect(use_replica=True)
    found = {}
    for module_id, mnode in (rdb.hgetall("cluster/module_node") or {}).items():
        if str(mnode) != str(node_id) or module_id == os.environ.get("MODULE_ID"):
            continue
        image_url = rdb.hget(f"module/{module_id}/environment", "IMAGE_URL") or ""
        image_name = image_url.rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
        if image_name in MAIL_MODULE_PORTS or image_name == "kumomta":
            found[module_id] = image_name
    return found


def listener_ports(settings):
    ports = []
    if settings["inbound_enabled"]:
        ports.append(int(settings["inbound_port"]))
    if settings["submission_enabled"]:
        ports.append(int(settings["submission_port"]))
    return ports


def offers_cluster_relay(settings):
    """NS8 core configures a smarthost "app" with port 25 and no
    authentication: kumomta can be offered only with its port-25 listener"""
    return bool(settings["cluster_relay"] and settings["inbound_enabled"]
                and int(settings["inbound_port"]) == 25)


def cluster_relay_policy(settings):
    if not offers_cluster_relay(settings):
        return {}
    network, address = cluster_info()
    try:
        vpn = ipaddress.ip_network(network, strict=False)
        local = ipaddress.ip_address(address)
    except ValueError:
        return {}
    if local not in vpn:
        return {}
    return {"cluster_network": str(vpn), "cluster_address": str(local)}


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------

def dkim_paths(domain, selector):
    base = os.path.join(DKIM_DIR, domain)
    return os.path.join(base, f"{selector}.key"), os.path.join(base, f"{selector}.pub")


def generate_dkim_key():
    """(private PEM, public DER base64) of a new RSA 2048 key"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return pem, public_from_private(pem)


def public_from_private(pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("DKIM signing requires an RSA private key")
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def store_dkim_public(domain, selector, public_b64):
    _, pubfile = dkim_paths(domain, selector)
    os.makedirs(os.path.dirname(pubfile), mode=0o755, exist_ok=True)
    write_file(pubfile, public_b64 + "\n", 0o644)


def store_dkim_private(domain, selector, pem):
    keyfile, _ = dkim_paths(domain, selector)
    os.makedirs(os.path.dirname(keyfile), mode=0o755, exist_ok=True)
    write_file(keyfile, pem, 0o600)


def dkim_record(domain, selector):
    """The DNS TXT record to publish, or None without a public key"""
    _, pubfile = dkim_paths(domain, selector)
    try:
        with open(pubfile) as fp:
            public = fp.read().strip()
    except FileNotFoundError:
        return None
    return {
        "name": f"{selector}._domainkey.{domain}",
        "type": "TXT",
        "value": f"v=DKIM1; k=rsa; p={public}",
    }


def openbao_secret_path(settings, *parts):
    base = settings["vault_path"].strip("/")
    return "/".join([p for p in [base] + list(parts) if p])


def dkim_vault_path(settings, domain, selector):
    return openbao_secret_path(settings, "dkim", domain, selector)


class OpenBaoHTTPError(RuntimeError):
    def __init__(self, status, path):
        super().__init__(f"OpenBao answered {status} for {path}")
        self.status = status


def openbao_write(settings, path, value, env=None, *, create_only=False):
    """Write a KV v2 secret: {field: value}. Raises RuntimeError"""
    env = env if env is not None else read_openbao_env()
    address = env.get("VAULT_ADDR", "").rstrip("/")
    token = env.get("VAULT_TOKEN", "")
    if not address or not token:
        raise RuntimeError("OpenBao address or token not set")
    field = settings["vault_key"] or "key"
    url = f"{address}/v1/{settings['vault_mount'].strip('/')}/data/{path}"
    payload = {"data": {field: value}}
    if create_only:
        payload["options"] = {"cas": 0}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "X-Vault-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as ex:
        raise OpenBaoHTTPError(ex.code, path) from None
    except (urllib.error.URLError, OSError, ValueError) as ex:
        raise RuntimeError(f"cannot reach OpenBao: {ex}") from None


def openbao_read(settings, path, env=None):
    """Read the field of a KV v2 secret. Raises RuntimeError"""
    env = env if env is not None else read_openbao_env()
    address = env.get("VAULT_ADDR", "").rstrip("/")
    token = env.get("VAULT_TOKEN", "")
    if not address or not token:
        raise RuntimeError("OpenBao address or token not set")
    field = settings["vault_key"] or "key"
    url = f"{address}/v1/{settings['vault_mount'].strip('/')}/data/{path}"
    req = urllib.request.Request(url, method="GET", headers={"X-Vault-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as ex:
        raise OpenBaoHTTPError(ex.code, path) from None
    except (urllib.error.URLError, OSError, ValueError) as ex:
        raise RuntimeError(f"cannot reach OpenBao: {ex}") from None
    value = ((payload.get("data") or {}).get("data") or {}).get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"no '{field}' field in {path}")
    return value


def vault_only_items(settings):
    """Secrets that exist only in OpenBao: without OpenBao, KumoMTA cannot
    use them. Names and paths only, never the values."""
    if not settings["vault_enabled"]:
        return []
    items = []
    for dom in settings["domains"]:
        keyfile, pubfile = dkim_paths(dom["domain"], dom["selector"])
        if os.path.exists(pubfile) and not os.path.exists(keyfile):
            items.append({
                "kind": "dkim_key",
                "name": f"{dom['selector']}._domainkey.{dom['domain']}",
                "domain": dom["domain"],
                "selector": dom["selector"],
                "path": dkim_vault_path(settings, dom["domain"], dom["selector"]),
            })
    if settings["smarthost_password_set"] and not read_secret("smarthost_password"):
        items.append({"kind": "smarthost_password", "name": "smarthost_password",
                      "path": openbao_secret_path(settings, "smarthost")})
    if settings["webhook_token_set"] and not read_secret("webhook_token"):
        items.append({"kind": "webhook_token", "name": "webhook_token",
                      "path": openbao_secret_path(settings, "webhook")})
    if (settings.get("cluster_redis_password_set") and settings.get("cluster_store") == "manual"
            and not read_secret(CLUSTER_PASSWORD)):
        items.append({"kind": "cluster_redis_password", "name": "cluster_redis_password",
                      "path": openbao_secret_path(settings, "cluster_redis")})
    if settings.get("webhook_signing_secret_set") and not read_secret("webhook_signing_secret"):
        items.append({"kind": "webhook_signing_secret", "name": "webhook_signing_secret",
                      "path": openbao_secret_path(settings, "webhook_signing")})
    return items


def copy_vault_item_to_local(settings, item, env=None):
    """Copy one item of vault_only_items() into its local 0600 file.
    Raises RuntimeError"""
    value = openbao_read(settings, item["path"], env)
    if item["kind"] == "dkim_key":
        try:
            public = public_from_private(value)
        except Exception:
            raise RuntimeError("the OpenBao value is not a PEM private key") from None
        _, pubfile = dkim_paths(item["domain"], item["selector"])
        with open(pubfile) as fp:
            if fp.read().strip() != public:
                raise RuntimeError("the OpenBao key does not match the published DKIM record")
        store_dkim_private(item["domain"], item["selector"], value)
    elif item["kind"] == "smarthost_password":
        write_secret("smarthost_password", value)
    elif item["kind"] in ("webhook_token", "webhook_signing_secret", "cluster_redis_password"):
        write_secret(item["kind"], value)
    else:
        raise RuntimeError(f"unknown item kind {item['kind']}")


# --------------------------------------------------------------------------
# Sending domains: DKIM keys, DNS records, validation
# --------------------------------------------------------------------------

class DomainError(Exception):
    """A domain request the caller can fix: code is the validation code"""

    def __init__(self, code, value=""):
        super().__init__(code)
        self.code = code
        self.value = value


def read_shared_dkim_key(settings, domain, selector):
    """The private key at the OpenBao path of a domain, or None when there
    is none. Raises RuntimeError when OpenBao cannot answer."""
    try:
        return openbao_read(settings, dkim_vault_path(settings, domain, selector))
    except OpenBaoHTTPError as ex:
        if ex.status == 404:
            return None
        raise


def _dkim_file(path):
    try:
        with open(path) as fp:
            return fp.read()
    except FileNotFoundError:
        return None


def _dkim_public(pem):
    try:
        return public_from_private(pem)
    except Exception:
        raise DomainError("invalid_private_key") from None


def _create_shared_dkim_key(settings, domain, selector, pem):
    """Return the key committed at this selector, including on a concurrent create."""
    try:
        openbao_write(settings, dkim_vault_path(settings, domain, selector), pem, create_only=True)
    except OpenBaoHTTPError as ex:
        if ex.status == 400:  # KV v2 reports a CAS mismatch as HTTP 400
            winner = read_shared_dkim_key(settings, domain, selector)
            if winner is not None:
                return winner
        raise
    return pem


def install_dkim_key(settings, domain, selector, pem=None, *, source="domain", rotate=False):
    """Install a domain's key under the caller's settings lock. In a cluster a
    selector's fingerprint is immutable. Only explicit generation or shared
    OpenBao provisioning may create a missing key without an import."""
    cluster = clustered(settings)
    if cluster and rotate:
        raise DomainError("cluster_rotation_refused", domain)
    vault = settings["vault_enabled"]
    keyfile, pubfile = dkim_paths(domain, selector)
    local = _dkim_file(keyfile)
    published = _dkim_file(pubfile) if cluster else None
    supplied_public = _dkim_public(pem) if pem is not None else None
    local_public = _dkim_public(local) if cluster and local is not None else None

    def check_fingerprint(key):
        public = _dkim_public(key)
        if cluster:
            if (published is not None and published.strip() != public) or (local_public and local_public != public):
                raise DomainError("local_key_conflict", domain)
            if supplied_public and supplied_public != public:
                raise DomainError("shared_key_exists", domain)
        return public

    shared = None
    if vault and (cluster or source != "domain"):
        try:
            shared = read_shared_dkim_key(settings, domain, selector)
        except RuntimeError as ex:
            log(agent.SD_ERR + str(ex))
            raise DomainError("openbao_read_failed", domain) from None
    if source == "shared" and shared is None:
        raise DomainError("shared_key_missing", domain)
    if source == "shared" or (cluster and shared is not None):
        candidate = shared
    elif source == "generate" and rotate:
        candidate, _ = generate_dkim_key()
    elif pem is not None:
        candidate = pem
    elif local is not None:
        candidate = local
    elif shared is not None:
        candidate = shared
    else:
        if cluster and (published is not None or (not vault and source != "generate")):
            raise DomainError("cluster_key_required", domain)
        candidate, _ = generate_dkim_key()

    public = check_fingerprint(candidate)
    if vault:
        if cluster and shared is None:
            committed = _create_shared_dkim_key(settings, domain, selector, candidate)
            public = check_fingerprint(committed)
        elif not cluster and (shared is None or _dkim_public(shared) != public):
            openbao_write(settings, dkim_vault_path(settings, domain, selector), candidate)
    else:
        store_dkim_private(domain, selector, candidate)
    store_dkim_public(domain, selector, public)
    if vault and local is not None:
        os.unlink(keyfile)  # Only discard the local copy after both stores succeeded.
    return "openbao" if vault else "local"


def remove_dkim_files(domain, selector):
    keyfile, pubfile = dkim_paths(domain, selector)
    for path in (keyfile, pubfile):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    try:
        os.rmdir(os.path.dirname(keyfile))
    except OSError:
        pass


def key_location(settings, dom):
    keyfile, pubfile = dkim_paths(dom["domain"], dom["selector"])
    if settings["vault_enabled"]:
        if os.path.exists(keyfile):
            return "local_not_in_openbao"
        return "openbao" if os.path.exists(pubfile) else "missing"
    return "local" if os.path.exists(keyfile) else "missing"


def spf_mechanism(settings):
    return settings["spf_include"] or f"a:{settings['hostname']}"


def domain_records(settings, dom):
    """DNS records to publish for a sending domain"""
    domain = dom["domain"]
    records = []
    dkim = dkim_record(domain, dom["selector"])
    if dkim:
        records.append(dict(dkim, check="dkim", required=True,
                            purpose="DKIM public key of the selector"))
    records.append({
        "check": "spf", "required": True, "type": "TXT", "name": domain,
        "value": f"v=spf1 {spf_mechanism(settings)} ~all",
        "purpose": f"SPF: authorize this MTA. Add {spf_mechanism(settings)} to the existing SPF record, if any",
    })
    records.append({
        "check": "dmarc", "required": False, "type": "TXT", "name": f"_dmarc.{domain}",
        "value": f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
        "purpose": "DMARC policy (recommended): start with p=none, then quarantine or reject",
    })
    if settings["bounce_domain"]:
        records.append({
            "check": "return_path", "required": False, "type": "CNAME",
            "name": f"{RETURN_PATH_PREFIX}.{domain}", "value": settings["bounce_domain"] + ".",
            "purpose": f"Return path (recommended): envelope senders @{RETURN_PATH_PREFIX}.{domain} "
                       "bring bounces and feedback reports back to this MTA",
        })
    return records


def find_domain(settings, domain):
    domain = domain.lower().rstrip(".")
    return next((d for d in settings["domains"] if d["domain"] == domain), None)


def domain_view(settings, dom):
    """Public view of a sending domain: no secret"""
    return {
        "domain": dom["domain"],
        "selector": dom["selector"],
        "owner": dom.get("owner") or "",
        "tenant": dom.get("tenant") or "",
        "status": dom.get("status") or "pending",
        "last_checked": dom.get("last_checked") or "",
        "checks": dom.get("checks") or [],
        "key_location": key_location(settings, dom),
        "dkim_record": dkim_record(dom["domain"], dom["selector"]),
        "records": domain_records(settings, dom),
    }


def add_domain(settings, domain, selector="", owner="", tenant="", pem=None):
    """Add a sending domain and install its DKIM key. The caller holds
    settings_lock() and saves the settings. Raises DomainError"""
    domain = (domain or "").lower().rstrip(".")
    selector = (selector or "kumo1").lower()
    if not HOSTNAME_RE.fullmatch(domain):
        raise DomainError("invalid_domain", domain)
    if not SELECTOR_RE.fullmatch(selector):
        raise DomainError("invalid_selector", selector)
    if not TENANT_RE.fullmatch(tenant or ""):
        raise DomainError("invalid_tenant", tenant)
    if find_domain(settings, domain):
        raise DomainError("domain_exists", domain)
    try:
        install_dkim_key(settings, domain, selector, pem)
    except RuntimeError as ex:
        log(agent.SD_ERR + str(ex))
        raise DomainError("openbao_write_failed", domain) from None
    entry = {"domain": domain, "selector": selector, "owner": owner or "",
             "tenant": tenant or "", "status": "pending", "last_checked": "", "checks": [],
             "registration_id": secrets.token_hex(16)}
    settings["domains"] = sorted(settings["domains"] + [entry], key=lambda d: d["domain"])
    return entry


def remove_domain(settings, domain, owner=None):
    """Remove a sending domain and its local key files. owner restricts the
    removal to the domains of an integration. Raises DomainError"""
    dom = find_domain(settings, domain)
    if not dom or (owner is not None and (dom.get("owner") or "") != owner):
        raise DomainError("domain_not_found", domain)
    settings["domains"] = [d for d in settings["domains"] if d["domain"] != dom["domain"]]
    remove_dkim_files(dom["domain"], dom["selector"])
    return dom


def dns_txt(name, timeout=5.0):
    """(list of TXT strings, error): error is None, "nxdomain" or a message"""
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], "nxdomain"
    except (dns.exception.DNSException, OSError) as ex:
        return [], ex.__class__.__name__
    return [b"".join(r.strings).decode(errors="replace") for r in answer], None


def dns_cname(name, timeout=5.0):
    import dns.exception
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], "nxdomain"
    except (dns.exception.DNSException, OSError) as ex:
        return [], ex.__class__.__name__
    return [str(r.target).rstrip(".").lower() for r in answer], None


def dkim_p(value):
    """The p= tag of a DKIM TXT record, without blanks"""
    for tag in value.split(";"):
        key, _, val = tag.strip().partition("=")
        if key.strip() == "p":
            return re.sub(r"\s+", "", val)
    return None


def _check(name, required, status, detail):
    return {"name": name, "required": required, "status": status, "detail": detail}


def validate_domain(settings, dom, resolver_txt=dns_txt, resolver_cname=dns_cname):
    """Check the DNS of a sending domain and update dom in place: status
    (pending, verified, failed), last_checked and checks. A missing record
    is pending, a published but different record is failed."""
    checks = []
    domain = dom["domain"]
    _, pubfile = dkim_paths(domain, dom["selector"])
    try:
        with open(pubfile) as fp:
            public = fp.read().strip()
    except FileNotFoundError:
        public = None
    name = f"{dom['selector']}._domainkey.{domain}"
    values, err = resolver_txt(name)
    dkim_values = [v for v in values if "p=" in v]
    if public is None:
        checks.append(_check("dkim", True, "fail", "no DKIM key: generate it"))
    elif err:
        checks.append(_check("dkim", True, "missing", f"{name}: no TXT record ({err})"))
    elif any(dkim_p(v) == public for v in dkim_values):
        checks.append(_check("dkim", True, "pass", f"{name} matches the key"))
    elif dkim_values:
        checks.append(_check("dkim", True, "fail", f"{name} publishes another key"))
    else:
        checks.append(_check("dkim", True, "missing", f"{name}: no DKIM TXT record"))

    mechanism = spf_mechanism(settings).lower()
    values, err = resolver_txt(domain)
    spf = [v for v in values if v.lower().startswith("v=spf1")]
    if err or not spf:
        checks.append(_check("spf", True, "missing", f"{domain}: no SPF record" + (f" ({err})" if err else "")))
    elif len(spf) > 1:
        checks.append(_check("spf", True, "fail", f"{domain}: more than one SPF record"))
    elif mechanism in spf[0].lower().split():
        checks.append(_check("spf", True, "pass", f"SPF authorizes {mechanism}"))
    else:
        checks.append(_check("spf", True, "fail", f"SPF does not include {mechanism}"))

    values, err = resolver_txt(f"_dmarc.{domain}")
    dmarc = [v for v in values if v.lower().startswith("v=dmarc1")]
    if dmarc:
        checks.append(_check("dmarc", False, "pass", "DMARC record found"))
    else:
        checks.append(_check("dmarc", False, "missing", f"_dmarc.{domain}: no DMARC record (recommended)"))

    if settings["bounce_domain"]:
        name = f"{RETURN_PATH_PREFIX}.{domain}"
        targets, err = resolver_cname(name)
        if settings["bounce_domain"].lower() in targets:
            checks.append(_check("return_path", False, "pass", f"{name} points to {settings['bounce_domain']}"))
        elif targets:
            checks.append(_check("return_path", False, "fail", f"{name} points elsewhere"))
        else:
            checks.append(_check("return_path", False, "missing", f"{name}: no CNAME (recommended)"))

    required = [c for c in checks if c["required"]]
    if all(c["status"] == "pass" for c in required):
        status = "verified"
    elif any(c["status"] == "fail" for c in required):
        status = "failed"
    else:
        status = "pending"
    dom.update({"status": status, "last_checked": utcnow(), "checks": checks})
    return dom


def validate_domains(names=None, owner=None):
    """Validate the given domains (all if names is None; only those of
    owner if set) without holding the lock during the DNS queries, then
    store the results and apply the policy. Return the domain views."""
    def domain_snapshot(domain):
        _, public_path = dkim_paths(domain["domain"], domain["selector"])
        return (domain.get("registration_id"), domain["selector"], domain.get("owner") or "",
                _dkim_file(public_path))

    settings = load_settings()
    targets = [copy.deepcopy(d) for d in settings["domains"]
               if (names is None or d["domain"] in names)
               and (owner is None or (d.get("owner") or "") == owner)]
    snapshots = {d["domain"]: domain_snapshot(d) for d in targets}
    results = {d["domain"]: validate_domain(settings, d) for d in targets}
    checked = []
    with settings_lock():
        current = load_settings()
        if (spf_mechanism(current), current["bounce_domain"]) != (spf_mechanism(settings), settings["bounce_domain"]):
            return []
        policy_changed = False
        for dom in current["domains"]:
            name = dom["domain"]
            if name in results and snapshots[name] == domain_snapshot(dom):
                result = results[name]
                policy_changed |= (dom.get("status") == "verified") != (result["status"] == "verified")
                for key in ("status", "last_checked", "checks"):
                    dom[key] = result[key]
                checked.append(domain_view(current, dom))
        if checked:
            save_settings(current)
            if policy_changed:
                apply_policy()
    return checked


# --------------------------------------------------------------------------
# Multi-node cluster (docs/cluster.md). Every instance is a peer: no
# coordinator. A shared throttle store (an ns8-valkey instance or any
# Redis/Valkey) makes throttles and connection limits global; each peer
# can run tsa-daemon, and every kumod publishes its log records to the
# daemons of the peers that use the same store.
# --------------------------------------------------------------------------

CLUSTER_STORES = ["none", "valkey", "manual"]
CLUSTER_SERVICE = "kumomta-cluster"       # module/<id>/srv/tcp/kumomta-cluster
CLUSTER_EVENT = "kumomta-cluster-changed"
CLUSTER_FAILURES_BEFORE_LOCAL = 2         # failed checks before local throttles
# ns8-valkey integration: service records and the guarded action that
# creates the client credentials (role valkeyclient, authorization
# valkey@any:valkeyclient in build-images.sh)
VALKEY_SERVICE = "valkey"
VALKEY_GRANT_ACTION = "grant-client"     # every call rotates the password
VALKEY_REVOKE_ACTION = "revoke-client"

CLUSTER_REASONS = {
    "store_not_found": "the Valkey instance {store} does not exist or publishes no endpoint",
    "credentials_unavailable": "no credentials for the throttle store {store}",
    "store_unreachable": "the throttle store {store} does not answer",
    "no_cluster_address": "this node has no cluster VPN address",
}


def clustered(settings):
    return settings.get("cluster_store", "none") != "none"


def tsa_port():
    """TCP port of tsa-daemon: the third TCP port of the module, or the
    port allocated later by an install made with an image that asked for
    two ports only. None when missing."""
    ports = [p for p in os.environ.get("TCP_PORTS", "").split(",") if p]
    if len(ports) >= 3:
        return int(ports[2])
    if os.environ.get("KUMO_TSA_PORT"):
        return int(os.environ["KUMO_TSA_PORT"])
    return None


def ensure_tsa_port():
    """Allocate the TSA port of an upgraded install, once. The caller dumps
    the environment (agent.dump_env)."""
    port = tsa_port()
    if port:
        return port
    start, _end = agent.allocate_ports(1, "tcp", keep_existing=True)
    agent.set_env("KUMO_TSA_PORT", str(start))
    os.environ["KUMO_TSA_PORT"] = str(start)
    return start


def kumomta_modules():
    """{module_id: node_id} of the kumomta instances of the cluster"""
    rdb = agent.redis_connect(use_replica=True)
    found = {}
    for module_id, node_id in (rdb.hgetall("cluster/module_node") or {}).items():
        image_url = rdb.hget(f"module/{module_id}/environment", "IMAGE_URL") or ""
        image_name = image_url.rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
        if image_name == "kumomta":
            found[module_id] = str(node_id)
    return found


def service_records(service):
    """{module_id: record} of the providers of a tcp service (no secrets)"""
    rdb = agent.redis_connect(use_replica=True)
    return {rec["module_id"]: rec for rec in agent.list_service_providers(rdb, service, "tcp")}


def _read_json(path):
    try:
        with open(path) as fp:
            return json.load(fp)
    except (FileNotFoundError, ValueError):
        return {}


def read_cluster_state():
    return _read_json(CLUSTER_STATE)


def write_cluster_state(state):
    os.makedirs(CLUSTER_DIR, mode=0o700, exist_ok=True)
    return write_file(CLUSTER_STATE, json.dumps(state, indent=1, sort_keys=True) + "\n", 0o644)


def read_store_info():
    return _read_json(CLUSTER_STORE)


def write_store_info(info):
    os.makedirs(CLUSTER_DIR, mode=0o700, exist_ok=True)
    return write_file(CLUSTER_STORE, json.dumps(info, indent=1, sort_keys=True) + "\n", 0o644)


def bump_store_generation():
    """A new password was stored: kumod read the old one in its init event
    and must restart (the generation is part of the restart stamp; it is a
    random tag, not derived from the password)"""
    info = read_store_info()
    info["generation"] = secrets.token_hex(8)
    write_store_info(info)


def forget_store_credentials():
    """Drop the password and the user name of the throttle store"""
    changed = remove_secret(CLUSTER_PASSWORD)
    try:
        os.unlink(CLUSTER_STORE)
        changed = True
    except FileNotFoundError:
        pass
    return changed


def _truthy(value):
    return str(value).lower() in ("1", "true", "yes", "on")


def _node_url(host, port, tls=False):
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{'rediss' if tls else 'redis'}://{host}:{int(port)}/"


def store_identity(settings):
    """Peers with the same identity share the throttles, and publish to
    each other's tsa-daemon"""
    if settings["cluster_store"] == "valkey":
        return "valkey:" + settings["cluster_valkey"]
    if settings["cluster_store"] == "manual":
        nodes = sorted(u.rstrip("/").lower() for u in settings["cluster_redis_nodes"])
        return "manual:" + hashlib.sha256(json.dumps(nodes).encode()).hexdigest()[:16]
    return ""


def store_password(settings):
    """Password of the store: a local 0600 file, or OpenBao for a manual
    store while OpenBao is on. "" when unknown."""
    if settings["cluster_store"] == "manual" and settings["vault_enabled"] and not read_secret(CLUSTER_PASSWORD):
        try:
            return openbao_read(settings, openbao_secret_path(settings, "cluster_redis"))
        except RuntimeError as ex:
            log(agent.SD_WARNING + f"Cannot read the throttle store password from OpenBao: {ex}")
            return ""
    return read_secret(CLUSTER_PASSWORD)


def grant_valkey_client(valkey_id):
    """Ask the ns8-valkey instance for client credentials (guarded action,
    role valkeyclient). The password goes to a 0600 file; the task output
    is never logged. Raises RuntimeError."""
    import agent.tasks
    ret = agent.tasks.run(agent_id=f"module/{valkey_id}", action=VALKEY_GRANT_ACTION, data={},
                          extra={"isNotificationHidden": True})
    if ret.get("exit_code") != 0:
        raise RuntimeError(f"{VALKEY_GRANT_ACTION} of {valkey_id} failed (exit code {ret.get('exit_code')})")
    output = ret.get("output") or {}
    if not isinstance(output, dict) or not output.get("password"):
        raise RuntimeError(f"{VALKEY_GRANT_ACTION} of {valkey_id} returned no password")
    write_secret(CLUSTER_PASSWORD, output["password"])
    write_store_info({
        "valkey": valkey_id,
        "cluster_id": output.get("cluster_id") or "",
        # seeds and mode as granted, merged with those of the record
        "seeds": [f"{n['host']}:{int(n['port'])}" for n in (output.get("nodes") or [])
                  if isinstance(n, dict) and n.get("host") and n.get("port")],
        "cluster": bool(output.get("cluster")) or output.get("ha_mode") == "cluster",
        "granted_to": os.environ.get("MODULE_ID", ""),
        "username": output.get("username") or "",
        "generation": secrets.token_hex(8),
    })


def revoke_valkey_client(valkey_id):
    """Best effort: drop the Valkey user of this instance (ns8-valkey also
    drops it on module-removed)"""
    import agent.tasks
    try:
        ret = agent.tasks.run(agent_id=f"module/{valkey_id}", action=VALKEY_REVOKE_ACTION, data={},
                              extra={"isNotificationHidden": True})
        if ret.get("exit_code") != 0:
            log(agent.SD_WARNING + f"{VALKEY_REVOKE_ACTION} of {valkey_id} failed (exit code {ret.get('exit_code')})")
    except Exception as ex:
        log(agent.SD_WARNING + f"{VALKEY_REVOKE_ACTION} of {valkey_id} failed: {ex}")


def resolve_store(settings, fetch):
    """({nodes, username, cluster, label}, reason): where the throttle
    store is and how to log in, no secrets. nodes are redis:// URLs."""
    if settings["cluster_store"] == "valkey":
        valkey_id = settings["cluster_valkey"]
        info = read_store_info()
        try:
            records = service_records(VALKEY_SERVICE)
        except Exception as ex:
            log(agent.SD_WARNING + f"Cannot read the Valkey service records: {ex}")
            records = {}
        rec = records.get(valkey_id)
        if not rec and info.get("valkey") == valkey_id and info.get("cluster_id"):
            # The configured member was removed: another member of the same
            # Valkey cluster serves the same data with the same credentials
            rec = next((r for _mid, r in sorted(records.items())
                        if r.get("cluster_id") == info["cluster_id"] and r.get("host") and r.get("port")), None)
        if not rec or not rec.get("host") or not rec.get("port"):
            return None, "store_not_found"
        if fetch and (not read_secret(CLUSTER_PASSWORD) or info.get("valkey") != valkey_id
                      or info.get("granted_to") != os.environ.get("MODULE_ID", "")):
            try:
                grant_valkey_client(valkey_id)
            except Exception as ex:
                log(agent.SD_WARNING + f"Cannot get the Valkey credentials of {valkey_id}: {ex}")
            info = read_store_info()
        if not read_secret(CLUSTER_PASSWORD) or info.get("valkey") != valkey_id:
            return None, "credentials_unavailable"
        # Seeds: the record endpoint, its nodes list, and the nodes of the
        # grant-client output. ha_mode "cluster" (or cluster true) selects
        # the Valkey Cluster protocol, also with a single seed.
        tls = _truthy(rec.get("tls", ""))
        nodes = [_node_url(rec["host"], rec["port"], tls)]
        seeds = (rec.get("nodes") or "").split(",") + list(info.get("seeds") or [])
        for extra in seeds:
            host, _, port = extra.strip().rpartition(":")
            if host and port.isdigit() and _node_url(host.strip("[]"), port, tls) not in nodes:
                nodes.append(_node_url(host.strip("[]"), port, tls))
        is_cluster = (rec.get("ha_mode") == "cluster" or _truthy(rec.get("cluster", ""))
                      or bool(info.get("cluster")) or len(nodes) > 1)
        return {"nodes": nodes, "username": info.get("username") or "",
                "cluster": is_cluster,
                "label": valkey_id if rec.get("module_id") == valkey_id
                else f"{valkey_id} (via {rec.get('module_id')})"}, ""
    nodes = list(settings["cluster_redis_nodes"])
    if not store_password(settings) and settings["cluster_redis_password_set"]:
        return None, "credentials_unavailable"
    return {"nodes": nodes, "username": settings["cluster_redis_username"],
            "cluster": bool(settings["cluster_redis_cluster"]) or len(nodes) > 1,
            "label": ", ".join(nodes)}, ""


def store_ping(store, password, timeout=3.0):
    """(True, "") when a node of the store answers PING with these
    credentials. The error never contains the password."""
    import redis
    err = "no node"
    for url in store["nodes"]:
        try:
            conn = redis.Redis.from_url(url, username=store.get("username") or None,
                                        password=password or None, socket_timeout=timeout,
                                        socket_connect_timeout=timeout)
            try:
                if conn.ping():
                    return True, ""
            finally:
                conn.close()
        except Exception as ex:
            err = ex.__class__.__name__
    return False, err


def tsa_reachable(urls, timeout=2.0):
    """Number of tsa-daemon URLs that accept a TCP connection"""
    import socket
    count = 0
    for url in urls:
        host, _, port = url.split("//", 1)[-1].rpartition(":")
        try:
            with socket.create_connection((host.strip("[]"), int(port)), timeout=timeout):
                count += 1
        except (OSError, ValueError):
            pass
    return count


def designated_tsa_hosts(identity):
    """{module_id: url} of the designated TSA hosts of a store (records)"""
    hosts = {}
    for module_id, rec in service_records(CLUSTER_SERVICE).items():
        if rec.get("store") == identity and _truthy(rec.get("tsa", "")) and rec.get("host") and rec.get("port"):
            hosts[module_id] = f"http://{rec['host']}:{int(rec['port'])}"
    return hosts


def tsa_peers(identity, network):
    """Verified VPN addresses and designated TSA endpoints for this store."""
    addresses, urls = set(), []
    if not network:
        return addresses, urls
    try:
        vpn = ipaddress.ip_network(network, strict=False)
        modules = kumomta_modules()
        with agent.redis_connect(use_replica=True, socket_timeout=5, socket_connect_timeout=5) as rdb:
            for module_id, rec in sorted(service_records(CLUSTER_SERVICE).items()):
                node = modules.get(module_id)
                if (module_id == os.environ.get("MODULE_ID") or not node
                        or not re.fullmatch(r"kumomta[0-9]+", module_id)
                        or not rec.get("module_uuid") or rec.get("store") != identity):
                    continue
                address = rdb.hget(f"node/{node}/vpn", "ip_address")
                if not address or address != rec.get("host") or not is_ip_address(address):
                    continue
                if ipaddress.ip_address(address) not in vpn:
                    continue
                addresses.add(address)
                port = rec.get("port") or ""
                if _truthy(rec.get("tsa", "")) and port.isdecimal() and 0 < int(port) <= 65535:
                    host = f"[{address}]" if ":" in address else address
                    urls.append(f"http://{host}:{int(port)}")
    except Exception as ex:
        log(agent.SD_WARNING + f"Cannot read the cluster records: {ex}")
        return set(), []
    return addresses, urls


def _cluster_local(state, previous, reason, immediate):
    """Local throttles, unless the store failed only once since it last
    answered: a short restart of the store does not restart every peer
    (hysteresis of CLUSTER_FAILURES_BEFORE_LOCAL checks)"""
    failures = int(previous.get("failures") or 0) + 1
    if (not immediate and previous.get("mode") == "shared" and previous.get("store") == state["store"]
            and failures < CLUSTER_FAILURES_BEFORE_LOCAL):
        kept = dict(previous)
        kept.update({"failures": failures, "tsa_listen": state["tsa_listen"],
                     "tsa_publish": state["tsa_publish"], "tsa_subscribe": state["tsa_subscribe"],
                     "tsa_trusted_hosts": state["tsa_trusted_hosts"],
                     "tsa_reachable": state.get("tsa_reachable", 0)})
        return kept
    state.update({"mode": "local", "reason": reason, "redis": None, "failures": failures})
    return state


def evaluate_cluster(settings, fetch=True, immediate=False):
    """Decide how kumod uses the cluster and return the new state (no
    secrets): mode (standalone, shared, local), reason, store, redis
    {nodes, username, cluster}, tsa_listen, tsa_publish, tsa_subscribe.
    Network checks only: the caller writes the state and renders.

    fetch: ask ns8-valkey for credentials when needed (not in
    ExecStartPre). immediate: no hysteresis (startup, explicit changes)."""
    previous = read_cluster_state()
    port = tsa_port()
    state = {"mode": "standalone", "reason": "", "store": "", "store_label": "", "redis": None,
             "tsa_listen": "", "tsa_publish": [], "tsa_subscribe": [], "tsa_trusted_hosts": [], "failures": 0}
    if not clustered(settings):
        if settings["tsa_enabled"] and port:
            url = f"http://127.0.0.1:{port}"
            state.update({"tsa_listen": f"127.0.0.1:{port}", "tsa_publish": [url],
                          "tsa_subscribe": [url], "tsa_trusted_hosts": ["127.0.0.1"]})
        return state

    identity = store_identity(settings)
    state["store"] = identity
    network, address = cluster_info()
    own = ""
    if settings["tsa_enabled"] and port and address and is_ip_address(address):
        host = f"[{address}]" if ":" in address else address
        state["tsa_listen"] = f"{host}:{port}"
        own = f"http://{state['tsa_listen']}"
    # kumod publishes to the designated TSA hosts only, and subscribes to
    # its own daemon (or to one of them): peers without TSA joining or
    # leaving leave these lists, and kumod, untouched
    addresses, peers = tsa_peers(identity, network)
    if own:
        state["tsa_trusted_hosts"] = sorted(addresses | {address})
    state["tsa_publish"] = ([own] if own else []) + peers
    state["tsa_subscribe"] = [own] if own else peers[:1]
    state["tsa_reachable"] = tsa_reachable(state["tsa_publish"]) if peers else int(bool(own))
    if not address and settings["cluster_store"] == "valkey":
        # ns8-valkey is reached through the cluster VPN
        return _cluster_local(state, previous, "no_cluster_address", True)

    store, reason = resolve_store(settings, fetch)
    state["store_label"] = store["label"] if store else settings["cluster_valkey"]
    if not store:
        return _cluster_local(state, previous, reason, True)
    ok, err = store_ping(store, store_password(settings))
    if not ok and fetch and "Authentication" in err and settings["cluster_store"] == "valkey":
        # ns8-valkey rotated or revoked the credentials: ask again, once
        try:
            grant_valkey_client(settings["cluster_valkey"])
            store, reason = resolve_store(settings, False)
            if store:
                ok, err = store_ping(store, store_password(settings))
        except Exception as ex:
            log(agent.SD_WARNING + f"Cannot renew the Valkey credentials: {ex}")
    if not ok or not store:
        log(agent.SD_WARNING + f"Throttle store {state['store_label']} unreachable: {err}")
        return _cluster_local(state, previous, "store_unreachable", immediate)
    state.update({"mode": "shared", "redis": {k: store[k] for k in ("nodes", "username", "cluster")}})
    return state


def cluster_warnings(settings, state=None):
    """Warning shown on every page while a clustered instance uses local
    throttles"""
    state = read_cluster_state() if state is None else state
    if not clustered(settings):
        return []
    warnings = []
    if state.get("tsa_publish") and not state.get("tsa_reachable", 1):
        warnings.append({"id": "tsa_unreachable", "reason": "tsa_unreachable",
                         "message": "No designated TSA host answers: traffic shaping automation is paused "
                                    "(shaping limits still apply)"})
    if state.get("mode") != "local":
        return warnings
    reason = state.get("reason") or "store_unreachable"
    store = state.get("store_label") or settings.get("cluster_valkey") or "?"
    detail = CLUSTER_REASONS.get(reason, reason).format(store=store)
    return [{"id": "cluster_degraded", "reason": reason,
             "message": f"Cluster degraded: {detail}. Throttles and connection limits are local "
                        "to this instance until the store answers again; mail is still sent"}] + warnings


def cluster_record(settings, state):
    """Service record of this peer (no secrets), or None when standalone"""
    if not clustered(settings):
        return None
    _, address = cluster_info()
    port = tsa_port()
    return {
        "host": address or "",
        "port": str(port) if (settings["tsa_enabled"] and port) else "",
        "tsa": "1" if (settings["tsa_enabled"] and port) else "0",
        "store": store_identity(settings),
        "store_type": settings["cluster_store"],
        "node": os.environ.get("NODE_ID", ""),
        "module_uuid": os.environ.get("MODULE_UUID", ""),
        "hostname": settings["hostname"],
        "mode": state.get("mode") or "",
    }


def publish_cluster_record(settings, state, force_event=False):
    """Write module/<id>/srv/tcp/kumomta-cluster. The kumomta-cluster-changed
    event tells the peers to refresh their tsa-daemon list; a change of the
    mode alone fires no event."""
    agent_id = os.environ["AGENT_ID"]
    key = f"{agent_id}/srv/tcp/{CLUSTER_SERVICE}"
    rec = cluster_record(settings, state)
    with agent.redis_connect(privileged=True) as prdb:
        old = prdb.hgetall(key) or {}
        changed = (old != (rec or {}))
        strip = lambda r: {k: v for k, v in (r or {}).items() if k != "mode"}
        notify = force_event or strip(old) != strip(rec)
        trx = prdb.pipeline()
        if changed:
            trx.delete(key)
            if rec:
                trx.hset(key, mapping=rec)
        if notify:
            trx.publish(f"{agent_id}/event/{CLUSTER_EVENT}", json.dumps({
                "module_id": os.environ["MODULE_ID"],
                "module_uuid": os.environ.get("MODULE_UUID", ""),
                "node_id": int(os.environ["NODE_ID"]),
                "store": (rec or {}).get("store", ""),
            }))
        trx.execute()
    return changed


def systemctl(*args):
    return subprocess.run(["systemctl", "--user", *args], stdout=sys.stderr).returncode


def _unit_in_use(unit):
    return systemctl("-q", "is-enabled", unit) == 0 or systemctl("-q", "is-active", unit) == 0


def apply_cluster_services(settings, state):
    """Enable, start or stop tsa-daemon and the health check timer"""
    if state.get("tsa_listen"):
        systemctl("enable", "kumomta-tsa.service")
        if tsa_restart_required() or systemctl("-q", "is-active", "kumomta-tsa.service") != 0:
            if systemctl("restart", "kumomta-tsa.service") == 0:
                stamp_tsa()
    elif _unit_in_use("kumomta-tsa.service"):
        systemctl("disable", "--now", "kumomta-tsa.service")
    if clustered(settings):
        systemctl("enable", "--now", "kumomta-cluster-check.timer")
    elif _unit_in_use("kumomta-cluster-check.timer"):
        systemctl("disable", "--now", "kumomta-cluster-check.timer")


def _file_digest(path):
    try:
        with open(path, "rb") as fp:
            return hashlib.sha256(fp.read()).hexdigest()
    except FileNotFoundError:
        return ""


def tsa_restart_required():
    """tsa-daemon reads its listener only at startup"""
    try:
        with open(TSA_STAMP) as fp:
            stamp = fp.read().strip()
    except FileNotFoundError:
        stamp = None
    return stamp != _file_digest(os.path.join(CONFIG_DIR, "tsa_init.lua"))


def stamp_tsa():
    write_file(TSA_STAMP, _file_digest(os.path.join(CONFIG_DIR, "tsa_init.lua")) + "\n", 0o600)


def cluster_check(prestart=False, immediate=False):
    """Health check of a clustered peer (timer, events, ExecStartPre):
    evaluate the cluster, render the policy and restart kumod when the
    throttle store or the tsa-daemon list changes; KumoMTA reads both in
    its init event only. Returns the new state.

    In ExecStartPre (prestart) nothing is fetched or restarted: kumod
    starts with the policy rendered here. KumoMTA pings the store in its
    init event and does not start if it does not answer, so the startup
    decision is immediate."""
    settings = load_settings()
    if not clustered(settings) or not settings["hostname"]:
        return read_cluster_state()
    previous = read_cluster_state()
    # Network checks (and the credentials request) without the lock: the
    # domain API daemon must not wait for them
    state = evaluate_cluster(settings, fetch=not prestart, immediate=(prestart or immediate))
    with settings_lock():
        current = load_settings()
        if store_identity(current) != store_identity(settings) \
                or current["tsa_enabled"] != settings["tsa_enabled"]:
            return read_cluster_state()  # configure-module changed it meanwhile
        write_cluster_state(state)
        changed, restart = write_config(current)
    if prestart:
        return state
    if state.get("tsa_listen") != previous.get("tsa_listen"):
        apply_cluster_services(current, state)
    elif state.get("tsa_listen") and tsa_restart_required():
        if systemctl("restart", "kumomta-tsa.service") == 0:
            stamp_tsa()
    if previous.get("mode") != state.get("mode"):
        if state.get("mode") == "local":
            log(agent.SD_WARNING + cluster_warnings(settings, state)[0]["message"])
        else:
            log(f"Cluster: {state.get('mode')} throttles with {state.get('store_label')}")
    try:
        publish_cluster_record(settings, state)
    except Exception as ex:
        log(agent.SD_WARNING + f"Cannot publish the cluster record: {ex}")
    if systemctl("-q", "is-active", "kumomta.service") == 0:
        if restart:
            systemctl("restart", "kumomta.service")
        elif changed:
            try:
                api_request("/api/admin/bump-config-epoch", method="POST")
            except Exception as ex:
                log(agent.SD_WARNING + f"Configuration epoch bump failed: {ex}")
    return state


# --------------------------------------------------------------------------
# Sending IPs and their limits (docs/sending-ips.md). Native KumoMTA
# mechanisms only: one egress source per IP in the default pool; overall
# per-IP limits are named additional_message_rate_throttles and
# additional_connection_limits added in get_egress_path_config; per-IP
# per-provider limits are provider/domain source blocks of shaping.toml with
# the same named limits. Named limits live in the shared store when
# clustered, so they hold per IP across the nodes.
# --------------------------------------------------------------------------

def source_name(settings, address):
    """Egress source of a sending IP. The default route keeps the name
    "default" on a standalone instance (unchanged queues); in a cluster it
    is named after the node, so that its limits are per IP, not global."""
    if address:
        return "ip-" + re.sub(r"[^0-9A-Za-z]", "-", address)
    if clustered(settings):
        return f"node-{os.environ.get('NODE_ID', '0')}"
    return "default"


def limit_specs(entry, key):
    """({limit name: throttle spec}, {limit name: connections}) of a limits
    entry, the names starting with key"""
    rates, conns = {}, {}
    for field, period in PERIODS.items():
        if int(entry.get(field) or 0) > 0:
            rates[f"{key}-{period}"] = f"{int(entry[field])}/{period}"
    if int(entry.get("max_connections") or 0) > 0:
        conns[f"{key}-conn"] = int(entry["max_connections"])
    return rates, conns


def provider_block_name(rule):
    """The provider block of KumoMTA (a preset), or ns8-mx-<suffix> and
    ns8-domain-<domain> for the custom ones"""
    if rule["provider"] in PROVIDER_PRESETS:
        return rule["provider"]
    slug = re.sub(r"[^0-9a-z]", "-", rule["match"].lower().strip("."))
    return f"ns8-{rule['provider']}-{slug}"


def sending_ip_files(settings):
    """(sources, ip_limits, provider blocks, domain blocks) for the policy"""
    ips = settings["sending_ips"] or [{"address": ""}]
    sources, pool, overall, providers, domains = {}, {}, {}, {}, {}
    for ip in ips:
        name = source_name(settings, ip.get("address") or "")
        src = {"ehlo_domain": ip.get("ehlo_domain") or settings["hostname"]}
        if ip.get("address"):
            src["source_address"] = ip["address"]
        sources[name] = src
        pool[name] = {"weight": int(ip.get("weight") or 1)}
        rates, conns = limit_specs(ip, f"ns8-{name}")
        if rates or conns:
            overall[name] = {"rates": rates, "connections": conns}
        for rule in ip.get("providers") or []:
            rates, conns = limit_specs(rule, f"ns8-{name}-{provider_block_name(rule)}")
            block = {}
            if rates:
                block["additional_message_rate_throttles"] = rates
            if conns:
                block["additional_connection_limits"] = conns
            if not block:
                continue
            if rule["provider"] == "domain":
                # a destination domain: its own (domain, source) block
                domains.setdefault(rule["match"].lower(), {"sources": {}})["sources"][name] = block
                continue
            pname = provider_block_name(rule)
            prov = providers.setdefault(pname, {"sources": {}})
            if rule["provider"] == "mx":
                prov["match"] = [{"MXSuffix": "." + rule["match"].lower().lstrip(".")}]
            prov["sources"][name] = block
    return sources, pool, overall, providers, domains


# --------------------------------------------------------------------------
# Rendering of the KumoMTA policy
# --------------------------------------------------------------------------

def keysource(settings, name, local_file):
    """A KumoMTA KeySource: a vault block when OpenBao is enabled, else a
    file under the secrets directory"""
    if settings["vault_enabled"]:
        block = {
            "vault_mount": settings["vault_mount"],
            "vault_path": openbao_secret_path(settings, name),
        }
        if settings["vault_key"]:
            block["vault_key"] = settings["vault_key"]
        return block
    return f"{C_SECRETS}/{local_file}"


def init_settings(settings):
    """Settings KumoMTA reads only in its init event."""
    listeners = []
    if settings["inbound_enabled"]:
        listeners.append({"name": "inbound", "listen": f"0.0.0.0:{settings['inbound_port']}"})
    if settings["submission_enabled"]:
        listeners.append({"name": "submission", "listen": f"0.0.0.0:{settings['submission_port']}"})
    init = {
        "hostname": settings["hostname"],
        "http_listen": f"127.0.0.1:{os.environ.get('TCP_PORT', '8000')}",
        "auth_port": daemon_port(),
        "listeners": listeners,
        "max_message_size": int(settings["max_message_size"]) * 1024 * 1024,
        "tls_certificate": f"{C_TLS}/cert.pem",
        "tls_private_key": f"{C_TLS}/key.pem",
        "webhook": bool(settings["webhook_enabled"] and settings["webhook_url"]),
        "webhook_record_types": list(settings["webhook_record_types"]),
    }
    # Cluster: shared throttle store and tsa-daemon endpoints, as decided by
    # the last cluster evaluation (configure-module, health check). KumoMTA
    # reads both in its init event only. Absent for a standalone instance
    # without TSA: its policy does not change.
    cluster = read_cluster_state()
    if cluster.get("mode") == "shared" and cluster.get("redis"):
        store = cluster["redis"]
        nodes = list(store["nodes"])
        init["redis"] = {"node": nodes[0] if len(nodes) == 1 else nodes,
                         "cluster": bool(store.get("cluster"))}
        if store.get("username"):
            init["redis"]["username"] = store["username"]
    if cluster.get("tsa_publish"):
        init["tsa"] = {"publish": list(cluster["tsa_publish"]),
                       "subscribe": list(cluster.get("tsa_subscribe") or [])}
    return init


def render_tsa_init(template_dir):
    """Startup-only TSA listener and exact publisher addresses."""
    state = read_cluster_state()
    if not state.get("tsa_listen"):
        return None
    trusted = state.get("tsa_trusted_hosts")
    if not trusted:
        # On upgrade the old state has no address list. Permit only this
        # node until the cluster check discovers verified peer addresses.
        trusted = [state["tsa_listen"].rpartition(":")[0].strip("[]")]
    with open(os.path.join(template_dir, "tsa_init.lua")) as fp:
        template = fp.read()
    generated = f"local TSA = {lua_value({'listen': state['tsa_listen'], 'trusted_hosts': trusted})}\n"
    return template.replace("--@@GENERATED@@", generated)


def render(settings, template_path=None):
    """Return {filename: content} of the policy directory"""
    template_path = template_path or os.path.join(os.environ["AGENT_INSTALL_DIR"], "templates", "init.lua")
    with open(template_path) as fp:
        template = fp.read()

    init = init_settings(settings)
    keys = {
        "api_password": f"{C_SECRETS}/api_password",
        "metrics_password": f"{C_SECRETS}/metrics_password",
        "smarthost_password": keysource(settings, "smarthost", "smarthost_password"),
        "webhook_token": keysource(settings, "webhook", "webhook_token"),
        "webhook_signing_secret": keysource(settings, "webhook_signing", "webhook_signing_secret"),
    }
    if "redis" in init:
        # Password of the throttle store: a local 0600 file; for a manual
        # store with OpenBao on, the shared secret <path>/cluster_redis
        if settings["cluster_store"] == "manual" and not read_secret(CLUSTER_PASSWORD) \
                and settings["vault_enabled"] and settings["cluster_redis_password_set"]:
            keys["cluster_redis_password"] = keysource(settings, "cluster_redis", CLUSTER_PASSWORD)
        elif read_secret(CLUSTER_PASSWORD):
            keys["cluster_redis_password"] = f"{C_SECRETS}/{CLUSTER_PASSWORD}"
    generated = (
        "-- Settings read only at startup (a change restarts kumod)\n"
        f"local INIT = {lua_value(init)}\n\n"
        "-- Key sources of the secrets: files under " + C_SECRETS + ",\n"
        "-- or OpenBao/Vault blocks (VAULT_ADDR and VAULT_TOKEN come from the\n"
        "-- environment of kumod, never from this file)\n"
        f"local KEYS = {lua_value(keys)}\n"
    )
    files = {"init.lua": template.replace("--@@GENERATED@@", generated)}
    tsa_init = render_tsa_init(os.path.dirname(template_path))
    if tsa_init:
        files["tsa_init.lua"] = tsa_init
    with open(os.path.join(os.path.dirname(template_path), "acl.toml")) as fp:
        acl = fp.read()
    # HTTP injection by the integration credentials with the inject scope
    for integ in settings["integrations"]:
        if "inject" in (integ.get("scopes") or []):
            acl += ("\n[[acl.\"http_listener/*/api/inject\"]]\nallow = true\n"
                    "privileges = [\"POST\"]\n"
                    f"identity.Individual = {toml_value(integ['name'])}\n")
    files["acl.toml"] = acl

    head = "Generated by ns8-kumomta configure-module: do not edit, changes are overwritten."

    # Inbound (relay_to) domains
    listener_domains = {}
    for route in settings["inbound_routes"]:
        listener_domains[route["domain"]] = {"relay_to": True}
    files["listener_domains.toml"] = toml_dumps(listener_domains, header=head + "\nDomains accepted from anyone and relayed to their inbound route.")

    # Explicit relay networks are opt-in. The NS8 smarthost trust also
    # requires the local VPN address on port 25.
    relay = {"networks": list(dict.fromkeys(settings["relay_networks"]))}
    relay.update(cluster_relay_policy(settings))
    files["relay_hosts.toml"] = toml_dumps(relay, header=head + "\nClients of these networks relay without SMTP AUTH.")

    # Pick the strictest rate when several credentials share a fixed tenant.
    tenant_rates = {}
    for integ in sorted(settings["integrations"], key=lambda item: item["name"]):
        tenant, rate = integ.get("tenant"), integ.get("max_message_rate")
        if tenant and rate:
            amount, period = rate.split("/")
            seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[period[0]]
            candidate = (Fraction(int(amount), seconds), rate)
            tenant_rates[tenant] = min(candidate, tenant_rates.get(tenant, candidate))
    files["tenant_rates.toml"] = toml_dumps({"rates": {key: rate for key, (_, rate) in tenant_rates.items()}}, header=head)

    # Egress sources and pool
    ip_sources, ip_pool, ip_overall, ip_providers, ip_domains = sending_ip_files(settings)
    files["sources.toml"] = toml_dumps({
        "source": ip_sources,
        "pool": {"default": ip_pool},
    }, header=head)
    # Overall limits of each sending IP, added by get_egress_path_config
    files["ip_limits.toml"] = toml_dumps({"source": ip_overall}, header=head + "\nOverall limits of each sending IP (egress source), all destinations together.")

    # DKIM signing data (format of policy-extras.dkim_sign, plus vault_key)
    base = {"headers": ["From", "To", "Subject", "Date", "MIME-Version", "Content-Type",
                        "Message-ID", "Reply-To", "Cc", "List-Unsubscribe"]}
    if settings["vault_enabled"]:
        base["vault_mount"] = settings["vault_mount"]
        base["vault_path_prefix"] = openbao_secret_path(settings, "dkim")
        if settings["vault_key"]:
            base["vault_key"] = settings["vault_key"]
    dkim_domains = {}
    for dom in settings["domains"]:
        entry = {
            "selector": dom["selector"],
            "owner": dom.get("owner") or "",
            "tenant": dom.get("tenant") or "",
            "verified": (dom.get("status") == "verified"),
            "tenant_from_admin": bool(dom.get("tenant_from_admin")),
        }
        if not settings["vault_enabled"]:
            entry["filename"] = f"{C_DKIM}/{dom['domain']}/{dom['selector']}.key"
        dkim_domains[dom["domain"]] = entry
    files["dkim_data.toml"] = toml_dumps({"base": base, "domain": dkim_domains}, header=head)

    # Scheduled queues: retention, inbound routes and smarthost
    routes = {}
    for route in settings["inbound_routes"]:
        host = route["host"]
        mx = f"[{host}]" if is_ip_address(host) else host
        routes[route["domain"]] = {"mx_list": [mx], "port": int(route.get("port") or 25)}
    smarthost = {"enabled": bool(settings["smarthost_enabled"])}
    if settings["smarthost_enabled"]:
        host = settings["smarthost_host"]
        smarthost.update({
            "mx_list": [f"[{host}]" if is_ip_address(host) else host],
            "port": int(settings["smarthost_port"]),
            "enable_tls": SMARTHOST_TLS.get(settings["smarthost_tls"], "Required"),
            "username": settings["smarthost_username"],
        })
    files["queues.toml"] = toml_dumps({
        "sink": {"enabled": bool(settings["sink_enabled"])},
        "default": {
            "egress_pool": "default",
            "retry_interval": settings["retry_interval"],
            "max_age": settings["max_age"],
        },
        "smarthost": smarthost,
        "route": routes,
    }, header=head)

    # Traffic shaping, merged over the default shaping.toml of KumoMTA
    shaping = {}
    for rule in settings["shaping"]:
        entry = {"mx_rollup": False}
        for key in ("connection_limit", "max_deliveries_per_connection"):
            if rule.get(key):
                entry[key] = int(rule[key])
        if rule.get("max_message_rate"):
            entry["max_message_rate"] = rule["max_message_rate"]
        shaping[rule["domain"]] = entry
    # Per-IP limits of a destination: provider (and domain) source blocks
    for dname, block in ip_domains.items():
        dentry = shaping.setdefault(dname, {"mx_rollup": False})
        dentry.setdefault("sources", {}).update(block["sources"])
    if ip_providers:
        shaping["provider"] = ip_providers
    files["shaping.toml"] = toml_dumps(shaping, header=head + "\nPer-destination limits, over /opt/kumomta/share/policy-extras/shaping.toml.")

    # Webhook of the log records
    files["webhook.toml"] = toml_dumps({
        "url": settings["webhook_url"],
        "token": bool(settings.get("webhook_token_set")),
        "signing": bool(settings.get("webhook_signing_secret_set")),
    }, header=head)

    # Sending platforms: domain policy of the integration credentials,
    # return path / bounce / feedback domain
    managed = sorted(d["domain"] for d in settings["domains"])
    files["platform.toml"] = toml_dumps({
        "require_verified_domains": bool(settings["require_verified_domains"]),
        "bounce_domain": settings["bounce_domain"],
        "return_path_domains": [f"{RETURN_PATH_PREFIX}.{d}" for d in managed] if settings["bounce_domain"] else [],
    }, header=head + "\nPolicy of the integration credentials (HTTP injection, SMTP), bounce and feedback domains.")
    return files


def write_config(settings, template_path=None, stamp=True):
    """Write the policy directory. Return (changed, restart_required).
    stamp=False leaves the restart stamp to configure-module"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    files = render(settings, template_path)
    changed = False
    for name, content in files.items():
        changed |= write_file(os.path.join(CONFIG_DIR, name), content, 0o644)
    # Settings read only at startup, the environment of kumod included
    stamped = {
        "init": init_settings(settings),
        "openbao": read_openbao_env() if settings["vault_enabled"] else {},
    }
    # KumoMTA caches resolved pools and sources separately from the policy
    # epoch. Restart when explicit sources change so existing queues cannot
    # keep selecting a removed address. Rate limits are in other files.
    if settings["sending_ips"]:
        stamped["sources"] = files["sources.toml"]
    # SMTP sessions can cache a relay decision for a recipient domain.
    # Reopen the listeners when relay trust changes to clear that cache.
    stamped["relay_hosts"] = files["relay_hosts.toml"]
    if clustered(settings):
        # KUMO_NODE_ID of the environment follows the cluster mode, and
        # kumod reads the store password in its init event only
        stamped["clustered"] = True
        stamped["store_generation"] = read_store_info().get("generation", "")
    digest = hashlib.sha256(json.dumps(stamped, sort_keys=True).encode()).hexdigest()
    try:
        with open(RESTART_STAMP) as fp:
            restart = fp.read().strip() != digest
    except FileNotFoundError:
        restart = True
    if restart and stamp:
        write_file(RESTART_STAMP, digest + "\n", 0o600)
    return changed, restart


# --------------------------------------------------------------------------
# Local HTTP API of kumod (127.0.0.1 only, HTTP basic authentication)
# --------------------------------------------------------------------------

def daemon_port():
    """Port of the domain management daemon: the second TCP port"""
    ports = [p for p in os.environ.get("TCP_PORTS", "").split(",") if p]
    return ports[1] if len(ports) > 1 else ""


def apply_policy():
    """Render the policy and apply it live (configuration epoch bump), for
    the changes outside configure-module (domain actions, API daemon).
    Settings read at startup do not change there."""
    changed, _ = write_config(load_settings(), stamp=False)
    if changed:
        try:
            api_request("/api/admin/bump-config-epoch", method="POST")
        except Exception as ex:
            log(agent.SD_WARNING + f"Configuration epoch bump failed: {ex}")
    return changed


def api_request(path, method="GET", body=None, timeout=10):
    env = agent.read_envfile(API_ENV)
    url = f"http://127.0.0.1:{os.environ['TCP_PORT']}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    auth = base64.b64encode(f"{env['KUMO_API_USER']}:{env['KUMO_API_PASSWORD']}".encode()).decode()
    req.add_header("Authorization", "Basic " + auth)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
        ctype = resp.headers.get("Content-Type", "")
    if "json" in ctype:
        return json.loads(payload or b"null")
    return payload.decode(errors="replace")


def configure_payload(settings):
    """configure-module input with every setting of settings.json, for
    restore and clone. Secrets are already in the state directory."""
    data = {k: v for k, v in settings.items() if k in DEFAULTS and not k.endswith("_set")}
    data["lets_encrypt"] = False
    data["smtp_users"] = [{"username": name} for name in sorted(read_smtp_users())]
    data["domains"] = [{"domain": d["domain"], "selector": d["selector"]}
                       for d in settings["domains"] if not d.get("owner")]
    data["integrations"] = [{k: i.get(k) for k in ("name", "tenant", "scopes", "max_message_rate")}
                            for i in settings["integrations"]]
    return data
