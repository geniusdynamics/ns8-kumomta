# Copyright (C) 2026 Genius Dynamics
# SPDX-License-Identifier: GPL-3.0-or-later

"""Source-side approvals for the clusterpeer actions."""

import contextlib
import fcntl
import json
import os
import sys

import agent
import kumomta_ns8 as kumo

# Relative to state/. Backups and clones must start with fresh approvals.
ACCESS_DIR = "peer-access"
GRANTS = os.path.join(ACCESS_DIR, "grants.json")


@contextlib.contextmanager
def access_lock(mode):
    os.makedirs(ACCESS_DIR, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(ACCESS_DIR, "lock"), os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock, mode)
        yield


def read_grants():
    try:
        with open(GRANTS) as fp:
            return json.load(fp)
    except FileNotFoundError:
        return {}


def registered_uuid(peer):
    """Read from the leader. The cluster owns module_uuid, even on a restore."""
    if peer == os.environ["MODULE_ID"] or not kumo.MODULE_ID_RE.fullmatch(peer):
        return None
    with agent.redis_connect(socket_timeout=5, socket_connect_timeout=5) as rdb:
        # The read-only NS8 Redis user permits HGET, while MULTI/EXEC is
        # reserved for privileged clients.
        with rdb.pipeline(transaction=False) as pipe:
            module_uuid, image_url = (
                pipe.hget("cluster/module_uuid", peer)
                .hget(f"module/{peer}/environment", "IMAGE_URL")
                .execute()
            )
    image_name = (image_url or "").rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
    return module_uuid if image_name == "kumomta" else None


def fail_peer(error, peer=""):
    agent.set_status("validation-failed")
    json.dump([{"field": "peer", "parameter": "peer", "value": peer, "error": error}], sys.stdout)
    raise SystemExit(3)


def set_peer_access(peer, allowed):
    with access_lock(fcntl.LOCK_EX):
        grants = read_grants()
        if allowed:
            module_uuid = registered_uuid(peer)
            if not module_uuid:
                fail_peer("not_a_kumomta_instance", peer)
            grants[peer] = module_uuid
        else:
            grants.pop(peer, None)
        kumo.write_file(GRANTS, json.dumps(grants, sort_keys=True) + "\n", 0o600)


def approved_peers():
    """Effective approvals for display. A new instance with an old ID needs a new grant."""
    grants = read_grants()
    if not grants:
        return set()
    with agent.redis_connect(socket_timeout=5, socket_connect_timeout=5) as rdb:
        uuids = rdb.hmget("cluster/module_uuid", list(grants))
    return {peer for peer, uid in zip(grants, uuids) if uid and uid == grants[peer]}


@contextlib.contextmanager
def authorized_peer():
    # The API server puts the authenticated token identity in AGENT_TASK_USER.
    # A direct Redis task, a human caller and a missing identity cannot export.
    user = os.environ.get("AGENT_TASK_USER", "")
    prefix, _, peer = user.partition("/")
    if prefix != "module" or not kumo.MODULE_ID_RE.fullmatch(peer):
        fail_peer("peer_not_authorized")
    # Keep an in-flight export ordered with revocation. Both Redis and
    # OpenBao reads have timeouts.
    with access_lock(fcntl.LOCK_SH):
        expected = read_grants().get(peer)
        if not expected or expected != registered_uuid(peer):
            fail_peer("peer_not_authorized")
        yield peer
