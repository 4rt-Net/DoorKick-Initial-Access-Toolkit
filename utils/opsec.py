#!/usr/bin/env python3
"""
OPSEC utilities for DoorKick.
Provides hostname spoofing, User-Agent rotation, connection jitter,
and non-identifying validation markers to reduce operational footprint.
"""
import socket
import time
import random
import string

# ---------------------------------------------------------------------------
# Hostname pool — realistic Windows / Linux workstation names
# ---------------------------------------------------------------------------
_HOSTNAMES = [
    "DESKTOP-A7K3M2", "WORKSTATION-X9P4Q1", "CLIENT-BOB-PC",
    "WIN-2024-SRV01", "SVR-DB-01", "IT-ADMIN-WKSTN",
    "DEV-MACHINE", "WS-CHRIS-01", "LAPTOP-JANE",
    "SRV-BACKUP-01", "DEVOPS-WEB01", "MONITOR-01",
    "WS-FINANCE-03", "HR-PC-01", "HELPDESK-WS",
    "IT-JSCHNEIDER", "WS-MKRUEGER", "DEV-THOMAS",
    "CLT-ACCT-02", "SRV-FILE-01",
]

# ---------------------------------------------------------------------------
# User-Agent pool — current mainstream browser strings
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
    "Gecko/20100101 Firefox/133.0",

    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 "
    "Safari/605.1.15",

    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 "
    "Edg/131.0.0.0",
]


def random_hostname():
    """Return a plausible hostname from the pool."""
    return random.choice(_HOSTNAMES)


def random_user_agent():
    """Return a realistic browser User-Agent string."""
    return random.choice(_USER_AGENTS)


def jitter(min_s=0.3, max_s=1.5):
    """Sleep for a randomized duration to mimic human timing."""
    time.sleep(random.uniform(min_s, max_s))


def random_marker(prefix=""):
    """Generate a non-identifying validation marker.

    Never includes tool-identifying strings like DOORKICK.
    Uses a hex-style suffix that looks like a session token or request ID.
    """
    chars = string.ascii_lowercase + string.digits
    suffix = ''.join(random.choices(chars, k=12))
    return f"{prefix}{suffix}" if prefix else suffix


class hostname_spoof:
    """Context manager to temporarily override socket.gethostname() / getfqdn().

    Libraries like pymysql, mysql.connector, and impacket read
    socket.gethostname() to build protocol handshakes.  Wrapping a
    connection call with this context manager replaces the real hostname
    with a plausible decoy.

    Usage::

        with hostname_spoof("DESKTOP-A7K3M2"):
            conn = pymysql.connect(host=target, ...)
    """

    def __init__(self, hostname=None):
        self.hostname = hostname or random_hostname()
        self._orig_hostname = None
        self._orig_fqdn = None

    def __enter__(self):
        self._orig_hostname = socket.gethostname
        self._orig_fqdn = socket.getfqdn
        hn = self.hostname
        socket.gethostname = lambda: hn
        socket.getfqdn = lambda: hn
        return self.hostname

    def __exit__(self, *args):
        socket.gethostname = self._orig_hostname
        socket.getfqdn = self._orig_fqdn