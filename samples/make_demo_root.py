"""Creates a fake filesystem root for demos and tests.

Usage:
    python samples/make_demo_root.py /tmp/demo_insecure
    python samples/make_demo_root.py /tmp/demo_secure --secure
    python -m hardening_checker --root /tmp/demo_insecure
"""
import os
import sys


def make_root(root: str, secure: bool = False) -> str:
    def w(rel: str, content: str, mode: int = 0o644) -> None:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)

    base_passwd = "root:x:0:0:root:/root:/bin/bash\nali:x:1000:1000::/home/ali:/bin/bash\n"
    base_shadow = "root:$6$abc:19000:0:90:7:::\nali:$6$def:19000:0:90:7:::\n"

    if secure:
        w("etc/ssh/sshd_config",
          "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nPasswordAuthentication no\n"
          "PermitEmptyPasswords no\nX11Forwarding no\nMaxAuthTries 3\n", 0o600)
        w("etc/ssh/sshd_config.d/50-local.conf", "# local settings\n")
        w("etc/passwd", base_passwd, 0o644)
        w("etc/shadow", base_shadow, 0o640)
        w("etc/group", "root:x:0:\n", 0o644)
        w("etc/gshadow", "root:*::\n", 0o640)
        w("etc/login.defs", "PASS_MAX_DAYS   90\n")
        sysctl = {"net/ipv4/ip_forward": "0", "net/ipv4/tcp_syncookies": "1",
                  "net/ipv4/conf/all/accept_redirects": "0",
                  "net/ipv4/icmp_echo_ignore_broadcasts": "1", "kernel/randomize_va_space": "2"}
    else:
        # The drop-in file is read first and the first value wins (the "no" in the main file doesn't count)
        w("etc/ssh/sshd_config",
          "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication no\n"
          "PermitEmptyPasswords yes\nX11Forwarding yes\nMaxAuthTries 10\n", 0o644)
        w("etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication yes\n")
        w("etc/passwd", base_passwd + "toor:x:0:0::/root:/bin/bash\n", 0o666)
        w("etc/shadow", base_shadow + "guest::19000:0:99999:7:::\n", 0o644)
        w("etc/group", "root:x:0:\n", 0o666)
        w("etc/gshadow", "root:*::\n", 0o644)
        w("etc/login.defs", "PASS_MAX_DAYS   99999\n")
        sysctl = {"net/ipv4/ip_forward": "1", "net/ipv4/tcp_syncookies": "0",
                  "net/ipv4/conf/all/accept_redirects": "1",
                  "net/ipv4/icmp_echo_ignore_broadcasts": "0", "kernel/randomize_va_space": "0"}
    for rel, val in sysctl.items():
        w("proc/sys/" + rel, val + "\n")
    return root


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: make_demo_root.py <directory> [--secure]")
    make_root(sys.argv[1], secure="--secure" in sys.argv)
    print(f"Created: {sys.argv[1]}")
