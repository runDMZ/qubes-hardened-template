#!/usr/bin/env bash
# harden-template.sh - harden a Debian-based Qubes OS template
#
# Run as root INSIDE a fresh clone of a Debian template (never in dom0):
#   sudo ./harden-template.sh            apply, then verify
#   sudo ./harden-template.sh --check    verify only, change nothing
#
# Options:
#   --remove-cups   also purge the printing system (CUPS)
#   --force         run even if this is not a Qubes TemplateVM (for testing)
#
# Safe to run several times: every step checks before it changes anything.
# References: ANSSI-BP-028 v2.0 (Rxx), CIS Debian Linux 12 Benchmark v1.1.0 (CIS x.y).

set -euo pipefail

CHECK_ONLY=0
REMOVE_CUPS=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --remove-cups) REMOVE_CUPS=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
FAILURES=0

# ---------------------------------------------------------------- safety checks
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }
[ -r /etc/debian_version ] || { echo "Debian-based templates only." >&2; exit 1; }

vm_type="$(qubesdb-read /type 2>/dev/null || echo unknown)"
if [ "$vm_type" != "TemplateVM" ] && [ "$FORCE" -eq 0 ]; then
  echo "This is not a Qubes TemplateVM (type: $vm_type)." >&2
  echo "Changes made in a regular qube vanish at reboot. Use --force to run anyway." >&2
  exit 1
fi

# ------------------------------------------------------------------ the measures

apply_sysctl() {
  say "Step 2 - kernel and network settings (ANSSI R9, R12-R14, CIS 1.5, 3.3)"
  # "99-zz" sorts after the distribution's own files, so these values win.
  # A leading "-" makes systemd-sysctl skip a key the kernel does not know.
  cat > /etc/sysctl.d/99-zz-hardening.conf <<'EOF'
# Managed by harden-template.sh
# Kernel: hide information useful to an attacker (ANSSI R9, CIS 1.5)
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 2
kernel.unprivileged_bpf_disabled = 1
kernel.randomize_va_space = 2
kernel.sysrq = 0
-kernel.yama.ptrace_scope = 1

# Network: ignore spoofed or redirected traffic (ANSSI R12, CIS 3.3)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.core.bpf_jit_harden = 2

# IPv6 off: Qubes does not enable it by default (ANSSI R13)
-net.ipv6.conf.all.disable_ipv6 = 1
-net.ipv6.conf.default.disable_ipv6 = 1

# File systems: protected links and FIFOs, no setuid core dumps (ANSSI R14)
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
  ok "/etc/sysctl.d/99-zz-hardening.conf"
}

apply_modules() {
  say "Step 3 - unneeded kernel modules (CIS 1.1.1, 3.2)"
  # "install <module> /bin/false" blocks loading, even as a dependency.
  # In Qubes, USB drives stay attached to sys-usb and reach qubes as block
  # devices (qvm-block), which does not need usb-storage in the qube.
  {
    echo "# Managed by harden-template.sh"
    for m in cramfs freevxfs hfs hfsplus jffs2 udf dccp sctp rds tipc usb-storage; do
      echo "install $m /bin/false"
    done
  } > /etc/modprobe.d/hardening.conf
  ok "/etc/modprobe.d/hardening.conf"
}

apply_packages() {
  say "Step 4 - unneeded packages and services (CIS 2.1, 2.2, 3.1.3)"
  local pkgs=(avahi-daemon bluez rpcbind nfs-common telnet ftp tnftp rsh-client talk nis ldap-utils xinetd)
  [ "$REMOVE_CUPS" -eq 1 ] && pkgs+=(cups cups-daemon)
  local removed=()
  for p in "${pkgs[@]}"; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "$p" >/dev/null
      removed+=("$p")
    fi
  done
  DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y -q >/dev/null
  ok "purged: ${removed[*]:-nothing to remove}"
}

apply_sudo_su() {
  say "Step 5a - sudo logging and no 'su' (CIS 5.2.2, 5.2.3, 5.2.7)"
  local tmp
  tmp="$(mktemp)"
  printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults loglinelen=0\n' > "$tmp"
  # Validate before installing: a broken sudoers file locks sudo out.
  visudo -cf "$tmp" >/dev/null
  install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/zz-hardening
  rm -f "$tmp"
  visudo -c >/dev/null
  ok "/etc/sudoers.d/zz-hardening"

  # "su" is allowed to an empty group: nobody. Root has no password in Qubes,
  # so without this rule anyone in the qube could become root with "su".
  getent group sugroup >/dev/null || groupadd sugroup
  # Look for an ACTIVE line: Debian ships commented-out pam_wheel examples.
  if ! grep -qE '^auth.*pam_wheel\.so' /etc/pam.d/su; then
    sed -i '/^auth.*pam_rootok\.so/a auth       required   pam_wheel.so use_uid group=sugroup' /etc/pam.d/su
  fi
  ok "pam_wheel in /etc/pam.d/su"
}

# set_login_def KEY VALUE: replace the active KEY line in login.defs, or append it
set_login_def() {
  if grep -qE "^$1[[:space:]]" /etc/login.defs; then
    sed -i -E "s/^$1[[:space:]].*/$1\t\t$2/" /etc/login.defs
  else
    printf '%s\t\t%s\n' "$1" "$2" >> /etc/login.defs
  fi
}

apply_umask() {
  say "Step 5b - umask 027 for every session (CIS 5.4.3.3)"
  # Qubes starts terminals and apps through qrexec: /etc/profile is not read,
  # the umask comes from pam_umask in the qrexec PAM session.
  # Only touch real setting lines: Debian's comments also start with "# UMASK ...".
  set_login_def UMASK 027        # Debian 13 dropped this line: it is then appended
  set_login_def USERGROUPS_ENAB no
  # Explicit arguments: without them pam_umask still applied the "user group"
  # rule and turned 027 into 007.
  local f
  for f in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    [ -f "$f" ] || continue
    sed -i -E 's/^(session\s+optional\s+pam_umask\.so)\s*$/\1 umask=0027 nousergroups/' "$f"
  done
  ok "login.defs + pam_umask arguments"
}

apply_coredumps() {
  say "Step 5c - no core dumps (CIS 1.5.3)"
  # pam_limits: "90-" sorts after Debian 13's 10-coredump-debian.conf,
  # which sets the hard limit to infinity.
  printf '# Managed by harden-template.sh\n*     hard  core  0\nroot  hard  core  0\n' \
    > /etc/security/limits.d/90-hardening-coredump.conf
  # systemd: processes it starts (qrexec included) get a zero core limit.
  mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d /etc/systemd/coredump.conf.d
  printf '[Manager]\nDefaultLimitCORE=0\n' > /etc/systemd/system.conf.d/50-hardening-coredump.conf
  printf '[Manager]\nDefaultLimitCORE=0\n' > /etc/systemd/user.conf.d/50-hardening-coredump.conf
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/50-hardening.conf
  ok "limits.d + systemd + coredump.conf"
}

# ------------------------------------------------------------------ verification
# check "description" command...  -> OK if the command succeeds, FAIL otherwise
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
sugroup_empty() { getent group sugroup | grep -qE '^sugroup:[^:]*:[0-9]+:$'; }
not_installed() { ! dpkg -s "$1" >/dev/null 2>&1; }
one_umask_line() { [ "$(grep -cE '^UMASK[[:space:]]' /etc/login.defs)" -eq 1 ] && grep -qE '^UMASK[[:space:]]+027$' /etc/login.defs; }

verify() {
  say "Verification (files in this template)"
  local f p
  for f in /etc/sysctl.d/99-zz-hardening.conf /etc/modprobe.d/hardening.conf \
           /etc/sudoers.d/zz-hardening /etc/security/limits.d/90-hardening-coredump.conf \
           /etc/systemd/system.conf.d/50-hardening-coredump.conf; do
    check "$f present" test -f "$f"
  done
  check "sudo configuration valid" visudo -c
  check "sugroup exists and is empty" sugroup_empty
  check "su restricted (pam_wheel)" grep -qE '^auth\s+required\s+pam_wheel\.so.*group=sugroup' /etc/pam.d/su
  check "UMASK 027 in login.defs (once)" one_umask_line
  check "pam_umask arguments" grep -qE 'pam_umask\.so.*umask=0027.*nousergroups' /etc/pam.d/common-session
  for p in avahi-daemon bluez rpcbind telnet xinetd; do
    check "$p not installed" not_installed "$p"
  done

  cat <<'EOF'

Runtime checks: shut this template down, then from dom0, with a test qube
based on it (replace test-hardened with its name):

  qvm-run -p test-hardened 'cat /proc/sys/kernel/kptr_restrict /proc/sys/fs/protected_regular'   # 2 2
  qvm-run -p test-hardened 'umask; grep -i core /proc/$PPID/limits'                               # 0027, 0 0
  qvm-run -p test-hardened '/usr/sbin/modprobe --showconfig | grep -E "install (cramfs|usb_storage) "'  # 2 lines, /bin/false
  qvm-run -p test-hardened 'sudo true && echo sudo OK'                                             # sudo OK
  qvm-run -p test-hardened 'su -c true root </dev/null; echo "su exit code: $?"'                    # not 0
EOF
}

# ------------------------------------------------------------------------- main
if [ "$CHECK_ONLY" -eq 0 ]; then
  apply_sysctl
  apply_modules
  apply_packages
  apply_sudo_su
  apply_umask
  apply_coredumps
fi
verify

if [ "$FAILURES" -gt 0 ]; then
  printf '\n%s check(s) failed.\n' "$FAILURES"
  exit 1
fi
printf '\nAll file checks passed.\n'
