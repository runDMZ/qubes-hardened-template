# 🧱 qubes-hardened-template

> *Harden once in the template, every qube inherits it, and gets it back intact at each reboot.*

A hardened Debian template for **Qubes OS 4.3**, built by hand step by step, then turned into a script that reproduces it. Measures come from **ANSSI-BP-028** and the **CIS Debian Linux Benchmark**, adapted to how Qubes actually works.

The interesting part is not the checklist: it is **what did not behave like on a server**, and why. See [What Qubes changes](#what-qubes-changes) and [Pitfalls](#pitfalls-met-on-the-way).

Tested on Qubes OS 4.3.2 with a Debian 13 (trixie) template.

---

## Why a hardened template

In Qubes, every qube boots on the root file system of its template, read-only, and only keeps its own `/home`, `/rw` and `/usr/local`. So:

- a setting written **in the template** applies to **every qube based on it**;
- a setting written **in a qube** disappears at the next reboot.

Hardening the template is therefore the natural place to do it, and the qube's reset at each boot keeps the hardening intact.

## Architecture

```
debian-13-xfce          stock template, left untouched
  └─ system qubes (sys-net, sys-firewall, sys-usb...)

debian-13-hardened      clone of the stock template + this hardening
  ├─ everyday qubes and disposables
  └─ cloned again into specialised templates (tools added on top)
```

A clone made with `qvm-clone` is a full, independent copy: changes made later to `debian-13-hardened` do **not** reach templates cloned from it. Re-apply the script to them, or clone again.

> ⚠️ **Never use this template for `sys-net`, `sys-firewall` or `sys-usb`.** `ip_forward = 0` stops them from routing (no network for any qube), and blocking `usb-storage` breaks USB drives in `sys-usb`. If `sys-firewall` or `sys-usb` are disposables, do not change the template of the disposable template they are based on: create a separate one for your own disposables.

---

## Usage

**1. Clone the stock template** (dom0):

```bash
qvm-clone debian-13-xfce debian-13-hardened
qvm-prefs debian-13-hardened label purple      # recognise its windows at a glance
```

**2. Copy the script into the template.** From the qube where you downloaded it:

```bash
qvm-copy-to-vm debian-13-hardened harden-template.sh
```

**3. Run it** (in a terminal of `debian-13-hardened`):

```bash
cd ~/QubesIncoming/*/
chmod +x harden-template.sh
sudo ./harden-template.sh                 # apply, then verify
sudo ./harden-template.sh --check         # verify only, at any time
```

Options: `--remove-cups` also removes the printing system. The script refuses to run outside a TemplateVM, where changes would vanish at reboot.

**4. Shut the template down and test it** (dom0):

```bash
qvm-shutdown --wait debian-13-hardened
qvm-create --class AppVM --template debian-13-hardened --label red test-hardened
```

Then run the [runtime checks](#verification), open a browser in `test-hardened`, and delete it once satisfied: `qvm-remove test-hardened`.

**5. Use it.** Move qubes to it (`qvm-prefs <qube> template debian-13-hardened`, qube shut down), and for hardened disposables:

```bash
qvm-create --class AppVM --template debian-13-hardened --label red hardened-dvm
qvm-prefs hardened-dvm template_for_dispvms True
qubes-prefs default_dispvm hardened-dvm
```

---

## What it does

| Step | Measure | Threat addressed | Reference |
|---|---|---|---|
| 2 | Kernel pointers and logs hidden, eBPF and perf restricted, ptrace limited, ASLR | Information leaks that make kernel exploits easier | ANSSI R9, R11, CIS 1.5 |
| 2 | Reverse-path filtering, no ICMP redirects or source routing, SYN cookies, no forwarding | Spoofed and redirected traffic, SYN floods | ANSSI R12, CIS 3.3 |
| 2 | IPv6 disabled | Unused attack surface (Qubes does not enable it by default) | ANSSI R13 |
| 2 | Protected symlinks, hardlinks, FIFOs and regular files; no setuid core dumps | `/tmp` race attacks, secrets in dumps | ANSSI R14 |
| 3 | `cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `udf`, `dccp`, `sctp`, `rds`, `tipc`, `usb-storage` cannot be loaded | Bugs in rarely used kernel code, often exploitable | CIS 1.1.1, 3.2 |
| 4 | avahi, Bluetooth, rpcbind/NFS, telnet, ftp, rsh, talk, NIS, LDAP tools, xinetd removed | Listening services and clear-text protocols | CIS 2.1, 2.2, 3.1.3 |
| 5 | sudo logged to `/var/log/sudo.log`, with its own pseudo-terminal | Traceability, TTY hijacking | CIS 5.2.2, 5.2.3 |
| 5 | `su` limited to an empty group | Root has no password in Qubes: anyone could `su` | CIS 5.2.7 |
| 5 | umask `027` for every session | Files readable by other accounts | CIS 5.4.3.3 |
| 5 | No core dumps (soft and hard limits at 0, systemd-coredump off) | Memory, passwords included, written to disk | CIS 1.5.3 |

Settings live in drop-in files (`sysctl.d/`, `modprobe.d/`, `sudoers.d/`, `limits.d/`, `systemd/*.conf.d/`) rather than in package files, so updates do not overwrite them. Two package files are edited in place (`/etc/login.defs`, `/etc/pam.d/su` and the `pam_umask` line), see [Keeping it up to date](#keeping-it-up-to-date).

---

## What Qubes changes

Several classic server measures do not apply, or apply differently:

| Server habit | In Qubes | What this template does |
|---|---|---|
| Host firewall with inbound default drop | Every qube already has an nftables `qubes` table: inbound `policy drop`, only established traffic, loopback and some ICMP accepted, plus anti-spoofing | Nothing added inside the qube |
| Outbound filtering on the host | Done **outside** the qube by `sys-firewall`, per qube (`qvm-firewall`), so a compromised qube cannot lift it | Nothing in the template; rules are set per qube from dom0 |
| `sudo` hardening (`noexec`, `requiretty`, passwords) | `user` has password-less root by design: the security boundary is **between** qubes | Logging only; `su` closed |
| umask in `/etc/profile.d` | Terminals and apps start through **qrexec**, not a login shell: `/etc/profile` is never read | umask set through `pam_umask`, used by the qrexec PAM session |
| Core limits in `/etc/security/limits.d` | Only `pam_limits` reads them; processes otherwise inherit systemd's limits | Both: `limits.d` **and** systemd `DefaultLimitCORE=0` |
| `/var/log/sudo.log` as a history | The qube's root file system is reset at every boot | The log covers the current session only |

## Pitfalls met on the way

Every one of these came from testing on the real machine:

1. **umask stayed at `0002`, then `0007`.** The profile.d file was never read (qrexec, see above). Then `pam_umask` still applied its "user private group" rule, which copies the owner bits to the group bits and turns `027` into `007`. The fix was to pass `umask=0027 nousergroups` to `pam_umask` explicitly.
2. **Debian 13 has no `UMASK` line in `/etc/login.defs`**, so a `sed` that replaces it silently does nothing. The script appends it when missing. A first version of the script also turned the comment `# UMASK is the default umask...` into a second active line: only real setting lines are edited now.
3. **The hard core limit stayed `unlimited`.** Debian 13 ships `limits.d/10-coredump-debian.conf`, which sets it to `infinity`. A later-sorting `90-hardening-coredump.conf` overrides it, without editing the package's file.
4. **`su` still worked** after adding `pam_wheel`: the check `grep pam_wheel.so` matched Debian's *commented-out* examples, so the line was never added. Only active lines are checked now.
5. **`modprobe -n -v cramfs` said "module not found".** Not an error: the qube's kernel comes from dom0 and simply does not contain it. `modprobe --showconfig` proves the rule is loaded for the day a kernel does.
6. **`sysctl: command not found` through `qvm-run`.** Commands run as `user`, whose `PATH` has no `/usr/sbin`: use full paths, or read `/proc/sys` directly.
7. **Settings that "worked" and then disappeared** had been typed in the test qube instead of the template. A distinct label colour for the template avoids it.
8. **sysctl file naming matters.** Files are applied in name order across `/etc`, `/run` and `/usr/lib`: `99-zz-` makes sure the distribution's own `99-*` files do not override these values.

---

## Verification

The script verifies its files at the end of every run, and `--check` does it on demand. The runtime effect is checked from dom0, in a qube based on the template:

```bash
qvm-run -p test-hardened 'cat /proc/sys/kernel/kptr_restrict /proc/sys/fs/protected_regular'   # 2, 2
qvm-run -p test-hardened 'umask; grep -i core /proc/$PPID/limits'                               # 0027, core 0 0
qvm-run -p test-hardened '/usr/sbin/modprobe --showconfig | grep -E "install (cramfs|usb_storage) "'
qvm-run -p test-hardened 'sudo true && echo sudo OK'                                             # sudo OK
qvm-run -p test-hardened 'su -c true root </dev/null; echo "su exit code: $?"'                    # not 0
qvm-run -p test-hardened 'sudo ss -tulpn'                                                        # nothing listening
```

## Keeping it up to date

- **Updates**: update the template as usual (Qubes Update). Afterwards, run `sudo ./harden-template.sh --check`: a package upgrade can rewrite `/etc/pam.d/su`, `/etc/login.defs` or the `pam_umask` line, and the check will say so. Re-running the script fixes it.
- **Cloned templates** do not follow later changes to `debian-13-hardened`: run the script in them too.

## Limits

- Tested on one machine (Qubes OS 4.3.2, Debian 13 template). Debian 12 templates should work; Fedora templates are not supported.
- This is a baseline for everyday qubes, not a compliance profile: password policy, auditd, AppArmor tuning, per-qube outbound rules and replacing password-less root with a dom0 prompt are not covered.

## References

- [ANSSI, Recommandations de configuration d'un système GNU/Linux (BP-028 v2.0)](https://messervices.cyber.gouv.fr/guides/recommandations-de-securite-relatives-un-systeme-gnulinux)
- [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux)
- [Qubes OS documentation: templates](https://www.qubes-os.org/doc/templates/)
- [Qubes OS documentation: firewall](https://www.qubes-os.org/doc/firewall/)
