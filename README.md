# Linux Baseline Audit

**A read-only-first Bash script that inventories a Linux host, checks a
handful of well-known security controls, and writes both a human-readable
evidence file and a machine-readable JSON findings list.**

It is designed for the first 15 minutes of an engagement: run it once, read
the summary at the top of the report, decide what to investigate further.

> ⚠️ **Status: early development.** Ubuntu 22.04/24.04 is the validation
> target. Other Debian-family, RHEL-family, and Alpine hosts are best-effort.
> Treat every finding as an *indicator to investigate*, not proof of a
> vulnerability or compromise.

---

## Quick start

```bash
git clone https://example.com/your-user/linux-baseline-audit.git
cd linux-baseline-audit
chmod +x baseline_audit.sh

sudo ./baseline_audit.sh
