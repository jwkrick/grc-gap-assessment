# Security Configuration Gap Assessment: Ubuntu Server (Home Lab)

A CIS Benchmark gap assessment mapped to NIST SP 800-53 Rev 5, with a remediation roadmap and POA&M.

> **Home lab / educational project.** This assessment was performed on a personal lab system running in an isolated VirtualBox environment. It contains no production, client, employer, or classified data. All output has been sanitized (hostnames and IPs replaced with lab designations). Published to demonstrate GRC methodology, not to disclose any real environment.

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Description](#2-system-description)
3. [Scope & Methodology](#3-scope--methodology)
4. [Standards & Frameworks](#4-standards--frameworks)
5. [Findings Summary](#5-findings-summary)
6. [Detailed Findings](#6-detailed-findings)
7. [Risk Rating Methodology](#7-risk-rating-methodology)
8. [Remediation Roadmap](#8-remediation-roadmap)
9. [Plan of Action & Milestones (POA&M)](#9-plan-of-action--milestones-poam)
10. [Lessons Learned](#10-lessons-learned)
11. [Appendices](#11-appendices)

## 1. Executive Summary

A configuration gap assessment was performed against `ralph-lab`, an Ubuntu 22.04 LTS server running in an isolated home lab environment, using the Lynis 3.0.7 security auditing tool aligned to CIS Ubuntu Linux Benchmark controls. The system achieved a hardening index of 58/100 across 249 automated tests, with findings concentrated in audit/accountability, system integrity, and network boundary protection. Five high-severity gaps were identified, including a firewall with no active rules and a complete absence of audit logging infrastructure. Findings are mapped to NIST SP 800-53 Rev 5 control families; this report documents the top 8 findings by severity, assigns qualitative risk ratings, and provides a prioritized remediation roadmap and POA&M.

| Metric | Result |
|---|---|
| Assessment date | 2026-07-16 |
| Tool | Lynis 3.0.7 |
| Hardening index | 58 / 100 |
| Tests performed | 249 |
| High severity findings | 5 |
| Medium severity findings | 3 |
| Total findings documented | 8 |

## 2. System Description

| Attribute | Detail |
|---|---|
| System name | `ralph-lab` (lab designation; hostname sanitized) |
| Role / purpose | Ubuntu general-purpose host; home lab target system |
| OS / version | Ubuntu 22.04.5 LTS (Jammy Jellyfish) |
| Environment | Isolated VirtualBox VM, bridged to home lab network |
| Data sensitivity | None (lab only, no PII, production, or classified data) |
| Provisional categorization | FIPS 199 Low (practice exercise; no real data) |

> **Note:** A true FIPS 199 categorization is not applicable to a lab system with no real data. A provisional Low is assigned to exercise the RMF Categorize step methodology.

## 3. Scope & Methodology

**In scope:** Operating-system configuration of `ralph-lab` measured against CIS Ubuntu Linux Benchmark hardening controls via Lynis audit.

**Out of scope:** Application-layer security, network devices, physical security, and penetration testing. This is a configuration compliance assessment, not a pen test.

**Method:**

1. Installed Lynis 3.0.7 on the target system via apt.
2. Executed `sudo lynis audit system`: full system audit in normal mode.
3. Extracted warnings and suggestions from `/var/log/lynis-report.dat`.
4. Triaged findings by severity; selected top 8 for documentation.
5. Mapped each finding to the relevant NIST SP 800-53 Rev 5 control family.
6. Assigned qualitative risk ratings using a likelihood × impact matrix.
7. Drafted remediation actions and POA&M milestones.

Tooling: Lynis 3.0.7. Sanitized scan output in [`/evidence/sanitized/`](evidence/sanitized/).

## 4. Standards & Frameworks

| Framework | How it's used here |
|---|---|
| CIS Ubuntu Linux Benchmark | Measurement baseline: defines what "good" looks like |
| NIST SP 800-53 Rev 5 | Control families each finding maps to |
| NIST CSF 2.0 | Higher-level function mapping (Identify / Protect / Detect) |
| NIST SP 800-37 Rev 2 (RMF) | Lifecycle context: this assessment fits the Assess step |

## 5. Findings Summary

| Severity | Count | Primary control families affected |
|---|---|---|
| High | 5 | SC-7, SI-2, AU-2, AU-12, SI-7, SI-3 |
| Medium | 3 | IA-5, AC-2, AC-8, CM-6, SC-39 |
| **Total** | **8** | |

## 6. Detailed Findings

### GAP-001: Firewall Present but No Rules Active

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 3.5.1: Ensure firewall is configured |
| Lynis check | FIRE-4512 |
| NIST 800-53 control | SC-7 (Boundary Protection), CM-7 (Least Functionality) |
| NIST CSF function | Protect (PR.AC-5) |
| Severity | High |
| Status | Open |

**Description.** The iptables kernel module is loaded, indicating a firewall subsystem is present, but no rules are configured. All inbound and outbound traffic passes through without inspection or restriction. The system has no network boundary controls in effect.

**Risk / impact.** Any service listening on any port is reachable by any host on the network segment. This directly undermines confidentiality and availability: an attacker on the same network can reach all exposed services with no filtering layer. Fails the SC-7 boundary protection objective entirely.

**Evidence.** Lynis warning FIRE-4512: "iptables module(s) loaded, but no rules active". See [`/evidence/sanitized/lynis-warnings.txt`](evidence/sanitized/lynis-warnings.txt).

**Recommendation.** Implement a default-deny UFW ruleset: enable UFW, set default policies to deny inbound and allow outbound, then explicitly permit only required services (e.g., SSH on port 22). Run `sudo ufw enable` and `sudo ufw status verbose` to verify.

### GAP-002: Vulnerable Packages Present / System Unpatched

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 1.9: Ensure updates are applied |
| Lynis check | PKGS-7392 |
| NIST 800-53 control | SI-2 (Flaw Remediation), CM-6 (Configuration Settings) |
| NIST CSF function | Identify (ID.RA-1), Protect (PR.IP-12) |
| Severity | High |
| Status | Open |

**Description.** The system has known-vulnerable packages installed with security updates available but not applied. Confirmed unpatched packages include curl, gzip, dnsmasq-base, and a full CUPS printing suite (10 packages), among others.

**Risk / impact.** Unpatched curl and gzip represent exploitable CVEs with public proof-of-concept code. An attacker with access to the system or network could exploit these to achieve privilege escalation or data exfiltration. Directly fails SI-2 flaw remediation requirements.

**Evidence.** Lynis warning PKGS-7392. Upgradable packages confirmed via `sudo apt list --upgradable`. Notable entries: curl 7.81.0-1ubuntu1.24 → 1ubuntu1.25, gzip 1.10-4ubuntu4.1 → 4ubuntu4.2. Full list in [`/evidence/sanitized/upgradable-packages.txt`](evidence/sanitized/upgradable-packages.txt).

**Recommendation.** Run `sudo apt update && sudo apt upgrade -y` to apply all available security patches. Establish a recurring patch cadence (weekly for security updates). Consider enabling unattended-upgrades for automatic security patch application.

### GAP-003: Audit Daemon (auditd) Not Installed

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 4.1.1: Ensure auditing is enabled |
| Lynis check | ACCT-9628 |
| NIST 800-53 control | AU-2 (Event Logging), AU-12 (Audit Record Generation) |
| NIST CSF function | Detect (DE.CM-3) |
| Severity | High |
| Status | Open |

**Description.** The auditd daemon is not installed. The system has no kernel-level audit subsystem capturing security-relevant events such as privilege escalation, file access, user authentication, or system calls. Default syslog captures application logs but not the security event audit trail that auditd provides.

**Risk / impact.** Without auditd, there is no forensic trail for security incidents. Unauthorized access, privilege abuse, or data exfiltration could occur with no record for investigation. This directly fails AU-2 and AU-12: two controls assessed in every DoD RMF ATO package. Non-repudiation is impossible without an audit trail.

**Evidence.** Lynis suggestion ACCT-9628: "Enable auditd to collect audit information".

**Recommendation.** Install and enable auditd: `sudo apt install auditd audispd-plugins -y`, then `sudo systemctl enable auditd && sudo systemctl start auditd`. Configure rules in `/etc/audit/rules.d/` aligned to CIS benchmark section 4.1.

### GAP-004: No File Integrity Monitoring Tool Installed

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 4.4: Ensure AIDE is installed |
| Lynis check | FINT-4350 |
| NIST 800-53 control | SI-7 (Software, Firmware, and Information Integrity) |
| NIST CSF function | Detect (DE.CM-5) |
| Severity | High |
| Status | Open |

**Description.** No file integrity monitoring (FIM) tool is installed. Without a tool such as AIDE or Tripwire, unauthorized modifications to critical system binaries, configuration files, or libraries cannot be detected. There is no baseline to compare against.

**Risk / impact.** An attacker who achieves initial access could modify system binaries or plant persistent backdoors with no detection mechanism. Rootkit installation, configuration tampering, and credential file modification would all go undetected. Fails the SI-7 integrity verification requirement.

**Evidence.** Lynis suggestion FINT-4350: "Install a file integrity tool to monitor changes to critical and sensitive files".

**Recommendation.** Install AIDE: `sudo apt install aide -y`, initialize the database with `sudo aideinit`, then schedule daily checks via cron. Store the baseline database on read-only or off-system storage.

### GAP-005: No Malware Scanner Installed

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu: Ensure malware protection is in place |
| Lynis check | HRDN-7230 |
| NIST 800-53 control | SI-3 (Malicious Code Protection) |
| NIST CSF function | Protect (PR.DS-6), Detect (DE.CM-4) |
| Severity | High |
| Status | Open |

**Description.** No malware scanning tool is installed on the system. The Lynis scan confirmed the malware scanner component as not present [X]. Tools such as ClamAV, rkhunter, or chkrootkit are absent.

**Risk / impact.** Malicious code introduced via a vulnerable package, network service, or user action would not be detected. Rootkits, webshells, or trojanized binaries could persist indefinitely. Fails the SI-3 malicious code protection control.

**Evidence.** Lynis scan summary: "Malware scanner: [X]". Suggestion HRDN-7230: "Harden the system by installing at least one malware scanner".

**Recommendation.** Install rkhunter: `sudo apt install rkhunter -y`, update the database with `sudo rkhunter --update`, and run `sudo rkhunter --check`. Schedule weekly scans via cron. For a production environment, add ClamAV for on-access scanning.

### GAP-006: Password Policy Not Configured

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 5.4.1: Ensure password expiration, min age, and complexity |
| Lynis check | AUTH-9286, AUTH-9328 |
| NIST 800-53 control | IA-5 (Authenticator Management), AC-2 (Account Management) |
| NIST CSF function | Protect (PR.AC-1) |
| Severity | Medium |
| Status | Open |

**Description.** `/etc/login.defs` has no minimum or maximum password age configured, and the default umask is set to 022 rather than the CIS-recommended 027. Passwords never expire and new file permissions are more permissive than necessary by default.

**Risk / impact.** Without password expiration, compromised credentials remain valid indefinitely. A permissive umask means newly created files are group-readable by default, increasing the risk of unintended information disclosure. Partially fails IA-5 authenticator management requirements.

**Evidence.** Lynis suggestions AUTH-9286 (min/max password age) and AUTH-9328 (umask).

**Recommendation.** In `/etc/login.defs`, set `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 14`, and `UMASK 027`. Apply to existing accounts with the `chage` command.

### GAP-007: No Legal Warning Banners Configured

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 1.7: Ensure login warning banners are configured |
| Lynis check | BANN-7126, BANN-7130 |
| NIST 800-53 control | AC-8 (System Use Notification) |
| NIST CSF function | Protect (PR.AC) |
| Severity | Medium |
| Status | Open |

**Description.** Neither `/etc/issue` (local console) nor `/etc/issue.net` (SSH pre-login banner) contain a legal warning message. Both files are either empty or contain only OS version information.

**Risk / impact.** Absence of a use notification banner has legal and compliance implications. In a real environment, it weakens the legal basis for prosecuting unauthorized access. Courts have ruled that without a warning, users may claim they did not know access was restricted. AC-8 is a required control in DoD RMF baselines at all impact levels.

**Evidence.** Lynis suggestions BANN-7126 and BANN-7130.

**Recommendation.** Add an authorized-use-only warning to both `/etc/issue` and `/etc/issue.net`. For SSH, also set `Banner /etc/issue.net` in `/etc/ssh/sshd_config` and restart sshd.

### GAP-008: Kernel Hardening Parameters Not Configured

| Field | Detail |
|---|---|
| CIS benchmark item | CIS Ubuntu 3.1–3.3: Network parameter hardening |
| Lynis check | KRNL-6000, KRNL-5820 |
| NIST 800-53 control | CM-6 (Configuration Settings), SC-39 (Process Isolation) |
| NIST CSF function | Protect (PR.IP-1) |
| Severity | Medium |
| Status | Open |

**Description.** Multiple sysctl kernel parameters differ from the CIS hardening profile. Core dumps are not disabled. Hardening parameters governing network stack behavior (IP forwarding, ICMP redirects, source routing) are at permissive defaults rather than hardened values.

**Risk / impact.** Unrestricted core dumps can expose sensitive data including cryptographic keys and credentials from memory. Unhardened network stack parameters increase susceptibility to IP spoofing, redirect attacks, and reconnaissance. Fails CM-6 configuration baseline requirements.

**Evidence.** Lynis suggestions KRNL-6000 (sysctl values differ from scan profile) and KRNL-5820 (core dumps not disabled in `/etc/security/limits.conf`).

**Recommendation.** Add hardening parameters to `/etc/sysctl.d/99-hardening.conf` per CIS benchmark section 3. Key values: `net.ipv4.ip_forward=0`, `net.ipv4.conf.all.accept_redirects=0`, `net.ipv4.conf.all.rp_filter=1`, `fs.suid_dumpable=0`. Apply with `sudo sysctl --system`.

## 7. Risk Rating Methodology

Qualitative likelihood × impact matrix used to assign severity ratings:

| | Low impact | Moderate impact | High impact |
|---|---|---|---|
| **High likelihood** | Medium | High | High |
| **Moderate likelihood** | Low | Medium | High |
| **Low likelihood** | Low | Low | Medium |

- **Likelihood**: how easily the gap could be exploited in this environment given network exposure, attacker skill required, and available tooling.
- **Impact**: effect on confidentiality, integrity, or availability of the system and its data if the gap were exploited.

## 8. Remediation Roadmap

Prioritized by risk reduction per effort invested:

| Priority | Action | Findings addressed | Effort |
|---|---|---|---|
| 1 | Apply all pending security patches | GAP-002 | Low |
| 2 | Enable UFW with default-deny ruleset | GAP-001 | Low |
| 3 | Install and configure auditd with CIS rules | GAP-003 | Medium |
| 4 | Configure password policy in `/etc/login.defs` | GAP-006 | Low |
| 5 | Add legal warning banners to issue files | GAP-007 | Low |
| 6 | Apply sysctl kernel hardening parameters | GAP-008 | Medium |
| 7 | Install rkhunter malware scanner | GAP-005 | Low |
| 8 | Install and initialize AIDE file integrity | GAP-004 | Medium |

## 9. Plan of Action & Milestones (POA&M)

| POA&M ID | Weakness | 800-53 Control | Severity | Milestone | Scheduled completion | Status |
|---|---|---|---|---|---|---|
| PM-001 | Vulnerable packages unpatched | SI-2, CM-6 | High | Run apt upgrade; verify with `apt list --upgradable` | 2026-07-23 | Open |
| PM-002 | Firewall active with no rules | SC-7, CM-7 | High | Enable UFW; configure default-deny; permit SSH only | 2026-07-23 | Open |
| PM-003 | auditd not installed | AU-2, AU-12 | High | Install auditd; configure CIS rules; verify logging | 2026-07-30 | Open |
| PM-004 | No file integrity monitoring | SI-7 | High | Install AIDE; initialize DB; schedule daily cron check | 2026-08-06 | Open |
| PM-005 | No malware scanner | SI-3 | High | Install rkhunter; update DB; schedule weekly scan | 2026-07-30 | Open |
| PM-006 | Password policy not configured | IA-5, AC-2 | Medium | Set `PASS_MAX_DAYS`/`MIN_DAYS`/`UMASK` in login.defs | 2026-07-30 | Open |
| PM-007 | No login warning banners | AC-8 | Medium | Add authorized-use banner to `/etc/issue` and `/etc/issue.net` | 2026-07-23 | Open |
| PM-008 | Kernel hardening gaps | CM-6, SC-39 | Medium | Create `/etc/sysctl.d/99-hardening.conf`; apply and verify | 2026-08-06 | Open |

## 10. Lessons Learned

- **Default Ubuntu installs are not hardened.** A stock Ubuntu 22.04 install scores 58/100 on Lynis, meaning nearly half of standard hardening controls are unmet out of the box. This reinforces why a formal baseline and CM process matters before any system handles real data.
- **A firewall module is not a firewall.** iptables was loaded but had zero rules. That's a false sense of security that wouldn't appear in a casual inspection. Compliance requires verifying configured controls, not just installed ones. This distinction is central to RMF Assess.
- **Audit logging is consistently the highest-impact gap.** Without auditd, every other finding becomes harder to detect and investigate. In a real ATO package, AU-2 and AU-12 are among the first controls a validator checks. Installing it first maximizes defensive value per hour.
- **Configuration drift starts immediately.** Several gaps (unpatched packages, default sysctl values) exist simply because no hardening baseline was applied at build time. The right fix is upstream, in a hardened build script or Ansible playbook, not manual remediation after the fact.

## 11. Appendices

- **Appendix A**: Sanitized Lynis warnings output: [`/evidence/sanitized/lynis-warnings.txt`](evidence/sanitized/lynis-warnings.txt)
- **Appendix B**: Sanitized upgradable packages list: [`/evidence/sanitized/upgradable-packages.txt`](evidence/sanitized/upgradable-packages.txt)
- **Appendix C**: Tool & command reference:

```bash
sudo lynis audit system 2>&1 | tee ~/lynis-scan-raw.txt
sudo grep -E "warning|suggestion" /var/log/lynis-report.dat
sudo apt list --upgradable 2>/dev/null
```

---

*Assessment performed by J. Krick, 2026-07-16. Methodology: Lynis 3.0.7 aligned to CIS Ubuntu Linux Benchmark + NIST SP 800-53 Rev 5. Home lab project. No production data.*
