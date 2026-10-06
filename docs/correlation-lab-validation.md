# ThreatLens AI — Correlation Lab Validation

## Purpose

This controlled lab validates the telemetry and evidence required to test deterministic security-event correlation in ThreatLens AI.

The objective is to determine whether multiple security events can be linked using shared entities, event ordering, and bounded time windows without assuming causation.

## Environment

- Host: `soc-linux-01`
- Platform: Ubuntu Linux
- Telemetry: Syslog
- Collection: Azure Monitor Agent (AMA)
- SIEM: Microsoft Sentinel / Log Analytics
- Primary test account: `ctl-corr-user`
- Decoy account: `ctl-decoy-user`
- Test type: Authorized controlled lab

## Observed Event Timeline

### 1. Failed SSH Authentication

Three failed SSH authentication attempts were observed for the nonexistent account:

`ctl-corr-user`

Observed timestamps:

- `2026-10-05T23:44:21.105Z`
- `2026-10-05T23:44:37.911Z`
- `2026-10-05T23:44:42.064Z`

Observed source IP:

`192.168.145.1`

Host:

`soc-linux-01`

The account was reported by SSH as an invalid user during these events.

Evidence:

`docs/screenshots/07-correlation-lab-ssh-failures.png`

---

### 2. Local Account Creation

The account `ctl-corr-user` was subsequently created locally.

Timestamp:

`2026-10-06T00:08:39.271Z`

Observed attributes:

- UID: `1001`
- GID: `1001`
- Home: `/home/ctl-corr-user`
- Shell: `/bin/bash`
- Process: `useradd`

Evidence:

`docs/screenshots/08-correlation-lab-account-creation.png`

---

### 3. Sudo Group Addition

The same account was subsequently added to the local `sudo` group.

Timestamp:

`2026-10-06T00:17:14.242Z`

Process:

`usermod`

Observed message:

`add 'ctl-corr-user' to group 'sudo'`

Evidence:

`docs/screenshots/09-correlation-lab-sudo-addition.png`

---

### 4. Decoy Account Creation

A separate account was created on the same host within the surrounding test period:

`ctl-decoy-user`

Timestamp:

`2026-10-06T00:24:44.288Z`

Observed attributes:

- UID: `1002`
- GID: `1002`
- Home: `/home/ctl-decoy-user`
- Shell: `/bin/bash`
- Process: `useradd`

Evidence:

`docs/screenshots/10-correlation-lab-decoy-account.png`

## Expected Correlation Behavior

### C2 — Failed SSH → Account Creation

Candidate correlation:

`failed_ssh_authentication → local_account_created`

Required evidence:

- Same target account
- Same host
- Correct chronological order
- Within configured correlation window

Expected strength:

`MODERATE`

For this controlled dataset, the three failed SSH events for `ctl-corr-user` precede creation of the same account on `soc-linux-01`.

This relationship represents temporal and entity correlation only.

It does **not** prove that the SSH source created the account or compromised the host.

### C1 — Account Creation → Sudo Addition

Candidate correlation:

`local_account_created → sudo_group_addition`

Required evidence:

- Same target account
- Same host
- Correct chronological order
- Within configured correlation window

Expected strength:

`STRONG`

The creation of `ctl-corr-user` precedes the addition of the same account to the `sudo` group.

## False-Correlation Control

`ctl-decoy-user` was intentionally created on the same host within the surrounding test period.

It must remain separate from the `ctl-corr-user` investigation because the account identity is different.

Host proximity or temporal proximity alone must not cause investigation merging.

## Safety and Interpretation Boundary

This lab demonstrates observable event relationships.

It does not establish that:

- The SSH source compromised the host.
- The failed SSH attempts caused the account creation.
- The SSH source created `ctl-corr-user`.
- The SSH source performed the sudo-group modification.
- The observed sequence represents malicious activity.

The activity was intentionally generated as an authorized security lab.

ThreatLens must preserve the distinction between observed facts, deterministic correlation, interpretation, and analyst conclusions.

## Structured Evidence

The machine-readable observed event dataset is stored at:

`backend/data/correlation_lab_scenario.json`

## Validation Goal

The deterministic correlation engine should:

1. Correlate the failed SSH activity with the later creation of `ctl-corr-user` under rule C2.
2. Correlate creation of `ctl-corr-user` with its later sudo-group addition under rule C1.
3. Produce an ordered investigation timeline.
4. Preserve the evidence supporting every correlation link.
5. Keep `ctl-decoy-user` separate.
6. Avoid causal or compromise claims not supported by telemetry.
7. Require human analyst review for final security conclusions.