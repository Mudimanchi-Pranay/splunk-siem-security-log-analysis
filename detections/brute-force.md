# SSH Brute-Force Detection

## Overview

This detection documents a Splunk-based approach for identifying repeated failed SSH authentication attempts.

Brute-force activity occurs when an attacker or automated process repeatedly attempts authentication using different credentials or targeting one or more accounts.

This detection is designed as an investigation trigger. A high number of failed attempts does not by itself confirm malicious activity.

---

## Detection Objective

Identify source IP addresses associated with repeated failed SSH authentication attempts.

The detection can help a SOC analyst identify:

- Repeated authentication failures
- Potential password-guessing activity
- Targeted accounts
- High-volume authentication sources
- Sources requiring further investigation

---

## SPL Detection

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

The threshold of `10` is an example value and should be tuned according to the environment.

---

## Detection Logic

The detection follows these steps:

1. Search SSH authentication events.
2. Filter for failed authentication attempts.
3. Group events by source IP address.
4. Count failed attempts.
5. Compare the count against a threshold.
6. Return sources requiring investigation.

---

## Investigation Workflow

```text
Failed SSH Events
       |
       v
Group by Source IP
       |
       v
Count Failed Attempts
       |
       v
Threshold Check
       |
       v
Suspicious Source
       |
       v
Review Raw Events
       |
       v
Check Targeted Accounts
       |
       v
Check Successful Login
       |
       v
Correlate Additional Evidence
```

---

## Source and Account Analysis

To determine which accounts are being targeted:

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip user
| sort - failed_attempts
```

This provides a source-to-account relationship that can help determine whether the activity is broad or targeted.

---

## Failed vs Successful Authentication

A useful investigation step is to compare failed and successful authentication activity.

```spl
index=main sourcetype=sshd
| stats
    count(eval(action="failed")) as failed_attempts
    count(eval(action="success")) as successful_attempts
    values(user) as users
    by src_ip
| sort - failed_attempts
```

A source showing repeated failures followed by a successful authentication may warrant additional investigation.

However, this pattern alone does not prove that an account was compromised.

---

## Investigation Questions

When this detection triggers, the analyst should ask:

### Source

- What is the source IP?
- Is the source internal or external?
- Is the source expected?
- Is it associated with an approved system?

### Authentication

- Which accounts were targeted?
- How many failures occurred?
- Were successful logins observed?
- Did the activity occur within a short time period?

### Context

- Was there scheduled maintenance?
- Could the activity be caused by a misconfigured service?
- Is the source a known scanner or monitoring system?
- Are similar events occurring on other systems?

### Correlation

- Are there related DNS events?
- Are there related HTTP events?
- Are there other authentication anomalies?
- Are there additional indicators associated with the source?

---

## False Positive Considerations

Possible legitimate causes include:

- User repeatedly entering an incorrect password
- Misconfigured applications
- Automated services using outdated credentials
- Administrative testing
- Internal monitoring systems
- Security testing activities

Detection thresholds should therefore be tuned using the normal activity baseline.

---

## Severity Considerations

Severity can depend on context.

| Situation | Suggested Investigation Priority |
|---|---|
| Small number of failed attempts | Low |
| Repeated failures from one source | Medium |
| High-volume failures against multiple accounts | High |
| Repeated failures followed by unexpected success | High |
| Activity combined with other suspicious indicators | High/Critical depending on evidence |

These categories are investigation guidance rather than fixed incident-severity rules.

---

## Analyst Response

If the activity appears suspicious:

1. Preserve relevant event information.
2. Identify the source and targeted accounts.
3. Review authentication timelines.
4. Check for successful authentication.
5. Correlate with other available security telemetry.
6. Validate any identified indicators.
7. Document the investigation.
8. Escalate according to the organization's incident-response process.

---

## Detection Tuning

The threshold should be adjusted according to:

- Authentication volume
- Number of users
- Server role
- Normal administrative activity
- Internal vs external sources
- Authentication mechanisms
- Historical baselines

For example, an enterprise authentication server may naturally generate significantly more authentication events than a small Linux server.

---

## SOC Perspective

From a SOC analyst perspective, this detection demonstrates the process of moving from:

```text
Raw Authentication Logs
        ↓
SPL Query
        ↓
Detection Signal
        ↓
Triage
        ↓
Investigation
        ↓
Evidence Correlation
        ↓
Incident Decision
```

The objective is not simply to detect a large number of failed logins, but to determine whether the activity represents a meaningful security event.

---

## Key Takeaways

This detection demonstrates practical experience with:

- Splunk SPL
- SSH log analysis
- Authentication monitoring
- Brute-force detection
- Source IP analysis
- Account targeting analysis
- Detection thresholds
- False-positive analysis
- SOC investigation methodology

---

## Related Documentation

- [Detection SPL Queries](../spl/detection/README.md)
- [SSH SPL Analysis](../spl/ssh/README.md)
- [SSH Investigation](../investigations/ssh-investigation.md)
