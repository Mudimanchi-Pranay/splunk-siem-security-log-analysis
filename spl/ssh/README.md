# SSH Security Analysis – SPL Queries

## Overview

SSH authentication logs provide valuable evidence for investigating login activity, repeated authentication failures, suspicious source systems, and potential brute-force behavior.

This section contains SPL searches for analyzing SSH authentication activity and supporting brute-force investigations.

> **Note:** Field names can vary depending on the SSH log source and Splunk configuration. The searches below use common field names and can be adapted to the actual ingested dataset.

---

## 1. Search SSH Authentication Events

A basic search can be used to identify SSH-related events.

```spl
index=main sourcetype=sshd
| table _time src_ip user action
| sort - _time
```

### Purpose

Provides a basic view of:

- Event timestamp
- Source IP
- Username
- Authentication action

---

## 2. Identify Failed SSH Logins

Failed authentication attempts can be filtered for investigation.

```spl
index=main sourcetype=sshd action="failed"
| table _time src_ip user action
| sort - _time
```

### Investigation Value

This can help identify:

- Repeated failed logins
- Source IP addresses
- Target usernames
- Authentication patterns

---

## 3. Count Failed Logins by Source IP

Group failed authentication attempts by source.

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### Purpose

Helps identify source systems generating large numbers of failed authentication attempts.

A high number of failures may warrant further investigation but does not automatically confirm malicious activity.

---

## 4. Failed Logins by Username

Analyze which accounts are receiving failed authentication attempts.

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by user
| sort - failed_attempts
```

### Investigation Questions

- Which accounts are being targeted?
- Are multiple accounts being targeted?
- Is one account receiving an unusual number of attempts?
- Is the activity associated with a particular source?

---

## 5. Failed Logins by Source and Username

Correlate source IPs with targeted accounts.

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip user
| sort - failed_attempts
```

This provides more context than analyzing source IPs or usernames independently.

---

## 6. Identify High-Frequency Authentication Failures

A threshold can be used to highlight sources with repeated failures.

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

### Purpose

This can help prioritize sources for investigation.

> The threshold is an example and should be tuned according to the environment and normal authentication behavior.

---

## 7. SSH Failed Logins Over Time

Analyze authentication failures using time-based aggregation.

```spl
index=main sourcetype=sshd action="failed"
| timechart span=1h count
```

### Investigation Value

This can help identify:

- Authentication spikes
- Unusual periods of activity
- Repeated attack windows
- Changes in normal authentication behavior

---

## 8. Failed Login Activity by Source Over Time

```spl
index=main sourcetype=sshd action="failed"
| timechart span=1h count by src_ip
```

This can help identify source IPs associated with repeated authentication activity.

---

## 9. Identify Successful Logins

Successful authentication events can provide important context during investigations.

```spl
index=main sourcetype=sshd action="success"
| table _time src_ip user action
| sort - _time
```

---

## 10. Correlate Failed and Successful Logins

A source generating repeated failures followed by a successful authentication may warrant additional investigation.

```spl
index=main sourcetype=sshd
| stats
    count(eval(action="failed")) as failed_attempts
    count(eval(action="success")) as successful_attempts
    values(user) as users
    by src_ip
| sort - failed_attempts
```

### Investigation Value

This can help identify:

- Sources with repeated authentication failures
- Sources that eventually authenticated successfully
- Accounts involved in the activity

A successful login after failed attempts does not by itself prove compromise and should be investigated with additional evidence.

---

# Brute-Force Detection

## Detection Concept

A potential SSH brute-force pattern can involve repeated authentication failures from the same source within a defined time period.

```text
Multiple Failed Logins
          |
          v
      Same Source
          |
          v
    High Attempt Count
          |
          v
   Investigate Source
          |
          v
Check Successful Login
          |
          v
    Correlate Evidence
```

---

## 11. Basic Brute-Force Detection

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

### Detection Logic

The search:

1. Filters failed SSH authentication events
2. Groups events by source IP
3. Counts failed attempts
4. Applies an investigation threshold
5. Sorts sources by activity volume

---

## 12. Brute-Force Activity by Source and Account

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip user
| where failed_attempts >= 5
| sort - failed_attempts
```

This can help identify whether a source is repeatedly targeting a specific account.

---

## 13. Time-Based Brute-Force Investigation

```spl
index=main sourcetype=sshd action="failed"
| bin _time span=15m
| stats count as failed_attempts by _time src_ip
| where failed_attempts >= 5
| sort - failed_attempts
```

### Purpose

This can help identify concentrated bursts of authentication failures within short time windows.

---

# Investigation Workflow

```text
                SSH Logs
                   |
                   v
             Authentication
                 Analysis
                   |
                   v
             Failed Logins
                   |
                   v
             Source IP Analysis
                   |
                   v
            Attempt Frequency
                   |
                   v
          Identify Suspicious Sources
                   |
                   v
        Check Successful Authentication
                   |
                   v
            Correlate Evidence
                   |
                   v
              Investigation
```

---

# Investigation Checklist

When investigating potential SSH brute-force activity, consider:

- Which source IP generated the failures?
- How many attempts occurred?
- Over what time period?
- Which usernames were targeted?
- Was one account targeted repeatedly?
- Did authentication eventually succeed?
- Were multiple systems targeted?
- Is the source expected in the environment?
- Is there supporting network or endpoint evidence?
- Does the activity require escalation?

---

# Detection Tuning

Authentication thresholds should not be treated as universal values.

Detection logic should be tuned according to:

- Normal authentication behavior
- Number of users
- Number of systems
- Administrative activity
- Service accounts
- Expected automation
- Organizational security requirements

The purpose of a threshold is to prioritize suspicious activity for investigation rather than automatically classify every threshold violation as malicious.

---

# Key Takeaways

SSH SPL analysis can help a SOC analyst:

- Monitor authentication activity
- Identify repeated failures
- Investigate suspicious source IPs
- Identify targeted accounts
- Detect potential brute-force behavior
- Correlate failed and successful logins
- Support incident investigation

---

## Related Documentation

- [Main Project README](../../README.md)
- [DNS SPL Analysis](../dns/README.md)
- [Detection Use Cases](../../detections/)
- [Investigations](../../investigations/)
