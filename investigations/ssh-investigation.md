# SSH Security Investigation

## Overview

This document describes a structured SOC investigation workflow for analyzing SSH authentication activity using Splunk.

The investigation focuses on identifying repeated authentication failures, determining the source and targeted accounts, reviewing successful authentication activity, establishing a timeline, and correlating the source with other available telemetry.

This is an investigation methodology and does not represent a specific historical security incident.

---

## Investigation Objective

The primary objectives are to:

- Identify unusual SSH authentication activity
- Analyze failed authentication attempts
- Identify source IP addresses
- Identify targeted accounts
- Check for successful authentication
- Establish the activity timeline
- Correlate SSH activity with other telemetry
- Determine whether additional investigation is required

---

## Investigation Workflow

```text
SSH Authentication Events
          |
          v
Identify Failed Attempts
          |
          v
Identify Source IP
          |
          v
Identify Targeted Account
          |
          v
Check Successful Authentication
          |
          v
Analyze Timeline
          |
          v
Correlate Other Telemetry
          |
          v
Document Findings
```

---

## Step 1 — Review SSH Authentication Events

Start by reviewing SSH authentication activity:

```spl
index=main sourcetype=sshd
| table _time src_ip user action
| sort - _time
```

This provides a chronological view of SSH authentication events.

The exact fields depend on the SSH log source and Splunk field extraction configuration.

---

## Step 2 — Identify Failed Authentication

```spl
index=main sourcetype=sshd action="failed"
| table _time src_ip user action
| sort - _time
```

This query isolates failed authentication attempts for further analysis.

---

## Step 3 — Identify High-Volume Sources

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

This helps identify source IP addresses associated with repeated authentication failures.

A high number of failures should be treated as an investigation signal rather than automatic proof of brute-force activity.

---

## Step 4 — Identify Targeted Accounts

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by user
| sort - failed_attempts
```

This identifies accounts receiving the highest number of failed authentication attempts.

---

## Step 5 — Analyze Source and Account Relationship

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip user
| sort - failed_attempts
```

This helps determine whether a source is:

- Targeting one account
- Targeting multiple accounts
- Generating repeated attempts against a particular user

---

## Step 6 — Check for Potential Brute-Force Activity

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

The threshold of `10` is an example and should be tuned according to the environment.

---

## Step 7 — Analyze Authentication Over Time

```spl
index=main sourcetype=sshd action="failed"
| timechart span=1h count
```

This helps identify periods with increased failed authentication activity.

Time-based analysis can help distinguish between:

- Isolated failures
- Continuous activity
- Short bursts
- Repeated authentication attempts

---

## Step 8 — Check for Successful Authentication

```spl
index=main sourcetype=sshd action="success"
| table _time src_ip user action
| sort - _time
```

Successful authentication following repeated failures may require additional investigation.

However, this pattern alone does not prove account compromise.

---

## Step 9 — Correlate Failed and Successful Authentication

```spl
index=main sourcetype=sshd
| stats
    count(eval(action="failed")) as failed_attempts
    count(eval(action="success")) as successful_attempts
    values(user) as users
    by src_ip
| sort - failed_attempts
```

This provides a source-level summary of failed and successful authentication activity.

---

## Step 10 — Investigate a Specific Source

Once a source IP requires investigation:

```spl
index=main sourcetype=sshd src_ip="<source_ip>"
| table _time src_ip user action
| sort _time
```

Replace `<source_ip>` with the source being investigated.

This allows the analyst to establish a detailed authentication timeline.

---

## Step 11 — Correlate With Other Telemetry

The source IP can be searched across other available security telemetry.

```text
                 Source IP
                     |
        +------------+------------+
        |            |            |
        v            v            v
       SSH          DNS          HTTP
        |            |            |
        +------------+------------+
                     |
                     v
              Event Timeline
                     |
                     v
               Investigation
```

Useful questions include:

- Did the source generate DNS activity?
- Did the source generate HTTP requests?
- Did the source appear in other security events?
- Did related activity occur around the same time?

---

## Investigation Questions

### Source Analysis

- What is the source IP?
- Is the source internal or external?
- Is the source expected?
- Is the source associated with a known system?

### Account Analysis

- Which account was targeted?
- Were multiple accounts targeted?
- Were successful logins observed?
- Is the targeted account privileged?

### Timeline Analysis

- When did the authentication failures begin?
- How long did they continue?
- Were failures concentrated within a short period?
- Did a successful login occur afterward?

### Context

- Could the activity be caused by a user mistake?
- Could a service be using outdated credentials?
- Was administrative testing taking place?
- Is the source a known scanner or monitoring system?

---

## False Positive Analysis

Potential legitimate causes include:

- Users entering incorrect passwords
- Misconfigured applications
- Services using outdated credentials
- Administrative testing
- Security testing
- Monitoring systems
- Automated internal processes

The analyst should validate the context before classifying the activity.

---

## Evidence Collection

Useful evidence may include:

| Evidence | Purpose |
|---|---|
| Timestamp | Establish authentication timeline |
| Source IP | Identify originating system |
| Username | Identify targeted account |
| Action | Identify authentication outcome |
| Attempt count | Measure activity volume |
| Related events | Provide additional context |

Only fields actually available in the telemetry should be documented.

---

## Investigation Outcome

An SSH investigation may result in:

### Benign

Activity is consistent with expected behavior.

### Requires Monitoring

Activity is unusual but insufficient evidence exists to classify it as malicious.

### Suspicious

Repeated or unusual authentication behavior requires additional investigation.

### Escalation Required

Available evidence supports following the organization's incident-response process.

The final assessment should be based on evidence and context.

---

## Investigation Record

```text
Investigation Title:
Investigation Date:
Analyst:

Source IP:
Targeted Account(s):
First Observed:
Last Observed:

Failed Attempts:
Successful Attempts:

Related DNS Activity:
Related HTTP Activity:

Initial Assessment:
Evidence Collected:
False Positive Considerations:

Final Assessment:
Recommended Action:
```

---

## SOC Analyst Response

If the authentication activity remains suspicious:

1. Preserve relevant authentication evidence.
2. Identify the source system.
3. Identify targeted accounts.
4. Review successful authentication events.
5. Search the source across available telemetry.
6. Validate whether the activity is expected.
7. Document the findings.
8. Escalate according to the incident-response process when appropriate.

---

## Investigation Limitations

The investigation depends on the available SSH telemetry.

Potential limitations include:

- Missing authentication logs
- Incomplete field extraction
- Limited log retention
- Shared source IP addresses
- NAT environments
- Incomplete successful-login visibility
- Incorrect event classification

Therefore, authentication activity should always be interpreted in context.

---

## Key Takeaways

This investigation demonstrates:

- SSH log analysis
- Splunk SPL investigation
- Authentication monitoring
- Brute-force analysis
- Source IP investigation
- Account analysis
- Timeline analysis
- Cross-telemetry correlation
- False-positive assessment
- Evidence documentation
- SOC investigation methodology

---

## Related Documentation

- [SSH SPL Analysis](../spl/ssh/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [Brute-Force Detection](../detections/brute-force.md)
- [IOC Detection](../detections/ioc-detection.md)
- [Splunk SOC Dashboards](../dashboards/README.md)
