# HTTP Security Investigation

## Overview

This document describes a structured SOC investigation workflow for analyzing HTTP activity using Splunk.

The investigation focuses on identifying unusual request volume, reviewing HTTP status codes, identifying source systems and requested resources, establishing an activity timeline, and correlating HTTP activity with other available telemetry.

This is an investigation methodology and does not represent a specific historical security incident.

---

## Investigation Objective

The primary objectives are to:

- Identify unusual HTTP activity
- Analyze request volume
- Identify source IP addresses
- Identify requested URIs
- Review HTTP methods and status codes
- Establish an activity timeline
- Correlate HTTP activity with other telemetry
- Determine whether additional investigation is required

---

## Investigation Workflow

```text
HTTP Events
     |
     v
Identify Anomaly
     |
     v
Identify Source IP
     |
     v
Identify URI / Resource
     |
     v
Review HTTP Status
     |
     v
Analyze Timeline
     |
     v
Correlate Other Telemetry
     |
     v
Validate Activity
     |
     v
Document Findings
```

---

## Step 1 — Review HTTP Activity

Start by reviewing HTTP events:

```spl
index=main sourcetype=http
| table _time src_ip dest_ip method uri status
| sort - _time
```

This provides a chronological view of HTTP activity.

The exact fields available depend on the HTTP log source and Splunk field extraction configuration.

---

## Step 2 — Identify High-Volume Sources

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| sort - request_count
```

This identifies source IP addresses generating the highest number of HTTP requests.

High request volume does not automatically indicate malicious activity.

---

## Step 3 — Identify Frequently Requested URIs

```spl
index=main sourcetype=http
| stats count as request_count by uri
| sort - request_count
```

This identifies resources receiving a high number of requests.

Frequently requested resources may be completely legitimate and should be evaluated in context.

---

## Step 4 — Analyze HTTP Methods

```spl
index=main sourcetype=http
| stats count by method
| sort - count
```

This provides visibility into the HTTP methods observed in the telemetry.

Unexpected method patterns may require additional investigation depending on the application.

---

## Step 5 — Analyze HTTP Status Codes

```spl
index=main sourcetype=http
| stats count by status
| sort - count
```

This provides an overview of HTTP response codes.

The distribution can help identify unusual concentrations of errors or unexpected response behavior.

---

## Step 6 — Investigate HTTP Errors

### 4xx Errors

```spl
index=main sourcetype=http status>=400 status<500
| stats count as errors by src_ip status
| sort - errors
```

### 5xx Errors

```spl
index=main sourcetype=http status>=500 status<600
| stats count as errors by src_ip status
| sort - errors
```

These searches can help identify sources associated with repeated client-side or server-side errors.

---

## Step 7 — Analyze HTTP Activity Over Time

```spl
index=main sourcetype=http
| timechart span=1h count
```

This provides a time-based view of HTTP activity.

The analyst can look for:

- Sudden increases
- Unusual periods of activity
- Repeated request bursts
- Changes from the normal baseline

---

## Step 8 — Analyze HTTP Errors Over Time

```spl
index=main sourcetype=http status>=400
| timechart span=1h count
```

This helps identify periods where HTTP errors increased.

A spike should be investigated in relation to application activity and other available telemetry.

---

## Step 9 — Investigate a Specific Source

Once a source IP requires investigation:

```spl
index=main sourcetype=http src_ip="<source_ip>"
| table _time src_ip method uri status
| sort _time
```

Replace `<source_ip>` with the source being investigated.

This helps establish the HTTP activity timeline associated with the source.

---

## Step 10 — Investigate a Specific URI

```spl
index=main sourcetype=http uri="<uri>"
| table _time src_ip method uri status
| sort _time
```

Replace `<uri>` with the resource being investigated.

This can help identify which systems requested the resource and when.

---

## Step 11 — Identify High-Volume Sources

A threshold-based investigation can be performed using:

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| where request_count >= 100
| sort - request_count
```

The threshold of `100` is an example and should be tuned according to the environment.

---

## Step 12 — Identify High Error Sources

```spl
index=main sourcetype=http status>=400
| stats count as error_count by src_ip
| where error_count >= 20
| sort - error_count
```

This identifies sources associated with repeated HTTP errors.

The threshold should be adapted to the normal application baseline.

---

## Step 13 — Correlate With Other Telemetry

HTTP activity can be correlated with other available security telemetry.

```text
                 Source IP
                     |
        +------------+------------+
        |            |            |
        v            v            v
       HTTP         DNS          SSH
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

- Did the same source generate DNS activity?
- Did the same source generate SSH authentication events?
- Did the source appear in other detections?
- Did related events occur around the same timestamp?

---

## Investigation Questions

### Source Analysis

- What is the source IP?
- Is the source expected?
- Is the source internal or external?
- Does the source normally generate this amount of HTTP traffic?

### Request Analysis

- Which URI was requested?
- Which HTTP method was used?
- Was the resource expected?
- Was the same URI requested repeatedly?

### Response Analysis

- Which status codes were returned?
- Are errors concentrated on one source?
- Are errors concentrated on a specific URI?
- Are server-side errors increasing?

### Timeline Analysis

- When did the activity begin?
- Was there a sudden increase?
- Did the activity occur in bursts?
- Did related DNS or SSH activity occur during the same period?

---

## False Positive Analysis

Potential legitimate explanations include:

- Popular web applications
- API clients
- Monitoring systems
- Web crawlers
- Load testing
- Application bugs
- Automated integrations
- Misconfigured clients

The analyst should determine whether the behavior is expected before escalating.

---

## Evidence Collection

Useful evidence may include:

| Evidence | Purpose |
|---|---|
| Timestamp | Establish activity timeline |
| Source IP | Identify originating system |
| Destination | Identify target system |
| HTTP method | Understand request behavior |
| URI | Identify requested resource |
| Status code | Understand response |
| Request count | Measure activity volume |
| Related events | Provide additional context |

Only fields actually available in the telemetry should be documented.

---

## Investigation Outcome

An HTTP investigation may result in:

### Benign

Activity is consistent with expected application or user behavior.

### Requires Monitoring

Activity is unusual but insufficient evidence exists to classify it as malicious.

### Suspicious

The observed behavior contains multiple indicators requiring additional investigation.

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
Destination:
URI:
HTTP Method:

First Observed:
Last Observed:

Request Count:
HTTP Status Codes:

Related DNS Activity:
Related SSH Activity:

Initial Assessment:
Evidence Collected:
False Positive Considerations:

Final Assessment:
Recommended Action:
```

---

## SOC Analyst Response

If the HTTP activity remains suspicious:

1. Preserve relevant HTTP evidence.
2. Identify the source and destination.
3. Review requested URIs and methods.
4. Analyze HTTP status codes.
5. Establish the activity timeline.
6. Search the source across other available telemetry.
7. Validate whether the activity is expected.
8. Document the findings.
9. Escalate according to the incident-response process when appropriate.

---

## Investigation Limitations

The investigation depends on the available HTTP telemetry.

Potential limitations include:

- Missing HTTP logs
- Incomplete field extraction
- Limited retention
- Reverse-proxy or load-balancer effects
- Shared source IP addresses
- NAT environments
- Missing request metadata
- Incomplete application context

Therefore, HTTP behavior should always be interpreted in context.

---

## Key Takeaways

This investigation demonstrates:

- HTTP log analysis
- Splunk SPL investigation
- Request-volume analysis
- URI analysis
- HTTP status-code analysis
- Timeline analysis
- Source investigation
- Cross-telemetry correlation
- False-positive assessment
- Evidence documentation
- SOC investigation methodology

---

## Related Documentation

- [HTTP SPL Analysis](../spl/http/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [Abnormal HTTP Detection](../detections/abnormal-http.md)
- [IOC Detection](../detections/ioc-detection.md)
- [Splunk SOC Dashboards](../dashboards/README.md)
