# Abnormal HTTP Traffic Detection

## Overview

This detection documents a Splunk-based approach for identifying unusual HTTP activity.

HTTP telemetry can provide useful visibility into request volume, response status codes, source systems, and requested resources.

The objective is to identify abnormal patterns that may require further SOC investigation.

---

## Detection Objectives

This detection helps identify:

- High-volume HTTP sources
- Excessive HTTP errors
- Frequently requested URIs
- Unusual HTTP activity over time
- Potentially suspicious web traffic
- Sources requiring additional investigation

---

## Detection 1 — High HTTP Request Volume

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| where request_count >= 100
| sort - request_count
```

This query identifies source IP addresses generating a high number of HTTP requests.

The threshold of `100` is an example and should be tuned according to the environment.

---

## Detection 2 — High HTTP Error Volume

```spl
index=main sourcetype=http status>=400
| stats count as error_count by src_ip
| where error_count >= 20
| sort - error_count
```

This query identifies sources associated with a high number of HTTP error responses.

Repeated errors can be useful for investigation, but they may also result from legitimate application behavior.

---

## Detection 3 — Frequently Requested URIs

```spl
index=main sourcetype=http
| stats count as request_count by uri
| where request_count >= 50
| sort - request_count
```

This query identifies URIs receiving a high number of requests.

Frequently accessed resources may be legitimate, so the results should be evaluated in context.

---

## Detection 4 — HTTP Errors by Status Code

```spl
index=main sourcetype=http status>=400
| stats count as errors by src_ip status
| sort - errors
```

This query provides visibility into which source IPs are generating HTTP errors and which status codes are involved.

It can help distinguish between different categories of web activity.

---

## Detection 5 — HTTP Activity Over Time

```spl
index=main sourcetype=http
| timechart span=1h count
```

This query visualizes HTTP activity over time.

Sudden increases or unusual changes in request volume can be investigated further.

---

## Detection 6 — HTTP Error Activity Over Time

```spl
index=main sourcetype=http status>=400
| timechart span=1h count
```

This query shows HTTP error activity over time.

It can help identify periods where web errors increased significantly.

---

## Investigation Workflow

```text
HTTP Events
     |
     v
Analyze Request Volume
     |
     v
Review HTTP Status Codes
     |
     v
Identify Source IP
     |
     v
Identify Requested URI
     |
     v
Analyze Time Pattern
     |
     v
Correlate With Other Events
     |
     v
Determine Investigation Outcome
```

---

## Investigation Questions

When abnormal HTTP activity is identified, consider:

### Source

- Which source IP generated the requests?
- Is the source expected?
- Is it an internal or external system?
- Does the source normally generate this amount of traffic?

### Request

- Which URI was requested?
- Which HTTP method was used?
- Was the URI expected?
- Was the same resource requested repeatedly?

### Response

- What HTTP status code was returned?
- Are errors concentrated on one source?
- Are errors concentrated on a particular URI?

### Timing

- When did the activity begin?
- Was there a sudden increase?
- Did the activity continue for an extended period?
- Does the pattern repeat?

---

## Potential Security Scenarios

Abnormal HTTP patterns may warrant investigation for scenarios such as:

- Automated scanning
- Excessive request activity
- Repeated requests to unusual resources
- Authentication-related failures
- Application probing
- Misconfigured clients
- Automated security testing

These patterns are investigation indicators and should not automatically be classified as attacks.

---

## False Positive Considerations

High HTTP request volume or error rates can result from:

- Popular web applications
- Legitimate API clients
- Automated monitoring
- Web crawlers
- Load testing
- Application bugs
- Misconfigured clients
- Software integrations

Detection thresholds should therefore be based on the normal behavior of the environment.

---

## Source Investigation

To investigate HTTP activity from a specific source:

```spl
index=main sourcetype=http src_ip="<source_ip>"
| table _time src_ip method uri status
| sort _time
```

Replace `<source_ip>` with the source being investigated.

---

## URI Investigation

To investigate a specific URI:

```spl
index=main sourcetype=http uri="<uri>"
| table _time src_ip method uri status
| sort _time
```

Replace `<uri>` with the resource being investigated.

---

## Error Investigation

To investigate HTTP errors by source and status code:

```spl
index=main sourcetype=http status>=400
| stats count as errors by src_ip status
| sort - errors
```

This can help identify sources producing repeated errors and determine which response codes are involved.

---

## Correlation Opportunities

HTTP activity can be correlated with other telemetry available in the environment.

Examples include:

```text
HTTP Activity
     |
     +---- DNS Activity
     |
     +---- SSH Authentication
     |
     +---- Source IP
     |
     +---- Requested URI
     |
     +---- Event Timeline
```

Correlation can provide additional context before deciding whether activity is suspicious.

---

## SOC Analyst Response

If abnormal HTTP activity appears suspicious:

1. Identify the source IP.
2. Review the requested URI.
3. Examine HTTP methods and status codes.
4. Review the activity timeline.
5. Determine whether the behavior is expected.
6. Correlate with DNS and authentication telemetry.
7. Preserve relevant investigation evidence.
8. Document the findings.
9. Escalate according to the incident-response process when appropriate.

---

## Detection Tuning

Thresholds should be adjusted according to:

- Normal request volume
- Application architecture
- Number of clients
- Server role
- Expected API traffic
- Monitoring activity
- Business hours
- Historical traffic patterns

For example, a public-facing web application may naturally receive significantly more HTTP requests than an internal application.

---

## Detection Limitations

HTTP volume and status-code analysis alone cannot determine whether traffic is malicious.

Additional investigation may be required to evaluate:

- Request patterns
- User-agent information
- Authentication context
- URI structure
- Source reputation
- Application behavior
- Related network telemetry

Detection accuracy also depends on the quality and completeness of the available HTTP logs.

---

## SOC Perspective

This detection demonstrates the workflow of moving from:

```text
HTTP Telemetry
      ↓
Behavioral Analysis
      ↓
Abnormal Pattern
      ↓
Source / URI Identification
      ↓
Timeline Analysis
      ↓
Event Correlation
      ↓
Investigation Decision
```

The objective is to identify meaningful anomalies while reducing false positives through contextual analysis.

---

## Key Takeaways

This detection demonstrates practical experience with:

- Splunk SPL
- HTTP log analysis
- Request-volume analysis
- HTTP status-code analysis
- URI analysis
- Time-based detection
- Source investigation
- False-positive analysis
- Detection tuning
- SOC investigation methodology

---

## Related Documentation

- [HTTP SPL Analysis](../spl/http/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [HTTP Investigation](../investigations/http-investigation.md)
- [IOC Detection](./ioc-detection.md)
