# IOC Detection and Investigation

## Overview

Indicators of Compromise (IOCs) are observable artifacts that may help identify potentially suspicious activity.

In this project, Splunk is used to search available security telemetry for indicators such as:

- Source IP addresses
- Domains
- Requested URIs
- Authentication activity
- Related event patterns

IOC identification is treated as an investigation step rather than automatic proof of compromise.

---

## Investigation Objectives

The objective is to:

1. Identify potentially relevant indicators.
2. Search the available telemetry for those indicators.
3. Determine when and where the indicator appeared.
4. Identify systems associated with the indicator.
5. Correlate the indicator with other security events.
6. Document the investigation findings.

---

## IOC 1 — Source IP Analysis

To identify source IP addresses appearing in the available telemetry:

```spl
index=main
| stats count by src_ip
| sort - count
```

This provides an overview of source IP activity.

High event counts do not automatically indicate malicious behavior. The source should be investigated using additional context.

---

## IOC 2 — DNS Domain Analysis

To identify domains appearing in DNS telemetry:

```spl
index=main sourcetype=dns
| stats count by query
| sort - count
```

This can help identify frequently observed domains for additional investigation.

---

## IOC 3 — HTTP URI Analysis

To identify frequently observed HTTP resources:

```spl
index=main sourcetype=http
| stats count by uri
| sort - count
```

The resulting URIs can be reviewed for unusual or unexpected activity.

---

## IOC 4 — Search for a Specific Source IP

Once an IP address has been identified as an investigation target:

```spl
index=main src_ip="<source_ip>"
| table _time sourcetype src_ip dest_ip query uri user action status
| sort _time
```

Replace `<source_ip>` with the indicator being investigated.

This query attempts to provide a broader view of activity associated with the source.

Field availability depends on the underlying log source.

---

## IOC 5 — Search for a Specific Domain

To investigate a specific DNS domain:

```spl
index=main sourcetype=dns query="<domain>"
| table _time src_ip query
| sort _time
```

Replace `<domain>` with the domain being investigated.

This can help determine:

- Which systems queried the domain
- When the query occurred
- Whether the domain was queried repeatedly

---

## IOC 6 — Search for a Specific URI

To investigate a specific HTTP resource:

```spl
index=main sourcetype=http uri="<uri>"
| table _time src_ip method uri status
| sort _time
```

Replace `<uri>` with the URI being investigated.

---

## IOC Investigation Workflow

```text
Potential Indicator
        |
        v
Search Splunk
        |
        v
Identify Related Events
        |
        v
Determine Timeline
        |
        v
Identify Affected Source
        |
        v
Correlate DNS / HTTP / SSH
        |
        v
Validate Indicator
        |
        v
Document Findings
```

---

## IOC Correlation

An indicator becomes more useful when correlated with multiple telemetry sources.

Example:

```text
Source IP
   |
   +---- DNS Queries
   |
   +---- HTTP Requests
   |
   +---- SSH Authentication
   |
   +---- Event Timeline
```

For example, a source IP associated with repeated SSH authentication failures may be investigated further if the same source also appears in unusual HTTP or DNS activity.

Correlation should be based on actual available evidence.

---

## Investigation Checklist

### Indicator

- What type of IOC was identified?
- Where was it observed?
- When was it observed?

### Source

- Which system generated the event?
- Is the source expected?
- Is the source associated with normal activity?

### Timeline

- When did the activity begin?
- How long did it continue?
- Were there related events before or after the indicator appeared?

### Correlation

- Is the indicator present in DNS logs?
- Is it present in HTTP logs?
- Is it present in SSH logs?
- Are multiple systems associated with the indicator?

### Validation

- Does the indicator require external reputation checking?
- Is there enough evidence to classify the activity?
- Could the activity have a legitimate explanation?

---

## False Positive Considerations

An IOC-like artifact may be legitimate.

Examples include:

- Internal infrastructure
- Security scanners
- Monitoring systems
- Administrative systems
- Common web services
- Approved external services
- Testing environments

Therefore, an indicator should be validated before treating it as evidence of compromise.

---

## Evidence Documentation

For each investigated IOC, useful evidence may include:

| Evidence | Purpose |
|---|---|
| Indicator | Identifies the investigated artifact |
| Timestamp | Establishes when activity occurred |
| Source IP | Identifies originating system |
| Destination | Identifies communication target |
| Domain | Provides DNS context |
| URI | Provides HTTP context |
| Username | Provides authentication context |
| Action | Identifies authentication outcome |
| Status | Provides HTTP response context |

Only fields available in the underlying telemetry should be documented.

---

## Example Investigation Record

```text
IOC Type:
Indicator:
First Observed:
Last Observed:
Associated Source:
Associated Destination:
Related DNS Activity:
Related HTTP Activity:
Related SSH Activity:
Initial Assessment:
Additional Validation:
Final Investigation Status:
```

This format can be used as a structured investigation note.

---

## SOC Analyst Response

When an IOC requires investigation:

1. Record the indicator.
2. Search the available Splunk indexes.
3. Identify related events.
4. Establish the timeline.
5. Identify affected systems.
6. Correlate activity across available log sources.
7. Validate the indicator using approved sources when required.
8. Document the evidence.
9. Determine whether escalation is necessary.

---

## Detection Limitations

IOC searches are dependent on the quality and completeness of the available telemetry.

Limitations may include:

- Missing log sources
- Incomplete fields
- Incorrect field extraction
- Short log-retention periods
- Shared infrastructure
- Dynamic IP addresses
- Legitimate services producing common indicators

An IOC match should therefore be interpreted in context.

---

## SOC Perspective

IOC investigation demonstrates the transition from:

```text
Indicator
    ↓
Search
    ↓
Evidence Collection
    ↓
Timeline Analysis
    ↓
Correlation
    ↓
Validation
    ↓
Investigation Decision
```

The goal is to determine whether an observable indicator has meaningful security relevance.

---

## Key Takeaways

This detection demonstrates practical experience with:

- IOC identification
- Splunk searches
- Source IP analysis
- DNS investigation
- HTTP investigation
- SSH investigation
- Timeline analysis
- Event correlation
- Evidence documentation
- False-positive analysis
- SOC investigation methodology

---

## Related Documentation

- [Detection SPL Queries](../spl/detection/README.md)
- [DNS SPL Analysis](../spl/dns/README.md)
- [SSH SPL Analysis](../spl/ssh/README.md)
- [HTTP SPL Analysis](../spl/http/README.md)
- [Brute-Force Detection](./brute-force.md)
- [Suspicious DNS Detection](./suspicious-dns.md)
- [Abnormal HTTP Detection](./abnormal-http.md)
