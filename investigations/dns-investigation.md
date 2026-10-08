# DNS Security Investigation

## Overview

This document describes a structured SOC investigation workflow for analyzing potentially unusual DNS activity using Splunk.

The investigation focuses on identifying abnormal DNS patterns, determining the source system, reviewing queried domains, establishing a timeline, and correlating the activity with other available telemetry.

This is an investigation methodology and does not represent a specific historical security incident.

---

## Investigation Objective

The primary objectives are to:

- Identify unusual DNS activity
- Determine the source of the DNS queries
- Identify frequently queried domains
- Establish when the activity occurred
- Review the relationship between sources and domains
- Correlate DNS activity with other telemetry
- Determine whether additional investigation is required

---

## Investigation Workflow

```text
DNS Activity
     |
     v
Identify Anomaly
     |
     v
Identify Source IP
     |
     v
Identify Queried Domain
     |
     v
Analyze Timeline
     |
     v
Correlate Other Events
     |
     v
Validate Activity
     |
     v
Document Findings
```

---

## Step 1 — Identify DNS Activity

Start by reviewing DNS events:

```spl
index=main sourcetype=dns
| table _time src_ip dest_ip query
| sort - _time
```

This provides a chronological view of DNS activity.

The exact fields available depend on the DNS log source and field extraction configuration.

---

## Step 2 — Identify High-Volume Sources

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

This helps identify systems generating a high volume of DNS queries.

High volume does not automatically indicate malicious behavior.

---

## Step 3 — Identify Frequently Queried Domains

```spl
index=main sourcetype=dns
| stats count as query_count by query
| sort - query_count
```

The results can be reviewed to identify domains requiring additional context.

---

## Step 4 — Analyze Source-to-Domain Relationships

```spl
index=main sourcetype=dns
| stats count as query_count by src_ip query
| sort - query_count
```

This helps determine which systems are repeatedly querying specific domains.

---

## Step 5 — Analyze Activity Over Time

```spl
index=main sourcetype=dns
| timechart span=1h count
```

The time-series view can help identify:

- Sudden increases
- Repeated activity
- Unusual time periods
- Changes from the normal baseline

---

## Step 6 — Investigate a Specific Source

After identifying a source that requires investigation:

```spl
index=main sourcetype=dns src_ip="<source_ip>"
| table _time src_ip query
| sort _time
```

Replace `<source_ip>` with the source being investigated.

This helps establish the DNS activity timeline for the selected source.

---

## Step 7 — Investigate a Specific Domain

```spl
index=main sourcetype=dns query="<domain>"
| table _time src_ip query
| sort - _time
```

Replace `<domain>` with the domain being investigated.

This helps determine which systems queried the domain and when the queries occurred.

---

## Step 8 — Correlate With Other Telemetry

DNS activity should be correlated with other available security telemetry where possible.

```text
                DNS Activity
                     |
          +----------+----------+
          |          |          |
          v          v          v
        HTTP        SSH       Source IP
          |          |          |
          +----------+----------+
                     |
                     v
              Event Timeline
                     |
                     v
              Investigation
```

Useful correlation questions include:

- Did the same source generate HTTP requests?
- Did the same source generate SSH authentication events?
- Did suspicious activity occur around the same timestamp?
- Does the source normally perform this activity?

---

## Investigation Questions

### Source Analysis

- What system generated the DNS query?
- Is the source expected?
- Is the source a server, workstation, or security tool?
- Does the source normally generate this volume of DNS traffic?

### Domain Analysis

- What domain was queried?
- Is the domain expected?
- Is the domain associated with a known service?
- Does the domain require additional reputation checking?

### Timeline Analysis

- When did the activity begin?
- Did the activity occur once or repeatedly?
- Was there a sudden increase?
- Did related events occur before or after the DNS activity?

---

## False Positive Analysis

Potential legitimate explanations include:

- Operating-system activity
- Software updates
- Web browsing
- Enterprise applications
- Monitoring systems
- Security tools
- Automated services
- DNS caching behavior

The analyst should establish whether the activity is expected before escalating.

---

## Evidence Collection

Useful investigation evidence may include:

| Evidence | Purpose |
|---|---|
| Timestamp | Establish activity timeline |
| Source IP | Identify originating system |
| Destination | Identify DNS infrastructure |
| Domain | Identify queried resource |
| Query count | Measure activity volume |
| Related events | Provide additional context |

Only fields actually available in the telemetry should be recorded.

---

## Investigation Outcome

A DNS investigation can result in several possible outcomes:

### Benign

The activity is consistent with expected system or user behavior.

### Requires Monitoring

The activity is unusual but insufficient evidence exists to classify it as malicious.

### Suspicious

The activity contains multiple indicators requiring additional investigation.

### Escalation Required

Sufficient evidence exists to follow the organization's incident-response process.

The final classification should be based on available evidence rather than query volume alone.

---

## Investigation Record

The following template can be used to document an investigation:

```text
Investigation Title:
Investigation Date:
Analyst:

Source IP:
Domain:
First Observed:
Last Observed:

Observed DNS Activity:
Related HTTP Activity:
Related SSH Activity:

Initial Assessment:
Evidence Collected:
False Positive Considerations:

Final Assessment:
Recommended Action:
```

---

## SOC Analyst Response

If the activity remains suspicious:

1. Preserve relevant evidence.
2. Identify affected systems.
3. Validate the domain using approved intelligence sources.
4. Search for related indicators.
5. Correlate available telemetry.
6. Document the investigation.
7. Escalate according to the incident-response process when appropriate.

---

## Investigation Limitations

This investigation methodology depends on the available Splunk telemetry.

Potential limitations include:

- Missing DNS logs
- Incomplete field extraction
- Limited retention
- Shared infrastructure
- Dynamic IP addresses
- Insufficient historical baseline
- Legitimate services producing high query volumes

Therefore, DNS behavior should always be interpreted in context.

---

## Key Takeaways

This investigation demonstrates:

- DNS log analysis
- Splunk SPL investigation
- Source IP analysis
- Domain analysis
- Timeline analysis
- Cross-telemetry correlation
- False-positive assessment
- Evidence documentation
- SOC investigation methodology

---

## Related Documentation

- [DNS SPL Analysis](../spl/dns/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [Suspicious DNS Detection](../detections/suspicious-dns.md)
- [IOC Detection](../detections/ioc-detection.md)
- [Splunk SOC Dashboards](../dashboards/README.md)
