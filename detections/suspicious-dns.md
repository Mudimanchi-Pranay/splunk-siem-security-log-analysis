# Suspicious DNS Detection

## Overview

This detection documents a Splunk-based approach for identifying unusual DNS activity.

DNS is commonly used for legitimate name resolution, but abnormal query volume, unusual domains, or unexpected source-to-domain relationships can provide useful indicators for further security investigation.

This detection is intended to identify suspicious patterns rather than automatically classify DNS traffic as malicious.

---

## Detection Objectives

The detection helps identify:

- High-volume DNS sources
- Frequently queried domains
- Unusual source-to-domain relationships
- Potentially suspicious DNS activity
- Indicators requiring additional investigation

---

## Detection 1 — High DNS Query Volume

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

This query identifies source IP addresses generating the highest number of DNS queries.

High query volume alone does not confirm malicious activity and should be compared with the expected behavior of the system.

---

## Detection 2 — Frequently Queried Domains

```spl
index=main sourcetype=dns
| stats count as query_count by query
| sort - query_count
```

This query identifies domains that appear frequently in the DNS telemetry.

Frequently queried domains may be completely legitimate, so the results should be investigated in context.

---

## Detection 3 — Source and Domain Relationship

```spl
index=main sourcetype=dns
| stats count as query_count by src_ip query
| sort - query_count
```

This query helps determine which source systems are repeatedly querying specific domains.

The source-to-domain relationship can provide additional context during an investigation.

---

## Detection 4 — DNS Activity Over Time

```spl
index=main sourcetype=dns
| timechart span=1h count
```

This query visualizes DNS activity over time.

Sudden increases in DNS activity may be useful for identifying:

- Unusual application behavior
- Configuration problems
- Automated processes
- Security events requiring investigation

A spike should always be validated against the surrounding environment.

---

## Detection 5 — DNS Activity by Source Over Time

```spl
index=main sourcetype=dns
| timechart span=1h count by src_ip
```

This query helps identify which source systems contribute to DNS activity over time.

It can be useful when investigating whether an increase is isolated to one system or distributed across multiple systems.

---

## Investigation Workflow

```text
DNS Events
    |
    v
Analyze Query Volume
    |
    v
Identify Frequent Domains
    |
    v
Identify Source IP
    |
    v
Review Time Pattern
    |
    v
Validate Domain Context
    |
    v
Correlate With Other Logs
    |
    v
Determine Investigation Outcome
```

---

## Investigation Questions

When suspicious DNS activity is identified, consider:

### Source

- Which host generated the query?
- Is the source system expected to generate this traffic?
- Is the source internal or external?

### Domain

- What domain was queried?
- Is the domain expected for the application or user?
- Is the domain associated with a known business service?
- Does the domain require additional reputation or threat-intelligence validation?

### Timing

- When did the activity occur?
- Was there a sudden increase?
- Does the activity repeat at regular intervals?

### Correlation

- Are there related HTTP connections?
- Are there authentication events from the same source?
- Are there other suspicious events around the same timestamp?

---

## False Positive Considerations

High DNS activity can occur because of:

- Operating-system services
- Software updates
- Web browsing
- Enterprise applications
- Monitoring systems
- Security tools
- DNS caching behavior
- Automated services

Therefore, volume-based detection should be treated as an investigation signal rather than proof of malicious activity.

---

## Threshold Tuning

A fixed threshold should not be blindly applied to every environment.

Useful tuning factors include:

- Normal DNS query volume
- Number of hosts
- Server role
- User activity
- Application behavior
- Time of day
- Historical DNS baseline

The appropriate threshold should be determined from the environment's normal behavior.

---

## IOC Investigation

If a domain appears suspicious, additional investigation can be performed using the domain as an indicator.

Example:

```spl
index=main sourcetype=dns query="<domain>"
| table _time src_ip query
| sort - _time
```

Replace `<domain>` with the domain being investigated.

This can help identify:

- Which systems queried the domain
- When the domain was queried
- Whether multiple systems contacted it
- Whether the activity occurred repeatedly

---

## Source Investigation

To investigate DNS activity from a specific source:

```spl
index=main sourcetype=dns src_ip="<source_ip>"
| table _time src_ip query
| sort _time
```

Replace `<source_ip>` with the source being investigated.

---

## SOC Analyst Response

If DNS activity appears suspicious:

1. Identify the source system.
2. Identify the queried domain.
3. Review the timeline.
4. Determine whether the activity is expected.
5. Correlate the source with other available telemetry.
6. Validate the domain using approved threat-intelligence sources.
7. Document relevant evidence.
8. Escalate according to the incident-response process when appropriate.

---

## Detection Limitations

This detection does not automatically determine whether a domain is malicious.

Additional analysis may be required for:

- Domain reputation
- Newly registered domains
- DNS tunneling indicators
- High-entropy subdomains
- Repeated periodic queries
- Known malicious infrastructure

The available DNS fields and telemetry quality will also affect detection accuracy.

---

## SOC Perspective

The investigation demonstrates how a SOC analyst can move from:

```text
DNS Telemetry
      ↓
Behavioral Analysis
      ↓
Anomalous Pattern
      ↓
Source Identification
      ↓
Domain Investigation
      ↓
Correlation
      ↓
Security Decision
```

The goal is to identify unusual behavior and collect enough evidence to determine whether further response is required.

---

## Key Takeaways

This detection demonstrates practical experience with:

- Splunk SPL
- DNS log analysis
- Behavioral detection
- Source IP analysis
- Domain analysis
- Time-based analysis
- IOC investigation
- False-positive analysis
- Detection tuning
- SOC investigation methodology

---

## Related Documentation

- [DNS SPL Analysis](../spl/dns/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [DNS Investigation](../investigations/dns-investigation.md)
- [IOC Detection](./ioc-detection.md)
