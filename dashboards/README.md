# Splunk SOC Monitoring Dashboards

## Overview

Dashboards provide a visual way to monitor security telemetry and identify patterns that may require investigation.

This section documents the dashboard concepts used for the Splunk SIEM security log analysis project.

The dashboards are designed around three primary telemetry sources:

- DNS
- SSH
- HTTP

The dashboard views can help a SOC analyst move from high-level monitoring to detailed investigation.

---

## Dashboard Objectives

The dashboard design focuses on:

- Security event volume
- Authentication activity
- DNS activity
- HTTP activity
- Potential anomalies
- Detection results
- Investigation trends

The exact panels and visualizations depend on the available Splunk data and field extractions.

---

## SOC Dashboard Structure

```text
+-------------------------------------------------------+
|              SOC SECURITY OVERVIEW                    |
+-------------------------------------------------------+
| Total Events | SSH Failures | DNS Queries | HTTP Req |
+-------------------------------------------------------+
|                                                       |
|              Security Events Over Time                |
|                                                       |
+-------------------------------------------------------+
| SSH Authentication | DNS Activity | HTTP Activity    |
+-------------------------------------------------------+
|                                                       |
|              Detection / Investigation               |
|                                                       |
+-------------------------------------------------------+
```

---

## Dashboard 1 — Security Overview

The security overview dashboard provides a high-level view of activity across the monitored telemetry.

### Recommended Panels

- Total security events
- Failed SSH authentication attempts
- DNS query volume
- HTTP request volume
- HTTP error volume
- Top source IPs
- Top queried domains
- Top requested URIs

---

## Total Events

Example SPL:

```spl
index=main
| stats count as total_events
```

This provides a high-level event count for the selected time range.

---

## SSH Authentication Failures

Example SPL:

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts
```

This panel provides visibility into failed SSH authentication activity.

---

## DNS Query Volume

Example SPL:

```spl
index=main sourcetype=dns
| stats count as dns_queries
```

This provides the total number of DNS events within the selected time range.

---

## HTTP Request Volume

Example SPL:

```spl
index=main sourcetype=http
| stats count as http_requests
```

This provides the total number of HTTP requests observed.

---

## HTTP Error Volume

Example SPL:

```spl
index=main sourcetype=http status>=400
| stats count as http_errors
```

This provides visibility into HTTP responses associated with errors.

---

# Dashboard 2 — Authentication Monitoring

This dashboard focuses on SSH authentication activity.

## Recommended Panels

- Failed authentication attempts
- Successful authentication attempts
- Failed attempts over time
- Top source IPs
- Top targeted accounts
- Failed attempts by source and user

### Failed Authentication Over Time

```spl
index=main sourcetype=sshd action="failed"
| timechart span=1h count
```

### Failed Authentication by Source

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### Failed Authentication by Account

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by user
| sort - failed_attempts
```

---

# Dashboard 3 — DNS Monitoring

This dashboard focuses on DNS activity and domain behavior.

## Recommended Panels

- DNS queries over time
- Top queried domains
- Top DNS sources
- Source-to-domain activity
- DNS query volume

### DNS Activity Over Time

```spl
index=main sourcetype=dns
| timechart span=1h count
```

### Top Queried Domains

```spl
index=main sourcetype=dns
| stats count as query_count by query
| sort - query_count
```

### Top DNS Sources

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

---

# Dashboard 4 — HTTP Monitoring

This dashboard focuses on HTTP request behavior.

## Recommended Panels

- HTTP requests over time
- Requests by source
- Requests by URI
- HTTP status-code distribution
- HTTP errors
- High-volume sources

### HTTP Activity Over Time

```spl
index=main sourcetype=http
| timechart span=1h count
```

### Requests by Source

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| sort - request_count
```

### Requests by URI

```spl
index=main sourcetype=http
| stats count as request_count by uri
| sort - request_count
```

### Status-Code Distribution

```spl
index=main sourcetype=http
| stats count by status
| sort - count
```

---

# Dashboard 5 — Detection Monitoring

This dashboard brings the primary detection queries together.

## Recommended Detection Panels

### SSH Brute Force

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

### Suspicious DNS Volume

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

### High HTTP Request Volume

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| where request_count >= 100
| sort - request_count
```

### High HTTP Error Volume

```spl
index=main sourcetype=http status>=400
| stats count as error_count by src_ip
| where error_count >= 20
| sort - error_count
```

---

# Dashboard 6 — IOC Monitoring

IOC-focused panels can provide quick visibility into indicators requiring further investigation.

## Source IP Activity

```spl
index=main
| stats count by src_ip
| sort - count
```

## DNS Domains

```spl
index=main sourcetype=dns
| stats count by query
| sort - count
```

## HTTP URIs

```spl
index=main sourcetype=http
| stats count by uri
| sort - count
```

These panels can be used as starting points for deeper investigation.

---

# Recommended Dashboard Filters

Useful dashboard filters include:

- Time range
- Source IP
- Username
- Domain
- URI
- HTTP status
- Event type

A time-range selector is particularly useful because analysts frequently need to compare activity before, during, and after a suspected event.

---

# SOC Investigation Workflow

The dashboards support the following workflow:

```text
Dashboard Overview
       |
       v
Identify Anomaly
       |
       v
Select Relevant Panel
       |
       v
Filter by Source / Indicator
       |
       v
Run Detailed SPL Search
       |
       v
Review Raw Events
       |
       v
Correlate With Other Telemetry
       |
       v
Document Findings
```

---

# Dashboard Design Principles

The dashboard should prioritize:

### Visibility

Important security activity should be visible without requiring multiple searches.

### Simplicity

Panels should communicate useful information without unnecessary visual complexity.

### Investigation

Dashboard panels should allow an analyst to identify an event and continue into a detailed investigation.

### Context

Activity should be interpreted using time, source, user, destination, and related events where available.

### Tuning

Thresholds and panels should be adjusted based on the environment's normal behavior.

---

# Example Dashboard Layout

```text
=========================================================
                 SOC SECURITY OVERVIEW
=========================================================

Total Events       SSH Failures       DNS Queries
     12540              48                4210

HTTP Requests       HTTP Errors        Detection Alerts
     8730               126                 14

---------------------------------------------------------

                EVENT ACTIVITY OVER TIME

              [Time-Series Visualization]

---------------------------------------------------------

 SSH AUTHENTICATION       DNS ACTIVITY       HTTP ACTIVITY

 [Visualization]          [Visualization]    [Visualization]

---------------------------------------------------------

 TOP SOURCE IPs           TOP DOMAINS        TOP URIs

 [Table]                  [Table]             [Table]

---------------------------------------------------------

              DETECTION / INVESTIGATION

 [Brute Force] [DNS Anomaly] [HTTP Anomaly] [IOC]

=========================================================
```

The numbers shown above are illustrative dashboard placeholders and are not claimed as historical project results.

---

# Dashboard Investigation Example

A SOC analyst may observe an unusual increase in SSH failures.

The analyst can then:

1. Select the relevant time range.
2. Identify the source IP.
3. Review targeted accounts.
4. Check for successful authentication.
5. Search the source IP across other telemetry.
6. Review DNS and HTTP activity.
7. Determine whether the activity is expected.
8. Document the investigation.

This demonstrates how dashboards can support an investigation rather than replace detailed log analysis.

---

# Limitations

Dashboard effectiveness depends on:

- Available log sources
- Correct field extraction
- Consistent sourcetypes
- Data retention
- Search performance
- Appropriate thresholds
- Quality of event timestamps

The SPL examples in this project use generic field names and may require modification for a different Splunk environment.

---

# Key Takeaways

This dashboard documentation demonstrates practical understanding of:

- Splunk dashboard design
- SOC monitoring
- SPL-based visualization
- Security metrics
- Detection monitoring
- IOC monitoring
- Investigation workflows
- Security-event correlation

The goal is to provide an analyst-friendly starting point for monitoring and investigating security telemetry.

---

## Related Documentation

- [DNS SPL Analysis](../spl/dns/README.md)
- [SSH SPL Analysis](../spl/ssh/README.md)
- [HTTP SPL Analysis](../spl/http/README.md)
- [Detection SPL Queries](../spl/detection/README.md)
- [Brute-Force Detection](../detections/brute-force.md)
- [Suspicious DNS Detection](../detections/suspicious-dns.md)
- [Abnormal HTTP Detection](../detections/abnormal-http.md)
- [IOC Detection](../detections/ioc-detection.md)
