# Detection SPL Queries

## Overview

This section contains detection-oriented SPL searches developed for the Splunk SIEM project.

The searches focus on identifying patterns that may require SOC investigation, including:

- SSH brute-force activity
- Suspicious DNS behavior
- Abnormal HTTP traffic
- Authentication anomalies
- Potential IOC activity

These searches are intended as investigation and detection examples rather than definitive proof of malicious activity.

---

# Detection Workflow

```text
Security Logs
      |
      v
    Splunk
      |
      v
   SPL Search
      |
      v
Detection Logic
      |
      v
 Suspicious Pattern
      |
      v
Evidence Validation
      |
      v
IOC Identification
      |
      v
Investigation
```

---

# 1. SSH Brute-Force Detection

## Objective

Identify source IP addresses generating repeated failed SSH authentication attempts.

## SPL

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

## Detection Logic

The search:

1. Filters failed SSH authentication events
2. Groups events by source IP
3. Counts failed attempts
4. Applies an example threshold
5. Sorts sources by activity

## Investigation Questions

- Which source generated the failures?
- How many attempts occurred?
- Over what period?
- Which accounts were targeted?
- Did the source eventually authenticate successfully?
- Is the source expected?

---

# 2. SSH Brute-Force by Account

## Objective

Identify repeated failed authentication attempts against individual accounts.

## SPL

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip user
| where failed_attempts >= 5
| sort - failed_attempts
```

## Investigation Value

This can help identify:

- Targeted accounts
- Repeated authentication attempts
- Source-to-account relationships

---

# 3. SSH Authentication Correlation

## Objective

Compare failed and successful authentication activity from the same source.

## SPL

```spl
index=main sourcetype=sshd
| stats
    count(eval(action="failed")) as failed_attempts
    count(eval(action="success")) as successful_attempts
    values(user) as users
    by src_ip
| sort - failed_attempts
```

## Investigation Value

A source generating repeated failed authentication attempts followed by a successful login may require additional investigation.

A successful login does not automatically indicate compromise.

---

# 4. Suspicious DNS Activity

## Objective

Identify high-frequency DNS activity that may require further investigation.

## SPL

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

## Investigation Logic

High query volumes can be investigated for:

- Automated applications
- Misconfigured systems
- Unexpected activity
- Potentially suspicious DNS behavior

High query volume alone does not confirm malicious activity.

---

# 5. Frequently Queried Domains

## Objective

Identify domains receiving unusually high query counts.

## SPL

```spl
index=main sourcetype=dns
| stats count as query_count by query
| sort - query_count
```

## Investigation Questions

- Which domains are queried most frequently?
- Is the activity expected?
- Is one endpoint responsible for the activity?
- Does the domain require further investigation?

---

# 6. DNS Activity by Source and Domain

## Objective

Correlate source systems with queried domains.

## SPL

```spl
index=main sourcetype=dns
| stats count as query_count by src_ip query
| sort - query_count
```

## Investigation Value

This provides context about:

- Which systems queried a domain
- How frequently the domain was queried
- Whether activity is isolated or distributed

---

# 7. Abnormal HTTP Request Volume

## Objective

Identify sources generating unusually high numbers of HTTP requests.

## SPL

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| where request_count >= 100
| sort - request_count
```

## Detection Logic

The search:

1. Searches HTTP events
2. Groups requests by source IP
3. Counts requests
4. Applies an example threshold
5. Sorts sources by request volume

The threshold should be tuned according to the normal traffic profile of the environment.

---

# 8. High HTTP Error Activity

## Objective

Identify sources generating unusually high numbers of HTTP errors.

## SPL

```spl
index=main sourcetype=http status>=400
| stats count as error_count by src_ip
| where error_count >= 20
| sort - error_count
```

## Investigation Value

Repeated HTTP errors may indicate:

- Invalid requests
- Automated activity
- Application problems
- Probing
- Misconfiguration
- Other suspicious behavior

Additional evidence is required before classifying the activity as malicious.

---

# 9. High-Volume URI Requests

## Objective

Identify resources receiving unusually high request volumes.

## SPL

```spl
index=main sourcetype=http
| stats count as request_count by uri
| where request_count >= 50
| sort - request_count
```

## Investigation Questions

- Which resource is receiving the requests?
- Which source systems are responsible?
- Is the activity expected?
- Are the requests associated with errors?
- Is there evidence of automated or suspicious behavior?

---

# 10. HTTP Error Activity Over Time

## Objective

Identify time periods with increased HTTP error activity.

## SPL

```spl
index=main sourcetype=http status>=400
| timechart span=1h count
```

## Investigation Value

This can help identify:

- Traffic spikes
- Unusual activity windows
- Changes in normal behavior
- Potential anomalies

---

# 11. Authentication Activity Over Time

## Objective

Visualize SSH authentication activity over time.

## SPL

```spl
index=main sourcetype=sshd
| timechart span=1h count
```

This can help identify unusual authentication activity and periods requiring further investigation.

---

# 12. DNS Activity Over Time

## Objective

Visualize DNS activity and identify unusual changes in query volume.

## SPL

```spl
index=main sourcetype=dns
| timechart span=1h count
```

---

# 13. HTTP Activity Over Time

## Objective

Visualize HTTP traffic volume over time.

## SPL

```spl
index=main sourcetype=http
| timechart span=1h count
```

---

# 14. Potential IOC Identification

Security events can be reviewed to identify potentially relevant indicators.

## Source IP Analysis

```spl
index=main
| stats count by src_ip
| sort - count
```

## Domain Analysis

```spl
index=main sourcetype=dns
| stats count by query
| sort - count
```

## URI Analysis

```spl
index=main sourcetype=http
| stats count by uri
| sort - count
```

These searches provide starting points for further investigation.

---

# Detection Validation

Detection results should be validated before being treated as confirmed security incidents.

A useful validation workflow is:

```text
Detection Triggered
       |
       v
Review Raw Events
       |
       v
Check Timestamp
       |
       v
Identify Source
       |
       v
Analyze Context
       |
       v
Correlate Other Evidence
       |
       v
Validate IOC
       |
       v
Determine Severity
       |
       v
Document Finding
```

---

# Detection Tuning

Detection thresholds should be adapted to the environment.

Factors to consider include:

- Normal authentication volume
- Normal DNS activity
- Normal HTTP traffic
- Automated services
- Monitoring systems
- Administrative activity
- Application behavior
- Expected network patterns

A threshold violation should be treated as an **investigation signal**, not automatic proof of malicious activity.

---

# Detection-to-Investigation Workflow

```text
             Detection
                |
                v
        Suspicious Activity
                |
                v
           Initial Triage
                |
                v
          Evidence Review
                |
                v
        Correlate Events
                |
                v
          IOC Analysis
                |
                v
       Incident Investigation
                |
                v
          Documentation
```

---

# Key Learning Outcomes

This detection section provided practical experience with:

- SPL detection logic
- Authentication monitoring
- Brute-force detection
- DNS anomaly investigation
- HTTP anomaly investigation
- Threshold-based detection
- IOC identification
- Detection validation
- Detection tuning
- SOC investigation workflows

---

# Important Note

The SPL examples in this repository are intended for controlled security learning and investigation practice.

Field names, indexes, sourcetypes, and thresholds may need to be adapted to the actual Splunk environment and ingested data.

A detection result should always be validated against the underlying events and additional available evidence.
