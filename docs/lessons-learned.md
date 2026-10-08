# Lessons Learned

## Overview

This project provided practical experience with Splunk SIEM, SPL-based security log analysis, detection development, investigation workflows, and SOC monitoring.

The project focused on analyzing DNS, SSH, and HTTP telemetry and using the results to identify patterns that may require further investigation.

---

## 1. Importance of Log Visibility

Security monitoring depends heavily on the availability and quality of logs.

Without appropriate telemetry, a SOC analyst may not have enough evidence to investigate an event effectively.

This project demonstrated the importance of collecting and analyzing:

- DNS logs
- SSH authentication logs
- HTTP logs

---

## 2. SPL Is Central to Splunk Investigation

Splunk Processing Language (SPL) provides the ability to transform raw security events into useful investigation information.

Common SPL operations used in this project included:

```text
table
stats
where
sort
timechart
```

These commands can be combined to perform filtering, aggregation, time-based analysis, and investigation.

---

## 3. Detection Requires Context

A high number of events does not automatically mean malicious activity.

For example:

- High DNS volume may be normal for a busy system.
- Multiple SSH failures may be caused by incorrect credentials.
- High HTTP traffic may be expected for a public application.

Therefore, detections should be treated as investigation signals.

---

## 4. Thresholds Require Tuning

Thresholds such as:

```text
10 failed SSH attempts
100 HTTP requests
20 HTTP errors
```

are example values used to demonstrate detection logic.

Real environments require thresholds to be adjusted based on:

- Normal activity
- System role
- User behavior
- Application architecture
- Historical baselines
- Business requirements

---

## 5. Correlation Improves Investigation

Analyzing one log source provides limited context.

Correlation can provide a broader picture:

```text
DNS
 |
 +---- Source IP
 |
 +---- HTTP
 |
 +---- SSH
 |
 +---- Timeline
```

For example, a source IP associated with unusual SSH authentication activity can be searched across DNS and HTTP telemetry to identify related behavior.

---

## 6. Time-Based Analysis Is Important

Security events should be analyzed in chronological context.

Time-based searches can help identify:

- Sudden activity spikes
- Repeated behavior
- Short attack bursts
- Changes from normal activity
- Events occurring before or after a detection

Splunk's `timechart` command was particularly useful for this type of analysis.

---

## 7. IOC Investigation Requires Validation

Finding an IP address, domain, or URI in security logs does not automatically make it malicious.

An indicator should be evaluated using:

- Source context
- Timeline
- Related events
- System role
- Expected behavior
- Approved threat-intelligence sources when required

This reduces the risk of treating legitimate infrastructure as malicious.

---

## 8. False Positives Are Part of SOC Work

Security detections can generate legitimate alerts.

Examples include:

- Misconfigured applications
- Monitoring systems
- Administrative activity
- Security testing
- Automated services
- User mistakes

A SOC analyst must distinguish between expected behavior and activity requiring escalation.

---

## 9. Dashboards Support, But Do Not Replace, Investigation

Dashboards provide useful visibility into security activity.

However, a dashboard alert is only the starting point.

A typical workflow is:

```text
Dashboard
   |
   v
Identify Anomaly
   |
   v
Run Detailed SPL
   |
   v
Review Raw Events
   |
   v
Correlate Evidence
   |
   v
Determine Outcome
```

Detailed investigation is still required before making a security decision.

---

## 10. Documentation Is an Important SOC Skill

A technically correct investigation is more useful when the evidence and reasoning are documented clearly.

Useful investigation documentation should include:

- What was observed
- When it occurred
- Which systems were involved
- What evidence was reviewed
- What additional searches were performed
- False-positive considerations
- Final assessment
- Recommended action

---

## 11. Data Quality Directly Affects Detection Quality

Detection accuracy depends on the quality of the underlying telemetry.

Important factors include:

- Correct timestamps
- Correct field extraction
- Appropriate sourcetypes
- Complete logs
- Sufficient retention
- Consistent data formats

Poor data quality can result in incomplete or misleading detection results.

---

## 12. Practical SOC Investigation Mindset

The project reinforced an investigation mindset based on asking questions rather than immediately assuming malicious activity.

For example:

```text
What happened?
      |
      v
When did it happen?
      |
      v
Which system generated it?
      |
      v
What was the system doing?
      |
      v
Is the behavior expected?
      |
      v
What other evidence exists?
      |
      v
Does the evidence support escalation?
```

This approach helps reduce premature conclusions.

---

## 13. Reusable Detection Logic

Another important lesson was the value of reusable SPL queries.

A detection can be adapted to different environments by changing:

- Index
- Sourcetype
- Field names
- Thresholds
- Time ranges

This makes SPL knowledge transferable across different datasets and environments.

---

## 14. Investigation Should Be Evidence-Driven

Security decisions should be based on available evidence.

The general process is:

```text
Observation
    ↓
Evidence Collection
    ↓
Analysis
    ↓
Correlation
    ↓
Validation
    ↓
Assessment
    ↓
Response
```

This helps maintain a structured and defensible investigation process.

---

## 15. Skills Demonstrated

This project demonstrates practical exposure to:

### SIEM

- Splunk
- Security log analysis
- Event investigation

### SPL

- Filtering
- Aggregation
- Sorting
- Threshold-based detection
- Time-series analysis

### Detection

- SSH brute-force detection
- Suspicious DNS activity
- Abnormal HTTP activity
- IOC identification

### Investigation

- Source IP analysis
- Domain analysis
- URI analysis
- Authentication analysis
- Timeline analysis
- Cross-log correlation

### SOC Operations

- Alert triage
- False-positive assessment
- Evidence collection
- Investigation documentation
- Detection tuning

---

## 16. Future Improvements

Possible future enhancements include:

- Adding additional log sources
- Creating more advanced SPL detections
- Adding automated alerting
- Building richer Splunk dashboards
- Integrating threat-intelligence feeds
- Adding MITRE ATT&CK mapping
- Creating risk-based detections
- Developing correlation searches
- Adding automated response workflows
- Using more realistic synthetic datasets for reproducible testing

---

## Final Takeaway

The project demonstrates the complete flow from security telemetry to investigation:

```text
Security Logs
      ↓
SPL Analysis
      ↓
Detection
      ↓
Triage
      ↓
Investigation
      ↓
Correlation
      ↓
Evidence
      ↓
Assessment
```

The main lesson is that effective SOC analysis is not simply about finding unusual events.

It is about understanding normal behavior, identifying meaningful deviations, collecting evidence, correlating multiple data sources, reducing false positives, and making evidence-based security decisions.

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
- [DNS Investigation](../investigations/dns-investigation.md)
- [SSH Investigation](../investigations/ssh-investigation.md)
- [HTTP Investigation](../investigations/http-investigation.md)
- [Splunk SOC Dashboards](../dashboards/README.md)
