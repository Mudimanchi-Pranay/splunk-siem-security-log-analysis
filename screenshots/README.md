# Splunk Screenshots

## Overview

This directory is intended to contain screenshots demonstrating the Splunk SIEM analysis and investigation workflow.

Screenshots can provide visual evidence of:

- SPL searches
- Search results
- Detection results
- Dashboards
- Investigation workflows
- Security log analysis

Only genuine screenshots from the project environment should be presented as project evidence.

---

## Recommended Screenshots

The following screenshots can be added when available.

### 1. Splunk Search Interface

Demonstrates the Splunk Search & Reporting interface being used to execute SPL searches.

Suggested filename:

```text
splunk-search-interface.png
```

---

### 2. DNS SPL Search

Demonstrates a DNS investigation query and its results.

Suggested filename:

```text
dns-spl-search.png
```

Example search:

```spl
index=main sourcetype=dns
| table _time src_ip dest_ip query
| sort - _time
```

---

### 3. SSH Brute-Force Detection

Demonstrates the SSH brute-force detection query and investigation results.

Suggested filename:

```text
ssh-bruteforce-detection.png
```

Example search:

```spl
index=main sourcetype=sshd action="failed"
| stats count as failed_attempts by src_ip
| where failed_attempts >= 10
| sort - failed_attempts
```

---

### 4. HTTP Analysis

Demonstrates HTTP traffic analysis using SPL.

Suggested filename:

```text
http-analysis.png
```

Example search:

```spl
index=main sourcetype=http
| stats count as request_count by src_ip
| sort - request_count
```

---

### 5. Suspicious DNS Detection

Demonstrates DNS activity requiring additional investigation.

Suggested filename:

```text
suspicious-dns-detection.png
```

Example search:

```spl
index=main sourcetype=dns
| stats count as dns_queries by src_ip
| sort - dns_queries
```

---

### 6. Splunk SOC Dashboard

Demonstrates the security monitoring dashboard.

Suggested filename:

```text
splunk-soc-dashboard.png
```

The dashboard may contain panels for:

- Total events
- SSH failures
- DNS activity
- HTTP requests
- HTTP errors
- Top source IPs
- Top domains
- Top URIs
- Detection results

---

### 7. Authentication Investigation

Demonstrates detailed SSH authentication analysis.

Suggested filename:

```text
ssh-investigation.png
```

The screenshot can show:

- Source IP
- Username
- Failed attempts
- Successful attempts
- Timeline

---

### 8. IOC Investigation

Demonstrates searching Splunk for an indicator.

Suggested filename:

```text
ioc-investigation.png
```

Possible indicators include:

- Source IP
- Domain
- URI

---

## Screenshot Naming Convention

Use descriptive lowercase filenames.

Recommended format:

```text
<technology>-<purpose>.png
```

Examples:

```text
dns-spl-search.png
ssh-bruteforce-detection.png
http-analysis.png
splunk-soc-dashboard.png
ioc-investigation.png
```

---

## Screenshot Guidelines

Before adding a screenshot:

### Remove Sensitive Information

Do not expose:

- Passwords
- API keys
- Access tokens
- Private keys
- Personal information
- Internal credentials
- Confidential organizational information

### Keep Relevant Information Visible

Where possible, keep the following visible:

- SPL query
- Search results
- Relevant fields
- Time range
- Detection result
- Dashboard panels

### Use Clear Screenshots

Screenshots should be:

- Readable
- Properly cropped
- Relevant to the documented project
- Free from unnecessary personal information

---

## Evidence Integrity

Screenshots should accurately represent the environment in which they were captured.

Do not create or modify a screenshot in a way that makes it appear to be historical evidence when it is not.

If an illustrative or recreated visual is used, clearly label it as:

```text
Illustrative
```

or:

```text
Recreated
```

---

## Suggested Screenshot Structure

Once screenshots are available, this directory may contain:

```text
screenshots/
├── README.md
├── splunk-search-interface.png
├── dns-spl-search.png
├── ssh-bruteforce-detection.png
├── http-analysis.png
├── suspicious-dns-detection.png
├── splunk-soc-dashboard.png
├── ssh-investigation.png
└── ioc-investigation.png
```

Only add files that actually exist and accurately represent the project.

---

## Relationship With Project Documentation

The screenshots complement the documented workflow:

```text
SPL Queries
    |
    v
Detection
    |
    v
Investigation
    |
    v
Dashboard / Visualization
    |
    v
Screenshot Evidence
```

The written documentation remains the primary explanation of the project.

Screenshots provide supporting visual context.

---

## Important Note

The original Splunk lab environment and its historical screenshots are no longer available.

Therefore, this repository does not claim recreated or illustrative screenshots as original historical evidence.

If genuine screenshots from the original project become available, they can be added to this directory using the naming convention described above.

---

## Related Documentation

- [DNS Investigation](../investigations/dns-investigation.md)
- [SSH Investigation](../investigations/ssh-investigation.md)
- [HTTP Investigation](../investigations/http-investigation.md)
- [Splunk SOC Dashboards](../dashboards/README.md)
- [IOC Detection](../detections/ioc-detection.md)
