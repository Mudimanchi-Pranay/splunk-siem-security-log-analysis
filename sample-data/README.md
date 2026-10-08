# Sample Data

## Overview

This directory documents the sample security telemetry used or expected for the Splunk SIEM security log analysis project.

The project focuses on three primary log categories:

- DNS
- SSH
- HTTP

The original lab environment and its historical Splunk data are no longer available. Therefore, this repository does not present fabricated logs as original project evidence.

The SPL queries in this repository are documented as reusable examples and may require field, index, and sourcetype adjustments for a specific Splunk environment.

---

## Supported Log Categories

### DNS

DNS telemetry can provide information about domain-resolution activity.

Common fields may include:

```text
_time
src_ip
dest_ip
query
```

Example conceptual event:

```text
Timestamp:
Source IP:
DNS Server:
Query:
```

---

### SSH

SSH authentication telemetry can provide visibility into authentication activity.

Common fields may include:

```text
_time
src_ip
user
action
```

Possible authentication actions include:

```text
failed
success
```

Example conceptual event:

```text
Timestamp:
Source IP:
Username:
Action:
```

---

### HTTP

HTTP telemetry can provide information about web requests and responses.

Common fields may include:

```text
_time
src_ip
dest_ip
method
uri
status
```

Example conceptual event:

```text
Timestamp:
Source IP:
Destination:
Method:
URI:
Status:
```

---

## Example Data Structure

The following examples demonstrate the type of fields expected by the SPL queries.

### DNS

```text
_time,src_ip,dest_ip,query
timestamp,192.0.2.10,192.0.2.53,example.com
```

### SSH

```text
_time,src_ip,user,action
timestamp,192.0.2.20,admin,failed
```

### HTTP

```text
_time,src_ip,dest_ip,method,uri,status
timestamp,192.0.2.30,192.0.2.40,GET,/index.html,200
```

The IP addresses above use documentation-safe address space and are illustrative only.

---

## Suggested Splunk Organization

A possible Splunk configuration could organize the data using:

```text
Index:
main
```

Example sourcetypes:

```text
dns
sshd
http
```

The repository SPL examples use these values for consistency:

```spl
index=main sourcetype=dns
```

```spl
index=main sourcetype=sshd
```

```spl
index=main sourcetype=http
```

Actual index names and sourcetypes depend on the Splunk environment.

---

## Field Extraction

For the SPL searches to work correctly, the relevant fields must be available in Splunk.

Examples include:

```text
src_ip
dest_ip
query
user
action
method
uri
status
```

If a different field naming convention is used, the SPL searches should be modified accordingly.

For example:

```text
source_ip
```

may need to be used instead of:

```text
src_ip
```

depending on the data source.

---

## Data Quality Considerations

Before using the detection queries, an analyst should verify:

- Events are being indexed correctly
- Timestamps are accurate
- Sourcetypes are correct
- Required fields are extracted
- Source IP fields contain valid values
- HTTP status codes are numeric where required
- Authentication actions are correctly classified
- DNS query fields contain the expected domain values

Incorrect field extraction can produce misleading detection results.

---

## Data Privacy

Security logs can contain sensitive information.

Before uploading sample data to a public repository:

- Remove usernames where appropriate
- Remove internal IP addresses
- Remove hostnames
- Remove authentication information
- Remove credentials or tokens
- Remove confidential domains
- Remove organization-specific information
- Sanitize timestamps when necessary

Never commit passwords, API keys, access tokens, private keys, or other credentials.

---

## Using Synthetic Data

Synthetic data can be used to demonstrate the SPL queries without exposing real security telemetry.

Synthetic data should be clearly labeled as:

```text
Synthetic
```

or:

```text
Illustrative
```

It should not be presented as historical production or laboratory evidence.

---

## Reproducing the Analysis

A user reproducing this project can:

1. Generate or obtain appropriate test telemetry.
2. Import the data into Splunk.
3. Configure the appropriate index.
4. Configure the required sourcetypes.
5. Verify field extraction.
6. Run the SPL searches.
7. Adjust thresholds according to the test environment.
8. Build dashboard panels.
9. Investigate detected patterns.

---

## Relationship With SPL Queries

The sample data structure supports the following project areas:

```text
Sample Telemetry
      |
      +---- DNS
      |      |
      |      +---- DNS Analysis
      |      +---- Suspicious DNS Detection
      |
      +---- SSH
      |      |
      |      +---- SSH Analysis
      |      +---- Brute-Force Detection
      |
      +---- HTTP
             |
             +---- HTTP Analysis
             +---- Abnormal HTTP Detection
```

---

## Important Note

The examples in this file are intended to explain the expected structure of the project data.

They are **not claimed to be the original historical Splunk events** from the project.

This distinction keeps the repository technically useful while maintaining accurate project documentation.

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
