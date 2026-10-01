# Troubleshooting Notes 

## Issue 1 — DNS Response Code Field Produced an Error

An initial NXDOMAIN query attempted to use:

```text
dns.response.code
```

while the output referenced:

```text
dns.response_code
```

This resulted in a field-related error.

The query was simplified to use only fields confirmed to exist in the available DNS telemetry.

### Resolution

Use:

```esql
FROM logs-*
| WHERE dns.question.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name, process.pid, dns.question.name
| SORT @timestamp DESC
```

This successfully returned DNS events.

### Lesson

Do not assume that every ECS field is populated in every Elastic integration.

Always verify the fields available in the actual dataset.

---

## Issue 2 — NXDOMAIN Hunting Was Not Used

Because the DNS response-code field was not confirmed in the available telemetry, an NXDOMAIN-specific hunt was not relied upon.

Instead, the investigation focused on fields that were confirmed:

```text
dns.question.name
host.name
user.name
process.name
process.pid
@timestamp
```

### Lesson

A SOC investigation should adapt to available telemetry rather than forcing a query based on fields that are not present.

---

## Issue 3 — DNS Frequency Query Returned Many Results

The following query:

```esql
FROM logs-*
| WHERE dns.question.name IS NOT NULL
| STATS query_count = COUNT() BY dns.question.name
| SORT query_count DESC
```

returned:

```text
123 documents
51 groups
```

This was not treated as suspicious by itself.

### Reason

Windows and installed applications continuously generate DNS traffic.

Examples observed included:

```text
settings-win.data.microsoft.com
harmonydl.adobe.com
wpad
aka.ms
download.windowsupdate.com
```

### Lesson

DNS volume should first be treated as a baseline before it is treated as a threat indicator.

---

## Issue 4 — Detailed DNS Query Returned 72 Results

The following query:

```esql
FROM logs-*
| WHERE dns.question.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name, process.pid, dns.question.name
| SORT @timestamp DESC
```

returned:

```text
72 documents
```

This was expected because the query retrieves individual DNS events rather than aggregating them.

### Lesson

Use aggregation to identify patterns and detailed queries to investigate individual events.

---

## Issue 5 — Same Domain Appeared Under Different Processes

The domain:

```text
dc.services.visualstudio.com
```

was observed with:

```text
pwsh.exe
PID 6444
User Dell
```

and:

```text
mc-fw-host.exe
PID 5712
User SYSTEM
```

### Interpretation

The same domain being queried by multiple processes does not automatically mean either process is malicious.

The processes must be investigated independently.

### Lesson

Always preserve process and user context during DNS hunting.

---

## Issue 6 — Network Query Returned Zero Results

The following query:

```esql
FROM logs-*
| WHERE destination.address == "172.217.24.14"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, destination.address, destination.port, network.transport
| SORT @timestamp DESC
```

returned:

```text
0 documents processed
```

### Interpretation

This does not prove that the endpoint never communicated with the address.

It only means that no matching network event was returned under the current search conditions.

### Possible Causes

```text
DNS returned multiple addresses
Different resolved address was used
Network event occurred outside the time window
Network telemetry was unavailable
Destination was not present in the dataset
```

### Resolution

Do not manufacture a network correlation.

Document the result as:

```text
No matching network telemetry was observed within the selected search conditions.
```

---

## Issue 7 — Time Range Limitation

The investigation used:

```text
Last 15 minutes
```

This is useful for controlled lab activity but can exclude earlier DNS or network events.

If a correlation cannot be found:

1. Confirm the event timestamp.
2. Expand the time range.
3. Search using the exact domain.
4. Search using the resolved IP.
5. Compare the timestamps of DNS and network events.

### Lesson

A zero-result query may be caused by time-range selection rather than absence of the underlying activity.

---

## Issue 8 — DNS and Network Events Cannot Always Be Correlated by One IP

DNS can return:

```text
A
AAAA
Multiple A records
CNAME chains
```

The network connection may subsequently use only one of the returned addresses.

Therefore:

```text
DNS Domain
    ↓
Multiple Possible Addresses
    ↓
One Actual Network Destination
```

should be expected.

### Lesson

Do not assume:

```text
One domain = One IP
```

---

