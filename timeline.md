# Timeline — DNS-Based Threat Hunting

## Investigation Timeline

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| Investigation start | DNS baseline | `dns.question.name IS NOT NULL` | DNS telemetry confirmed |
| Investigation | DNS frequency hunt | 123 documents / 51 groups | Established DNS baseline |
| Investigation | Frequent domains identified | Microsoft, Adobe, Windows Update, `wpad`, `aka.ms` | Mostly normal application/system activity |
| 07:10:12 | DNS activity observed | `dc.services.visualstudio.com` | Requires process context |
| 07:10:13.613 | DNS query | `pwsh.exe`, PID `6444`, user `Dell` | PowerShell-generated DNS activity observed |
| 07:10:16.491 | DNS query | `mc-fw-host.exe`, PID `5712`, user `SYSTEM` | SYSTEM process-generated DNS activity observed |
| Investigation | Network correlation attempted | `172.217.24.14` | No matching network event |
| Investigation end | Assessment | No confirmed malicious DNS behavior | Evidence insufficient to establish compromise |

## DNS Baseline

The DNS frequency query processed:

```text
123 documents
51 groups
```

Frequently observed domains included:

```text
settings-win.data.microsoft.com
harmonydl.adobe.com
wpad
aka.ms
download.windowsupdate.com
```

These observations established that the endpoint generates significant DNS activity from normal applications and operating-system components.

## 07:10:12 — DNS Activity

The detailed DNS investigation identified activity involving:

```text
dc.services.visualstudio.com
```

This domain was observed in the current investigation window.

## 07:10:13.613 — PowerShell DNS Activity

Observed:

```text
Host: desktop-9mmm37v
User: Dell
Process: pwsh.exe
PID: 6444
DNS Query: dc.services.visualstudio.com
```

The event establishes that PowerShell was associated with a DNS query for the domain.

The event alone does not demonstrate malicious activity.

## 07:10:16.491 — SYSTEM DNS Activity

Observed:

```text
Host: desktop-9mmm37v
User: SYSTEM
Process: mc-fw-host.exe
PID: 5712
DNS Query: dc.services.visualstudio.com
```

The same domain was therefore associated with a different process and user context.

This demonstrated the importance of process-level correlation during DNS investigations.

## Network Correlation Attempt

The destination address:

```text
172.217.24.14
```

was investigated using:

```esql
FROM logs-*
| WHERE destination.address == "172.217.24.14"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, destination.address, destination.port, network.transport
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No matching network event was confirmed within the selected search conditions.

## Correlation Limitation

The failed network lookup was documented as a telemetry/search limitation.

Possible explanations include:

```text
Multiple DNS results
Different destination address used
Event outside the 15-minute window
Missing network telemetry
Destination not present in the available dataset
```

No assumption was made that a network connection occurred.

## Final Assessment

The investigation established:

```text
DNS telemetry
    ↓
123 documents
    ↓
51 DNS groups
    ↓
Process-level DNS activity
    ↓
pwsh.exe / Dell
    ↓
mc-fw-host.exe / SYSTEM
```

However:

```text
DNS activity
    ↓
172.217.24.14
    ↓
Network correlation
    ↓
No matching event observed
```

No DNS tunneling, command-and-control, malware execution, data exfiltration, or confirmed compromise was demonstrated.

The investigation concluded that DNS activity must be evaluated using **domain, process, user, timestamp, frequency, and network context together**.
