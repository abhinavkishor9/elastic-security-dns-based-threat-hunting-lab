# Timeline 

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

