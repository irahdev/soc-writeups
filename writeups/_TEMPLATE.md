Suspicious PowerShell Encoded Command — Workstation WIN-FIN-04

Date: 2026-08-01 | Analyst: [you] | Severity: Medium | Verdict: True Positive (simulated)

1. Alert
Sentinel rule Encoded PowerShell Execution fired at 14:22 UTC. Source: WIN-FIN-04, user jdoe. Triggered on powershell.exe invoked with -enc and a base64 payload.

2. Initial triage
Decoded the base64 string offline — it resolved to a download cradle pulling from hxxp://185.x.x.x/a.ps1. The parent process was winword.exe, which is the detail that moved this from noise to real: Word spawning PowerShell is not normal user behaviour and matches T1566.001 (spearphishing attachment) into T1059.001 (PowerShell).

3. Investigation steps

Pulled process tree from Defender for Endpoint: outlook.exe → winword.exe → powershell.exe
Checked network logs for the destination IP — one outbound connection, 4KB transferred, no further beaconing
Queried for the same IP across the estate: no other hosts contacted it
Checked jdoe's sign-in logs for the prior 24h: nothing anomalous, no impossible travel
Looked for persistence: no new scheduled tasks, no Run key modifications in the window

4. Findings
Single host affected. The payload downloaded but the follow-on execution failed — the script attempted to write to a directory blocked by AppLocker. No evidence of lateral movement, credential access, or persistence.

5. Actions taken
Host isolated pending confirmation. Hash and IP submitted for blocking. Escalated to Tier 2 with the process tree and decoded payload attached.

6. Recommendation
The Word-spawns-PowerShell relationship isn't currently a standalone detection — it should be. Draft rule in detections/office-spawns-script-host.kql.

7. Detection logic used

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
