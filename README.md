# Reverse Shell Network Detection Study

## Overview

This project demonstrates detection engineering techniques for identifying reverse shell behavior using network traffic analysis and Splunk SIEM.

A Kali Linux machine simulates attacker activity while a Ubuntu host is monitored. Network connections are captured using tcpdump/Wireshark and analyzed in Splunk to detect abnormal long-lived outbound connections, suspicious ports, and reverse shell indicators.

---

## Objectives

- Detect reverse shell activity using network logs
- Analyze TCP connection behavior using Splunk
- Identify long-lived suspicious sessions
- Detect abnormal destination ports (e.g. 4444, 1337)
- Build SIEM detection rules for outbound connections
- Visualize attack behavior using dashboards

---

## Lab Environment

### Attacker
- Kali Linux
- Netcat (nc)
- Nmap (for noise generation/testing)

### Target
- Ubuntu Linux
- tcpdump / Wireshark packet capture

### SIEM
- Splunk Enterprise

---

## Attack Scenario

A reverse shell connection is established between a Kali attacker machine and a monitored Ubuntu host. The attacker opens a listening port using Netcat, and the target system initiates outbound connections.

Packet captures are generated using tcpdump/Wireshark and ingested into Splunk for behavioral analysis.

The goal is to detect:

- Persistent TCP sessions
- Unusual outbound ports (e.g., 4444)
- Long-lived connections between internal and external hosts

---

## Detection Methodology

Reverse shell activity is identified using behavioral network analysis:

- Long connection duration between source and destination
- Repeated packet exchange on uncommon ports
- Persistent sessions not typical of normal application traffic
- External IP communication with internal host over suspicious ports

---

## Key Detection Query

```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats min(_time) as start max(_time) as end count by src_ip dest_ip dest_port
| eval duration = end - start
| where duration > 30 OR count > 50
| sort -duration
