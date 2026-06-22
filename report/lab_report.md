# Reverse Shell Network Detection – Technical Report

## 1. Introduction

This lab focuses on detecting reverse shell network behavior using packet captures and SIEM analysis. The goal is to identify abnormal TCP connections that indicate potential remote command execution.

---

## 2. Environment Setup

Two virtual machines were used:

- Kali Linux (Attacker)
- Ubuntu Linux (Target)

Traffic was captured using:
- tcpdump
- Wireshark

Logs were later imported into Splunk for analysis.

---

## 3. Attack Simulation

A reverse shell connection was established using Netcat:

- Attacker listens on port 4444
- Target initiates outbound connection

Multiple network interactions were generated to simulate real-world attack behavior.

---

## 4. Data Collection

Network traffic was captured and stored in:

- reverse_shell_1.log
- reverse_shell_2.pcapng

These logs contain TCP sessions including DNS traffic, HTTPS traffic, and suspicious persistent connections.

---

## 5. Detection Logic

Detection is based on:

- Duration of TCP sessions
- Number of packets exchanged
- Unusual destination ports
- Repeated communication between same hosts

Threshold:

- Sessions longer than 30 seconds OR high packet count are flagged as suspicious.

---

## 6. Splunk Queries

### Long-lived connections

```spl
source="*reverse_shell*.log"
| rex "IP (?<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > (?<dest_ip>\d+\.\d+\.\d+\.\d+)\.(?<dest_port>\d+)"
| stats min(_time) as start max(_time) as end count by src_ip dest_ip dest_port
| eval duration = end - start
| where duration > 30
