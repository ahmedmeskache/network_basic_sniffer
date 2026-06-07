# Basic Network Sniffer 🖥️

A Python-based network packet sniffer built as part of the **CodeAlpha Cybersecurity Internship** (Task 1).

---

## 📌 Features

- 📡 **Live packet capture** on a selected network interface
- 🔍 **Protocol detection** — TCP, UDP, ICMP
- 🗂️ **Application identification** — 25+ protocols mapped by port (HTTPS, DNS, SSH, RDP, FTP, etc.)
- 🌐 **DNS decoder** — reads actual domain names from DNS queries and responses
- 🔐 **TLS/HTTPS detection** — identifies encrypted payloads and shows byte size
- 🎨 **Color-coded terminal output** — easy to read at a glance
- 📊 **Live stats dashboard** — protocol breakdown, top talkers, domains resolved
- 💾 **Auto-save logs** — every capture saved to a timestamped `.log` file
- 🔎 **BPF filter support** — filter by protocol, port, or IP

---

## 🛠️ Requirements

- Python 3.x
- Windows OS
- [Npcap](https://npcap.com/#download) — packet capture driver

### Install dependencies

```bash
pip install scapy colorama
```

---

## 🚀 Usage

> ⚠️ **Must run as Administrator** — raw packet access requires elevated privileges.

```bash
# Capture all traffic
python sniffer_final.py

# Capture TCP only
python sniffer_final.py tcp

# Capture UDP only
python sniffer_final.py udp

# Capture HTTP traffic (port 80)
python sniffer_final.py "port 80"

# Capture DNS traffic (port 53)
python sniffer_final.py "port 53"

# Capture traffic to/from a specific IP
python sniffer_final.py "host 8.8.8.8"
```

Press `Ctrl+C` to stop — a full stats dashboard will be displayed and the capture saved to a log file.

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════╗
║                Basic Network Sniffer                 ║
║     Packet Capture, Analysis & Protocol Decoder      ║
╚══════════════════════════════════════════════════════╝

  Started    : 2026-05-28 18:15:00
  Interface  : Wi-Fi (172.20.10.5)
  Filter     : none — capturing all traffic
  Log file   : logs/capture_20260528_181500.log

════════════════════════════════════════════════════════
  #1    18:15:01.123  TCP  [HTTPS]
────────────────────────────────────────────────────────
  Source       : 172.20.10.5
  Destination  : 104.208.16.91
  TTL          : 128
  Ports        : 49775 → 443
  Flags        : PA  (ACK + PUSH)
  Payload      : [TLS encrypted — 118 bytes]

════════════════════════════════════════════════════════
  📊  CAPTURE SUMMARY
════════════════════════════════════════════════════════
  Duration       : 60s
  Total packets  : 270
  Avg rate       : 15.9 pkt/s
  BPF Filter     : none (all traffic)

  Protocol Breakdown:
  TCP        259  ██████████████████████████████ 95.9%
  UDP         11  ████ 4.1%

  Top Applications:
  HTTPS           259 packets
  DNS               9 packets

  Top Talkers:
  172.20.10.5         127 packets
  13.107.253.43        59 packets

  Domains Resolved (3 unique):
  ⬡ v10.events.data.microsoft.com
  ⬡ settings-win.data.microsoft.com
  ⬡ displaycatalog.mp.microsoft.com
```

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
├── network_basic_sniffer.py     
└── README.md            
```

---

## 🔬 What I Learned

- How network packets are structured across layers (IP → TCP/UDP → Application)
- How TCP handshakes work (SYN, ACK, PUSH, FIN, RST flags)
- How DNS resolves domain names to IP addresses
- How TLS encrypts application data (HTTPS)
- How to use Scapy for live packet capture and analysis
- How BPF filters work to narrow down captured traffic

---

## ⚠️ Disclaimer

This tool is built for **educational purposes only** as part of the CodeAlpha Cybersecurity Internship. Only use it on networks you own or have explicit permission to monitor.

---

## 👨‍💻 Author

**Ahmed meskache**
CodeAlpha Cybersecurity Intern
GitHub: [ahmedmeskache]
LinkedIn: [www.linkedin.com/in/ahmed-meskache-6671453b7]
