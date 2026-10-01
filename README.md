# PacketWatch

![version](https://img.shields.io/badge/version-1.0.0-0075b8?style=flat-square)
![platform](https://img.shields.io/badge/platform-Linux-e05d2c?style=flat-square)
![language](https://img.shields.io/badge/language-Python-3776ab?style=flat-square)
![scapy](https://img.shields.io/badge/powered%20by-Scapy-ff3d81?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-4c9a1d?style=flat-square)

<p align="center">
  <img src="assets/logo.svg" width="200" alt="PacketSniffer logo">
</p>

<p align="center">
  Capture live network traffic and see who talks to your machine
</p>

## Overview
This tools is designed to monitor packets in the network with an easy and understandable UI window for users to detect and watch the packets comming through there and leaving their device.

## Requirements
- Root Privilages (sudo for the sniff() function to capture packets)
Libraries:
- Scapy
- PySide6

## Installation
Two libraries where used in this project:
- Scapy (for capturing packets)
- PySide6 (UI)

```bash
sudo apt install -y python3-scapy
pip install PySide6
```

## Usage
After installing the needed libraries:
```bash
sudo python3 Dashboard.py
```
## Dashboard
The dashboard window contains the following information about the netwerk traffic:
- Number of packets
- Total number of bytes
- Uptime of the window
- Protocols
- IP's
- Ports
