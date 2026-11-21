# Sensor Utility & Traffic Generation Scripts (`sensor/scripts/`)

## Overview
Utility scripts supporting the NetShield network packet sensor microservice.

## Scripts
- `generate_sample_pcap.py`: Generates the canonical `sensor/samples/sample_test.pcap` fixture using Scapy. Synthesizes three network flows:
  1. TCP HTTP 3-way handshake + GET request + 200 OK data + FIN teardown.
  2. UDP DNS query and response.
  3. ICMP Ping echo request and reply.
- `simulate_hulk_dos.py`: Simulates high-frequency HTTP GET Hulk DoS attack requests against the NetShield ingestion API.
