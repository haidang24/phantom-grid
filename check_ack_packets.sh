#!/bin/bash
# Check if server receives ACK packets from Kali

echo "=== Checking ACK Packets on Server ==="
echo ""

echo "From Kali tcpdump, we see:"
echo "  ✅ SYN from Kali → Server"
echo "  ✅ SYN-ACK from Server → Kali (checksum correct)"
echo "  ✅ ACK from Kali → Server (checksum incorrect - from Kali side)"
echo ""

echo "But server retransmits SYN-ACK, suggesting:"
echo "  - Server doesn't receive ACK from Kali"
echo "  - Or ACK is dropped before reaching honeypot"
echo ""

echo "Test:"
echo "  1. On server, run:"
echo "     sudo tcpdump -i ens33 -n 'tcp port 9999 and tcp[tcpflags] & tcp-ack != 0' -v"
echo ""
echo "  2. From Kali, try to connect:"
echo "     nc -v 192.168.174.163 9999"
echo ""
echo "  3. Check if server receives ACK packets"
echo ""

echo "If server DOES receive ACK:"
echo "  → ACK reaches server, but honeypot doesn't accept"
echo "  → Check honeypot Accept() logic"
echo ""

echo "If server DOES NOT receive ACK:"
echo "  → ACK is dropped between Kali and Server"
echo "  → Check firewall/routing"
echo ""

