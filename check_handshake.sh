#!/bin/bash
# Check TCP handshake issue

echo "=== Checking TCP Handshake Issue ==="
echo ""

echo "Tcpdump shows:"
echo "  ✅ SYN from Kali → Server (checksum correct)"
echo "  ✅ SYN-ACK from Server → Kali (checksum correct)"
echo "  ❌ Kali does NOT send ACK"
echo ""

echo "Possible causes:"
echo "  1. Kali not receiving SYN-ACK (firewall/routing issue)"
echo "  2. Kali receiving but not responding (network issue)"
echo "  3. Honeypot not accepting connection (but kernel sent SYN-ACK)"
echo ""

echo "Check in dashboard:"
echo "  - Look for '[DEBUG] Honeypot accepted connection on port 9999'"
echo "  - Look for '[TRAP HIT]' message"
echo ""

echo "If you see '[DEBUG] Honeypot accepted connection':"
echo "  → Honeypot is accepting, but Kali is not sending ACK"
echo "  → Check firewall/routing on Kali side"
echo ""

echo "If you DON'T see '[DEBUG] Honeypot accepted connection':"
echo "  → Honeypot is not accepting (but kernel sent SYN-ACK)"
echo "  → This is strange - kernel should only send SYN-ACK after Accept()"
echo ""

echo "Test from Kali side:"
echo "  # On Kali, capture packets:"
echo "  sudo tcpdump -i eth0 -n 'tcp port 9999' -v"
echo ""
echo "  # Then try to connect:"
echo "  nc -v 192.168.174.163 9999"
echo ""
echo "  # Check if Kali receives SYN-ACK"
echo ""

echo "If Kali receives SYN-ACK but doesn't send ACK:"
echo "  → Check Kali firewall: sudo iptables -L -n -v"
echo "  → Check Kali routing: ip route"
echo ""

echo "If Kali doesn't receive SYN-ACK:"
echo "  → Check server firewall: sudo iptables -L OUTPUT -n -v"
echo "  → Check server routing: ip route"
echo ""

