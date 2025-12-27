#!/bin/bash
# Debug script for "filtered" ports issue

echo "=== Debug: Tại Sao Ports Vẫn Hiện 'Filtered' ==="
echo ""

# 1. Check honeypot process
echo "1. Checking honeypot process..."
if pgrep -f phantom-grid > /dev/null; then
    echo "   ✅ phantom-grid is running (PID: $(pgrep -f phantom-grid))"
else
    echo "   ❌ phantom-grid is NOT running"
    echo "   Run: sudo ./phantom-grid -interface ens33"
    exit 1
fi

# 2. Check port 9999 listening
echo ""
echo "2. Checking port 9999 listening..."
if netstat -tlnp 2>/dev/null | grep -q ":9999" || ss -tlnp 2>/dev/null | grep -q ":9999"; then
    echo "   ✅ Port 9999 is listening"
    netstat -tlnp 2>/dev/null | grep ":9999" || ss -tlnp 2>/dev/null | grep ":9999"
else
    echo "   ❌ Port 9999 is NOT listening"
    echo "   This is CRITICAL - honeypot must bind port 9999!"
    echo "   Check logs for binding errors"
fi

# 3. Check XDP attachment
echo ""
echo "3. Checking XDP attachment..."
XDP_ATTACHED=$(ip link show ens33 2>/dev/null | grep -i xdp | wc -l)
if [ "$XDP_ATTACHED" -gt 0 ]; then
    echo "   ✅ XDP is attached to ens33"
    ip link show ens33 | grep -i xdp
else
    echo "   ❌ XDP is NOT attached to ens33"
    echo "   Check if phantom-grid started successfully"
fi

# 4. Check XDP programs
echo ""
echo "4. Checking XDP programs..."
if command -v bpftool &> /dev/null; then
    XDP_PROGS=$(sudo bpftool prog list 2>/dev/null | grep -i phantom | wc -l)
    if [ "$XDP_PROGS" -gt 0 ]; then
        echo "   ✅ Found $XDP_PROGS XDP program(s)"
        sudo bpftool prog list 2>/dev/null | grep -i phantom | head -3
    else
        echo "   ❌ No XDP programs found"
    fi
else
    echo "   ⚠️  bpftool not found, skipping"
fi

# 5. Test local connection
echo ""
echo "5. Testing local connection to port 9999..."
if timeout 2 bash -c "echo > /dev/tcp/localhost/9999" 2>/dev/null; then
    echo "   ✅ Local connection to port 9999 works"
else
    echo "   ❌ Local connection to port 9999 FAILED"
    echo "   Honeypot is not accepting connections"
fi

# 6. Check firewall
echo ""
echo "6. Checking firewall rules..."
if command -v iptables &> /dev/null; then
    BLOCKING_RULES=$(sudo iptables -L INPUT -n -v 2>/dev/null | grep -c "DROP\|REJECT" || echo "0")
    if [ "$BLOCKING_RULES" -gt 0 ]; then
        echo "   ⚠️  Found blocking firewall rules:"
        sudo iptables -L INPUT -n -v 2>/dev/null | grep -E "DROP|REJECT" | head -5
    else
        echo "   ✅ No blocking firewall rules found"
    fi
fi

# 7. Check XDP statistics
echo ""
echo "7. Checking XDP statistics..."
if command -v bpftool &> /dev/null; then
    echo "   Attack stats (redirected packets):"
    sudo bpftool map dump name attack_stats 2>/dev/null | head -3 || echo "   (Could not read stats)"
fi

# 8. Test with tcpdump (if available)
echo ""
echo "8. Instructions for packet capture:"
echo "   Run this in another terminal to capture packets:"
echo "   sudo tcpdump -i ens33 -n 'tcp port 80' -v"
echo ""
echo "   Then from external machine, run:"
echo "   nmap -p 80 <SERVER_IP>"
echo ""
echo "   You should see SYN packets being captured"

# 9. Common issues
echo ""
echo "=== Common Issues ==="
echo ""
echo "Issue 1: Port 9999 not bound"
echo "  Solution: Check honeypot logs, free port 9999 if needed"
echo ""
echo "Issue 2: XDP not attached"
echo "  Solution: Rebuild and restart: make clean && make build && sudo ./phantom-grid"
echo ""
echo "Issue 3: XDP Generic mode not working"
echo "  Solution: Check code has 'Flags: link.XDPGenericMode' in AttachXDP"
echo ""
echo "Issue 4: Checksum update wrong"
echo "  Solution: Ensure update_csum16() is called before changing port"
echo ""
echo "Issue 5: Testing from localhost"
echo "  Solution: MUST test from EXTERNAL machine (Kali, Windows, etc.)"
echo "            Localhost scans go through loopback, not XDP"

echo ""
echo "=== Debug Complete ==="

