#!/bin/bash
# Debug script to check Phantom Grid connectivity

echo "=== Phantom Grid Connection Debug ==="
echo ""

# Check if phantom-grid is running
echo "1. Checking if phantom-grid is running..."
if pgrep -f phantom-grid > /dev/null; then
    echo "   ✅ phantom-grid is running (PID: $(pgrep -f phantom-grid))"
else
    echo "   ❌ phantom-grid is NOT running"
    echo "   Run: sudo ./phantom-grid -interface <interface>"
    exit 1
fi

# Check if port 9999 is listening
echo ""
echo "2. Checking if port 9999 is listening..."
if netstat -tlnp 2>/dev/null | grep -q ":9999" || ss -tlnp 2>/dev/null | grep -q ":9999"; then
    echo "   ✅ Port 9999 is listening"
    netstat -tlnp 2>/dev/null | grep ":9999" || ss -tlnp 2>/dev/null | grep ":9999"
else
    echo "   ❌ Port 9999 is NOT listening"
    echo "   Check honeypot logs for binding errors"
fi

# Check XDP programs
echo ""
echo "3. Checking XDP programs..."
if command -v bpftool &> /dev/null; then
    XDP_PROGS=$(sudo bpftool prog list 2>/dev/null | grep -i phantom | wc -l)
    if [ "$XDP_PROGS" -gt 0 ]; then
        echo "   ✅ Found $XDP_PROGS XDP program(s)"
        sudo bpftool prog list 2>/dev/null | grep -i phantom
    else
        echo "   ❌ No XDP programs found"
    fi
else
    echo "   ⚠️  bpftool not found, skipping XDP check"
fi

# Check XDP attachment
echo ""
echo "4. Checking XDP attachment..."
XDP_IFACES=$(ip link show | grep -i xdp | wc -l)
if [ "$XDP_IFACES" -gt 0 ]; then
    echo "   ✅ Found XDP attached interfaces:"
    ip link show | grep -A 2 -i xdp
else
    echo "   ❌ No XDP attached interfaces found"
fi

# Check firewall
echo ""
echo "5. Checking firewall rules..."
if command -v iptables &> /dev/null; then
    PORT9999_RULES=$(sudo iptables -L -n 2>/dev/null | grep -c "9999" || echo "0")
    if [ "$PORT9999_RULES" -gt 0 ]; then
        echo "   ⚠️  Found firewall rules for port 9999:"
        sudo iptables -L -n 2>/dev/null | grep "9999"
    else
        echo "   ✅ No blocking firewall rules for port 9999"
    fi
fi

# Test local connection
echo ""
echo "6. Testing local connection to port 9999..."
if timeout 2 bash -c "echo > /dev/tcp/localhost/9999" 2>/dev/null; then
    echo "   ✅ Local connection to port 9999 works"
else
    echo "   ❌ Local connection to port 9999 FAILED"
    echo "   This indicates honeypot is not accepting connections"
fi

# Check network interface
echo ""
echo "7. Checking network interfaces..."
echo "   Available interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print "   - " $2}'

# Get server IP
echo ""
echo "8. Server IP addresses:"
ip addr show | grep -E "inet " | awk '{print "   - " $2}'

echo ""
echo "=== Debug Complete ==="
echo ""
echo "To test from external machine:"
echo "  nc <SERVER_IP> 9999"
echo "  or"
echo "  telnet <SERVER_IP> 9999"

