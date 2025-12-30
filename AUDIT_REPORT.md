# Logic Audit Report - Phantom Grid

**Date**: 2025-01-XX  
**Scope**: Full codebase logic review

---

## Critical Issues

### 1. **Fallback Port Mismatch Logic Error**

**Location**: `internal/honeypot/honeypot.go:70-79`

**Problem**:  
If port 9999 (HONEYPOT_PORT) cannot be bound, the code tries alternative ports (9998, 9997, etc.) and binds successfully. However, the eBPF program (`phantom.c`) **always redirects** to port 9999. This creates a mismatch:

- eBPF redirects traffic → port 9999
- Honeypot listens on → alternative port (e.g., 9998)
- **Result**: Connections fail silently

**Impact**: High - Traffic redirected by XDP will never reach honeypot

**Fix Required**:

- Option A: Make eBPF configurable to redirect to alternative port (complex)
- Option B: Fail fast if port 9999 cannot be bound (recommended)
- Option C: Update eBPF program dynamically via map (requires eBPF map update)

**Current Code**:

```go
// Line 70-79: Tries alternatives but eBPF still redirects to 9999
for _, altPort := range config.FallbackPorts {
    fallbackListener, err := net.Listen("tcp", fmt.Sprintf(":%d", altPort))
    if err == nil {
        h.logChan <- fmt.Sprintf("[WARN] Using alternative fallback port %d instead of %d", altPort, config.HoneypotPort)
        h.logChan <- fmt.Sprintf("[WARN] NOTE: XDP is still redirecting to port %d - connections may fail!", config.HoneypotPort)
        // PROBLEM: Bound to altPort but eBPF redirects to 9999
    }
}
```

---

### 2. **Race Condition: log.Fatalf in Goroutine**

**Location**: `internal/agent/agent.go:110-114`

**Problem**:  
`log.Fatalf` is called inside a goroutine. This can crash the entire process without proper cleanup (XDP programs remain attached, resources not freed).

**Impact**: Medium - Process crash without cleanup

**Fix Required**:  
Return error from goroutine and handle in main, or use proper shutdown mechanism.

**Current Code**:

```go
// Line 110-114: Goroutine with log.Fatalf
go func() {
    if err := a.honeypot.Start(); err != nil {
        log.Fatalf("[!] Failed to start honeypot: %v", err)  // PROBLEM: Crash in goroutine
    }
}()
```

---

## Medium Issues

### 3. **Incorrect Comment Path**

**Location**: `internal/honeypot/honeypot.go:68`

**Problem**:  
Comment previously referenced `bpf/phantom.c` but has been updated to `internal/ebpf/programs/phantom.c`

**Impact**: Low - Documentation confusion

**Fix**: Update comment to correct path

---

### 4. **Error Ignored: Interface Addresses**

**Location**: `internal/agent/agent.go:95`

**Problem**:  
Error from `a.iface.Addrs()` is ignored with `_`. If this fails, IP addresses won't be logged but no error is reported.

**Impact**: Low - Missing debug info

**Fix**: Log error or handle gracefully

**Current Code**:

```go
// Line 95: Error ignored
addrs, _ := a.iface.Addrs()  // PROBLEM: Error ignored
```

---

### 5. **Inconsistent Error Handling: Panic vs Return Error**

**Location**: `internal/dashboard/dashboard.go:40-42`

**Problem**:  
Dashboard uses `panic()` for initialization failure, but other components return errors. Inconsistent error handling pattern.

**Impact**: Low - Inconsistent but functional

**Fix**: Return error and handle in `cmd/agent/main.go`

**Current Code**:

```go
// Line 40-42: Panic instead of error
if err := ui.Init(); err != nil {
    panic(fmt.Sprintf("failed to initialize termui: %v", err))  // PROBLEM: Inconsistent
}
```

---

### 6. **Port Overlap: FakePorts vs FallbackPorts**

**Location**: `internal/config/config.go:42, 46`

**Problem**:  
Port 8888 appears in both `FakePorts` (line 42) and `FallbackPorts` (line 46). This is not a bug but can cause confusion:

- If honeypot binds 8888 as fake port → OK
- If honeypot needs fallback and tries 8888 → Already bound, will skip

**Impact**: Low - Works but confusing

**Fix**: Remove overlap or document clearly

---

## Minor Issues / Observations

### 7. **SPA Whitelist Expiry Logic**

**Location**: `internal/ebpf/programs/phantom.c:146-149`

**Observation**:  
SPA whitelist uses LRU map with `max_entries=100`. Expiry is handled by LRU eviction, not explicit TTL. The comment says "30 seconds" but there's no actual timer - expiry happens when map is full and new entries push out old ones.

**Impact**: Low - Functional but not precise timing

**Note**: This is documented in README as "approximate 30 seconds"

---

### 8. **Missing Error Check: Dashboard Stats**

**Location**: `internal/dashboard/dashboard.go:58-72`

**Observation**:  
`ProcessLogMessage` updates stats based on string matching. No validation that log messages are well-formed. Could miss updates if log format changes.

**Impact**: Very Low - String matching is intentional

---

### 9. **Hardcoded Interface Names**

**Location**: `internal/network/interface.go:49`

**Observation**:  
Auto-detection uses hardcoded list: `["wlx00127b2163a6", "wlan0", "ens33", "eth0", ...]`. This works but may not cover all systems.

**Impact**: Very Low - Falls back to loopback if not found

---

## Logic Correctness

### Port Protection Logic

- **Correct**: Critical ports checked BEFORE fake ports in eBPF
- **Correct**: SPA whitelist check happens before allowing critical port access
- **Correct**: Fake ports (non-critical) pass through without SPA
- **Correct**: Stealth scans are detected and dropped

### Honeypot Logic

- **Correct**: Fake ports binding failure is handled gracefully
- **Correct**: Fallback port binding attempts alternatives
- **Issue**: Fallback port mismatch (see Critical Issue #1)

### SPA Logic

- **Correct**: Token verification matches expected length
- **Correct**: Whitelist uses LRU map for auto-expiry
- **Correct**: Statistics tracking works correctly

---

## Recommendations

### Priority 1 (Must Fix)

1. **Fix fallback port mismatch** - Either fail fast or make eBPF configurable
2. **Fix goroutine error handling** - Don't use `log.Fatalf` in goroutines

### Priority 2 (Should Fix)

3. Update comment paths to match actual file structure
4. Improve error handling consistency (panic vs return error)
5. Handle ignored errors properly

### Priority 3 (Nice to Have)

6. Remove port overlap between FakePorts and FallbackPorts
7. Add explicit TTL for SPA whitelist (if precise timing needed)
8. Document hardcoded interface names

---

## Summary

**Total Issues Found**: 9

- Critical: 2
- Medium: 4
- Minor: 3

**Logic Correctness**: Overall sound, with 2 critical issues that need fixing

**Recommendation**: Fix Critical Issues #1 and #2 before production deployment.
