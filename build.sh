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

echo ""
echo "=== End Security Audit ==="
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
