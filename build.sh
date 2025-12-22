#! /bin/bash

echo "=== CPU Info ==="
cat /proc/cpuinfo || echo "Note: /proc/cpuinfo not available on this system"

# Calculate effective CPUs from cgroup limits
# Linux cgroups limit CPU via quota/period: effective_cpus = quota_us / period_us
# Example: quota=600000, period=100000 → 600000/100000 = 6 CPUs
effective_cpus=""
cgroup_version=""
quota=""
period=""

# cgroups v1: reads from /sys/fs/cgroup/cpu/
if [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
  cgroup_version="v1"
  quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
  period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
  if [ "$quota" != "-1" ]; then
    effective_cpus=$(awk "BEGIN {printf \"%.0f\", $quota / $period}")
  fi
fi

# cgroups v2: reads from /sys/fs/cgroup/cpu.max (format: "quota period")
if [ -f /sys/fs/cgroup/cpu.max ]; then
  cgroup_version="v2"
  cpu_max=$(cat /sys/fs/cgroup/cpu.max)
  quota=$(echo $cpu_max | awk '{print $1}')
  period=$(echo $cpu_max | awk '{print $2}')
  if [ "$quota" != "max" ]; then
    effective_cpus=$(awk "BEGIN {printf \"%.0f\", $quota / $period}")
  fi
fi

# Display prominent summary
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                      BUILD RESOURCES                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
if [ -n "$effective_cpus" ]; then
echo "║                                                              ║"
echo "║              >>>  $effective_cpus CPUs AVAILABLE  <<<                  ║"
echo "║                                                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  How we calculated this:                                     ║"
echo "║  • Source: cgroups $cgroup_version (Linux container CPU limits)            ║"
echo "║  • Quota: $quota µs per period                              ║" | awk '{printf "%-65s║\n", substr($0, 1, 64)}'
echo "║  • Period: $period µs                                       ║" | awk '{printf "%-65s║\n", substr($0, 1, 64)}'
echo "║  • Formula: quota ÷ period = $quota ÷ $period = $effective_cpus CPUs    ║" | awk '{printf "%-65s║\n", substr($0, 1, 64)}'
else
echo "║              CPUs: unlimited (no cgroup limit)               ║"
fi
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Host machine (for reference):                               ║"
echo "║  • nproc reports: $(printf '%-43s' "$(nproc 2>/dev/null || echo 'unknown') logical CPUs")║"
echo "║  • Memory: $(printf '%-52s' "$(free -h 2>/dev/null | awk '/Mem:/ {print $2 " total, " $7 " available"}' || echo 'unknown')")║"
echo "║                                                              ║"
echo "║  Note: nproc shows host CPUs, not your container's limit.   ║"
echo "║  The cgroup quota is what actually constrains your build.    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
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
