#! /bin/bash

echo "=== CPU Info ==="
cat /proc/cpuinfo || echo "Note: /proc/cpuinfo not available on this system"
echo ""
echo "--- CPU Summary ---"
echo "nproc (host logical CPUs): $(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 'unknown')"
echo ""
echo "--- Cgroup CPU Limits (actual allocation) ---"
# cgroups v1
if [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
  quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
  period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
  if [ "$quota" != "-1" ]; then
    effective_cpus=$(echo "scale=2; $quota / $period" | bc)
    echo "cgroups v1 - Effective CPUs: $effective_cpus (quota: $quota, period: $period)"
  else
    echo "cgroups v1 - No CPU limit set (unlimited)"
  fi
fi
# cgroups v2
if [ -f /sys/fs/cgroup/cpu.max ]; then
  cpu_max=$(cat /sys/fs/cgroup/cpu.max)
  echo "cgroups v2 - cpu.max: $cpu_max"
  quota=$(echo $cpu_max | awk '{print $1}')
  period=$(echo $cpu_max | awk '{print $2}')
  if [ "$quota" != "max" ]; then
    effective_cpus=$(echo "scale=2; $quota / $period" | bc)
    echo "cgroups v2 - Effective CPUs: $effective_cpus"
  else
    echo "cgroups v2 - No CPU limit set (unlimited)"
  fi
fi
# Memory for context
echo ""
echo "--- Memory ---"
free -h 2>/dev/null || vm_stat 2>/dev/null | head -5 || echo "Memory info not available"
echo "================"

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
