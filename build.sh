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
echo "========================"
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
