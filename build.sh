#! /bin/bash

echo "=== CPU Info ==="
cat /proc/cpuinfo || echo "Note: /proc/cpuinfo not available on this system"
echo "Logical CPUs available: $(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 'unknown')"
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
