#! /bin/bash

# first, generate 1000 random pages

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
bench_incr=public/bench-incremental.txt

echo "starting build $build_id"

# --- COLD BUILD ---
# Reset benchmark-marker.tsx to baseline state before cold build
# This ensures consistent starting point for every cold build
cat > app/benchmark-marker.tsx << 'EOF'
// This file is modified during incremental builds to trigger recompilation
// It gets reset to this baseline state before each cold build
// Marker: baseline
export function BenchmarkMarker() {
  return <span data-benchmark="baseline" style={{ display: 'none' }} />
}
EOF

echo "build_id=$build_id" > $bench
echo "push_ts=$push_ts" >> $bench
echo "start_ts=$(date +%s)" >> $bench

npm run build-only

echo "end_ts=$(date +%s)" >> $bench
echo "next_version=$(node -p "require('next/package.json').version")" >> $bench
echo "bundler=webpack" >> $bench

echo "=== Cold build results ==="
cat $bench

# --- INCREMENTAL BUILD ---
# Capture the moment incremental build phase begins (this becomes push_ts for incremental)
incremental_push_ts=$(date +%s.%N)

# Check if build cache exists from the cold build (confirms cache will be used)
if [ -d ".next/cache" ]; then
    cache_exists="true"
    cache_size=$(du -sh .next/cache 2>/dev/null | cut -f1 || echo "unknown")
    echo "Build cache found: .next/cache (size: $cache_size)"
else
    cache_exists="false"
    cache_size="0"
    echo "WARNING: No build cache found at .next/cache - incremental build may not use cache!"
fi

# Modify benchmark-marker.tsx to trigger incremental rebuild
cat > app/benchmark-marker.tsx << EOF
// This file is modified during incremental builds to trigger recompilation
// Marker: ${build_id}-incr-$(date +%s)
export function BenchmarkMarker() {
  return <span data-benchmark="${build_id}-incr" style={{ display: 'none' }} />
}
EOF

echo "build_id=$build_id" > $bench_incr
echo "push_ts=$incremental_push_ts" >> $bench_incr
echo "cache_exists=$cache_exists" >> $bench_incr
echo "cache_size=$cache_size" >> $bench_incr
echo "start_ts=$(date +%s)" >> $bench_incr

npm run build-only

echo "end_ts=$(date +%s)" >> $bench_incr
echo "next_version=$(node -p "require('next/package.json').version")" >> $bench_incr
echo "bundler=webpack" >> $bench_incr

echo "=== Incremental build results ==="
cat $bench_incr
