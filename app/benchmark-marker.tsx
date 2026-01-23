// This file is modified during incremental builds to trigger recompilation
// It gets reset to this baseline state before each cold build
// Marker: baseline
export function BenchmarkMarker() {
  return <span data-benchmark="baseline" style={{ display: 'none' }} />
}
