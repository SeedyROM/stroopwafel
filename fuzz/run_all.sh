#!/usr/bin/env bash
set -e

# Run all fuzz targets sequentially
# Usage: ./run_all.sh [duration_per_target_in_seconds]
#
# Arguments:
#   duration_per_target_in_seconds: How long to fuzz each target (default: 60)
#
# Examples:
#   ./run_all.sh 60        # Fuzz each target for 60s
#   ./run_all.sh 120       # Fuzz each target for 120s

DURATION=${1:-60}  # Default: 60 seconds per target

echo "Running all fuzz targets for ${DURATION} seconds each..."
echo "================================================"

# Get list of all fuzz targets
TARGETS=$(cargo fuzz list)

for target in $TARGETS; do
    echo ""
    echo "Running fuzz target: $target"
    echo "----------------------------------------"
    rustup run nightly cargo fuzz run "$target" -- -max_total_time="$DURATION" || {
        echo "Warning: $target exited with an error"
    }
    echo "Completed: $target"
done

echo ""
echo "================================================"
echo "All fuzz targets completed!"
echo ""
echo "To view coverage results, check:"
echo "  fuzz/corpus/<target_name>/"
echo "  fuzz/artifacts/<target_name>/ (if crashes found)"
