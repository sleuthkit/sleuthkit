#!/bin/bash
set -e

GCOV=$(which gcov)

# Determine script location
script_home=$(cd "$(dirname "$0")" && pwd)
cd "$script_home/.."

# Clean old coverage data (optional)
find . -name '*.gcda' -o -name '*.gcno' -delete

# Bootstrap and build
sh bootstrap
./configure CFLAGS='-g -O0 -fprofile-arcs -ftest-coverage' CXXFLAGS='-g -O0 -fprofile-arcs -ftest-coverage' -q
make -j V=0
make check V=0

# Set gcov tool (optional but safer)
export GCOV=$(which gcov)

# Run gcov (safely by directory)
find . -name '*.gcno' -exec dirname {} \; | sort -u | while read dir; do
  gcov -o "$dir" "$dir"/*.cpp "$dir"/*.c 2>/dev/null || true
done

# Generate lcov report
lcov --gcov-tool "$GCOV" \
     --capture \
     --directory . \
     --output-file coverage.info \
     --ignore-errors gcov,missing,path,inconsistent,format
genhtml coverage.info --output-directory coverage_html  --ignore-errors inconsistent,corrupt,category

echo "Coverage report available in coverage_html/index.html"
