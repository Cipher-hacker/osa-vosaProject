#!/bin/sh
PYTHON_BIN="${PYTHON_BIN:-python3}"
script_path="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 || exit 1; pwd -P)"

# Go to parent directory
cd -- "$script_path/.." || exit 1

# Run mPVAS for various parameters
$PYTHON_BIN -m testrun.main -p plain -n 2 -m 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plain -n 10 -m 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plain -n 10 -m 0.1 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plus -n 2 -m 0 -c 2 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plus -n 10 -m 0 -c 2 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plus -n 10 -m 0 -c 3 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p plus -n 10 -m 0.1 -c 2 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 2 -m 0 --tamper-type final --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 10 -m 0.1 --tamper-type final --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 10 -m 0 --tamper-type partial --tamper-ratio 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 10 -m 0.1 --tamper-type partial --tamper-ratio 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 10 -m 0 --tamper-type partial --tamper-ratio 0.1 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p iv -n 10 -m 0.1 --tamper-type partial --tamper-ratio 0.1 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p ud -n 2 -m 0 -d 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p ud -n 10 -m 0.1 -d 0 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p ud -n 10 -m 0 -d 0.1 --suppress-writes || exit 2
$PYTHON_BIN -m testrun.main -p ud -n 10 -m 0.1 -d 0.1 --suppress-writes || exit 2
