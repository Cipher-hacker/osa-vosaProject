#!/bin/sh
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Navigate to directory
self_path="$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 || exit 1; pwd -P)"
cd -- "$self_path/.." || exit 1
printf "Current working directory: %s.\n" "$PWD"

# Count completed experiments
out_dir="../out/data/"
if [ -d "$out_dir" ]; then
    files="$(find "$out_dir" -type f -printf x | wc -c)"
    if [ "$files" -eq "0" ]; then
        completed="0"
    else
        lines="$(cat "$out_dir/"* | wc -l)"
        completed="$((lines - files))"
    fi
else
    completed="0"
fi
mkdir -p -- "$out_dir"
printf "Storing outputs in: %s.\n" "$(realpath -- "$out_dir")"

# Runs the experiment specified by `$@`. If the experiment fails, the entire script is stopped.
#
# If global `$real` is not `1`, or if global `$current` is less than global `$completed`, then the experiment is
# skipped.
#
# The global `$current` is always incremented.
maybe_run() {
    if [ "$current" -ge "$completed" ] && [ "$real" -eq "1" ]; then
        printf "Running experiment %d/%d.\n" "$((current + 1))" "$total"
        $PYTHON_BIN -m testrun.main -s "17+$current" "$@" || exit 1
    fi

    current=$((current + 1))
    return 0
}

# Run mPVAS for various parameters.
#
# Returns the number of experiments in `$current`.
#
# If `$1` is `0`, then no experiments are actually executed, but the value `$current` still represents the total number
# of experiments.
experiments() {
    real="$1"

    current=0
    for _ in $(seq 1 3); do
        for n in 50 100 250 500 750 1000; do
            for malicious_ratio in 0.0 0.1 0.2 0.3; do
                maybe_run -p plain -n $n -m $malicious_ratio
                maybe_run -p plus -n $n -m $malicious_ratio
                maybe_run -p iv -n $n -m $malicious_ratio --tamper-type final
                maybe_run -p ud -n $n -m $malicious_ratio

                for tamper_ratio in 0.1 0.5 1.0; do
                    maybe_run -p iv -n $n -m $malicious_ratio --tamper-type partial --tamper-ratio $tamper_ratio
                done

                for dropout_ratio in 0.1 0.3 0.5; do
                    maybe_run -p ud -n $n -m $malicious_ratio --dropout-ratio $dropout_ratio
                done
            done
        done
    done
}

# Count number of experiments
experiments "0"
total="$current"

# Actually run experiments
printf "Previously completed experiments: %d/%d.\n" "$completed" "$total"
experiments "1"

# Done!
printf "Completed all %d experiments.\n" "$completed"
