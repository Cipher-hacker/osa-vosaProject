# Willow Benchmarks

These benchmarks are using simple loops for now.

Get information with:
```
bazel run -c opt //willow/benches:run_shell_benchmark -- --help
```

For example:

```
bazel run -c opt //willow/benches:run_shell_benchmark -- -l 10000 -n 10 --handler server_handle_client_message --n-iterations 10
```

You can also use the `shell_benchmarks` crate in another binary, e.g., to loop through multiple configurations.
