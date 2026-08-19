# Seccomp derivation toolchain image (container-validated observation only).
# Native Linux re-runs of the same workloads use the host toolchain instead
# (see trace_workloads.py --native).
#
# NOTE: python3 here is CPython 3.12 (ubuntu 24.04); the supervisor targets
# 3.11+. Syscall-surface differences between 3.11/3.12 are small and are
# flagged in the classification notes where they matter.
FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        strace \
        python3 \
        git \
        coreutils \
        bash \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
