#!/usr/bin/env bash
# Runs inside a virtme-ng guest (Sensors workflow, kernel matrix): the privileged sensor tests on
# the guest's kernel. The guest sees the runner's filesystem, so the test binaries built there run
# as they are.
#
#   kernel-check.sh <sensor-conformance test binary> <daemon functional test binary>
#
# Without BTF (/sys/kernel/btf/vmlinux) the eBPF sensor can't load and scribed falls back to pcap:
# then only the pcap sensor is checked, with a warning in the run.
set -euo pipefail

conformance=$1
daemon=$2

echo "kernel $(uname -r) on $(uname -m)"
[[ $(id -u) == 0 ]] || { echo "::error::kernel-check.sh must run as root in the guest"; exit 1; }
ip link set lo up 2>/dev/null || true

if [[ -e /sys/kernel/btf/vmlinux ]]; then
    "$conformance" --ignored --test-threads 1 sensors::
    # Alone in its process: it drops the privileges of the whole test binary.
    "$daemon" --ignored --exact service::privileges_keeper_restarts_capture_as_a_user
else
    echo "::warning::kernel $(uname -r) has no BTF: the eBPF sensor can't load there (pcap fallback); checking pcap only"
    "$conformance" --ignored --exact sensors::pcap_sensor_conforms
fi
