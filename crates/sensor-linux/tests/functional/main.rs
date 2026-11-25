//! Functional tests of the Linux sensor's decoding half: ring-buffer records, the join with
//! packet observations, and the samples in `testdata/events/linux-ebpf` (no privileges).

mod owners;
mod record;
mod samples;
