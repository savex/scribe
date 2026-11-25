//! Functional tests of the Windows sensor's decoding half: ETW event layouts, DNS answers as DNS
//! messages, flows from ETW alone, process paths from Kernel-Process, and the samples in
//! `testdata/events/windows-etw` (no privileges, every system).

mod dns;
mod events;
mod flows;
mod processes;
mod samples;
