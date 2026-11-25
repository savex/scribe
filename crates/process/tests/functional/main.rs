//! Functional tests of `scribe_process`: `/proc/net` parsing, matching flows to sockets, the
//! sensor wrapper, this process's own sockets found in the real table of this system, and the join
//! of native sensors' connection reports with packet observations.

mod join;
mod live;
mod parse;
mod resolver;
