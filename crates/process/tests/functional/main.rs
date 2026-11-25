//! Functional tests of `scribe_process`: `/proc/net` parsing, matching flows to sockets, the
//! sensor wrapper, and this process's own sockets found in the real table of this system.

mod live;
mod parse;
mod resolver;
