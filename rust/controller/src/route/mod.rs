//! Routing tables: round-robin LB, bad-address tracking, and the host/port
//! resolution table. Port of the Go `route` package.

mod badaddr;
mod rrlb;
mod table;

pub use badaddr::BadAddrs;
pub use rrlb::Rrlb;
pub use table::Table;
