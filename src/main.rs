//! pseudo-bridge: multi-guest MAC-NAT over a single-MAC upstream.
//! See ARCHITECTURE.md. Control plane (this binary) programs an in-kernel offload
//! (nft or ebpf) and learns guest ip→mac bindings from a copy path.

mod afpacket;
mod apf;
mod backend;
mod cli;
mod core;
mod netlink;
mod packet;
mod state;
mod types;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Fail before logging/initialising anything for an unsupported watchdog combination
    // (notably `-e nft`): there is intentionally no polling fallback for this feature.
    // This also resolves --apf-method, which cannot be combined with every address mode.
    crate::cli::validate_apf_plan(&cli).map_err(anyhow::Error::msg)?;
    // --loglevel sets the default filter; RUST_LOG (if set) still overrides it.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cli.loglevel.clone()))
        .format_timestamp_millis()
        .init();

    log::info!(
        "pbridge start: if={} engine={:?} mode={:?} bridge={:?} fwd0={} fwd1={} nflog-group={} timeout={}s \
         offload-workaround={:?} arp-keepalive={}s apf-watchdog-guests={:?} apf-watchdog-debounce={}ms \
         apf-method={:?} loglevel={}",
        cli.interface,
        cli.engine,
        cli.mode,
        cli.bridge,
        cli.fwd0(),
        cli.fwd1(),
        cli.nflog_group,
        cli.timeout,
        cli.offload_workaround,
        cli.arp_keepalive,
        cli.apf_watchdog_guest,
        cli.apf_watchdog_debounce_ms,
        cli.apf_method,
        cli.loglevel,
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(core::run(cli))
}
