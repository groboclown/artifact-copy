//! Thin shell over the library.
//!
//! Everything of substance lives in `artifact_copy`; this parses
//! arguments, sets up logging, and maps the outcome to an exit code.

use std::process::ExitCode;

use artifact_copy::Ctx;
use artifact_copy::cli::logging::{self, Arguments, Logging, Secrets};
use artifact_copy::cli::{Cli, subcmd};
use artifact_copy::core::log::Log;
use artifact_copy::core::problem::ProblemSink;
use artifact_copy::model::Cause;
use clap::Parser;

/// The run finished, but something was skipped or refused.
const EXIT_PROBLEMS: u8 = 1;

/// The run could not complete at all.
const EXIT_FAILED: u8 = 2;

/// Killed by a second Ctrl-C: the shell convention of 128 + SIGINT.
const EXIT_INTERRUPTED: i32 = 130;

fn main() -> ExitCode {
    let cli = Cli::try_parse().unwrap_or_else(|err| {
        if let Some(renamed) = artifact_copy::cli::renamed_command(&err) {
            eprintln!("artifact-copy: that sub-command is now `{renamed}`");
        }

        err.exit()
    });
    let log = Log::default();

    let logging = match start_logging(&cli, &log) {
        Ok(logging) => logging,
        Err(err) => {
            eprintln!("artifact-copy: {err}");
            return ExitCode::from(EXIT_FAILED);
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("artifact-copy: cannot start: {err}");
            return ExitCode::from(EXIT_FAILED);
        }
    };

    let ctx = Ctx::new(
        Cause::Requested {
            arg: std::env::args().skip(1).collect::<Vec<_>>().join(" "),
        },
        ProblemSink::new(),
        logging.progress(),
    )
    .logging_with(log.with_secrets(logging.secrets()));

    // Spawning needs the runtime; the guard drops before the runtime does.
    let _entered = runtime.enter();
    handle_interrupts(&ctx);

    match runtime.block_on(subcmd::run(cli, &ctx, &logging)) {
        // A recorded abort unwound the run, the same as an error would.
        Ok(action) if action.is_fatal() => ExitCode::from(EXIT_FAILED),

        // A warning is not a failure; a skipped artifact is.
        Ok(action) if !action.is_failure() => ExitCode::SUCCESS,

        Ok(_) => ExitCode::from(EXIT_PROBLEMS),

        Err(err) => {
            ctx.log().error(err);
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// Start logging from the command line; `setup.log` applies once the
/// configuration loads.
fn start_logging(cli: &Cli, log: &Log) -> artifact_copy::Result<Logging> {
    let logging = logging::install(Arguments::read(cli, std::env::args_os())?)?;

    if logging.secrets() == Secrets::Revealed {
        log.warn("--unsafe-debug is on: output may contain passwords and tokens");
    }

    Ok(logging)
}

/// The first Ctrl-C stops the run gracefully; the second kills it.
///
/// A user pressing it twice has stopped asking politely. The library only
/// installs the graceful half, since exiting is the binary's decision.
fn handle_interrupts(ctx: &Ctx) {
    ctx.cancel().cancel_on_interrupt();

    let log = ctx.log().clone();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }

        log.warn("stopping; press Ctrl-C again to exit now");

        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }

        eprintln!("artifact-copy: interrupted twice; exiting");
        std::process::exit(EXIT_INTERRUPTED);
    });
}
