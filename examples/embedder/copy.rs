//! Copy named artifacts from one configured repository to another,
//! driving the library directly. The shape `docs/embedding-guide.md`
//! describes.

use std::sync::Arc;

use artifact_copy::Ctx;
use artifact_copy::advisory::Screening;
use artifact_copy::cli::ConfigLoader;
use artifact_copy::commands::spider::SpiderSetting;
use artifact_copy::commands::{copy, inspect};
use artifact_copy::core::problem::Action;
use artifact_copy::core::{NullSink, ProblemSink, Unit};
use artifact_copy::model::Cause;
use artifact_copy::report::{self, Record, ReportSpec, Summary, header};
use artifact_copy::session::Session;
use artifact_copy::version::PreRelease;

#[tokio::main]
async fn main() -> artifact_copy::Result<()> {
    // 1. Settings: from files, as the command line reads them.
    let config = ConfigLoader::new()
        .add_path("examples/embedder/migrate.yaml")
        .load()?;

    // 2. The run's context: why it runs, where problems and progress go.
    let ctx = Ctx::new(
        Cause::Requested {
            arg: "nightly-migration".to_owned(),
        },
        ProblemSink::new(),
        Arc::new(NullSink),
    );

    // 3. The live objects the configuration describes.
    let mut session = Session::open(&config, false)?;

    // 4. Where the run writes: a JSON line report here.
    let spec = ReportSpec::parse("json,run.jsonl").map_err(artifact_copy::Error::Config)?;
    let writer = report::open(Some(&spec), None).await?;

    let screening = Screening::none();
    writer.write(&Record::Header(header("copy", &screening)))?;

    // 5. The work, and the command that does it.
    let artifacts = ["pkg:npm/lodash@4.17.21".to_owned()];
    let targets = ["internal-npm".to_owned()];

    let request = copy::Request {
        what: inspect::Request {
            source: "public-npm",
            artifacts: &artifacts,
            locks: &[],
            spider: SpiderSetting::SourceDefault,
            pre: PreRelease::Exclude,
            screen: None,
        },
        targets: &targets,
        from: copy::From::Requested,
    };

    let progress = ctx.progress("copy", Unit::Items, None);
    let outcome = copy::run(&mut session, &request, writer.as_ref(), &progress, &ctx).await;

    progress.finish();

    // 6. Close the report whatever happened, so a reader can tell a run
    // that finished from one that stopped.
    writer.write(&Record::Summary(Summary {
        artifacts: writer.artifact_count(),
        counts: ctx.problems().counts(),
        quarantined: ctx.problems().quarantined(),
        worst_action: ctx.problems().worst().unwrap_or(Action::Ignore),
        unmatched_suppressions: Vec::new(),
    }))?;
    writer.flush()?;

    for line in copy::describe(&outcome?) {
        println!("{line}");
    }

    Ok(())
}
