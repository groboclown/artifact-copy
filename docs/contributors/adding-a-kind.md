# Adding a Kind

Where to edit when adding something a configuration or command line selects by name, and which test fails when a step is missed. The general rule, from [module-layout.md](module-layout.md#kinds-sit-with-their-server): the code for a kind lives with the kind, and one central list names it.

## Repository server (source, target, enumerator)

1. Add `src/repo/<server>.rs` with the source, target, and enumerators it offers.
2. Declare `pub(super) const KINDS: Kinds` in it (types in `src/repo/kind.rs`): each kind's name, opener, and, where they apply, its option check, `names` support, version scheme, login, and native ecosystem.
3. Add one line to `SERVERS` in `src/repo.rs`.
4. If a kind will not open without options, add them to `minimal_options` in `src/repo.rs`'s tests.
5. Name the kinds in the `kind` descriptions of `schema/config.schema.json`, and document them in a `docs/configuration-<server>.md`.

Guarded by `every_advertised_kind_opens` and `every_advertised_target_kind_opens` (`src/repo.rs`), `every_built_in_enumerator_kind_validates` (`validate_config.rs`), and `kind_names_are_unique`.

## Proxy kind

Add the opener arm and the name to `open_proxy_source` and `proxy_source_kinds` in `src/repo/proxy.rs`, or to their enumerator twins in `src/repo/proxy/enumerator.rs`. Read [sources-and-targets.md](sources-and-targets.md) first: a merging proxy has no enumerator on purpose.

## Server kind (a configuration template)

1. Add `server-kinds/<kind>/` with `kind.yaml`, `server.yaml.hbs`, and one `<ecosystem>.yaml.hbs` per repository format.
2. Add a `builtin!` line per file to `BUILT_INS` in `src/config/lower/catalog.rs`.
3. Quote the kind in the description at `$defs/Server/properties/kind` in the schema, and add a `docs/configuration-<kind>.md`.

Guarded by `every_file_is_built_in`, `schema_names_every_built_in`, and `every_builtin_renders`.

## Advisor corpus

1. Add `src/advisory/<corpus>.rs` with its `KIND`, a `pub(super) const ADVISOR: AdvisorKind`, and the function that opens it.
2. Add one line to `ADVISORS` in `src/advisory.rs`.
3. Name it in the schema's `advisors` description and in the user docs.

Guarded by `every_advertised_kind_opens` in `src/advisory.rs`.

## Ecosystem

1. Add the name constant and constructor to `EcosystemId` in `src/model/ecosystem_id.rs`.
2. Add `src/ecosystem/<name>.rs` implementing `Ecosystem`.
3. Add one row to `BUILT_INS` in `src/ecosystem.rs`.

Guarded by `every_advertised_kind_opens` in `src/ecosystem.rs`.

## Version scheme

Add the constant, the `open` arm, and the `kinds()` entry in `src/version.rs`, then the name to `version-handler` in `schema/config.schema.json` and to `version-scheme` in `schema/extension-protocol.schema.json`.

Guarded by `every_advertised_kind_opens` in `src/version.rs`, `schema_lists_every_version_handler`, and `protocol_lists_every_version_scheme`.

## Lock file format

Add `src/lock/<format>.rs` with a `readers()` function, declare the module in `src/lock.rs`, and chain its readers into `Registry::builtin` in `src/lock/registry.rs`. Order matters: the registry is a precedence list, not a match table.

## Report format

Add the variant to `ReportFormat` in `src/report/format.rs`, with its arms in `as_str`, `every`, `rendering`, and `opening`. Name it in the `--to-report` help in `src/cli.rs` and in [reports.md](../reports.md).

Guarded by `every_name_parses_back_to_its_value` and `report_help_names_every_format`.

## Refresh part

Add the variant to `Part` in `src/report/refresh.rs`, with its `as_str` arm and `every` entry. `--help` lists it through `impl ValueEnum`; also add it to the `--refresh` help prose in `src/cli.rs`.

## Problem code

Add the variant to `Code` in `src/core/problem/code.rs`, with its arms, and to `ALL` (raise the length). If a configuration may set it, add it to the `problem-policy` names in the schema.

Guarded by `schema_knows_every_configurable_problem_code` and `setup_fault_cannot_be_configured_away` in `src/cli/config.rs`.

## Credential source, authentication, extension, and other closed settings

Add the variant to the serde enum (`SecretValue` and `Authentication` in `src/config/secret.rs`; `Extension`, `LogLevel`, `OutputFormat`, `Payloads`, `SigningScheme`, `UnknownPublishTime` in `src/config/model.rs`) and the matching `enum` value or `oneOf` branch in the schema. The compiler finds the `match` arms to add.

Guarded by the tests in `src/config/schema_sync.rs`.

## Sub-command

1. Add the variant and its `*Args` struct to `Command` in `src/cli.rs`, and its `writes_stdout` arm.
2. Add `src/cli/subcmd/<name>.rs` for argument handling and output, and its dispatch arm in `src/cli/subcmd.rs`.
3. Add `src/commands/<name>.rs` for the behavior, with no argument parsing or terminal output.
4. Document it in [README.md](../../README.md).

Guarded by `every_subcommand_parses` in `src/cli.rs`.
