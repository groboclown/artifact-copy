# Advisories

References: [OSV schema](https://ossf.github.io/osv-schema/).

Known-vulnerability and known-malware screening: `src/advisory/`. What is built, and what each piece settled. What is left is in [TODO.md](../../TODO.md).

```text
  corpus  --(purl, version)-->  Advisory records  -->  SecurityPolicy
```

A corpus is downloaded once, cached, and answered from locally: a walk of a million artifacts must cost a map lookup each rather than a request each, which is why this is an index rather than a client.

## The record shape

`advisory::osv` carries only the parts a screening run reads. Unknown fields are ignored rather than refused: OSV grows, and a corpus that stopped parsing because a new key appeared would take screening down with it.

Malware is recognized by the `MAL-` identifier prefix, on the id or any alias. OSV has no field for it, and the distinction decides the action: `malware-known` is a hard quarantine and `vulnerability-known` is a warning, so a malicious package read as a vulnerability gets copied.

## Matching is three-valued

`advisory::matching` answers whether one version falls in an advisory's affected set. It is its own module because it is the part that can be quietly wrong.

**Three answers, not two.** `Affected`, `Unaffected`, and `Unknown` -- and the third is the point. Raw tags have no order, `GIT` ranges name commit hashes, and a handler can decline a string it cannot parse. In all of those the honest answer is *not screened*, and reading it as *unaffected* turns an unanswered security question into a clean report. Same rule as `unknown-publish-time`, for the same reason.

The enumeration is checked before the ranges and answers alone when it hits: it is string equality against versions the publisher listed, so it cannot be wrong about an ordering because it never asks one.

`VersionHandler::compare` answers a four-valued `Ranking` with an `Indeterminate` that is **not** a tie. `select`'s doc said it had replaced a pairwise compare, but that was about the cost of *selection*; range matching is a different question and needs an ordering. `Tags` answers `Indeterminate` always, which is what makes the `Unknown` path reachable rather than theoretical.

A substituted comparator is caught: replacing `handler.compare` with a string comparison fails `maven_places_a_release_candidate_below_its_release` and `convention_without_an_order_answers_unknown`, which was checked rather than assumed.

## The purl-keyed index

`advisory::index` is `(ecosystem, name) -> records`, built once and answered from memory: a corpus is published as a flat pile of records with no lookup structure of its own.

**The key is built from an artifact's parts, not from its rendered purl**, which drops the version and the qualifiers for free -- and dropping the qualifiers is right rather than convenient: an advisory is about a package, so a Maven sources jar is covered by whatever covers its main jar. Namespace and name joined by `/` is one key shape that serves every ecosystem, because Maven's group and artifact, npm's scope and package, and a Go module's host and path all collapse to it.

**One `canonical` function runs over both sides** -- the corpus's OSV names as the index is built, the artifact's own parts as it is looked up -- so the two cannot be normalized differently. Maven's `group:artifact` becomes `group/artifact` and PyPI re-normalizes per PEP 503; each arm is a no-op on the side that was already right, which is what makes sharing the function safe rather than merely shorter.

**The ecosystem half is a table, not a rule.** `crates.io` is purl's `cargo` and `Go` is purl's `golang`; lowercasing `PyPI` happens to work only for the ones nobody had an opinion about. `Ecosystems::builtin` is seeded from each built-in ecosystem's `Ecosystem::osv_name`, through `Ecosystems::learn`, so nothing in the module has to have heard of one. An extension's `EcosystemDesc::osv_name` is not learned yet, so records about an extension ecosystem land in `Index::untranslated`. An ecosystem declaring an **empty** OSV name is skipped rather than recorded, and that is load-bearing: `github` declares one, because OSV has no GitHub-releases ecosystem, and recorded it would translate every record with a missing `ecosystem` field into a GitHub release and screen it against the wrong package.

**One listing per `(package, advisory)`, not per `affected` entry.** A record carrying a `SEMVER` range beside an `ECOSYSTEM` one is ordinary, and returning those as two hits would report one finding twice against one artifact. The index groups them and `Listing::verdict` folds them with `Match::worst`, so the de-duplication is by construction rather than something every caller has to remember. The record itself is behind an `Arc`, because one advisory affecting a dozen packages is listed under a dozen keys.

**Withdrawn records are dropped but still date the corpus.** Screening against a retraction costs a reviewer the same time as a real finding and teaches them to discount the list; a withdrawal is still an edit to the file, so it counts toward how fresh the file is.

`Index::modified` is the newest record, and `None` when nothing carried a parsable timestamp. A caller must **not** read that as fresh: a corpus that cannot say how old it is has not established that it is current, so the honest report is `CorpusAge::Unavailable` rather than a consultation with no timestamp. One malformed timestamp is ignored rather than fatal, for the same reason an unknown field is -- and it can only claim the corpus is *older* than it is, which is the safe direction.

`Index::untranslated` carries the OSV ecosystems the run does not speak. Not a fault on its own -- most of a malicious-package feed is about ecosystems a given run has no interest in -- but the same fact read the other way is a configuration mistake: an ecosystem extension whose description never reached `Ecosystems::learn` puts every record about it there, and the run then screens those artifacts against an index that knows nothing and reports them clean. Which of the two it is depends on what the run was asked to copy, so the index reports and does not judge.

`Index::insert` is public beside `Index::of` because the corpus arrives as hundreds of thousands of small files in a zip, and collecting them into a `Vec` first would hold the whole thing twice.

## The corpora

**An advisor loads into the caller's index rather than returning its own.** Two corpora are the recommended arrangement, so two indexes would mean two lookups per artifact and, worse, the same `MAL-` record reported twice from the pair. One index fed by each in turn de-duplicates by construction. What stays per corpus is its *age*, which `Loaded` carries: a report says how stale each corpus was, and a merged timestamp would let a fresh malware feed vouch for a year-old vulnerability database.

`Index::insert` therefore drops a record a key already carries under the same id, **first corpus wins**, so configuration order is precedence. That is the right resolution rather than a convenient one: the redundancy exists for *availability* -- OSV ingestion lags and malicious packages are yanked within days -- not to merge two records' ranges, and the finding a duplicate produces is the same either way.

`zip` is a dependency, with default features off and only `deflate` on, which drops bzip2, zstd, lzma, and AES. It is entailed by the design: the corpus *is* a zip, and the alternative is a request per artifact against a public service, which is both unusable at a million artifacts and a disclosure of everything the organization depends on.

### Reading an archive

**Nothing is extracted.** An entry is decompressed into memory, parsed, keyed, and dropped. Writing two hundred thousand small files in order to read each one back would cost more than the download, and it is also the step at which a crafted entry path escapes the sandbox -- a bug that cannot occur in code that never opens a file for writing.

**An archive off the network is untrusted input, and this one is a screening resource**, so mishandling it does not lose an artifact -- it reports a clean run. That makes a zip bomb here a denial of screening, and it is why there are three caps rather than a comment:

- `ENTRY_LIMIT` on one entry expanded.
- `CORPUS_LIMIT` on the decompressed total, which is what actually bounds the work: a thousand entries each just under the entry cap would pass a per-entry check alone.
- `ENTRY_COUNT_LIMIT`, because an archive of empty files costs time without costing bytes.

The entry cap is enforced **while decompressing** and never from the declared size, which is a field in the archive and therefore exactly how a cap gets bypassed. Reaching any cap is an error and never a short read: a corpus cut off part way answers "nothing found" about the rest.

**One bad record is not a bad corpus, and no good records is.** A single entry that will not parse is skipped and counted -- a quarter of a million machine-published files will eventually contain one this cannot read, and screening against the rest beats screening against nothing. But an archive that held candidate records and yielded *none* of them is refused, because zero records screens every artifact clean. `Tally` carries the counts and no verdict: whether four skipped out of two hundred thousand is acceptable is the run's question.

### Where a corpus is kept between runs

In the **host's own directory under `setup.cache-dir`**, which is to say the sandbox, reached the way every other download is. Not a new place and not a new mechanism: `Sandbox` is already keyed per host, already under `cache-dir`, and already survives a run, so a corpus cached anywhere else would be a second cache directory answering the same question. The `caches` collection in the configuration stays unimplemented and is not this.

That made the sandbox's contract worth stating exactly, because it reads as scratch space. An extension may **not rely** on anything being there -- a cold cache, a cleared `cache-dir`, and a first run all look identical, so a missing file must always be answerable by fetching -- but it may **use** what it finds. `Sandbox::staged` is the read side, and it answers `Option` rather than `Result` on purpose: an absent file, an unreadable directory, and a name that resolves out of the sandbox all mean the same thing to a caller, so returning an error would make every call site write the same `unwrap_or(None)`.

**A copy that cannot be dated is not fresh.** The same asymmetry `unknown-publish-time` and an unevaluable advisory range follow. Reading an unreadable or future-dated timestamp as current would pin a stale cache in place for as long as the clock stayed wrong, and the cost of the strict answer is one download.

`archive::acquire` is the whole caching policy, in three steps that are three different claims:

1. A copy younger than the advisor's TTL, unless `--refresh-advisories` said otherwise. Nothing is requested at all.
2. A download. What a first run, an expired cache, and a cleared `cache-dir` all do.
3. Failing that, **any** copy that is there, however old.

Step 3 is the one worth arguing for. A stale corpus is not the same as no corpus: it is an older answer, and `corpus-age` says exactly how old -- which is why that field is an absolute timestamp rather than a duration. [exit-codes.md](exit-codes.md) treats a screening resource being down harshly because "a run that copies everything and reports nothing looks identical to a clean run", and yesterday's advisories, reported as yesterday's, is not that run. This matters most for `ossf-malicious`, whose whole reason for existing is that a malicious package is yanked within days.

The caller still learns it happened, through `Origin::Stale`, because silently serving an expired corpus is the failure the module is arranged to prevent. `Origin` folds worst-first across a multi-archive corpus: one stale archive is the fact worth surfacing, however many of the others were current.

An error comes back from `acquire` only when there was nothing cached to fall back to. That is what lets `osv-offline` keep telling a 404 for an unpublished ecosystem apart from a corpus it could not reach: nothing was ever downloaded for such an ecosystem, so there is no copy to be stale, and the 404 still reaches the skip.

`Freshness` is a parameter to `load` rather than state on the advisor, while the TTL is state. `--refresh-advisories` is a statement about one invocation and an advisor cannot make it on a user's behalf; the TTL is configuration. The same split `Criteria::pre_release` makes, for the same reason.

### A corpus the user supplies

`from_file` on either advisor reads an archive from disk and makes no request at all. For an air-gapped run, or one whose corpora are mirrored by something other than this tool, or someone who already has a snapshot of the malicious-packages feed.

The file is **copied into the sandbox** rather than opened where it lies, which is what `--lock=FILE` does and for the same reason: a reader is handed a sandbox path and cannot reach anything beside it, so a corpus somebody points at is read under exactly the rules a downloaded one is. The copy is not free at a few hundred megabytes, and it buys two things worth the cost -- the archive cannot change under the reader part way through, and one code path reads every corpus however it arrived.

A supplied file **replaces the whole plan rather than narrowing it**: the user said which archive to read, so asking the bucket for the ecosystems it does not contain would be a request they did not ask for. `ecosystems` still narrows the records read out of it, since a combined `all.zip` holds every ecosystem. A file that is not there fails rather than quietly falling back to the network, because falling back would turn a typo into an unexpected few hundred megabytes.

Only an **archive** is supported. A working `git clone` of the malicious-packages feed is a directory tree rather than a zip, and reading one needs a second traversal with its own symlink handling; that is a to-do rather than a variant of this. `git archive` or GitHub's download button produces a zip that works today.

### `osv-offline`

**Reads which ecosystems to fetch from the index's own `Ecosystems` table.** Not tidiness: an advisor that downloaded an ecosystem the index cannot translate would file every record under `Index::untranslated` and screen those artifacts against nothing. One table makes the two lists the same list. It also has the URL's other half -- the OSV name is not derivable from the purl type and a bucket path is case-sensitive, so `pypi` 404s where `PyPI` succeeds, which is why `Ecosystems` keeps the published spelling beside its lower-cased lookup key.

A **404 for one ecosystem is skipped** and the others still load: OSV has no GitHub-releases feed, and a corpus that does not exist is a different claim from one that could not be reached. A 403 or a timeout fails the load, because carrying on would report every artifact in that ecosystem as screened and clean. An ecosystem the *user named* that has no OSV name is refused outright rather than skipped.

### `ossf-malicious`

Deliberately redundant with `osv-offline`, and the redundancy is the feature. OSV ingests this feed, so nearly every record arrives there too -- eventually. Ingestion lags, and malicious packages are yanked within days, which is what makes the window narrow and also what makes a mirror that already copied one the only place the package still exists.

**Fetched from `github.com`, which redirects to `codeload.github.com`.** A cross-host redirect is followed only to a host listed under the owning host's `additional-hosts`, so the configured host is `https://github.com/` with `codeload.github.com` as an additional host. See [wiring.md](wiring.md#redirects).

**`ecosystems` narrows as the snapshot is read**, not as it is fetched: the feed is one archive holding every ecosystem. A record keeps only its `affected` entries in the named ecosystems and is dropped when none remain. A named ecosystem with no OSV name is refused, as `osv-offline` refuses one.

**The cached snapshot is named for its repository and branch.** Two advisors on one host reading different feeds would otherwise answer from each other's copy inside the TTL.

Its entry claim is **loose on the prefix and strict on the exclusion**: a `.json` file under a `malicious` path component is a record, since the archive's top-level directory is named for the branch and no absolute prefix can be hardcoded; anything under a `withdrawn` component is not, whatever else it looks like, because the feed keeps retracted reports there and screening against one reports malware nobody claims any more. The exclusion is checked over the whole path rather than only beside `malicious`, so a reorganization that nests the two differently still cannot let one through. Being loose costs nothing -- a stray JSON file either fails to parse and is counted, or parses into a record naming no package and is keyed under nothing.

### Built from configuration

`advisory::open(kind, ...)` is the registry, and `Session::advisor` feeds it, as `open_source` and `Session::source` do for sources.

- **`host` is required.** Configuration mirrors the model one to one: an advisor fetches through a host capability, so it names a `hosts` entry. The host's url replaces the published location, which makes a mirror a host entry rather than an option. `path` still needs the host, whose cache directory holds the staged copy.
- **`options`** carries kind-specific keys, as a source's does. `ossf-malicious` reads the well-known `repository` and its own `branch`.
- **`ttl`, `ecosystems`, and `path`** are typed keys and reach `advisory::Settings`, which keeps this module free of `config`.
- **An extension kind** goes to `ext::gear::launch`, as an enumerator's does.

**Advisors load in configuration order**, which is what makes "first corpus wins" mean configuration order is precedence. `Config.advisors` is an `IndexMap`, and serde_json's `preserve_order` feature keeps key order from parsing through the multi-file merge; without it every `serde_json::Map` is a `BTreeMap` and the order is alphabetical before `Config` is built. Across files, an earlier file's advisors come first and a later file's new ones follow.

`subcmd::screening` builds every advisor **before** loading any, so a configuration fault stops the run rather than reading as one corpus being down. It then loads each into one `Index` through `advisory::consult`, which records the outcome in `Screening`: a failed load or an undated corpus is `unavailable`, and a corpus served past its TTL is `consulted` and reports `advisory-source-stale`. `--refresh-advisories` is `Freshness::Refresh`; `--no-advisories` loads nothing.

**A corpus's age comes from its own records**, carried on `Tally::modified`, and never from the index. The index is shared, so its age is the newest across every advisor, and reading it would let a fresh malware feed vouch for a stale vulnerability database.

### Neither advisor declares an ecosystem

`Description::ecosystems` says which ecosystems an extension *speaks*, and an advisor speaks none -- it reads whichever the run does. Listing them would be a second copy of the table that could disagree with the one the index keys by.

## Screening in the walk

`advisory::Screen::artifact` screens one artifact. `Spider` calls it beside the license verdict, under the narrowed per-artifact context and before the refusal is read, so `malware-known` and `advisory-version-unusable` drop the artifact and prune its subtree with no new control flow. `find` calls it per listing. Findings ride on the `Ctx` as `core::screened::Flag`, for the reason the license `Verdict` lives in `core`: the report reads them, and neither `report` nor `core` may name `advisory` or `policy`.

```text
  index.advisories(id) --verdict(version, handler)--> Affected | Unknown | Unaffected
     Unaffected  -> nothing
     otherwise   -> SecurityPolicy::screen -> Finding
        suppressed          -> Flag only
        Unknown             -> advisory-version-unusable
        Affected, malware   -> malware-known
        Affected, otherwise -> vulnerability-known (forbid: at least skip-artifact)
```

- **Always screened.** A source or enumerator with no security policy is screened under `SecurityPolicy::default()`. A host's policy wins over `setup`'s. What a finding does is the code's disposition, so `problem-policy` and the quarantine policy decide it, as for any other code.
- **Only a versioned artifact.** An advisory is about versions. The walk orders them with the source's own handler, so screening and resolution agree; `find` uses the ecosystem's, having no source. A listing without a version is not screened.
- **`advisory-version-unusable` is its own code**, hard quarantine by default: the package is named and no version in the advisory can be compared with this one. Not knowing is not clean, and the risk of copying malware outweighs an uncertain match. It is reported whatever the policy's stance, since the stance is about a known finding.
- **A suppression is the decision.** A finding a VEX statement clears is recorded with `suppressed-by` and raises no problem, so it bypasses `problem-policy` and every quarantine rule for that artifact. `Screening::answer` finds the statement; `SecurityPolicy::screen` applies the stance to what it left.
- **`vulnerabilities: forbid`** reports `vulnerability-known` raised to at least `skip-artifact` through `Ctx::report_at_least`, since the stance changes severity rather than the finding. It used to answer `license-forbidden`. Precedence, most specific first: a per-artifact quarantine rule for the artifact (the ruling carries a `bypass`) answers as written; otherwise the stance's floor beats a `problem-policy` entry. That second case is a conflict between two files, so `SecurityPolicy::stance_conflict` warns about it when the policy loads and under `validate-config`, and only when `problem-policy` names `vulnerability-known` below `skip-artifact`: the built-in `warn` is not something the user said.
- **The advisor is attributed** by `Index::attributing`, set before each advisor loads, so a corpus reader never learns its configured name. The first corpus to carry a record is the one named.
- `vex-incomplete` is reported when an advisory affects a package a VEX document covers and the document says nothing about it, by id or alias: the document was written before the advisory. Malware is left out, since a VEX document triages vulnerabilities.

## What the report's frame already does

`Header.corpus_age` and `Summary.unmatched_suppressions` were empty literals in three commands each, with nothing that could fail if a caller forgot. Both are now filled from the run's screening: `osv-offline` and `ossf-malicious` supply the corpora, and `Screening` records what each advisor did.

- `advisory::Screening` is the run's screening state, required by `report::header` rather than optional, so it cannot be skipped.
- `corpus-age` is **always serialized**, with one entry per configured advisor: `consulted`, `skipped-by-request`, or `unavailable`. An empty map means no advisor was configured. This is what [exit-codes.md](exit-codes.md) needs to keep an unscreened run from reading as a clean one.
- A run where no configured advisor was consulted reports `advisory-source-unavailable` -- abort by default, `problem-policy` to loosen, `--no-advisories` to skip for one run.
- `unmatched_suppressions` fills from `Screening::stale`: every VEX statement that was asked, because `Screening::screened` saw an artifact it covers, and answered nothing.

### VEX documents belong with the lock files

A VEX document says why a finding is acceptable for **specific artifacts**, not for a repository. That is a statement about a request, so it arrives the way a lock file does, and the security policy keeps only the organization-wide stances: `malware` and `vulnerabilities`. Inline `statements` leave with `vex`, for the same reason.

The scoping is what fixes staleness. A policy named in the configuration is organization-wide, so a run exercises only part of it, and "did this statement do anything" needed a second set recording which statements a run had asked. A document named for the request is expected to be exercised by that request in full:

- Its products are requested artifacts, so every statement is asked once its product resolves and is screened.
- A statement asked that no advisory matched is stale: `vex-unmatched`. One whose product never resolved was never asked, and only `artifact-not-found` is reported, which points at the package rather than the document.
- An advisory found against a covered product for a vulnerability the document does not mention means the document is out of date: `vex-incomplete`.
- A product in an ecosystem the source does not serve is not requested, and is reported as `bom-ecosystem-foreign`, ignored by default and shown by `--verbose`. An SBOM generated from a container image lists the operating system's packages beside the application's, so this is routine rather than a mistake. A statement naming only such products is no part of the run.

A CycloneDX document is an SBOM as well as a VEX, and it is read whole rather than by descending the dependency graph from its subject: the subject, `metadata.component`, and every component, nested ones included, are requested, and an `affects.ref` names one of them by `bom-ref`. A subject or internal package the source does not hold reports `artifact-not-found`; filtering those out is the *Artifact filters* item in [TODO.md](../../TODO.md).

VEX documents are read before the walk starts (`Lock::attests`), so a statement is known before the first artifact it covers is screened, wherever on the command line the document was named. Other lock files are read when the walk reaches them. `find` takes no `--lock`, so it screens with no statements.

`vex-unparsable` is an artifact code rather than a setup fault like the other lock codes: the document vouches for artifacts, so a quarantine rule may excuse it, and the document is then left out. It aborts by default.

It also puts per-request suppressions on the review cadence of the request rather than of the configuration, which is the argument the quarantine policy file makes for itself.
