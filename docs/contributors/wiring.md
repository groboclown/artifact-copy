# Sessions, Hosts, and Capabilities

How a configuration becomes the live objects a run uses.

## The capability pairing

`session::Hosts` turns a configured host into the `HostedExt` a source fetches through -- constraints from its url, retry plan, cache, credentials -- lazily and shared, so two sources naming one host reach it through one capability. It is the mirror of `repo::Sources`, which builds the other half.

- **One HTTP client per TLS setting, not per host.** `reqwest` decides certificate verification when the client is built, so a host that disables it genuinely needs its own; everything else is per-request, so every host that agrees shares one connection pool.
- **Retries wrap the shared client** rather than replacing it, because the plan is per host and the pool is not.
- **The cache is per repository**, under a directory named for the host and its path, and every capability on that folder shares one `Cache`. Two sources on one repository are fetching from one place, so a shared cache is what lets the second reuse what the first downloaded. Host names are free text from a file, so the directory name is sanitized to one ordinary component -- a test asserts that property rather than a spelling.
- **Credentials are handed over unresolved**, which is `HostedExt`'s design: it resolves each secret at the moment it attaches one, so a token is never held in a long-lived object an extension could be given. The cost is that a misspelled environment variable surfaces on the first fetch rather than when the host opens, which is why `validate-config` resolves secrets separately.

## A source is given its host as it is built, and that is a security property

`repo::Sources::open` takes an `ext::Capabilities`, which `session::Hosts` implements, and each source is constructed with the `ExtHost` for its own host; it holds that host for its lifetime. `ext::Unbound` is what `validate-config` passes: every host it hands out is one shared `ext::DenyingHost`, which has no HTTP client and refuses every request, because validation asks only whether a configuration builds.

**Sharing one capability across sources would be a credential leak**, and it is the finding most worth keeping. A proxy's upstreams are on different hosts. One capability cannot serve them: its constraints permit one repository's prefix, so the second upstream's fetch is refused. The obvious fix -- widen the constraints to cover every upstream -- is the dangerous one, because `HostedExt` attaches **its** credentials to any URL its constraints allow. A proxy over an internal mirror and a public registry would have sent the mirror's token to the public one, from a change that reads as loosening an allow-list.

So the host is given **as a source is built**, not afterwards: a proxy's upstreams are built inside `Sources`' own recursion and are never handed out individually, so a caller has nothing to give them a host through. A proxy holds no host of its own; it downloads a file through the first upstream whose host `permits` the file's URL.

Enumerators are built the same way through `enumerate::Enumerators`, confined to the host url joined with the optional `host-path`. A manager's catalog lives behind a REST API at the server root with the repository as a query parameter, so its enumerator leaves `host-path` absent; an index rooted under the server, such as Artifact Keeper's `pypi/{repo}`, sets it.

`repo::Bound` remains only to apply a configured `version-handler` around a source.

## Additional hosts: a second host a host's reads may reach

pypi.org's index lists its files on another host -- `https://files.pythonhosted.org/packages/...`, measured -- so a capability confined to the index refuses every file and every PEP 658 `.metadata` fetch. github.com answers a repository archive with a redirect to `codeload.github.com`. The obvious fix, widening the allow-list, is the leak the section above describes: `HostedExt` would attach the index's credentials to the second host too.

So a second host is a **route**, not a wider prefix. `HostedExt::route` tries the capability's own prefix first, with its own client and credentials; then each route, each with **its own** client and credentials; and refuses anything else, naming every prefix that is permitted. The URL is matched before any credential is attached, so a credential only ever travels where configuration sent it.

Routes belong to the **host**, under `hosts.*.additional-hosts`, so every capability built from the host gets them: sources, enumerators, targets, and advisors. Each entry is one of:

- `{host: name}`: an entry under `hosts`, reached at its url with its own credentials, TLS setting, and retry plan.
- `{hostname: x}`: a bare hostname, reached over `https` with no credentials and the default settings. `files.pythonhosted.org` is the case, and it saves declaring a host entry that exists only to say "no credentials".

Either form may add:

- `inherit`: the owning host's TLS setting and retry plan instead of the entry's own. Never its credentials.
- `inherit-parent-authentication`: the owning host's credentials.
- `authentication`: credentials for this entry alone.

The last two are exclusive. Both replace a named host's own credentials. Routes are not transitive: a named host's own additional hosts are not reached through this one, so two hosts naming each other cannot loop.

Three rules hold whichever route a request takes:

- **Reads only.** `head`, `fetch`, and `fetch_to_cache` may route; `send_file` and `send_form` stay on the capability's own prefix. Nothing publishes to an additional host.
- **The cache is the capability's.** A file fetched through a route lands where the caller looks for it, which is what lets `copy` hand it to a target without knowing it came from elsewhere.
- **A route counts against its own server.** A route to a configured host draws on that host's caps; a bare hostname has none. See [Concurrency caps](#concurrency-caps).

`copy` downloads payloads through `Source::download`, so a report-fed copy, whose recorded URLs are on the second host, reaches them through the same routes the source's own reads use.

## Mirrors: a copy of the host, asked first

A mirror is not a route. A route reaches **other** URLs, such as files an index lists elsewhere. A mirror answers the host's **own** URLs from another place: Google's GCS bucket holds Maven Central's files under the same paths as `repo1.maven.org`. A source never sees a mirror URL, so cache names, `Source::serves`, and a proxy's choice of upstream stay unchanged.

`HostedExt::read` handles `fetch`, `fetch_to_cache`, and `exists`. For a URL inside the capability's own constraints it tries each mirror with the URL rewritten (`Mirror::rewrite`), then hands the request to `follow` as before:

```text
  GET host/a.jar  ->  mirror 1/a.jar   not-found | unreachable | redirect -> next
                  ->  mirror n/a.jar
                  ->  host/a.jar       follow(): redirects and routes as before
```

- **No credentials.** A mirror is a public copy, so the host's token stays off it, and `Hosts::mirrors` gives it none to send.
- **No redirects.** A redirect hands the read on rather than being followed, because nothing configured where it may lead.
- **No `head`, but `exists`.** A mirror's `Last-Modified` is its copy time, and Maven reads publish times from it, so `ExtHost::head` stays with the owner. `ExtHost::exists` asks presence only, which a mirror answers as well as the owner.
- **No fall-through on a wrong answer.** A digest mismatch or an oversized body stops the read, as it stops a proxy.
- **`skip`** keeps paths a mirror cannot serve off it: `*/` for a bucket with no directory indexes.

## Concurrency caps

`hosts.*.maximum-concurrent-downloads` and `-uploads` cap requests in flight to one **server**, not one capability. `Hosts` keeps one `ext::Gates` per configured host name and clones it into every `HostedExt` built from that entry and every `Route` naming it, so ten repositories on one Nexus share one counter.

```text
  hosts.nexus (downloads: 4)
    |-- capability for /repository/maven-public --+
    |-- capability for /repository/npm-proxy -----+-- one counter of 4
    '-- additional host {host: nexus} -------------+
```

- **Every read takes a download slot, every write an upload slot.** `GET`, `HEAD`, and `exists` alike; a metadata request costs a server as much as a payload. Uploads count apart, so a publish never queues behind a walk.
- **Per hop.** `HostedExt::follow` takes the slot of whichever server a hop goes to, so a redirect to an additional host counts there.
- **Held through retries.** The retrying client sits inside the slot, so a throttled server sees fewer requests, not the same number later.
- **Mirrors and bare hostnames are uncapped.** Neither entry has a limit field.
- **Unset means no cap.** The walk's own concurrency still bounds traffic. Zero is refused at build, since it would admit nothing.

## Redirects

A client never follows a redirect. `ReqwestClient` turns reqwest's off, and every client reports one as `Error::Redirected`, because whether the next hop may be reached, and with whose credentials, is the capability's question. `HostedExt::follow` answers it per hop, up to ten:

```text
  read   ->  anywhere under the host's own url   the host's credentials
         ->  an additional host                  that route's credentials
  write  ->  inside the capability's prefix, and only for 307 or 308
  else   ->  Error::Redirected, not followed
```

A read may leave the capability's prefix but not the host: a manager moving `/repository/a` to `/repository/b` is followed with the manager's credentials, since it is the manager's own answer. A write stays inside its prefix, and only a redirect that promises to keep the method and body is followed, since the others let a client switch to `GET` and drop the upload. Each hop carries the credentials of wherever it lands, never the previous hop's.

## What `Session` is

`Session` holds the three registries -- `Hosts`, `Sources`, and the run's `Dispositions` -- and `Session::source(name)` returns an `ConfiguredSource`: a source already built with its host, plus the answer to *how are this repository's versions read*. `Session::deciding` derives the context a command works through, applied once here rather than by each command, because a command that forgot would silently ignore everything a user configured.

It **borrows** its configuration rather than owning one. A session with a private copy would be a second description of the run that could drift from the first; the cost is that a caller holds the `Config` alongside, which is why `cli::subcmd::run` loads it and passes a reference.

`Session::over` supplies a transport, so a session can be driven against canned responses. Written for the tests and useful on its own: an embedder with an HTTP client already has somewhere to put it.

## `inspect` and `find`

`commands::inspect` resolves requests and lock files into roots, walks them, and streams each artifact to a `Visitor`; `cli::subcmd::inspect` supplies a `commands::report::ToReport` and writes the header and summary around it.

`--enumerator` became **`--source`**: inspection resolves each request into a full record -- files, digests, license, publish time -- and every one of those is something only a source can answer. An enumerator enumerates, which is `find`.

`commands::find` walks an enumerator's catalog page by page and streams each finding to a `Sink`; `cli::subcmd::find` supplies the same `ToReport` and the same header and summary frame as `inspect`, so the two write one report format rather than two that drift.

**`find` does not resolve, and that is the design.** A `Found` carries an id, sometimes a version, and a last-download time; files, digests, license, and publish time cost a request each. `ArtifactRecord.version` became optional and gained `last-download` to say that honestly -- PyPI's simple index and npm's replication feed both list names only, and an invented version would be worse than none.

Three things fell out on the way:

- **`LastDownload` moved to `model`.** A report needs it, and `report -> enumerate` would have been a sideways dependency; it is domain vocabulary, not an enumerator's private type.
- **`Capabilities` and `Unbound` live in `ext`**, since enumerators need them as much as sources do and a capability is `ext`'s subject.
- `ToReport` reads `Ctx::reservations()` and fills `ArtifactRecord.quarantine`, and the list is keyed by the artifact the finding was decided under -- a publish-window step-down used to file findings about candidates it rejected against the version that won.

## A root lost its own provenance

`Spider::run` built each root's context from `call.ctx().clone()`, discarding the `Provenance` the `ArtifactRequest` arrived with. Every `parse_req` builds one, and `inspect` re-roots lock-file entries on the file -- all of it thrown away, so **`Cause::LockFile` could not appear in a report at all** and a requested artifact was filed under the whole command line rather than the coordinate somebody typed.

Invisible until something wrote a report, which is why `inspect` found it and the spider's own tests did not: they assert on counts and on dependency edges, and a dependency's provenance *is* built from its parent's context, so the half that worked was the half under test. `Ctx::rooted` replaces the chain rather than extending it, and `root_keeps_the_provenance_it_arrived_with` pins it.
