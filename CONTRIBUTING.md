# Contributing

## Building

To build, you'll need a Rust compiler + Cargo installed locally.

To build the extensions, you'll need to install the `wasm32-wasip1` Rust toolchain: `rustup target add wasm32-wasip1`.

To build for cross-platform, different host platforms have different requirements:

* For Linux, you'll need to install [`zigbuild`](https://ziglang.org/download/).  This comes from your distribution, so isn't installed locally. 
    * Debian/Ubuntu: `sudo apt-get install zig`
    * Arch Linux: `sudo pacman -S zig`
    * Any OS: `pip install ziglang`
* Linux will also need the `x86_64-w64-mingw32-gcc` Rust toolchain to cross-compile for Windows: `rustup target add x86_64-w64-mingw32-gcc`.

It also helps to have a `make` program installed, as the [`Makefile`](Makefile) provides easy-to-use helpers for common tasks.


## Developing

### Code Style

Rust code uses standard Rust style formatting.  The `make fmt` command ensures the code conforms to this standard.

### Architecture and Choices

The general architecture and choices made in developing/maintaining the tool live out in the [docs/contributors](docs/contributors/README.md) directory.

### External File Formats

Whenever this tool loads or writes files using an internal schema, then the file must use a JSON or YAML format, and the format must have an accompanying schema file in the [`schema`](schema) root directory.

Streaming data, such as the standardized logging output, uses a JSONL (newline delineated JSON records) format.

### Extension Mechanism

The tool's configuration has many extension points that the user can select.  Internally, this chooses either a built-in implementation or an extension (a WASM module or an executable file), which the registries route to the extension point's *gearing*.  Only a WASM source runs so far; every other extension-backed kind is refused with `unimplemented`.

A built-in is constructed with an `ExtHost` and does its own network I/O through it: the host applies the URL constraints, attaches credentials, caps sizes, and keeps downloads in a per-repository cache under `setup.cache-dir`.  A built-in holds no HTTP client of its own.  See [extensions.md](docs/contributors/extensions.md) and [wiring.md](docs/contributors/wiring.md).

An extension is held to more, by its gearing: no network I/O, stateless calls, and files only inside a scratch directory the gearing creates for it.

The WASM modules, as they run in-process, only allow for data processing and minimal I/O interaction.  For example, they can construct relative URLs for processing, but the outside code performs those requests.  It can inspect archive files, but the I/O for reading or writing those are processed through the host interface.  The module never makes external network calls itself, and the file access is limited to a sandbox.

Executables can run in either *unlimited* mode - just execute the command as requested, or run through [grackle-zero](https://github.com/groboclown/grackle-zero).


## Releasing

Follow this handy-dandy checklist:

1. Prepare the release notes.
2. Update the changelog.
3. Bump the version number.
4. Build the installer zips for each supported platform (`make installer` or `make installer-cross`).  Should be done through GitHub Actions.
5. Push the GitHub release with the version number and release notes.
