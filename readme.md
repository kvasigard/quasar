# Quasar EDR Engine

**Quasar** is a lightweight Endpoint Detection and Response (EDR) telemetry and analytics engine written in Rust. This project serves as my playground to research how to detect certain behaviours and how to collect telemetry without starving the system resources. Apart from learning myself, I hope this project serves as inspiration for others on how to start messing up with detections :)

## Architecture

Quasar is designed as a multi-component workspace, split between user-mode analysis, kernel-mode visibility, and shared definitions:

* **Pulsar (User-Mode):** This is the user-mode agent in charge of collecting system telemetry and routing it through an internal processing pipeline for real-time analysis. It manages data ingestion via "Sensors", dispatches the events across threads without blocking, and feeds them into analytical "Sinks" where the actual detection logic lives. It also orchestrates kernel-mode component lifecycles.
* **Singularity (Kernel-Mode):** A Windows Kernel-Mode Driver Framework (KMDF) driver written purely in Rust. It serves as the privileged component of the EDR, providing deep system visibility, Direct Kernel Object Manipulation (DKOM) capabilities, and robust event tracing that is otherwise inaccessible from user-land.
* **Shared:** A common `no_std` Rust crate used to bridge the gap between `pulsar` and `singularity`. It houses shared data structures, enum definitions, and IOCTL codes ensuring strict memory layout and communication consistency between user-mode and kernel-mode.

## Project Structure
```text
quasar/
├── docs/                     # Comprehensive multi-file documentation suite (v0.2)
│   ├── index.md              # Master documentation roadmap
│   ├── sensors/              # Dedicated sensor docs (ETW, Driver Callbacks)
│   ├── detections/           # Dedicated detection docs (Direct Syscalls, Injection)
│   └── *.md                  # Architecture, Context, Pipeline, PPL, Errors, Profiling, Tests
├── shared/                   # Common definitions between um and km (IOCTLs, Structs)
├── pulsar/                   # Core EDR Engine (User-Mode)
│   ├── tests/                # End-to-end synthetic pipeline replay integration tests
│   └── src/
│       ├── main.rs           # Orchestration & lifecycle management
│       ├── cli.rs            # Command-line interface definitions and LogMode
│       ├── lib.rs            # Library core
│       ├── error.rs          # Domain-partitioned error taxonomy (Win32, Driver, ETW, Handler)
│       ├── profiling.rs      # Structured tracing, spans & Chrome DevTools flame chart export
│       ├── context/          # Real-time knowledge graph (processes, files, network, injections)
│       │   ├── correlation/  # Stateful injection correlation state machine
│       │   ├── handlers/     # Domain-partitioned telemetry ingestion handlers (process, image, file)
│       │   ├── identity.rs   # Synthetic monotonic entity keys (ProcessKey, FileKey, etc.)
│       │   ├── models/       # Fine-grained process, module, file, handle & network models
│       │   ├── query/        # Lock-free query wrappers and ancestry graph walking
│       │   ├── registries/   # Concurrent ProcessTree, FileRegistry, NetworkRegistry
│       │   ├── retention/    # Dual-trigger GC & ancestry tombstones
│       │   └── tests.rs      # In-place mutability and context state machine unit tests
│       ├── drivers/          # Driver lifecycle management and SCM control
│       ├── pipeline/         # Two-stage telemetry pipeline (IngressParser + EventDispatcher)
│       │   ├── event/        # Strongly-typed domain events (process, image, syscall, file)
│       │   ├── dispatcher.rs # Fan-out worker pool & subscriber dispatching
│       │   └── ingress.rs    # Stage 1 binary deserialization & single-source ingestion
│       ├── sensors/          # Telemetry ingestion (ETW NT Kernel Logger)
│       ├── sinks/            # Analytical detection sinks (DirectSyscallSink)
│       └── helpers/          # Stack correlator, symbol resolver, string decoding
└── singularity/              # KMDF Driver (Kernel-Mode)
    ├── .cargo/config.toml    # Compiler flags for kernel environment
    ├── Makefile.toml         # cargo-make configuration for driver packaging
    ├── build.rs              # Bindgen execution for WDK headers
    ├── singularity.inx       # Driver installation and isolated package template
    └── src/
        ├── lib.rs            # DriverEntry and core kernel logic
        ├── device.rs         # WDF Device initialization and context
        ├── raii.rs           # Safe Resource Acquisition Is Initialization wrappers
        ├── internals/        # Implementation logic
        │   ├── mod.rs
        │   └── dkom.rs       # Direct Kernel Object Manipulation logic (PPL elevation)
        └── ioctls/           # IOCTL dispatching and handlers
            ├── mod.rs
            └── elevate.rs    # Token elevation handler
```

## Features

### Telemetry Sources
* **ETW (Event Tracing for Windows):** Programmatically builds, starts, and consumes NT Kernel Logger ETW sessions with dedicated 1MB non-paged pool ring buffers. Captures real-time system calls, process lifecycles, and DLL module loads directly from the Windows kernel.

### Detections & Analytics
* **Direct Syscall Detection:** Identifies processes attempting to bypass standard user-land API hooks (SysWhispers, Hell's Gate, Tartarus' Gate) by executing `syscall` instructions directly from unbacked memory or unauthorized modules. Achieves this via return address boundary filtering and dynamic PE export symbol resolution.
* **Stateful Code Injection Tracking:** Correlates multi-step cross-process memory tampering across time (`OpenProcess` $\rightarrow$ `VirtualAllocEx` $\rightarrow$ `WriteProcessMemory` $\rightarrow$ `NtCreateThreadEx`), escalating confidence to `Confirmed` and pinning entities in RAM for forensic preservation.
* **Process & Context Tracking:** Real-time knowledge graph (`SystemContext`) with synthetic `ProcessKey` temporal isolation against PID recycling, lock-free in-place interior mutability, and dual-trigger garbage collection with ancestry tombstones.
* **Execution Profiling & Flame Charts:** Structured span timing with `--profile-chrome` JSON export for visual bottleneck diagnostics in Chrome DevTools (`chrome://tracing`) and [Perfetto](https://ui.perfetto.dev).

## Documentation

Comprehensive documentation for all subsystems is available in the [`/docs`](docs/index.md) directory:
* [Architecture Overview](docs/01-architecture-overview.md)
* [System Context Engine](docs/02-context-engine.md)
* [Telemetry Ingress & Dispatcher Pipeline](docs/03-pipeline-and-dispatcher.md)
* [Sensors Subsystem](docs/sensors/overview.md)
* [Driver & PPL Elevation](docs/04-driver-and-ppl.md)
* [Bootstrap, Lifecycle & Teardown](docs/05-bootstrap-and-lifecycle.md)
* [Detection Sinks](docs/detections/overview.md)
* [Error Handling Taxonomy](docs/06-error-taxonomy.md)
* [Structured Tracing & Profiling](docs/07-tracing-and-profiling.md)
* [Testing Strategy & Verification](docs/08-testing-strategy.md)
* [System Expansion Notes](docs/09-system-expansion-notes.md)

## Prerequisites

To build both components, your development environment must have:
* The **Rust toolchain** installed.
* **LLVM/Clang** installed and added to your `PATH` (required by `bindgen` for the driver).
* The **Windows Driver Kit (WDK)** and an active eWDK environment (or standard WDK install).
* `cargo-make` installed globally: `cargo install --locked cargo-make --no-default-features --features tls-native`

## Building

Because user-mode and kernel-mode require fundamentally different compiler configurations, they are built separately.

### Building Pulsar (User-Mode Agent)
From the workspace root, build the agent using standard Cargo commands:

```bash
# Clone the repository
git clone https://github.com/kvasigard/quasar.git
cd quasar

# Build the release version
cargo build --release
```

### Running the Test Suite
The automated test suite runs locally in $< 0.5$s with zero driver dependencies:

```bash
cargo test --workspace
```

### Building Singularity (KMDF Driver)
To build the driver and generate the signed `.sys`, `.cat`, and `.inf` package, you must use `cargo make` from inside the driver directory:

```bash
cd singularity
cargo make
```
The final, isolated driver package will be output to `target/<debug|release>/singularity_package/`.

## Usage

### Pulsar (Command-Line Options)
Due to the restrictions of the Windows ETW API, you must run the compiled binary in an **Administrator** terminal.

```bash
# Run directly with cargo (must be in an Admin shell)
cargo run --release

# Or execute the built binary
.\target\release\pulsar.exe
```

#### CLI Configuration Flags
All detection and telemetry features are **enabled by default**. You can pass CLI flags to disable specific subsystems or configure runtime behavior:

| Option | Description |
| :--- | :--- |
| `-l, --log-mode <LEVEL>` | Sets the logging verbosity level (`off`, `error`, `warn`, `info`, `debug`, `trace`). |
| `-f, --log-file <PATH>` | Redirects log output to the specified file in append mode instead of the console. |
| `--profile <PATH>` | Exports interactive Chrome DevTools / Perfetto flame chart JSON trace data. |
| `--disable-syscalls` | Disables direct syscall anomaly detection and ETW kernel stack tracing. |
| `--disable-context` | Disables process tree and module mapping context tracking. |
| `--skip-driver` | Skips Singularity kernel driver loading and PPL elevation (useful for standalone ETW inspection). |
| `-u, --uninstall` | Stops and unregisters the Singularity driver service from the SCM and exits. |
| `-h, --help` | Displays the help menu with all available options. |

#### Examples
```powershell
# Run with all features enabled (default)
.\target\release\pulsar.exe

# Run with debug logging enabled
.\target\release\pulsar.exe --log-mode debug

# Write trace logs directly to a file
.\target\release\pulsar.exe -l trace -f C:\logs\pulsar.log

# Export Chrome DevTools / Perfetto interactive flame chart
.\target\release\pulsar.exe --profile trace.json

# Run in standalone ETW mode without driver/PPL elevation
.\target\release\pulsar.exe --skip-driver

# Disable direct syscall detection (run context tracking only)
.\target\release\pulsar.exe --disable-syscalls

# Disable context tracking (run syscall detection only)
.\target\release\pulsar.exe --disable-context
```

#### Logging Configuration
Logging can be controlled via CLI flags or the `RUST_LOG` environment variable:
- **CLI Flag (Recommended):** Use `-l, --log-mode <LEVEL>` (`off`, `error`, `warn`, `info`, `debug`, `trace`).
- **File Redirection:** Use `-f, --log-file <PATH>` to output logs to a file.
- **Environment Variable Fallback:** Set `$env:RUST_LOG="debug"` or `$env:RUST_LOG="trace"`.

To stop the agent, press `Ctrl+C`. The application will intercept the termination signal and initiate a graceful shutdown, safely stopping the ETW kernel session and releasing system resources.

#### Automated Driver Lifecycle
Pulsar automatically manages the driver's SCM lifecycle:
- **Automatic Loading**: If the `Singularity` driver service is not registered, Pulsar dynamically stages, registers, and starts the driver service at startup.
- **Dynamic Upgrades**: If a new version of `singularity.sys` is placed in the deploy folder, Pulsar detects the binary mismatch, stops/deletes the old service, and registers/starts the updated version.
- **Fail-Fast**: If SCM loading or PPL verification fail, Pulsar logs a critical trace and exits immediately with Win32 exit code `1068` (`ERROR_SERVICE_DEPENDENCY_FAIL`).

#### Uninstalling the Driver
To cleanly stop and uninstall the driver package from the SCM, run Pulsar with the `--uninstall` flag:
```bash
.\target\release\pulsar.exe --uninstall
```

### Singularity
To compile the driver, ensure Test Signing Mode is enabled on the test VM (`bcdedit /set testsigning on`).
Pulsar automates the service registration during its startup sequence using the INF package, but you can also interact with it manually using standard SCM tools:
```cmd
sc query singularity
```
