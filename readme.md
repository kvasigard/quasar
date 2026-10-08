# Quasar EDR Engine

**Quasar** is a lightweight Endpoint Detection and Response (EDR) telemetry and analytics engine written in Rust. This project serves as my playground to research how to detect certain behaviours and how to collect telemetry without starving the system resources. Apart from learning myself, I hope this project serves as inspiration for others on how to start messing up with detections :)

## Architecture

Quasar is designed as a multi-component workspace, split between user-mode analysis, kernel-mode visibility, and shared definitions:

* **Pulsar (User-Mode):** This is the user-mode agent in charge of collecting system telemetry and routing it through an internal processing pipeline for real-time analysis. It manages data ingestion via "Sensors" (ETW NT Kernel Logger and Singularity Per-CPU Ring Buffer), dispatches the events across threads without blocking, and feeds them into analytical "Sinks" (DirectSyscallSink, TamperDetectionSink) where the actual detection logic lives. It also orchestrates kernel-mode component lifecycles and self-elevation to PPL-Antimalware.
* **Singularity (Kernel-Mode):** A Windows Kernel-Mode Driver Framework (KMDF) driver written purely in Rust. It serves as the privileged component of the EDR, providing deep system visibility, Object Manager pre-operation handle interception (`ObRegisterCallbacks`), Process Protection Level (PPL) modification, and lock-free Per-CPU shared memory ring buffer telemetry streaming (<500 ns latency).
* **Shared:** A common `no_std` Rust crate bridging the gap between `pulsar` and `singularity`. It houses binary record layouts (`EventHeader`), domain event contracts (`TemplateEvent`, `DriverEvent`), modular event payloads (`shared::ring_buffer::events`), and IOCTL command definitions ensuring strict C-ABI stability and zero-copy synchronization.

## Project Structure
```text
quasar/
├── shared/                   # Common definitions between um and km (IOCTLs, Structs, Contracts)
│   └── src/
│       ├── ioctl/            # IOCTL codes and parameter structures (PPL, RingBuffer)
│       └── ring_buffer/      # Binary record headers, types, and modular domain events
│           └── events/       # Domain event payloads (handle, etc.)
├── pulsar/                   # Core EDR Engine (User-Mode)
│   └── src/
│       ├── main.rs           # Modularized orchestration & CLI parsing
│       ├── lib.rs            # Library core
│       ├── error.rs          # Custom AppError implementation
│       ├── bootstrap.rs      # PPL elevation & driver orchestration
│       ├── drivers/          # Driver lifecycle management and SCM control
│       ├── model/            # Normalized domain entities and events
│       ├── pipeline/         # Event dispatcher, call stack correlator, engine, and Event enum
│       ├── sensors/          # Ingestion sensors: ETW (kernel/user) and Driver (per-CPU ring buffer)
│       ├── sinks/            # Analytical detection modules (DirectSyscallSink, TamperDetectionSink)
│       ├── state/            # ProcessTree timeline and temporal context
│       └── helpers/          # Safe handle wrappers, string utilities
└── singularity/              # KMDF Driver (Kernel-Mode)
    ├── .cargo/config.toml    # Compiler flags for kernel environment
    ├── Makefile.toml         # cargo-make configuration for driver packaging
    ├── build.rs              # Bindgen execution for WDK headers
    ├── singularity.inx       # Driver installation and isolated package template
    └── src/
        ├── lib.rs            # DriverEntry and core kernel logic
        ├── device.rs         # Non-PnP WDF Control Device and sequential queue
        ├── comm/             # Lock-free Per-CPU shared memory ring buffer & double MDL mapping
        ├── domains/          # Core security domains (callbacks, anti_tampering PPL)
        ├── foundation/       # Error handling, IRQL guards, spinlocks, logging, driver state
        ├── ioctl/            # IOCTL dispatching and handlers
        └── wrappers/         # Safe EPROCESS and pool flag wrappers
```

## Features

Quasar combines kernel-level hooks with user-mode analytics to detect modern post-exploitation techniques with low system latency:

### Telemetry Sources
* **ETW (Event Tracing for Windows):** Programmatically builds, starts, and consumes NT Kernel Logger ETW sessions to capture real-time system calls, process lifecycles, and kernel call stack walking.
* **Singularity Per-CPU Ring Buffer:** A zero-copy lock-free ring buffer backed by `NonPagedPool` allocations. Partitions memory per logical core to eliminate cross-core lock contention, streaming kernel Object Manager handle events to user-space with sub-microsecond latency.

### Detections & Analytics
* **Direct Syscall Detection:** Identifies processes attempting to bypass user-land API hooking by executing `syscall` instructions directly, verified via ETW kernel stack trace unwinding.
* **Anti-Tampering & Credential Access:** Monitors sensitive handle operations (`PROCESS_VM_READ`, `PROCESS_DUP_HANDLE`, `PROCESS_CREATE_PROCESS`) targeting critical processes like `lsass.exe` using Object Manager callbacks (`ObRegisterCallbacks`).
* **Process & Context Tracking:** Maintains an in-memory graph (`ProcessTree`) mapping active process lifecycles, ancestry hierarchies, and temporal resolution for recycled PIDs.

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
All detection and telemetry features are **enabled by default**. You can pass CLI flags to disable specific subsystems:

| Option | Description |
| :--- | :--- |
| `--disable-syscalls` | Disables direct syscall anomaly detection and ETW kernel stack tracing. |
| `--disable-context` | Disables process tree and module mapping context tracking. |
| `--skip-driver` | Skips Singularity kernel driver loading and PPL elevation (useful for standalone ETW inspection). |
| `-u, --uninstall` | Stops and unregisters the Singularity driver service from the SCM and exits. |
| `-h, --help` | Displays the help menu with all available options. |

#### Examples
```powershell
# Run with all features enabled (default)
.\target\release\pulsar.exe

# Run in standalone ETW mode without driver/PPL elevation
.\target\release\pulsar.exe --skip-driver

# Disable direct syscall detection (run context tracking only)
.\target\release\pulsar.exe --disable-syscalls

# Disable context tracking (run syscall detection only)
.\target\release\pulsar.exe --disable-context
```

#### Logging Configuration
Set the `RUST_LOG` environment variable to configure runtime log verbosity:

```powershell
# Enable debug logs
$env:RUST_LOG="debug"
cargo run

# Enable high-frequency trace logging
$env:RUST_LOG="trace"
cargo run
```

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
