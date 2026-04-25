# Quasar EDR Engine

**Quasar** is a lightweight Endpoint Detection and Response (EDR) telemetry and analytics engine written in Rust. This project serves as my playground to research how to detect certain behaviours and how to collect telemetry without starving the system resources. Apart from learning myself, I hope this project serves as inspiration for others on how to start messing up with detections :)

## Architecture

Quasar is designed as a multi-component workspace, split between user-mode analysis and kernel-mode visibility:

* **Pulsar (User-Mode):** This is the user-mode agent in charge of collecting some system telemetry and routing it through an internal processing pipeline for real-time analysis. It manages data ingestion via "Sensors", dispatches the events across threads without blocking, and feeds them into analytical "Sinks" where the actual detection logic lives.
* **Singularity (Kernel-Mode):** A Windows Kernel-Mode Driver Framework (KMDF) driver written purely in Rust. It serves as the privileged component of the EDR, providing deep system visibility, robust event tracing, and other enforcement capabilities that are otherwise inaccessible or easily bypassed from user-land.

## Project Structure

```text
quasar/
├── Cargo.toml                # Workspace manifest (Profile and Dependency management)
├── pulsar/                   # Core EDR Engine (User-Mode)
│   ├── Cargo.toml            # Pulsar dependencies
│   └── src/
│       ├── main.rs           # Entry point and initialization
│       ├── lib.rs            # Library core
│       ├── error.rs          # Custom AppError implementation
│       ├── pipeline/         # Event dispatcher and routing logic
│       ├── sensors/          # ETW session builder, consumer, and director
│       ├── sinks/            # Analytical detection modules (DirectSyscallSink)
│       └── helpers/          # Stack unwinding and DbgHelp symbol resolution
└── singularity/              # KMDF Driver (Kernel-Mode)
    ├── .cargo/config.toml    # Compiler flags for kernel environment (panic=abort, crt-static)
    ├── Cargo.toml            # Driver dependencies (wdk, wdk-sys, etc.)
    ├── Makefile.toml         # cargo-make configuration for driver packaging
    ├── build.rs              # Bindgen execution for WDK headers
    ├── singularity.inx       # Driver installation and isolated package template
    └── src/
        └── lib.rs            # DriverEntry and core kernel logic
```

## Features

At the time of writing this, the project features are aligned with only one purpose: detect stack anomalies. More features will be added hopefully in the future.

### Telemetry Sources
* **ETW (Event Tracing for Windows):** Programmatically builds, starts, and consumes NT Kernel Logger ETW sessions. This allows the engine to capture real-time, high-fidelity and verbose system events (like system calls) directly from the Windows kernel.

### Detections
* **Direct Syscall:** Identifies processes attempting to bypass standard user-land API hooking by executing `syscall` instructions directly. It achieves this by capturing kernel-level system call events and utilizing stack unwinding/correlation to verify if the execution origin is legitimate.

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
git clone [https://github.com/kvasigard/quasar.git](https://github.com/kvasigard/quasar.git)
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

### Pulsar
Due to the restrictions of the Windows ETW API, you must run the compiled binary as an **Administrator**.

```bash
# Run directly with cargo (must be in an Admin shell)
cargo run --release

# Or execute the built binary
.\target\release\pulsar.exe
```

Set the `RUST_LOG` environment variable to configure logging output:

```bash
$env:RUST_LOG="debug"
cargo run
```

To stop the agent, press `Ctrl+C`. The application will intercept the termination signal and initiate a graceful shutdown, safely unregistering the ETW sessions and freeing system resources.

### Singularity
To install and start the driver for testing on a target machine (ensure Test Signing Mode is enabled: `bcdedit /set testsigning on`):

```cmd
# Right-click the singularity.inf file and select "Install", or use sc.exe:
sc create singularity type= kernel binPath= C:\Path\To\singularity.sys
sc start singularity
```
