# Quasar EDR Engine

**Quasar** is a lightweight Endpoint Detection and Response (EDR) telemetry and analytics engine written in Rust. This project serves as my playground to research how to detect certain behaviours and how to collect telemetry without starving the system resources. Apart from learning myself, I hope this project serves as inspiration for others on how to start messing up with detections :)

## Architecture

Currently Quasar is composed of one single component (I hope to implement more components soon).

* **Pulsar**: This is the user-mode agent in charge of collecting system telemetry and routing it through an internal, highly-concurrent pipeline for real-time analysis. It manages data ingestion via "Sensors", dispatches the events across threads without blocking, and feeds them into analytical "Sinks" where the actual detection logic lives. 

## Project Structure

```text
quasar/
├── Cargo.toml                # Workspace manifest
└── pulsar/                   # Core EDR Engine
    ├── Cargo.toml            # Pulsar dependencies
    └── src/
        ├── main.rs           # Entry point and initialization
        ├── lib.rs            # Library core
        ├── error.rs          # Custom AppError implementation
        ├── pipeline/         # Event dispatcher and routing logic
        ├── sensors/          # ETW session builder, consumer, and director
        ├── sinks/            # Analytical detection modules (DirectSyscallSink)
        └── helpers/          # Stack unwinding and DbgHelp symbol resolution
```

## Features

At the time of writing this, the project features are aligned with only one purpose: detect stack anomalies. More features will be added hopefully in the future. 

### Telemetry Sources
* **ETW (Event Tracing for Windows):** Programmatically builds, starts, and consumes NT Kernel Logger ETW sessions. This allows the engine to capture real-time, high-fidelity and verbose system events (like system calls) directly from the Windows kernel.

### Detections
* **Direct Syscall:** Identifies processes attempting to bypass standard user-land API hooking by executing `syscall` instructions directly. It achieves this by capturing kernel-level system call events and utilizing stack unwinding/correlation to verify if the execution origin is legitimate.

## Building

Clone the repository and build the workspace using Cargo.

```bash
# Clone the repository
git clone [https://github.com/kvasigard/quasar.git](https://github.com/kvasigard/quasar.git)
cd quasar

# Build the release version
cargo build --release
```

## Usage

Due to the restrictions of the Windows ETW API, you must run the compiled binary as an **Administrator**.

```bash
# Run directly with cargo (must be in an Admin shell)
cargo run --release

# Or execute the built binary
.\target\release\pulsar.exe
```

Set the `RUST_LOG` environment variable to configure logging output (powered by `env_logger`):

```bash
$env:RUST_LOG="debug"
cargo run
```

To stop the agent, press `Ctrl+C`. The application will intercept the termination signal and initiate a graceful shutdown, safely unregistering the ETW sessions and freeing system resources.

