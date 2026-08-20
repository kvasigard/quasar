# Stateful Code Injection Correlator

The Stateful Code Injection Correlator in `pulsar/src/context/correlation/injection.rs` tracks complex, multi-stage remote process memory tampering across time.

```
 [Actor Process]                                           [Target Process]
       │                                                          │
       ├──── Step 1: Open Target Handle (Write Access) ──────────>│
       │     (Recorded in InFlightInjection: Stage 1)             │
       │                                                          │
       ├──── Step 2: VirtualAllocEx (Allocated RWX Base) ────────>│
       │     (Recorded in InFlightInjection: Stage 2)             │
       │                                                          │
       ├──── Step 3: WriteProcessMemory (Memory Written) ─────────>│
       │     (Recorded in InFlightInjection: Stage 3)             │
       │                                                          │
       ├──── Step 4: Remote Execution Trigger (APC/Thread) ───────>│
       │     (Correlator matches sequence -> CONFIRMED INJECTION) │
       │                                                          │
       ▼                                                          ▼
  [Pin Actor Context]                                    [Pin Target Context]
```

## Why Single-Event Detections Fail

Attackers rarely execute code injection in a single API call. Instead, they perform a multi-step sequence over several seconds or minutes:
1. `OpenProcess` with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`
2. `VirtualAllocEx` with executable permissions (`PAGE_EXECUTE_READWRITE`)
3. `WriteProcessMemory` copying the shellcode payload
4. `NtCreateThreadEx`, `QueueUserAPC`, or `SetThreadContext` triggering execution

If an EDR only inspects events individually, opening a process handle looks benign, and allocating memory looks normal for developer tools. The true malicious intent only becomes evident when these events are linked together into a causal chain between the actor and target processes.

## How the Injection Correlator Works

The `InjectionCorrelator` maintains an in-flight state machine keyed by `(ActorKey, TargetKey)`:

When Step 1 occurs, the correlator registers a new potential injection candidate with `ConfidenceLevel::Low`.

When Step 2 and Step 3 occur on the same target address base, the candidate transitions to `ConfidenceLevel::High`.

When Step 4 occurs (such as a remote thread starting at the allocated address), the correlator confirms the attack, raises a high-priority alert, and records an `InteractionRecord` in the `InteractionRegistry`.

Upon confirmation, both the actor process and target process are automatically pinned (`proc.pin()`). This instructs the retention garbage collector to keep both process histories in RAM indefinitely so investigators have complete forensic records of the incident.
