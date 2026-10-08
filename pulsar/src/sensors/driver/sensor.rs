//! Driver telemetry sensor streaming kernel events from the per-CPU shared ring buffer.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use shared::ring_buffer::{DriverEventType, HandlePreOpEvent};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::consumer::DriverRingManager;
use crate::drivers::error::DriverError;
use crate::drivers::kmdf::Singularity;
use crate::helpers::SafeHandle;
use crate::pipeline::event::Event;

/// Telemetry sensor ingesting events from the Singularity driver's per-CPU shared ring buffers.
pub struct DriverSensor {
    ring_manager: DriverRingManager,
    notification_event: SafeHandle,
}

impl DriverSensor {
    /// Initializes the driver sensor by mapping shared memory and registering an auto-reset Win32 event.
    ///
    /// # Arguments
    ///
    /// * `driver` - Active Singularity KMDF driver client.
    ///
    /// # Returns
    ///
    /// Initialized [`DriverSensor`] instance ready to start background draining.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if memory mapping or event registration fails.
    pub fn initialize(driver: &Singularity) -> Result<Self, DriverError> {
        log::debug!(target: "driver_sensor", "Mapping per-CPU shared ring buffers into user address space...");
        let mapping = driver.map_per_cpu_buffer()?;

        log::debug!(
            target: "driver_sensor",
            "Per-CPU buffers mapped: Data @ {:#018X} ({} cores x {} KB), Status @ {:#018X}",
            mapping.data_address,
            mapping.cpu_count,
            mapping.per_cpu_data_size / 1024,
            mapping.status_address
        );

        let event_handle = unsafe { CreateEventW(core::ptr::null(), 0, 0, core::ptr::null()) };
        let auto_event = SafeHandle::new(event_handle).ok_or_else(|| {
            let code = unsafe { GetLastError() };
            DriverError::from_win32_code(code)
        })?;

        log::debug!(target: "driver_sensor", "Registering notification event with Singularity driver...");
        driver.register_event(auto_event.raw())?;

        let ring_manager = DriverRingManager::new(&mapping);

        log::info!(
            target: "driver_sensor",
            "Driver sensor initialized successfully for {} logical cores.",
            mapping.cpu_count
        );

        Ok(Self {
            ring_manager,
            notification_event: auto_event,
        })
    }

    /// Spawns the named background worker thread that drains telemetry and feeds domain events to the callback.
    ///
    /// # Arguments
    ///
    /// * `shutdown_flag` - Atomic flag checked periodically to initiate graceful termination.
    /// * `event_callback` - Closure invoked for each decoded domain event.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the background worker thread.
    pub fn start<F>(
        mut self,
        shutdown_flag: Arc<AtomicBool>,
        mut event_callback: F,
    ) -> JoinHandle<()>
    where
        F: FnMut(Event) + Send + 'static,
    {
        thread::Builder::new()
            .name("pulsar-driver-sensor".to_string())
            .spawn(move || {
                log::info!(target: "driver_sensor", "Driver sensor background worker started.");
                let mut spin_count: u32 = 0;

                while !shutdown_flag.load(Ordering::Relaxed) {
                    let drained = self.ring_manager.drain_all(|cpu_id, event_type, latency_us, payload| {
                        if event_type == DriverEventType::HandlePreOperation as u16 {
                            if payload.len() >= core::mem::size_of::<HandlePreOpEvent>() {
                                let event = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const HandlePreOpEvent) };
                                log::trace!(
                                    target: "driver_sensor",
                                    "[CPU {cpu_id}] Ingested HandlePreOp: Source PID {} -> Target PID {} (Latency: {:.2} us)",
                                    event.source_pid,
                                    event.target_pid,
                                    latency_us
                                );
                                event_callback(Event::HandlePreOp(event));
                            }
                        } else {
                            log::trace!(
                                target: "driver_sensor",
                                "[CPU {cpu_id}] Unknown/unhandled driver event type: {event_type:#06X}"
                            );
                        }
                    });

                if drained > 0 {
                    spin_count = 0;
                } else {
                    // Adaptive spin-then-wait: 100 spins -> yield -> WaitForSingleObject(50ms)
                    spin_count += 1;
                    if spin_count < 100 {
                        core::hint::spin_loop();
                    } else if spin_count < 200 {
                        thread::yield_now();
                    } else {
                        unsafe {
                            WaitForSingleObject(self.notification_event.raw(), 50);
                        }
                    }
                }
            }

            // Final sweep on shutdown
            let trailing = self.ring_manager.drain_all(|_cpu_id, event_type, _latency_us, payload| {
                if event_type == DriverEventType::HandlePreOperation as u16 && payload.len() >= core::mem::size_of::<HandlePreOpEvent>() {
                    let event = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const HandlePreOpEvent) };
                    event_callback(Event::HandlePreOp(event));
                }
            });

            if trailing > 0 {
                log::debug!(target: "driver_sensor", "Drained {trailing} trailing driver events during shutdown.");
            }

            log::info!(target: "driver_sensor", "Driver sensor background worker terminated.");
        })
        .expect("Failed to spawn pulsar-driver-sensor thread")
    }
}
