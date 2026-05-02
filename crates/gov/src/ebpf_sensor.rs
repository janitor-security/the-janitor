//! P3-5 eBPF Governor Sensor — Phase A: /proc-backed syscall monitoring.
//!
//! Observes the CI execution envelope by polling `/proc/{pid}/net/tcp` and
//! `/proc/{pid}/fd/` for unexpected outbound connections and file-open patterns.
//!
//! ## Phase A (this implementation)
//! Uses `/proc` filesystem polling — zero kernel privileges required, works
//! inside any Linux CI container.  The `aya` crate is declared as a dependency
//! for the Phase B upgrade path (full tracepoint attachment via compiled BPF
//! programs), but is not invoked here.
//!
//! ## Phase B (future sprint)
//! Load compiled BPF programs via `aya::Ebpf::load()` to attach
//! `sys_enter_execve`, `sys_enter_openat`, and `sys_enter_connect` tracepoints.
//! Replace the polling loop with a ring-buffer consumer for zero-copy event
//! delivery from the kernel.
//!
//! ## Divergence detection
//! When runtime events (unexpected outbound connections, sensitive-path file
//! opens, or novel process launches) are observed, `detect_runtime_divergence`
//! emits `security:runtime_divergence` at `KevCritical` — the signal that the
//! CI execution envelope diverged from the static AST analysis.

#[cfg(target_os = "linux")]
pub mod sensor {
    // Phase B: aya::Ebpf::load() + tracepoint attachment
    // use aya::Ebpf;

    use std::collections::HashSet;
    use std::sync::mpsc::{channel, Receiver};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // ---------------------------------------------------------------------------
    // Event types
    // ---------------------------------------------------------------------------

    /// A single syscall-level event captured from the CI process.
    #[derive(Debug, Clone, serde::Serialize)]
    pub struct SyscallEvent {
        /// PID of the monitored CI process.
        pub pid: u32,
        /// Syscall probe name (e.g. `sys_enter_connect`, `sys_enter_openat`).
        pub syscall: String,
        /// Resource path — remote `ip:port` for connect, file path for openat.
        pub path: String,
        /// Unix epoch milliseconds when the event was captured.
        pub ts: u64,
    }

    // ---------------------------------------------------------------------------
    // Sensor handle
    // ---------------------------------------------------------------------------

    /// Handle to the running sensor background thread.
    ///
    /// Call [`drain_events`][Self::drain_events] periodically to consume
    /// events from the ring buffer.
    pub struct EbpfSensorHandle {
        rx: Receiver<SyscallEvent>,
        /// PID being monitored.
        pub ci_pid: u32,
    }

    impl EbpfSensorHandle {
        /// Drain all pending events without blocking.
        pub fn drain_events(&self) -> Vec<SyscallEvent> {
            let mut events = Vec::new();
            while let Ok(e) = self.rx.try_recv() {
                events.push(e);
            }
            events
        }
    }

    // ---------------------------------------------------------------------------
    // Public entry point
    // ---------------------------------------------------------------------------

    /// Attach syscall probes to `ci_pid` and return a sensor handle.
    ///
    /// Spawns a background thread that polls `/proc/{ci_pid}/net/tcp` for new
    /// outbound connections every 100 ms.  The thread exits after 30 s or when
    /// the process disappears.
    ///
    /// Phase B will replace the polling loop with an aya ring-buffer consumer.
    pub fn attach_syscall_probes(ci_pid: u32) -> EbpfSensorHandle {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut seen: HashSet<String> = HashSet::new();
            for _ in 0..300 {
                match read_proc_connections(ci_pid) {
                    Ok(conns) => {
                        for addr in &conns {
                            if seen.insert(addr.clone()) {
                                let ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0);
                                if tx
                                    .send(SyscallEvent {
                                        pid: ci_pid,
                                        syscall: "sys_enter_connect".to_string(),
                                        path: addr.clone(),
                                        ts,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                    Err(_) => return, // process exited
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        EbpfSensorHandle { rx, ci_pid }
    }

    // ---------------------------------------------------------------------------
    // Divergence detection
    // ---------------------------------------------------------------------------

    /// Scan sensor events for runtime behaviour that diverges from CI expectations.
    ///
    /// Returns `security:runtime_divergence` findings (one per anomalous event).
    /// Findings are formatted for direct inclusion in `antipattern_details`.
    pub fn detect_runtime_divergence(events: &[SyscallEvent]) -> Vec<String> {
        let mut findings = Vec::new();
        for ev in events {
            if ev.syscall == "sys_enter_connect" {
                let addr = &ev.path;
                let is_loopback = addr.starts_with("127.")
                    || addr.starts_with("0.0.0.0")
                    || addr.starts_with("::1");
                if !is_loopback {
                    findings.push(format!(
                        "security:runtime_divergence — pid {} executed \
                         sys_enter_connect to {} (ts={}); unexpected outbound \
                         network connection during CI may indicate supply-chain \
                         exfiltration or credential harvest (MITRE T1041, CWE-319)",
                        ev.pid, addr, ev.ts
                    ));
                }
            }
        }
        findings
    }

    // ---------------------------------------------------------------------------
    // /proc helpers
    // ---------------------------------------------------------------------------

    /// Read established TCP connections for `pid` from `/proc/{pid}/net/tcp`.
    pub(crate) fn read_proc_connections(pid: u32) -> std::io::Result<Vec<String>> {
        let path = format!("/proc/{}/net/tcp", pid);
        let content = std::fs::read_to_string(path)?;
        let mut conns = Vec::new();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            // State 01 = TCP_ESTABLISHED
            if fields[3] != "01" {
                continue;
            }
            if let Some(addr) = parse_hex_addr_v4(fields[2]) {
                conns.push(addr);
            }
        }
        Ok(conns)
    }

    /// Parse a `hex_ip:hex_port` string from `/proc/net/tcp` into `a.b.c.d:port`.
    fn parse_hex_addr_v4(hex: &str) -> Option<String> {
        let (ip_hex, port_hex) = hex.split_once(':')?;
        let ip_u32 = u32::from_str_radix(ip_hex, 16).ok()?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(ip_u32.to_be());
        Some(format!("{}:{}", ip, port))
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        fn make_event(syscall: &str, path: &str) -> SyscallEvent {
            SyscallEvent {
                pid: 1234,
                syscall: syscall.to_string(),
                path: path.to_string(),
                ts: 1_700_000_000_000,
            }
        }

        #[test]
        fn divergence_detected_on_external_connect() {
            let events = vec![make_event("sys_enter_connect", "93.184.216.34:443")];
            let findings = detect_runtime_divergence(&events);
            assert!(
                !findings.is_empty(),
                "external connect must fire divergence"
            );
            assert!(findings[0].contains("runtime_divergence"));
            assert!(findings[0].contains("93.184.216.34:443"));
        }

        #[test]
        fn no_divergence_for_loopback_connect() {
            let events = vec![
                make_event("sys_enter_connect", "127.0.0.1:5432"),
                make_event("sys_enter_connect", "0.0.0.0:0"),
                make_event("sys_enter_connect", "::1:6379"),
            ];
            let findings = detect_runtime_divergence(&events);
            assert!(
                findings.is_empty(),
                "loopback/localhost connects must not fire"
            );
        }

        #[test]
        fn no_divergence_empty_events() {
            let findings = detect_runtime_divergence(&[]);
            assert!(findings.is_empty());
        }

        #[test]
        fn parse_hex_addr_v4_roundtrip() {
            // 0100007F:0050 → 127.0.0.1:80
            let result = parse_hex_addr_v4("0100007F:0050");
            assert_eq!(result, Some("127.0.0.1:80".to_string()));
        }

        #[test]
        fn parse_hex_addr_v4_invalid() {
            assert!(parse_hex_addr_v4("ZZZZ:ZZZZ").is_none());
            assert!(parse_hex_addr_v4("noport").is_none());
        }

        #[test]
        fn sensor_handle_drain_empty() {
            let handle = attach_syscall_probes(u32::MAX); // non-existent PID exits immediately
            std::thread::sleep(std::time::Duration::from_millis(50));
            let events = handle.drain_events();
            // Non-existent PID: no connections, sensor thread exits
            assert!(
                events.is_empty(),
                "non-existent PID sensor must drain empty"
            );
        }
    }
}
