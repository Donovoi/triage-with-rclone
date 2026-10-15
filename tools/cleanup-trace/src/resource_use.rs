//! Pure, once-only post-failure observation. Never retries or changes removal.
pub const CAPACITY: usize = 64;
pub const PREFIX: &str = "runtime_cleanup_resource_use=";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    None,
    TraceUnclosed,
    PriorProbeUnclosed,
    PrimaryUnwritten,
    RegistrationUnavailable,
    PreIdentity,
    PreClose,
    Start,
    Register,
    List,
    Capacity,
    Shape,
    PostIdentity,
    PostClose,
    End,
}
impl Reason {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TraceUnclosed => "trace_unclosed",
            Self::PriorProbeUnclosed => "prior_probe_unclosed",
            Self::PrimaryUnwritten => "primary_unwritten",
            Self::RegistrationUnavailable => "registration_unavailable",
            Self::PreIdentity => "pre_identity",
            Self::PreClose => "pre_close",
            Self::Start => "start",
            Self::Register => "register",
            Self::List => "list",
            Self::Capacity => "capacity",
            Self::Shape => "shape",
            Self::PostIdentity => "post_identity",
            Self::PostClose => "post_close",
            Self::End => "end",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub matched: bool,
    pub closed: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub total: u32,
    pub caller: bool,
    // Unknown, main window, other window, service, Explorer, console, critical.
    pub types: [u32; 7],
}
#[derive(Debug)]
pub struct Query {
    pub status: u32,
    pub counts: Result<Counts, Reason>,
}
pub trait Api {
    fn probe(&mut self) -> Probe;
    fn start(&mut self) -> u32;
    fn register(&mut self) -> u32;
    fn list(&mut self) -> Query;
    fn end(&mut self) -> u32;
}
#[derive(Debug)]
pub struct Report {
    pub reason: Reason,
    pub pre: Option<Probe>,
    pub post: Option<Probe>,
    pub statuses: [Option<u32>; 4],
    pub counts: Option<Counts>,
}
impl Report {
    pub fn unavailable(reason: Reason) -> Self {
        Self {
            reason,
            pre: None,
            post: None,
            statuses: [None; 4],
            counts: None,
        }
    }
    /// Includes prefix and newline in the bound. All strings are closed literals/hash.
    pub fn line(
        &self,
        runtime: &str,
        trace_closed: bool,
        prior_probe_closed: bool,
    ) -> Option<String> {
        if runtime.len() != 64
            || !runtime
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let number = |n: Option<u32>| n.map_or_else(|| "null".into(), |v| v.to_string());
        let boolean = |b: Option<bool>| b.map_or_else(|| "null".into(), |v| v.to_string());
        let counts = self.counts.map_or_else(
            || "null".into(),
            |c| {
                format!(
                    "{{\"total\":{},\"other_processes\":{},\"types\":[{},{},{},{},{},{},{}]}}",
                    c.total,
                    c.total - u32::from(c.caller),
                    c.types[0],
                    c.types[1],
                    c.types[2],
                    c.types[3],
                    c.types[4],
                    c.types[5],
                    c.types[6]
                )
            },
        );
        let line = format!("{PREFIX}{{\"schema\":1,\"scope\":\"post_failure_resource_use\",\"phase\":\"after_trace_before_residue\",\"original_os_code\":32,\"original_result_preserved\":true,\"causal_owner\":false,\"hard_deadline\":false,\"runtime_sha256\":\"{}\",\"availability\":\"{}\",\"reason\":\"{}\",\"trace_closed\":{},\"prior_probe_closed\":{},\"pre_identity\":{},\"pre_closed\":{},\"post_identity\":{},\"post_closed\":{},\"start_status\":{},\"register_status\":{},\"list_status\":{},\"end_status\":{},\"caller_listed\":{},\"counts\":{}}}\n",
            runtime, if self.reason == Reason::None { "available" } else { "unavailable" }, self.reason.label(), trace_closed, prior_probe_closed,
            boolean(self.pre.map(|p| p.matched)), boolean(self.pre.map(|p| p.closed)), boolean(self.post.map(|p| p.matched)), boolean(self.post.map(|p| p.closed)),
            number(self.statuses[0]), number(self.statuses[1]), number(self.statuses[2]), number(self.statuses[3]), boolean(self.counts.map(|c| c.caller)), counts);
        (line.len() <= 1024).then_some(line)
    }
}

/// No fallible early return after successful Start: End is attempted exactly once.
/// Calls are synchronous and have no hard time bound; no watchdog or Drop retry.
pub fn observe(api: &mut impl Api) -> Report {
    let mut report = Report::unavailable(Reason::None);
    let pre = api.probe();
    report.pre = Some(pre);
    if !pre.closed || !pre.matched {
        report.reason = if !pre.closed {
            Reason::PreClose
        } else {
            Reason::PreIdentity
        };
        return report;
    }
    let start = api.start();
    report.statuses[0] = Some(start);
    if start != 0 {
        report.reason = Reason::Start;
        return report;
    }
    let register = api.register();
    report.statuses[1] = Some(register);
    if register != 0 {
        report.reason = Reason::Register;
    } else {
        let query = api.list();
        report.statuses[2] = Some(query.status);
        if query.status != 0 {
            report.reason = if query.status == 234 {
                Reason::Capacity
            } else {
                Reason::List
            };
        } else {
            match query.counts {
                Ok(c)
                    if c.total <= CAPACITY as u32
                        && c.types.iter().map(|v| u64::from(*v)).sum::<u64>()
                            == u64::from(c.total)
                        && (!c.caller || c.total > 0) =>
                {
                    report.counts = Some(c)
                }
                _ => report.reason = Reason::Shape,
            }
        }
    }
    let end = api.end();
    report.statuses[3] = Some(end);
    // The post-check is read-only and closes its probe even after failed End.
    let post = api.probe();
    report.post = Some(post);
    if !post.matched {
        report.reason = Reason::PostIdentity;
    }
    if !post.closed {
        report.reason = Reason::PostClose;
    }
    if end != 0 {
        report.reason = Reason::End;
    }
    if report.reason != Reason::None {
        report.counts = None;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<&'static str>,
        codes: [u32; 4],
        probes: [Probe; 2],
        bad_shape: bool,
    }
    impl Api for Fake {
        fn probe(&mut self) -> Probe {
            let n = self.calls.iter().filter(|v| **v == "probe").count();
            self.calls.push("probe");
            self.probes[n]
        }
        fn start(&mut self) -> u32 {
            self.calls.push("start");
            self.codes[0]
        }
        fn register(&mut self) -> u32 {
            self.calls.push("register");
            self.codes[1]
        }
        fn list(&mut self) -> Query {
            self.calls.push("list");
            Query {
                status: self.codes[2],
                counts: if self.bad_shape {
                    Err(Reason::Shape)
                } else {
                    Ok(Counts::default())
                },
            }
        }
        fn end(&mut self) -> u32 {
            self.calls.push("end");
            self.codes[3]
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: vec![],
            codes: [0; 4],
            probes: [Probe {
                matched: true,
                closed: true,
            }; 2],
            bad_shape: false,
        }
    }
    #[test]
    fn once_only_order_and_empty_is_not_ownership() {
        let mut f = fake();
        let r = observe(&mut f);
        assert_eq!(
            f.calls,
            ["probe", "start", "register", "list", "end", "probe"]
        );
        assert_eq!(r.reason, Reason::None);
        assert_eq!(r.counts, Some(Counts::default()));
        let line = r.line(&"a".repeat(64), true, true).unwrap();
        assert!(line.len() <= 1024);
        assert!(line.contains("\"causal_owner\":false"));
    }
    #[test]
    fn all_api_error_edges_preserve_end_obligation() {
        for index in 0..4 {
            let mut f = fake();
            f.codes[index] = 5;
            let r = observe(&mut f);
            assert_ne!(r.reason, Reason::None);
            assert!(r.counts.is_none());
            assert_eq!(
                f.calls.iter().filter(|x| **x == "end").count(),
                usize::from(index != 0)
            );
            assert_eq!(f.calls.iter().filter(|x| **x == "start").count(), 1);
        }
        let mut f = fake();
        f.codes[2] = 234;
        assert_eq!(observe(&mut f).reason, Reason::Capacity);
    }
    #[test]
    fn probe_and_shape_uncertainty_never_credits_counts() {
        for n in 0..2 {
            for closed in [false, true] {
                let mut f = fake();
                f.probes[n] = Probe {
                    matched: false,
                    closed,
                };
                let r = observe(&mut f);
                assert!(r.counts.is_none());
                if n == 0 {
                    assert_eq!(f.calls, ["probe"]);
                }
            }
        }
        let mut f = fake();
        f.bad_shape = true;
        assert_eq!(observe(&mut f).reason, Reason::Shape);
        let mut f = fake();
        f.codes[3] = 6;
        f.probes[1].closed = false;
        assert_eq!(observe(&mut f).reason, Reason::End);
    }
    #[test]
    fn serialization_bound_and_private_string_rejection() {
        let mut r = Report::unavailable(Reason::End);
        r.statuses = [Some(u32::MAX); 4];
        assert!(r.line(&"f".repeat(64), false, false).unwrap().len() <= 1024);
        assert!(r.line("PRIVATE_CANARY", true, true).is_none());
    }
}
