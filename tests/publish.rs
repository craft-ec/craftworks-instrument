//! THE ONE PUBLISH FILTER, property-tested (craftworks-docs OBSERVABILITY §2.4; craftworks-sdk#399). For generated
//! rings and windows, a record holds only publishable keys, only values at the published grain, no ordinal that could
//! count the page's operations, and at most B bytes; each property has a mutant that goes red (the PR body lists them).
//! The generator is a seeded xorshift in-crate: this crate has NO dependencies, and that is load-bearing (Cargo.toml).

use instrument::label::{DOMAIN_SCHEMA_MAX, DOMAIN_UNLISTED};
use instrument::publish::WINDOW_MS;
use instrument::publish::{
    publish, Header, PubEvent, Published, Window, MAX_RECORD_BYTES, UNKNOWN_SITE,
};
use instrument::vocab::UNANSWERED_LEAK;
use instrument::vocab::{
    self, Grain, Publish, ALL, HEADER_LEAK, OUTCOME_LEAK, PUBLISHED_OFFSET_GRAIN_MS,
};
use instrument::{
    Bucket, Dir, Entry, Event, Key, Kind, Label, OpId, Outcome, Record, Site, SizeClass,
};

/// THE FIRST CUT, pinned here and not read from the table (the architect's ruling on #399): a key moved into or out of
/// the published set changes this list in the same, privacy-reviewed diff.
const PUBLISHED: [Key; 8] = [
    Key::RecordReads,
    Key::RecordWrites,
    Key::RecordFails,
    Key::RecordBytesRead,
    Key::RecordBytesWritten,
    Key::Attempts,
    Key::StatusClass,
    Key::OffsetMs,
];
const DOMAIN_KEYS: [Key; 5] = [
    Key::RecordReads,
    Key::RecordWrites,
    Key::RecordFails,
    Key::RecordBytesRead,
    Key::RecordBytesWritten,
];

const SITES: [Site; 3] = [
    Site::of("page::send"),
    Site::of("page::server"),
    Site::of("loader::fetch"),
];

/// A recording, as the filter sees one window of it.
struct Ring {
    events: Vec<Event>,
    dropped: u64,
}

impl Record for Ring {
    fn events(&self) -> Vec<Event> {
        self.events.clone()
    }
    fn offered(&self) -> u64 {
        self.events.len() as u64 + self.dropped
    }
    fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A window starting an HOUR or more into the recording (so an offset from the recording's start is ≥ 3600 s and
/// can't pass for one from the window's), with the ring's running drop count at its start.
fn window(rng: &mut Rng, ring_dropped: u64) -> Window {
    Window {
        minute: 29_000_000 + rng.below(1_000),
        start_ms: 3_600_000 + rng.below(10_000_000),
        dropped_at_start: ring_dropped - rng.below(ring_dropped.min(60) + 1),
    }
}

/// Ring ordinals are LARGE (a page long past its first thousand ops): a record that kept them would publish them.
/// A ring draws its operations from a small POOL, so exits, counters and stalls meet on the same operations.
fn pool(rng: &mut Rng) -> Vec<OpId> {
    (0..1 + rng.below(24))
        .map(|_| {
            let kind = [Kind::Request, Kind::Block, Kind::Fetch, Kind::Span][rng.below(4) as usize];
            Label::new(kind, 1_000 + rng.below(1_000_000) as u32)
                .expect("in range")
                .op()
        })
        .collect()
}

fn ring(rng: &mut Rng, start_ms: u64) -> Vec<Event> {
    let ops = pool(rng);
    let pick = |rng: &mut Rng| ops[rng.below(ops.len() as u64) as usize];
    let big = rng.below(10) == 0;
    let n = if big {
        12_000 + rng.below(4_000) as usize
    } else {
        rng.below(200) as usize
    }; // sometimes past B
    let mut events = Vec::with_capacity(n);
    for _ in 0..n {
        let site = SITES[rng.below(3) as usize];
        events.push(match rng.below(6) {
            0 => Event::Enter {
                site,
                op: pick(rng),
            },
            1 => {
                let outcome = [
                    Outcome::Ok,
                    Outcome::Ok,
                    Outcome::Missing,
                    Outcome::Refused(rng.below(9) as u16),
                    Outcome::Timeout,
                    Outcome::Withdrawn,
                ][rng.below(6) as usize];
                Event::Exit {
                    site,
                    op: pick(rng),
                    outcome,
                }
            }
            2 => Event::Edge {
                site,
                dir: if rng.below(2) == 0 {
                    Dir::Request
                } else {
                    Dir::Response
                },
                id: Label::of_op(pick(rng)).expect("a label"),
            },
            3 => {
                // A data domain's count under its label: a schema index, unlisted, or (a defect upstream) PAST the bound.
                let d = match rng.below(10) {
                    0 => DOMAIN_UNLISTED,
                    1 => DOMAIN_UNLISTED + 1 + rng.below(1_000) as u32,
                    _ => rng.below(DOMAIN_SCHEMA_MAX as u64) as u32,
                };
                let key = DOMAIN_KEYS[rng.below(5) as usize];
                Event::Counter {
                    site,
                    op: Label::new(Kind::Domain, d).expect("in range").op(),
                    entry: Entry {
                        key,
                        value: rng.below(2_000_000),
                    },
                }
            }
            _ => {
                // Any key at all, Local ones included, with exact values; offsets mostly in the window, some not.
                let key = ALL[rng.below(ALL.len() as u64) as usize];
                let value = match key {
                    Key::OffsetMs => match rng.below(5) {
                        0 => start_ms.saturating_sub(1 + rng.below(100_000)),
                        1 => start_ms + WINDOW_MS + rng.below(100_000),
                        _ => start_ms + rng.below(WINDOW_MS),
                    },
                    Key::StatusClass => rng.below(8),
                    _ => rng.below(100_000),
                };
                Event::Counter {
                    site,
                    op: if rng.below(5) == 0 {
                        OpId::NONE
                    } else {
                        pick(rng)
                    },
                    entry: Entry { key, value },
                }
            }
        });
    }
    events
}

fn cases() -> impl Iterator<Item = (Ring, Window, Published)> {
    let mut rng = Rng(0x0B5E_7A71_5EED_0399);
    (0..400).map(move |i| {
        let total = rng.below(4) * rng.below(400);
        let w = window(&mut rng, total);
        let r = Ring {
            events: ring(&mut rng, w.start_ms),
            dropped: total,
        };
        let header = (i % 7 == 0).then_some(Header {
            sdk_sha: [i as u8; 32],
            app_version: 3,
        });
        let p = publish(&r, w, header);
        (r, w, p)
    })
}

/// THE ORACLE of what leaves, written apart from the filter: an operation leaves if its LAST exit in the window is
/// not Ok (or it has none: a stall); its non-Ok exits, its published counters and (a stall) one Unanswered event leave.
fn expected_events(r: &Ring, w: Window) -> usize {
    let is_op =
        |op: OpId| op != OpId::NONE && Label::of_op(op).is_some_and(|l| l.kind() != Kind::Domain);
    let mut last: std::collections::BTreeMap<u32, Option<Outcome>> = Default::default();
    for e in &r.events {
        let (op, exit) = match *e {
            Event::Enter { op, .. } | Event::Counter { op, .. } => (op, None),
            Event::Exit { op, outcome, .. } => (op, Some(outcome)),
            Event::Edge { .. } => continue,
        };
        if !is_op(op) {
            continue;
        }
        let slot = last.entry(op.raw()).or_insert(None);
        if exit.is_some() {
            *slot = exit;
        }
    }
    let leaves = |op: OpId| {
        last.get(&op.raw())
            .is_some_and(|x| !matches!(x, Some(Outcome::Ok)))
    };
    let mut n = 0;
    for e in &r.events {
        match *e {
            Event::Exit { op, outcome, .. } if outcome != Outcome::Ok && leaves(op) => n += 1,
            Event::Counter { op, entry, .. }
                if is_op(op)
                    && leaves(op)
                    && PUBLISHED.contains(&entry.key)
                    && !DOMAIN_KEYS.contains(&entry.key) =>
            {
                n += match entry.key {
                    Key::StatusClass => usize::from(entry.value < 6),
                    Key::OffsetMs => usize::from(
                        entry.value >= w.start_ms && entry.value - w.start_ms < WINDOW_MS,
                    ),
                    _ => 1,
                }
            }
            _ => {}
        }
    }
    n + last.values().filter(|x| x.is_none()).count()
}

#[test]
fn the_leak_table_publishes_only_the_first_cut_and_every_published_key_states_its_leak() {
    for k in ALL {
        match vocab::publish(*k) {
            Publish::Local => assert!(
                !PUBLISHED.contains(k),
                "{k:?} is in the first cut but the table keeps it Local"
            ),
            Publish::Published { grain, leak } => {
                assert!(
                    PUBLISHED.contains(k),
                    "{k:?} is PUBLISHED but is not in the reviewed first cut"
                );
                assert!(
                    leak.len() > 20,
                    "{k:?} is published with no real leak statement: {leak:?}"
                );
                if DOMAIN_KEYS[..3].contains(k) || *k == Key::Attempts {
                    assert_eq!(
                        grain,
                        Grain::Bucket,
                        "{k:?} counts activity and must leave bucketed"
                    );
                }
                if DOMAIN_KEYS[3..].contains(k) {
                    assert_eq!(
                        grain,
                        Grain::SizeClass,
                        "{k:?} is a volume and must leave as a padded class"
                    );
                }
            }
        }
    }
    assert!(
        HEADER_LEAK.len() > 20 && OUTCOME_LEAK.len() > 20 && UNANSWERED_LEAK.len() > 20,
        "a non-key field is published without its leak line"
    );
    const _: () = assert!(
        PUBLISHED_OFFSET_GRAIN_MS >= 1_000,
        "the published offset grain is finer than a second"
    );
}

/// P1: a record holds ONLY published keys (by the pinned first cut, not by the table under test), and domain counts
/// never ride as plain counters.
#[test]
fn p1_only_published_keys_leave() {
    for (_, _, p) in cases() {
        for e in &p.events {
            if let PubEvent::Counter { key, .. } = e {
                assert!(
                    PUBLISHED.contains(key),
                    "a LOCAL key left the device: {key:?}"
                );
                assert!(
                    !DOMAIN_KEYS.contains(key),
                    "a domain count rode as a plain counter: {key:?}"
                );
            }
        }
    }
}

/// P2: every value is at its grain: attempts a BUCKET code, a status an enum code, an offset whole SECONDS inside the
/// WINDOW's minute (0..59: never below the minute, never from the recording's start).
#[test]
fn p2_every_value_is_at_the_published_grain() {
    for (_, _, p) in cases() {
        for e in &p.events {
            if let PubEvent::Counter { key, value, .. } = *e {
                match key {
                    Key::Attempts => assert!(value <= Bucket::Over999 as u64, "attempts left EXACT: {value}"),
                    Key::StatusClass => assert!(value < 6, "a status left that is no StatusClass code: {value}"),
                    Key::OffsetMs => assert!(value < 60, "an offset left outside the window's minute, finer than seconds, or from the recording's start: {value}"),
                    _ => {}
                }
            }
        }
    }
}

/// P3: the domain counts are the EXACT sums of the ring's domain counters, coarsened -- and an ordinal past the schema
/// bound FOLDS into `unlisted`, never truncated into another domain (an oracle recomputes them from the input).
#[test]
fn p3_domain_counts_are_the_coarsened_sums_and_nothing_else() {
    for (r, _, p) in cases() {
        let mut want: std::collections::BTreeMap<u32, [u64; 5]> = Default::default();
        for e in &r.events {
            if let Event::Counter { op, entry, .. } = e {
                // A domain count counts only under its domain's label; one under any other operation is dropped.
                let Some(l) = Label::of_op(*op).filter(|l| l.kind() == Kind::Domain) else {
                    continue;
                };
                if let Some(slot) = DOMAIN_KEYS.iter().position(|k| *k == entry.key) {
                    want.entry(l.ordinal().min(DOMAIN_UNLISTED)).or_default()[slot] += entry.value;
                }
            }
        }
        let got: Vec<u32> = p.domains.iter().map(|d| d.domain).collect();
        assert_eq!(
            got,
            want.keys().copied().collect::<Vec<_>>(),
            "the domains differ from the ring's"
        );
        for d in &p.domains {
            let w = want[&d.domain];
            assert_eq!(
                (d.reads, d.writes, d.fails),
                (Bucket::of(w[0]), Bucket::of(w[1]), Bucket::of(w[2])),
                "domain {}'s counts",
                d.domain
            );
            assert_eq!(
                (d.bytes_read, d.bytes_written),
                (SizeClass::of(w[3] as usize), SizeClass::of(w[4] as usize)),
                "domain {}'s bytes",
                d.domain
            );
            assert!(
                d.domain <= DOMAIN_UNLISTED,
                "a domain ordinal past the schema bound: {}",
                d.domain
            );
        }
        let back = Published::decode(&p.encode(), &SITES).expect("reads back");
        assert_eq!(
            back.domains, p.domains,
            "a domain ordinal did not survive the encoding"
        );
    }
}

/// P4 (the architect's leak fix): OPERATIONS ARE RENUMBERED per record. No ordinal in a record is ≥ that record's
/// distinct-operation count, so no ordinal can be the page's operation count since load.
#[test]
fn p4_no_ordinal_counts_the_pages_operations() {
    for (_, _, p) in cases() {
        let ops: std::collections::BTreeSet<(u8, u32)> = p
            .events
            .iter()
            .filter_map(|e| match *e {
                PubEvent::Exit { op, .. } | PubEvent::Unanswered { op, .. } => Some(op),
                PubEvent::Counter { op, .. } => op,
            })
            .map(|o| (o.kind, o.ordinal))
            .collect();
        let distinct = ops.len() as u32;
        for (_, ordinal) in &ops {
            assert!(*ordinal < distinct, "ordinal {ordinal} in a record of {distinct} distinct operations: a ring ordinal left");
        }
    }
}

/// P5: every record is at most B bytes and holds exactly what the oracle says leaves, less what was cut to fit, and
/// `dropped` is THIS window's publishable loss -- the ring's drops since the window began plus the events cut.
#[test]
fn p5_bounded_and_the_loss_counted() {
    let mut cut_some = false;
    for (r, w, p) in cases() {
        let bytes = p.encode();
        assert!(
            bytes.len() <= MAX_RECORD_BYTES,
            "a record of {} bytes, past B",
            bytes.len()
        );
        let want = expected_events(&r, w);
        assert!(
            p.events.len() <= want,
            "{} events left where the rule lets {want}: an operation that must stay local left",
            p.events.len()
        );
        let cut = (want - p.events.len()) as u64;
        cut_some |= cut > 0;
        assert!(
            cut == 0 || bytes.len() > MAX_RECORD_BYTES - 64,
            "{cut} events missing from a record well under B ({} bytes)",
            bytes.len()
        );
        assert_eq!(
            p.dropped,
            Bucket::of(r.dropped - w.dropped_at_start + cut),
            "dropped is not this window's drops plus the events cut"
        );
    }
    assert!(
        cut_some,
        "THE SETUP: no generated ring reached B -- the bound is untested"
    );
}

/// P6: the encoding is canonical and reads back whole (support's view).
#[test]
fn p6_round_trip() {
    for (_, _, p) in cases() {
        let back = Published::decode(&p.encode(), &SITES).expect("a record reads back");
        assert_eq!(back, p);
    }
    assert_eq!(UNKNOWN_SITE.name(), "instrument::publish::unknown-site");
}

/// P7 (the architect on instrument#18): an Ok operation's events stay LOCAL -- no Ok exit ever leaves (its count would
/// be the page's exact activity, and OUTCOME_LEAK would be false); and a stall is said. The count side is P5's oracle.
#[test]
fn p7_no_ok_operation_leaves_and_a_stall_is_said() {
    let mut stalls = 0;
    for (_, _, p) in cases() {
        for e in &p.events {
            match e {
                PubEvent::Exit { outcome, .. } => {
                    assert_ne!(*outcome, Outcome::Ok, "an Ok exit left the device")
                }
                PubEvent::Unanswered { .. } => stalls += 1,
                _ => {}
            }
        }
    }
    assert!(
        stalls > 0,
        "THE SETUP: no generated ring had an unanswered operation"
    );
}

/// P8: `dropped` is PER WINDOW: a ring whose running drop count is large but lost nothing in THIS window publishes Zero.
#[test]
fn p8_dropped_is_this_windows_not_the_rings_total() {
    let ring = Ring {
        events: Vec::new(),
        dropped: 5_000,
    };
    let w = Window {
        minute: 1,
        start_ms: 0,
        dropped_at_start: 5_000,
    };
    assert_eq!(
        publish(&ring, w, None).dropped,
        Bucket::Zero,
        "the ring's total since load was published as this window's loss"
    );
}
