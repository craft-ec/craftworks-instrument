//! THE ONE PUBLISH FILTER, property-tested (craftworks-docs OBSERVABILITY §2.4; craftworks-sdk#399). For generated
//! rings and windows, a record holds only publishable keys, only values at the published grain, no ordinal that could
//! count the page's operations, and at most B bytes; each property has a mutant that goes red (the PR body lists them).
//! The generator is a seeded xorshift in-crate: this crate has NO dependencies, and that is load-bearing (Cargo.toml).

use instrument::label::{DOMAIN_SCHEMA_MAX, DOMAIN_UNLISTED};
use instrument::publish::{
    publish, Header, PubEvent, Published, Window, MAX_RECORD_BYTES, UNKNOWN_SITE,
};
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

/// A window starting an HOUR or more into the recording, so an offset measured from the recording's start (not the
/// window's) is at least 3600 s and can't pass for one measured from the window.
fn window(rng: &mut Rng) -> Window {
    Window {
        minute: 29_000_000 + rng.below(1_000),
        start_ms: 3_600_000 + rng.below(10_000_000),
    }
}

/// Ring ordinals are LARGE (a page long past its first thousand ops): a record that kept them would publish them.
fn op(rng: &mut Rng) -> OpId {
    let kind = [Kind::Request, Kind::Block, Kind::Fetch, Kind::Span][rng.below(4) as usize];
    Label::new(kind, 1_000 + rng.below(1_000_000) as u32)
        .expect("in range")
        .op()
}

fn ring(rng: &mut Rng, w: Window) -> Ring {
    let big = rng.below(10) == 0;
    let n = rng.below(if big { 4_000 } else { 200 }) as usize; // sometimes past B
    let mut events = Vec::with_capacity(n);
    for _ in 0..n {
        let site = SITES[rng.below(3) as usize];
        events.push(match rng.below(6) {
            0 => Event::Enter { site, op: op(rng) },
            1 => Event::Exit {
                site,
                op: op(rng),
                outcome: [
                    Outcome::Ok,
                    Outcome::Missing,
                    Outcome::Refused(rng.below(9) as u16),
                    Outcome::Timeout,
                    Outcome::Withdrawn,
                ][rng.below(5) as usize],
            },
            2 => Event::Edge {
                site,
                dir: if rng.below(2) == 0 {
                    Dir::Request
                } else {
                    Dir::Response
                },
                id: Label::of_op(op(rng)).expect("a label"),
            },
            3 => {
                // A data domain's count: its label's operation, a schema index or unlisted.
                let d = if rng.below(8) == 0 {
                    DOMAIN_UNLISTED
                } else {
                    rng.below(DOMAIN_SCHEMA_MAX as u64) as u32
                };
                let key = DOMAIN_KEYS[rng.below(5) as usize];
                Event::Counter {
                    site,
                    op: Label::domain(d).expect("bounded").op(),
                    entry: Entry {
                        key,
                        value: rng.below(2_000_000),
                    },
                }
            }
            _ => {
                // Any key at all, Local ones included, with exact values: offsets within the window's minute.
                let key = ALL[rng.below(ALL.len() as u64) as usize];
                let value = match key {
                    Key::OffsetMs => w.start_ms + rng.below(60_000),
                    Key::StatusClass => rng.below(8),
                    _ => rng.below(100_000),
                };
                Event::Counter {
                    site,
                    op: if rng.below(4) == 0 {
                        OpId::NONE
                    } else {
                        op(rng)
                    },
                    entry: Entry { key, value },
                }
            }
        });
    }
    Ring {
        events,
        dropped: rng.below(3) * rng.below(50),
    }
}

fn cases() -> impl Iterator<Item = (Ring, Window, Published)> {
    let mut rng = Rng(0x0B5E_7A71_5EED_0399);
    (0..400).map(move |i| {
        let w = window(&mut rng);
        let r = ring(&mut rng, w);
        let header = (i % 7 == 0).then_some(Header {
            sdk_sha: [i as u8; 32],
            app_version: 3,
        });
        let p = publish(&r, w, header);
        (r, w, p)
    })
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
        HEADER_LEAK.len() > 20 && OUTCOME_LEAK.len() > 20,
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

/// P2: every value is at its grain: attempts a BUCKET code, a status an enum code, an offset whole SECONDS from the
/// WINDOW's start (the generated offsets fall in the window's minute, and windows start ≥ 1 h into the recording).
#[test]
fn p2_every_value_is_at_the_published_grain() {
    for (_, _, p) in cases() {
        for e in &p.events {
            if let PubEvent::Counter { key, value, .. } = *e {
                match key {
                    Key::Attempts => assert!(value <= Bucket::Over999 as u64, "attempts left EXACT: {value}"),
                    Key::StatusClass => assert!(value < 6, "a status left that is no StatusClass code: {value}"),
                    Key::OffsetMs => assert!(value < 61, "an offset left finer than seconds, or measured from the recording's start: {value}"),
                    _ => {}
                }
            }
        }
    }
}

/// P3: the domain counts are the EXACT sums of the ring's domain counters, coarsened -- and only coarsened (an oracle
/// recomputes them from the input).
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
                    want.entry(l.ordinal()).or_default()[slot] += entry.value;
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
                PubEvent::Exit { op, .. } => Some(op),
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

/// P5: every record is at most B bytes, events are dropped (last first) before a domain count, the loss is counted,
/// and `dropped` means publishable events lost -- nothing else.
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
        let _ = w;
        // The events the filter would publish with no bound, counted independently of it.
        let publishable = r
            .events
            .iter()
            .filter(|e| match e {
                Event::Exit { op, .. } => Label::of_op(*op).is_some(),
                Event::Counter { entry, .. } => {
                    PUBLISHED.contains(&entry.key)
                        && !DOMAIN_KEYS.contains(&entry.key)
                        && (entry.key != Key::StatusClass || entry.value < 6)
                }
                _ => false,
            })
            .count();
        let cut = (publishable - p.events.len()) as u64;
        cut_some |= cut > 0;
        assert_eq!(
            p.dropped,
            Bucket::of(r.dropped + cut),
            "dropped is not the ring's drops plus the events cut"
        );
        assert!(cut == 0 || !p.domains.is_empty() || !r.events.iter().any(|e| matches!(e, Event::Counter { entry, .. } if DOMAIN_KEYS.contains(&entry.key))), "a domain count was cut to fit B");
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
