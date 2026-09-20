//! The same tests, against both recorders.
//!
//! Two recorders mean two chances for "what is outstanding" to drift, and the
//! drift would only show as a dump that was wrong — which is the failure this
//! crate exists to prevent, arriving through its own back door. So every
//! property below is written ONCE, generic over which recorder builds it, and
//! instantiated twice.

use instrument::{
    dump::render,
    label::{Kind, Labels},
    vocab::{Dir, Key, Outcome, Site},
    Entry, Event, OpId, Probe, Record, Recorder, Span, SyncRecorder,
};

const SITE: Site = Site::of("test::both");

/// What a test needs of a recorder: build one, write to it, read it back.
trait Build: Probe + Sized {
    fn build(capacity: usize) -> Self;
    fn read(&self) -> impl Record + '_;
    const WHICH: &'static str;
}

impl Build for Recorder {
    fn build(capacity: usize) -> Self {
        Recorder::with_capacity(capacity)
    }
    fn read(&self) -> impl Record + '_ {
        self.recording()
    }
    const WHICH: &'static str = "Recorder";
}

impl Build for SyncRecorder {
    fn build(capacity: usize) -> Self {
        SyncRecorder::with_capacity(capacity)
    }
    fn read(&self) -> impl Record + '_ {
        self.recording()
    }
    const WHICH: &'static str = "SyncRecorder";
}

/// Each property, once.
macro_rules! for_both {
    ($($name:ident),+ $(,)?) => {
        $(
            mod $name {
                #[test]
                fn cell() {
                    super::$name::<instrument::Recorder>();
                }
                #[test]
                fn sync() {
                    super::$name::<instrument::SyncRecorder>();
                }
            }
        )+
    };
}

for_both!(
    outstanding_is_a_subtraction,
    a_full_ring_drops_and_counts_and_never_grows,
    a_span_exits_even_when_dropped,
    an_unfinished_span_is_named,
);

fn outstanding_is_a_subtraction<R: Build>() {
    let rec = R::build(256);
    let mut labels: Labels<u32> = Labels::new();
    for i in 0..10 {
        let l = labels.label(Kind::Request, &i);
        rec.event(Event::Edge {
            site: SITE,
            dir: Dir::Request,
            id: l,
        });
    }
    for i in 0..3 {
        let l = labels.label(Kind::Request, &i);
        rec.event(Event::Edge {
            site: SITE,
            dir: Dir::Response,
            id: l,
        });
    }
    let r = rec.read();
    assert_eq!(r.outstanding().len(), 7, "{}", R::WHICH);
    let text = render(&r, "wedge", 5);
    assert!(text.contains("OUTSTANDING 7"), "{} {text}", R::WHICH);

    // The control: answered requests leave nothing outstanding, so the number
    // above is the unanswered ones and not a count of requests.
    let quiet = R::build(256);
    let mut l2: Labels<u32> = Labels::new();
    for i in 0..10 {
        let l = l2.label(Kind::Request, &i);
        quiet.event(Event::Edge {
            site: SITE,
            dir: Dir::Request,
            id: l,
        });
        quiet.event(Event::Edge {
            site: SITE,
            dir: Dir::Response,
            id: l,
        });
    }
    assert_eq!(quiet.read().outstanding().len(), 0, "{}", R::WHICH);
}

fn a_full_ring_drops_and_counts_and_never_grows<R: Build>() {
    let rec = R::build(8);
    for i in 0..100u64 {
        rec.event(Event::Counter {
            site: SITE,
            op: instrument::OpId::NONE,
            entry: Entry {
                key: Key::Sent,
                value: i,
            },
        });
    }
    let r = rec.read();
    assert_eq!(r.events().len(), 8, "{} never grew", R::WHICH);
    assert_eq!(r.offered(), 100, "{}", R::WHICH);
    assert_eq!(r.dropped(), 92, "{} counts every drop", R::WHICH);
    let vals: Vec<u64> = r
        .events()
        .iter()
        .filter_map(|e| match e {
            Event::Counter { entry, .. } => Some(entry.value),
            _ => None,
        })
        .collect();
    assert_eq!(
        vals,
        vec![92, 93, 94, 95, 96, 97, 98, 99],
        "{} keeps the LAST n",
        R::WHICH
    );
    assert!(
        render(&r, "overflow", 3).contains("the beginning of this recording is gone"),
        "{}",
        R::WHICH
    );
}

fn a_span_exits_even_when_dropped<R: Build>() {
    let rec = R::build(64);
    {
        let s = Span::enter(&rec, SITE, OpId(9));
        s.finish(Outcome::Missing);
    }
    {
        let _s = Span::enter(&rec, SITE, OpId(10));
    }
    let r = rec.read();
    assert!(r.unfinished().is_empty(), "{}", R::WHICH);
    assert_eq!(r.outcomes().len(), 2, "{} saw both outcomes", R::WHICH);
}

fn an_unfinished_span_is_named<R: Build>() {
    let rec = R::build(64);
    rec.event(Event::Enter {
        site: SITE,
        op: OpId(42),
    });
    let text = render(&rec.read(), "wedge", 5);
    assert!(text.contains("unfinished spans 1"), "{} {text}", R::WHICH);
    assert!(text.contains("test::both#42"), "{} {text}", R::WHICH);
}

// ---- and the one property only the Sync recorder can have ----------------

/// Many threads, one recorder, nothing lost and nothing counted twice.
///
/// `offered` is the sequence the spine promises, so it must equal exactly the
/// number of events handed in however many threads handed them in.
#[test]
fn the_sync_recorder_takes_events_from_many_threads() {
    use std::sync::Arc;
    const THREADS: u64 = 8;
    const EACH: u64 = 2_000;

    let rec = Arc::new(SyncRecorder::with_capacity(64));
    let mut hs = Vec::new();
    for t in 0..THREADS {
        let rec = Arc::clone(&rec);
        hs.push(std::thread::spawn(move || {
            for i in 0..EACH {
                rec.event(Event::Counter {
                    site: SITE,
                    op: instrument::OpId::NONE,
                    entry: Entry {
                        key: Key::Sent,
                        value: t * EACH + i,
                    },
                });
            }
        }));
    }
    for h in hs {
        h.join().expect("no thread panicked");
    }
    let r = rec.recording();
    assert_eq!(r.offered(), THREADS * EACH, "every event was counted once");
    assert_eq!(r.events().len(), 64, "the ring still never grew");
    assert_eq!(
        r.offered() - r.dropped(),
        64,
        "kept + dropped accounts for every event offered"
    );
}

/// A probe must never panic. Once a thread has panicked holding the lock, a
/// `lock().unwrap()` recorder would panic for every caller forever — turning
/// one failing test into a whole suite of them.
#[test]
fn a_poisoned_lock_does_not_take_the_next_caller_down() {
    use std::sync::Arc;
    let rec = Arc::new(SyncRecorder::with_capacity(16));
    let r2 = Arc::clone(&rec);
    let died = std::thread::spawn(move || {
        r2.event(Event::Enter {
            site: SITE,
            op: OpId(1),
        });
        panic!("this thread fails while the recorder is in use");
    })
    .join();
    assert!(died.is_err(), "the thread really did panic");

    // The recorder still works, and still has what it recorded.
    rec.event(Event::Exit {
        site: SITE,
        op: OpId(1),
        outcome: Outcome::Blocked,
    });
    let r = rec.recording();
    assert_eq!(r.offered(), 2, "both events are there");
    assert!(r.unfinished().is_empty(), "and the span is closed");
}
