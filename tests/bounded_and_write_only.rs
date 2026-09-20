//! The three guarantees that make a probe safe to leave switched on: it cannot
//! be read back, it cannot grow, and it cannot panic.

use instrument::{
    dump::{render, DumpOnPanic},
    label::{Kind, Labels},
    vocab::{Dir, Key, Outcome, Site},
    Entry, Event, NoProbe, OpId, Probe, Recorder, Span,
};

const SITE: Site = Site::of("test::conn");

fn req(rec: &dyn Probe, labels: &mut Labels<u32>, id: u32) {
    let l = labels.label(Kind::Request, &id);
    rec.event(Event::Edge {
        site: SITE,
        dir: Dir::Request,
        id: l,
    });
}

fn resp(rec: &dyn Probe, labels: &mut Labels<u32>, id: u32) {
    let l = labels.label(Kind::Request, &id);
    rec.event(Event::Edge {
        site: SITE,
        dir: Dir::Response,
        id: l,
    });
}

/// The number four voided harness runs could not see.
///
/// A reader had sent thousands of requests for keys no node held — requests
/// nothing would ever answer — and from outside it looked exactly like a
/// reader doing its job. OUTSTANDING is what separates them, and it is a
/// subtraction only because `Edge` pairs the two directions by id.
#[test]
fn outstanding_is_a_subtraction_not_a_guess() {
    let rec = Recorder::with_capacity(256);
    let mut labels = Labels::new();
    for i in 0..10 {
        req(&rec, &mut labels, i);
    }
    for i in 0..3 {
        resp(&rec, &mut labels, i);
    }
    let r = rec.recording();
    assert_eq!(r.outstanding().len(), 7);

    // And a dump leads with it, because a reader who sees that number has the
    // answer before reading a single event.
    let text = render(&r, "wedge", 5);
    assert!(text.contains("OUTSTANDING 7"), "{text}");
    assert!(text.contains("req#3"), "the labels are named: {text}");

    // The control: answered requests leave nothing outstanding, so the number
    // above is the unanswered ones and not simply a count of requests.
    let quiet = Recorder::with_capacity(256);
    let mut l2 = Labels::new();
    for i in 0..10 {
        req(&quiet, &mut l2, i);
        resp(&quiet, &mut l2, i);
    }
    assert_eq!(quiet.recording().outstanding().len(), 0);
}

/// A full ring drops the oldest, counts it, and says so in the dump. It never
/// grows (an unbounded buffer in a long run is a leak) and never panics (a
/// probe that fails a passing test is the worst kind of behaviour change).
#[test]
fn a_full_ring_drops_and_counts_and_never_grows() {
    let rec = Recorder::with_capacity(8);
    for i in 0..100u32 {
        rec.event(Event::Counter {
            site: SITE,
            entry: Entry {
                key: Key::Sent,
                value: i as u64,
            },
        });
    }
    let r = rec.recording();
    assert_eq!(r.events().len(), 8, "the ring never grew");
    assert_eq!(r.offered(), 100);
    assert_eq!(r.dropped(), 92, "and every drop is counted");

    // It kept the LAST eight, which is what a failure dump needs.
    let vals: Vec<u64> = r
        .events()
        .iter()
        .filter_map(|e| match e {
            Event::Counter { entry, .. } => Some(entry.value),
            _ => None,
        })
        .collect();
    assert_eq!(vals, vec![92, 93, 94, 95, 96, 97, 98, 99]);

    // And it warns, because a tail that silently begins mid-story is a dump
    // that misleads.
    let text = render(&r, "overflow", 3);
    assert!(text.contains("DROPPED 92"), "{text}");
    assert!(
        text.contains("the beginning of this recording is gone"),
        "{text}"
    );
}

/// A span's `Exit` is emitted by the drop, so an early return cannot lose it —
/// which is exactly when a reader needs it.
#[test]
fn a_span_exits_even_when_the_code_returns_early() {
    let rec = Recorder::with_capacity(64);
    fn early(p: &Recorder) -> Option<u32> {
        let span = Span::enter(p, SITE, OpId(9));
        span.finish(Outcome::Missing);
        None
    }
    assert_eq!(early(&rec), None);
    let r = rec.recording();
    assert!(r.unfinished().is_empty(), "the exit was emitted");
    assert_eq!(r.outcomes(), vec![(Outcome::Missing, 1)]);

    // A span that is simply dropped still exits, as Ok.
    {
        let _s = Span::enter(&rec, SITE, OpId(10));
    }
    assert!(rec.recording().unfinished().is_empty());
}

/// A span that never ends is what a wedge looks like, and the dump names it.
#[test]
fn a_span_that_never_exits_is_reported_by_site_and_op() {
    let rec = Recorder::with_capacity(64);
    rec.event(Event::Enter {
        site: SITE,
        op: OpId(42),
    });
    let text = render(&rec.recording(), "wedge", 5);
    assert!(text.contains("unfinished spans 1"), "{text}");
    assert!(text.contains("test::conn#42"), "{text}");
}

/// The no-op probe is a real probe, so "recording off" is a PARAMETER and not
/// a rebuild — and it is what the output differential compares against.
#[test]
fn the_no_op_probe_records_nothing_and_costs_a_call() {
    let p = NoProbe;
    for i in 0..1000 {
        p.event(Event::Counter {
            site: SITE,
            entry: Entry {
                key: Key::Sent,
                value: i,
            },
        });
    }
    // Nothing to assert about its contents: it HAS no contents, which is the
    // guarantee. That it compiles as a `Probe` is the test.
    fn takes_a_probe(_p: &dyn Probe) {}
    takes_a_probe(&p);
    takes_a_probe(&Recorder::with_capacity(1));
}

/// The dump renders without a panic, so the test that prints it cannot itself
/// be the thing that fails.
#[test]
fn the_dump_renders_on_an_empty_recording() {
    let rec = Recorder::with_capacity(4);
    let g = DumpOnPanic::new(&rec, "empty").last(10);
    let text = g.render();
    assert!(text.contains("OUTSTANDING 0"), "{text}");
    assert!(text.contains("offered 0"), "{text}");
}
