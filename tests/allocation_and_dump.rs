//! The dump appears when a test fails, and labelling stays bounded.

use instrument::{
    dump::DumpOnPanic,
    label::{Kind, Labels},
    vocab::{Dir, Site},
    Event, OpId, Probe, Recorder,
};

const SITE: Site = Site::of("test::alloc");

/// Labelling DOES allocate, once per newly seen id, and that is why it is
/// bounded and lives outside the event path.
#[test]
fn labelling_is_bounded_and_is_not_on_the_event_path() {
    let mut labels: Labels<u32> = Labels::new();
    for i in 0..Labels::<u32>::CAP + 10 {
        labels.label(Kind::Request, &i);
    }
    assert_eq!(
        labels.len(),
        Labels::<u32>::CAP as usize,
        "the table stops growing"
    );
}

/// The dump must appear when a test fails — that is its whole reason to exist.
///
/// Rendered rather than captured from stderr: a test that scrapes its own
/// stderr is a test about plumbing. The guard's `Drop` prints exactly this
/// text when the thread is panicking, and `the_guard_is_silent_when_nothing_
/// fails` covers the other half.
#[test]
fn a_failure_dump_shows_a_wedge_for_what_it_is() {
    let rec = Recorder::with_capacity(64);
    let mut labels: Labels<u32> = Labels::new();
    // A wedge: many requests, one answer, a span that never ends.
    rec.event(Event::Enter {
        site: SITE,
        op: OpId(1),
    });
    for i in 0..12 {
        let l = labels.label(Kind::Request, &i);
        rec.event(Event::Edge {
            site: SITE,
            dir: Dir::Request,
            id: l,
        });
    }
    let first = labels.label(Kind::Request, &0);
    rec.event(Event::Edge {
        site: SITE,
        dir: Dir::Response,
        id: first,
    });

    let text = DumpOnPanic::new(&rec, "a wedge").last(6).render();
    assert!(text.contains("OUTSTANDING 11"), "{text}");
    assert!(text.contains("unfinished spans 1"), "{text}");
    assert!(text.contains("test::alloc#1"), "{text}");
    assert!(text.contains("req#1"), "{text}");
    // A human reading this can tell a wedge from work, which is the one
    // requirement the vocabulary was designed against.
    assert!(text.contains("requests with no response"), "{text}");
}

#[test]
fn the_guard_is_silent_when_nothing_fails() {
    // Nothing is asserted about stderr: the guard only prints while the thread
    // is panicking, and this thread is not. If that were wrong, every passing
    // test in the workspace would be printing a dump.
    let rec = Recorder::with_capacity(4);
    let _g = DumpOnPanic::new(&rec, "quiet");
}

/// A recording whose pairing went wrong must SAY so in its dump.
///
/// `Owed` and `Ambiguous` exist for one failure: a bounded wait expired, the
/// node still owed that answer, it arrived later, and a transport pairing by
/// position handed it to a different operation — which printed a healthy line
/// over a stream that was shifted by one (freenet-harness#38).
///
/// The control is the point. A dump that prints these keys whether or not they
/// were recorded would pass this test while saying nothing, so a clean
/// recording is rendered too and must NOT mention either word.
#[test]
fn a_dump_says_when_its_pairing_stopped_being_trustworthy() {
    let clean = Recorder::with_capacity(64);
    clean.event(Event::Counter {
        site: SITE,
        entry: instrument::Entry {
            key: instrument::vocab::Key::Sent,
            value: 1,
        },
    });
    let clean = instrument::dump::render(&clean.recording(), "a clean run", 20);
    assert!(
        !clean.contains("Owed") && !clean.contains("Ambiguous"),
        "a recording that never lost its footing must not mention either key:\n{clean}"
    );

    let rec = Recorder::with_capacity(64);
    for (key, value) in [
        (instrument::vocab::Key::Sent, 2),
        (instrument::vocab::Key::Received, 1),
        (instrument::vocab::Key::Owed, 1),
        (instrument::vocab::Key::Ambiguous, 1),
    ] {
        rec.event(Event::Counter {
            site: SITE,
            entry: instrument::Entry { key, value },
        });
    }
    let shifted = instrument::dump::render(&rec.recording(), "a shifted run", 20);
    assert!(
        shifted.contains("Owed: 1"),
        "the dump must report what is still owed:\n{shifted}"
    );
    assert!(
        shifted.contains("Ambiguous: 1"),
        "and that an answer arrived while pairing was untrustworthy:\n{shifted}"
    );
}
