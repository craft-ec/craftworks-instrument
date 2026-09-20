//! What is left here after the shared properties moved to `both_recorders.rs`:
//! the no-op probe, and the dump's behaviour on an empty recording.
//!
//! Anything true of BOTH recorders belongs in `both_recorders.rs`, where it is
//! written once and instantiated twice — a property tested against only one of
//! them is a property the other can quietly lose.

use instrument::{
    dump::DumpOnPanic, vocab::Key, vocab::Site, Entry, Event, NoProbe, Probe, Recorder,
};

const SITE: Site = Site::of("test::conn");

/// The no-op probe is a real probe, so "recording off" is a PARAMETER and not
/// a rebuild — and it is what the output differential compares against.
#[test]
fn the_no_op_probe_records_nothing_and_costs_a_call() {
    let p = NoProbe;
    for i in 0..1000 {
        p.event(Event::Counter {
            site: SITE,
            op: instrument::OpId::NONE,
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
