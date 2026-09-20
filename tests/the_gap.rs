//! The GAP report, against the run that cost a night.

use instrument::{
    gap::{Expected, Gap},
    vocab::{Key, Site},
    Entry, Event, OpId, Probe, Recorder,
};

const S: Site = Site::of("test::gap");

fn moved(out: u64, inb: u64, ops: u64) -> Recorder {
    let rec = Recorder::with_capacity(64);
    for (key, value) in [(Key::BytesOut, out), (Key::BytesIn, inb), (Key::Ops, ops)] {
        rec.event(Event::Counter {
            site: S,
            op: OpId::NONE,
            entry: Entry { key, value },
        });
    }
    rec
}

/// F46, as it would have read on the FIRST run.
///
/// A 1 KiB block was measured costing 240–395 KB to fetch. Establishing that
/// took six rejected instruments and a night, because nothing said what it
/// should have cost: every candidate number looked plausible alone, so each had
/// to be argued down separately.
///
/// Against a derived expectation it is one line.
#[test]
fn f46_reads_as_a_ratio_rather_than_as_a_plausible_number() {
    // One 1 KiB block. The expectation is a property of the DATA — the block's
    // own size — not a previous measurement.
    let expected = Expected {
        bytes: 1_025,
        blocks: 1,
    };
    // The middle of the measured range, in one direction.
    let rec = moved(0, 341_024, 1);
    let gap = Gap::of(&rec.recording(), expected);

    let ratio = gap.ratio().expect("a ratio, since something was expected");
    assert!(
        (330.0..=340.0).contains(&ratio),
        "F46's middle figure should read as ~333x the payload, got {ratio:.1}x: {}",
        gap.line()
    );
    assert!(
        gap.line().contains("x"),
        "the line carries the ratio, which is the readable part: {}",
        gap.line()
    );
}

/// An operation that cost what it should shows as ~1x, so the report
/// distinguishes "fine" from "34x" without anyone doing arithmetic.
#[test]
fn an_operation_that_cost_what_it_should_reads_as_about_one() {
    let gap = Gap::of(
        &moved(1_025, 0, 1).recording(),
        Expected {
            bytes: 1_025,
            blocks: 1,
        },
    );
    let r = gap.ratio().unwrap();
    assert!((0.9..=1.1).contains(&r), "{}", gap.line());
}

/// A ratio against zero is UNDEFINED, not enormous.
///
/// Reporting it as a huge number is how a measurement about nothing gets
/// quoted as a finding — the same shape as a per-block cost computed from a
/// run where no blocks were asked for.
#[test]
fn nothing_expected_yields_no_ratio_rather_than_a_huge_one() {
    let gap = Gap::of(&moved(500, 500, 2).recording(), Expected::default());
    assert_eq!(gap.ratio(), None);
    assert!(
        gap.line().contains("undefined"),
        "the line says why there is no ratio: {}",
        gap.line()
    );
}

/// The actual side is READ FROM THE RECORDING, not passed in — so it cannot
/// drift from what the run recorded.
#[test]
fn the_actual_side_comes_from_the_recording() {
    let gap = Gap::of(
        &moved(7, 11, 3).recording(),
        Expected {
            bytes: 1,
            blocks: 1,
        },
    );
    assert_eq!(gap.actual.bytes_out, 7);
    assert_eq!(gap.actual.bytes_in, 11);
    assert_eq!(gap.actual.ops, 3);
    assert_eq!(gap.bytes_moved(), 18);
}
