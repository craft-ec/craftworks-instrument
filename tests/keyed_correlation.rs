//! The two failures that bought this, as tests.
//!
//! Both ran with the probe ON and the probe saw neither, because answers were
//! attributed by POSITION or by COUNT when each answer NAMED what it answered.

use instrument::{
    label::{Kind, Label},
    vocab::{Dir, Outcome, Site},
    Answered, Entry, Event, Key, OpId, Probe, Record, Recorder,
};

const S: Site = Site::of("test::transport");

fn l(n: u32) -> Label {
    Label {
        kind: Kind::Request,
        ordinal: n,
    }
}
fn req(rec: &Recorder, n: u32) {
    rec.event(Event::Edge {
        site: S,
        dir: Dir::Request,
        id: l(n),
    });
    rec.event(Event::Enter {
        site: S,
        op: l(n).op(),
    });
}
fn ans(rec: &Recorder, n: u32) {
    rec.event(Event::Edge {
        site: S,
        dir: Dir::Response,
        id: l(n),
    });
}
fn gave_up(rec: &Recorder, n: u32) {
    rec.event(Event::Exit {
        site: S,
        op: l(n).op(),
        outcome: Outcome::Timeout,
    });
}
fn state(rec: &Recorder, n: u32) -> Option<Answered> {
    rec.recording()
        .answers()
        .into_iter()
        .find(|(x, _)| *x == l(n))
        .map(|(_, a)| a)
}

/// harness#38: three puts time out, their acks arrive later, and every put
/// from then on receives the PREVIOUS put's answer. The run reported 0 of 20
/// against a node that had accepted 15.
///
/// With keyed pairing each late answer lands on ITS OWN operation and nothing
/// shifts.
#[test]
fn a_late_answer_lands_on_its_own_operation_and_shifts_nothing() {
    let rec = Recorder::with_capacity(256);
    for n in 0..6 {
        req(&rec, n);
    }
    // The first three are given up on.
    for n in 0..3 {
        gave_up(&rec, n);
    }
    // Now every answer arrives, in order, including the three late ones.
    for n in 0..6 {
        ans(&rec, n);
    }

    for n in 0..3 {
        assert_eq!(
            state(&rec, n),
            Some(Answered::Late),
            "op {n} was given up on and answered afterwards — that is LATE, not Ok"
        );
    }
    for n in 3..6 {
        assert_eq!(
            state(&rec, n),
            Some(Answered::Once),
            "op {n} was never given up on and got its own answer"
        );
    }
    // The defect's signature: an operation reported as ended by an answer that
    // belonged to a different one.
    assert!(
        !rec.recording()
            .answers()
            .iter()
            .any(|(_, a)| *a == Answered::Foreign),
        "no answer was attributed to an operation that did not ask for it"
    );
}

/// harness#39 run 1: a group waits until its ack map holds as many entries as
/// it has members. Group 1's late acks fill group 2's quota, the count reaches
/// n, and group 2's own keys go down as never answered while the line says
/// 15/15.
///
/// The recording must say group 2 is UNANSWERED and group 1 is LATE.
#[test]
fn one_groups_late_acks_cannot_fill_another_groups_quota() {
    let rec = Recorder::with_capacity(256);
    // Group 1: asked, given up on.
    for n in 0..3 {
        req(&rec, n);
    }
    for n in 0..3 {
        gave_up(&rec, n);
    }
    // Group 2: asked, and nothing of its own ever comes back.
    for n in 10..13 {
        req(&rec, n);
    }
    // What actually arrives is group 1's answers.
    for n in 0..3 {
        ans(&rec, n);
    }

    for n in 10..13 {
        assert_eq!(
            state(&rec, n),
            Some(Answered::Never),
            "group 2's key {n} was NOT answered, whatever the count says"
        );
    }
    for n in 0..3 {
        assert_eq!(state(&rec, n), Some(Answered::Late));
    }

    // And the projection a progress line reads is the SAME one the per-key
    // table reads, so they cannot disagree — which is what made the old
    // 99.5%-vs-92.1% split possible.
    let counts = rec.recording().answer_counts();
    let n_of = |a: Answered| {
        counts
            .iter()
            .find(|(x, _)| *x == a)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };
    assert_eq!(n_of(Answered::Never), 3, "{counts:?}");
    assert_eq!(n_of(Answered::Late), 3, "{counts:?}");
    assert_eq!(n_of(Answered::Once), 0, "{counts:?}");
}

/// A duplicate answer, and an answer for something never asked. Each reported,
/// neither closing another operation, neither panicking.
#[test]
fn a_duplicate_and_a_foreign_answer_are_each_reported_as_themselves() {
    let rec = Recorder::with_capacity(256);
    req(&rec, 1);
    ans(&rec, 1);
    ans(&rec, 1); // the same answer twice
    ans(&rec, 99); // never asked for

    assert_eq!(state(&rec, 1), Some(Answered::Twice(2)));
    assert_eq!(state(&rec, 99), Some(Answered::Foreign));
    assert_eq!(
        rec.recording().answers().len(),
        2,
        "one asked operation and one foreign answer, nothing invented"
    );
}

/// An answer that arrives BEFORE its request — a reordered transport. It must
/// not panic and must not be silently folded into something else.
#[test]
fn an_answer_before_its_request_does_not_panic_or_vanish() {
    let rec = Recorder::with_capacity(256);
    ans(&rec, 7);
    req(&rec, 7);
    // Asked once, answered once: the recording reports the pairing, not the
    // order the transport happened to deliver them in.
    assert_eq!(state(&rec, 7), Some(Answered::Once));
}

/// Bytes are attributed to the operation that caused them, and a counter that
/// belongs to no operation is not attributed to one.
#[test]
fn bytes_are_counted_per_operation_at_our_own_boundary() {
    let rec = Recorder::with_capacity(256);
    let count = |op: OpId, key: Key, value: u64| {
        rec.event(Event::Counter {
            site: S,
            op,
            entry: Entry { key, value },
        })
    };
    req(&rec, 1);
    count(l(1).op(), Key::BytesOut, 120_000);
    count(l(1).op(), Key::BytesIn, 1_024);
    req(&rec, 2);
    count(l(2).op(), Key::BytesOut, 98_000);
    // A connection-wide total belongs to no operation.
    count(OpId::NONE, Key::BytesOut, 7);

    assert_eq!(rec.recording().bytes(l(1).op()), (120_000, 1_024));
    assert_eq!(rec.recording().bytes(l(2).op()), (98_000, 0));
    assert_eq!(
        rec.recording().bytes(OpId::NONE),
        (7, 0),
        "an unattributed counter is readable, and is not folded into an operation"
    );
    // The whole-recording total still works and includes both.
    assert_eq!(rec.recording().total(Key::BytesOut), 218_007);
}

/// The labels are minted from real contract keys, and NONE of those keys — nor
/// any run of their bytes — may appear in a dump.
///
/// A correlation label is the one place a foreign id could leak by accident,
/// because it exists precisely to stand for one. The guard is that the id goes
/// into `Labels` and only the ordinal comes out.
#[test]
fn a_dump_made_from_real_contract_keys_contains_none_of_them() {
    use instrument::label::Labels;

    // Base58-ish contract ids, the shape the harness actually labels.
    let keys: Vec<String> = (0..8)
        .map(|i| format!("9nPgCTfiuX3Zycngp3vvgFiY9aqUmvKG64y86t6qgyK{i}"))
        .collect();

    let rec = Recorder::with_capacity(256);
    let mut labels: Labels<String> = Labels::new();
    for k in &keys {
        let id = labels.label(Kind::Contract, k);
        rec.event(Event::Edge {
            site: S,
            dir: Dir::Request,
            id,
        });
        rec.event(Event::Counter {
            site: S,
            op: id.op(),
            entry: Entry {
                key: Key::BytesOut,
                value: 101_641,
            },
        });
    }
    let dump = instrument::dump::render(&rec.recording(), "keys", 64);

    for k in &keys {
        assert!(
            !dump.contains(k.as_str()),
            "the dump contains a contract key verbatim"
        );
        // Not just the whole key: any run long enough to identify it.
        for w in 8..=k.len() {
            let mut start = 0;
            while start + w <= k.len() {
                let frag = &k[start..start + w];
                assert!(
                    !dump.contains(frag),
                    "the dump contains a {w}-byte run of a contract key: {frag}"
                );
                start += 1;
            }
        }
    }
    // And the labels ARE there, which is the point — the dump is still useful.
    assert!(dump.contains("contract#0"), "{dump}");
}

/// What labelling costs, measured — like any branch on a hot path.
///
/// Reported rather than asserted as a threshold, except for the one comparison
/// that IS the requirement: it must stay far below the grid the latency tables
/// resolve to, or it could move a median.
#[test]
fn labelled_edges_cannot_move_a_latency_median() {
    use std::time::Instant;
    const OPS: usize = 100_000;

    let rec = Recorder::with_capacity(1 << 16);
    let t = Instant::now();
    for i in 0..OPS {
        let id = l((i % 512) as u32);
        rec.event(Event::Edge {
            site: S,
            dir: Dir::Request,
            id,
        });
        rec.event(Event::Edge {
            site: S,
            dir: Dir::Response,
            id,
        });
    }
    let labelled = t.elapsed().as_secs_f64() / OPS as f64;

    let plain = Recorder::with_capacity(1 << 16);
    let t = Instant::now();
    for _ in 0..OPS {
        plain.event(Event::Counter {
            site: S,
            op: OpId::NONE,
            entry: Entry {
                key: Key::Sent,
                value: 1,
            },
        });
        plain.event(Event::Counter {
            site: S,
            op: OpId::NONE,
            entry: Entry {
                key: Key::Received,
                value: 1,
            },
        });
    }
    let unlabelled = t.elapsed().as_secs_f64() / OPS as f64;

    let over_a_run = labelled * 10_000.0 * 1e3;
    println!(
        "labelled edge pair {:.0} ns, unlabelled counter pair {:.0} ns; \
         {over_a_run:.2} ms over a 10,000-operation run, against a 250 ms grid",
        labelled * 1e9,
        unlabelled * 1e9
    );
    assert!(
        over_a_run < 250.0,
        "labelling adds {over_a_run:.1} ms over a long run, which is not inside one grid step"
    );
}

/// A WITHDRAWN operation (superseded, cancelled, stood in for) is CLOSED like a timed-out one: an answer that
/// arrives after it is LATE, not a success, and it closes nothing else (craftworks-sdk#407: a send superseded by
/// a later send of the same operation). Mutant "Withdrawn is not a close" -> this reads `Once`.
#[test]
fn an_answer_after_a_withdrawal_is_late() {
    let rec = Recorder::with_capacity(16);
    rec.event(Event::Edge {
        site: S,
        dir: Dir::Request,
        id: l(1),
    });
    rec.event(Event::Exit {
        site: S,
        op: l(1).op(),
        outcome: Outcome::Withdrawn,
    });
    ans(&rec, 1);
    assert_eq!(state(&rec, 1), Some(Answered::Late));
}
