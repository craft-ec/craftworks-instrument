//! The probes SHIP. So the question is not "is the payload small" but "can a
//! site put user bytes into a recording at all".
//!
//! These tests answer it the only way that counts: record over data that IS a
//! secret, render what a support bundle would contain, and look for the secret
//! in it.

use instrument::{
    dump::render,
    label::{Kind, Labels},
    vocab::{Bucket, Dir, Key, Outcome, Site, SizeClass},
    Entry, Event, Probe, Recorder,
};

const SITE: Site = Site::of("test::store");

/// Bytes that must never appear anywhere in a recording.
const SECRET: &[u8] = b"CORRECT-HORSE-BATTERY-STAPLE";
const SECRET_ID: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A store whose values are secret, instrumented exactly as a real one would
/// be: a span, an edge per lookup, counters for reads, misses and SIZE CLASS.
fn record_a_session(rec: &Recorder) {
    let mut labels: Labels<[u8; 32]> = Labels::new();
    let op = instrument::Label::new(instrument::Kind::Span, 1)
        .unwrap()
        .op();
    rec.event(Event::Enter { site: SITE, op });
    for i in 0..3u32 {
        let mut id = SECRET_ID;
        id[31] = i as u8;
        let label = labels.label(Kind::Block, &id);
        rec.event(Event::Edge {
            site: SITE,
            dir: Dir::Request,
            id: label,
        });
        rec.event(Event::Edge {
            site: SITE,
            dir: Dir::Response,
            id: label,
        });
        rec.event(Event::Counter {
            site: SITE,
            op: instrument::OpId::NONE,
            entry: Entry {
                key: Key::Reads,
                value: 1,
            },
        });
        // The SIZE of the secret, as its padded class — never the length.
        rec.event(Event::Counter {
            site: SITE,
            op: instrument::OpId::NONE,
            entry: Entry {
                key: Key::BytesClass,
                value: SizeClass::of(SECRET.len()) as u64,
            },
        });
    }
    // A count derived from user data, bucketed.
    rec.event(Event::Counter {
        site: SITE,
        op: instrument::OpId::NONE,
        entry: Entry {
            key: Key::CountBucket,
            value: Bucket::of(3) as u64,
        },
    });
    rec.event(Event::Exit {
        site: SITE,
        op,
        outcome: Outcome::Ok,
    });
}

#[test]
fn a_recording_of_secret_data_contains_none_of_it() {
    let rec = Recorder::with_capacity(256);
    record_a_session(&rec);
    let text = render(&rec.recording(), "secrets", 200);

    // The value.
    assert!(
        !text.contains(core::str::from_utf8(SECRET).unwrap()),
        "the secret's bytes are in the dump:\n{text}"
    );
    assert!(!text.contains(&hex(SECRET)), "the secret in hex:\n{text}");
    // The id — whole, and any prefix of it. Truncation is not offered, and
    // this is what proves it: even eight hex characters of a block id must not
    // appear, because an id drawn from an enumerable population is not made
    // anonymous by being shortened.
    let id_hex = hex(&SECRET_ID);
    for take in [64, 32, 16, 8] {
        assert!(
            !text.contains(&id_hex[..take]),
            "{take} hex chars of a block id are in the dump:\n{text}"
        );
    }

    // The control: the dump is not empty and does carry the LABELS, so the
    // assertions above are about redaction and not about an empty string.
    assert!(text.contains("block#0"), "labels must be present:\n{text}");
    assert!(text.contains("block#2"), "{text}");
    assert!(
        text.contains("Reads: 3"),
        "counters must be present:\n{text}"
    );
}

#[test]
fn a_size_is_a_class_and_a_count_is_a_bucket() {
    // The exact length of sealed bytes is a property of the plaintext.
    assert_eq!(SizeClass::of(0), SizeClass::Empty);
    assert_eq!(SizeClass::of(1), SizeClass::UpTo1K);
    assert_eq!(SizeClass::of(1024), SizeClass::UpTo1K);
    assert_eq!(SizeClass::of(1025), SizeClass::UpTo4K);
    assert_eq!(SizeClass::of(262_144), SizeClass::UpTo256K);
    assert_eq!(SizeClass::of(262_145), SizeClass::Over256K);
    // Two different secrets of different lengths in the same class are
    // indistinguishable, which is the whole point.
    assert_eq!(SizeClass::of(1100), SizeClass::of(4000));

    assert_eq!(Bucket::of(0), Bucket::Zero);
    assert_eq!(Bucket::of(1), Bucket::One);
    assert_eq!(Bucket::of(9), Bucket::UpTo9);
    assert_eq!(Bucket::of(10), Bucket::UpTo99);
    assert_eq!(Bucket::of(3), Bucket::of(7), "3 and 7 contacts look alike");
}

#[test]
fn a_time_is_a_coarsened_offset_never_a_clock() {
    use instrument::vocab::coarsen_ms;
    assert_eq!(coarsen_ms(0), 0);
    assert_eq!(coarsen_ms(7), 0);
    assert_eq!(coarsen_ms(19), 10);
    assert_eq!(coarsen_ms(1_234), 1_200);
    assert_eq!(coarsen_ms(61_999), 61_000);
    // Two events a few milliseconds apart are not separable, so a recording
    // cannot be used to line up against an outside timeline.
    assert_eq!(coarsen_ms(1_201), coarsen_ms(1_299));
}

#[test]
fn a_label_never_carries_the_id_and_saturates_rather_than_growing() {
    let mut labels: Labels<[u8; 32]> = Labels::new();
    let a = labels.label(Kind::Peer, &[7u8; 32]);
    let again = labels.label(Kind::Peer, &[7u8; 32]);
    assert_eq!(a, again, "the same id gets the same label");
    assert_eq!(a.to_string(), "peer#0");

    let b = labels.label(Kind::Peer, &[8u8; 32]);
    assert_eq!(b.to_string(), "peer#1");
    // Resolution is the recorder's own, and never part of a bundle.
    assert_eq!(labels.resolve(a), Some(&[7u8; 32]));

    // Bounded: a peer that sends a million ids cannot make the table grow
    // without limit. Everything past the cap shares the saturation label, and
    // a reader can see it IS the saturation label.
    let mut many: Labels<u32> = Labels::new();
    for i in 0..(Labels::<u32>::CAP + 50) {
        many.label(Kind::Request, &i);
    }
    assert_eq!(many.len(), Labels::<u32>::CAP as usize);
    let over = many.label(Kind::Request, &999_999);
    assert_eq!(over.ordinal(), Labels::<u32>::CAP);
}

/// A real per-call report, recorded and dumped, leaves NO user content.
///
/// This is the test the delegate's report needs before it ships, because that
/// report is the production support tool: the same bounded recording runs in a
/// user's app, and "report a problem" exports it. A number the engine counted
/// is not content; a key, a value or a domain name is — however small, however
/// well typed. `domain = "medical"` is a category and no grep finds it.
#[test]
fn a_per_call_report_carries_counts_and_nothing_else() {
    use instrument::vocab::{DropReason, Key};
    use instrument::Record as _;

    // The things a real call would have touched. None of them may appear.
    let secrets = [
        "medical",
        "alice@example.com",
        "9nPgCTfiuX3Zycngp3vvgFiY9aqUmvKG64y86t6qgyKi",
        "patient-notes",
        "my-private-domain",
    ];

    let rec = Recorder::with_capacity(256);
    let site = Site::of("delegate::call");
    let op = instrument::Label::new(instrument::Kind::Span, 7)
        .unwrap()
        .op();
    // Exactly what Reply::Call carries: six counts the engine already had.
    for (key, value) in [
        (Key::Effects, 3u64),
        (Key::Ops, 2),
        (Key::Awaiting, 1),
        (Key::ReadBack, 1),
        (Key::Stranded, 0),
        (Key::DroppedMsgs, DropReason::NotForUs.code()),
    ] {
        rec.event(Event::Counter {
            site,
            op,
            entry: instrument::Entry { key, value },
        });
    }

    let dump = instrument::dump::render(&rec.recording(), "a delegate call", 40);
    for s in secrets {
        assert!(
            !dump.contains(s),
            "the dump contains user content verbatim: {s}"
        );
        // And no run of it long enough to identify it.
        for w in 6..=s.len() {
            let mut i = 0;
            while i + w <= s.len() {
                assert!(
                    !dump.contains(&s[i..i + w]),
                    "the dump contains a {w}-byte run of user content: {}",
                    &s[i..i + w]
                );
                i += 1;
            }
        }
    }

    // And the report IS there, which is the point of keeping it.
    assert!(dump.contains("Effects"), "{dump}");
    assert!(
        dump.contains("Stranded") || rec.recording().total(Key::Stranded) == 0,
        "stranded is visible without arithmetic: {dump}"
    );
}

/// Every `DropReason` code is pinned, and no two share a number.
///
/// These codes are a WIRE VOCABULARY. A support bundle carries them off the
/// device and something else decodes them later, so a reason that quietly
/// changes number — or two reasons that share one — is a silent misreading in
/// a reader that has no way to know. Same class as a data file whose MEANING
/// changed while every field stayed where it was.
///
/// Pinned exactly rather than asserted to be "stable": a test that only checks
/// they are distinct would let every value shift together, which breaks any
/// bundle already written.
#[test]
fn drop_reason_codes_are_pinned_and_distinct() {
    use instrument::vocab::DropReason::*;

    // Each value, by hand. Changing one of these is changing what an already
    // written bundle means, and it should take an edit here to do it.
    assert_eq!(Unparseable.code(), 0);
    assert_eq!(TrailingBytes.code(), 1);
    assert_eq!(TooLarge.code(), 2);
    assert_eq!(Unexpected.code(), 3);
    assert_eq!(NotForUs.code(), 4);
    assert_eq!(ShortAnswer.code(), 5);
    assert_eq!(AnsweredAfterReask.code(), 6);

    // And no two share a number — the failure that pinning alone would not
    // catch if a SIXTH reason were added reusing one.
    let all = [
        Unparseable,
        TrailingBytes,
        TooLarge,
        Unexpected,
        NotForUs,
        ShortAnswer,
        AnsweredAfterReask,
    ];
    let codes: std::collections::BTreeSet<u64> = all.iter().map(|r| r.code()).collect();
    assert_eq!(
        codes.len(),
        all.len(),
        "two DropReasons share a code: {:?}",
        all.iter().map(|r| (*r, r.code())).collect::<Vec<_>>()
    );

    // The codes are contiguous from zero, which is what lets a reader treat an
    // unknown one as "newer than me" rather than as corruption.
    assert_eq!(
        codes.into_iter().collect::<Vec<_>>(),
        (0..all.len() as u64).collect::<Vec<_>>()
    );
}

/// Every `StatusClass` code is pinned, distinct and contiguous, for the same
/// reason as `DropReason`'s: a bundle is decoded long after it was written.
/// And `of_http` sorts the statuses the SDK's loader meets.
#[test]
fn status_class_codes_are_pinned_and_distinct() {
    use instrument::vocab::StatusClass::{self, *};
    assert_eq!(Ok.code(), 0);
    assert_eq!(NotFound.code(), 1);
    assert_eq!(ServerError.code(), 2);
    assert_eq!(OtherHttp.code(), 3);
    assert_eq!(Abort.code(), 4);
    assert_eq!(NetworkError.code(), 5);
    let codes: Vec<u64> = StatusClass::ALL.iter().map(|c| c.code()).collect();
    assert_eq!(
        codes,
        (0..StatusClass::ALL.len() as u64).collect::<Vec<_>>(),
        "not contiguous from zero, or ALL is out of order"
    );
    for (status, want) in [
        (200, Ok),
        (206, Ok),
        (404, NotFound),
        (503, ServerError),
        (500, ServerError),
        (403, OtherHttp),
        (302, OtherHttp),
    ] {
        assert_eq!(StatusClass::of_http(status), want, "{status}");
    }
}

/// The coarsening rule is its DATA: `coarsen_ms` is computed from
/// `COARSEN_BANDS`, which a generator copies to another language, so the
/// bands and the function cannot disagree. Pinned at each edge, and no
/// ceiling (a wrong clock's 1.8e12 ms sample stays itself).
#[test]
fn coarsening_is_its_bands() {
    use instrument::vocab::{coarsen_ms, COARSEN_BANDS, COARSEN_LAST_GRAIN};
    assert_eq!(COARSEN_BANDS, [(1_000, 10), (60_000, 100)]);
    assert_eq!(COARSEN_LAST_GRAIN, 1_000);
    for (ms, want) in [
        (0, 0),
        (9, 0),
        (999, 990),
        (1_000, 1_000),
        (1_099, 1_000),
        (59_999, 59_900),
        (60_000, 60_000),
        (60_999, 60_000),
        (1_790_253_181_367, 1_790_253_181_000),
    ] {
        assert_eq!(coarsen_ms(ms), want, "{ms}");
    }
}

/// Every label KIND has its own prefix and its own CODE, pinned: a dump names `req#3`, `fetch#3` and `span#3`
/// apart, and the code is what an operation id carries (`Label::op`). A label carries only a kind and an ordinal --
/// nothing of the id it stands for.
#[test]
fn every_label_kind_has_its_own_prefix_and_code() {
    use instrument::{Kind, Label};
    let prefixes: Vec<&str> = Kind::ALL.iter().map(|k| k.prefix()).collect();
    assert_eq!(
        prefixes,
        ["req", "block", "peer", "contract", "fetch", "span", "domain"]
    );
    let codes: Vec<u32> = Kind::ALL.iter().map(|k| k.code()).collect();
    assert_eq!(
        codes,
        [0, 1, 2, 3, 4, 5, 6],
        "a kind's code moved: an already written recording would mean something else"
    );
    for k in Kind::ALL {
        assert_eq!(Kind::of_code(k.code()), Some(k));
    }
    assert_eq!(Label::new(Kind::Fetch, 3).unwrap().to_string(), "fetch#3");
}

/// A DATA DOMAIN's label is BOUNDED (craftworks-sdk#399, OBSERVABILITY §2.2): a schema index `0..64`, or the one
/// `unlisted` bucket at 64 -- never a larger ordinal, so a domain label can never become a counter of anything.
#[test]
fn a_domain_label_is_a_bounded_schema_index() {
    use instrument::label::{DOMAIN_SCHEMA_MAX, DOMAIN_UNLISTED};
    use instrument::{Kind, Label};
    assert_eq!(DOMAIN_UNLISTED, DOMAIN_SCHEMA_MAX);
    for i in 0..=DOMAIN_UNLISTED {
        let l = Label::domain(i).expect("a schema index or unlisted");
        assert_eq!((l.kind(), l.ordinal()), (Kind::Domain, i));
        assert_eq!(
            Label::of_op(l.op()),
            Some(l),
            "a domain label's op does not decode back to it"
        );
    }
    assert_eq!(
        Label::domain(DOMAIN_UNLISTED + 1),
        None,
        "a domain ordinal past unlisted was made"
    );
    assert_eq!(Label::domain(u32::MAX), None);
}

/// AN OPERATION ID CARRIES ITS KIND (the architect's conditions on the op() fix): the same ordinal under two kinds
/// is two operations; every label's op decodes back to it; `OpId::NONE` is in no kind's range; and an ordinal that
/// would spill into the kind bits cannot be made (refused at `Label::new`, never wrapped into another kind).
/// Mutants "op() ignores the kind" and "new() does not check" -> red.
#[test]
fn an_operation_id_carries_its_kind_and_no_ordinal_spills_into_it() {
    use instrument::label::MAX_ORDINAL;
    use instrument::{Kind, Label, OpId};
    for ordinal in [0, 1, 7, MAX_ORDINAL] {
        let ops: Vec<OpId> = Kind::ALL
            .iter()
            .map(|k| Label::new(*k, ordinal).unwrap().op())
            .collect();
        let distinct: std::collections::BTreeSet<OpId> = ops.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            Kind::ALL.len(),
            "two kinds share an operation at ordinal {ordinal}: {ops:?}"
        );
        for k in Kind::ALL {
            let l = Label::new(k, ordinal).unwrap();
            assert_eq!(Label::of_op(l.op()), Some(l), "{l} does not decode back");
            assert_ne!(l.op(), OpId::NONE, "{l}'s operation is the NONE sentinel");
        }
    }
    assert_eq!(Label::of_op(OpId::NONE), None, "NONE decodes to a label");
    assert!(
        Label::new(Kind::Request, MAX_ORDINAL).is_some(),
        "the last ordinal is refused"
    );
    assert!(
        Label::new(Kind::Request, MAX_ORDINAL + 1).is_none(),
        "an ordinal past the kind bits was made: it would be another kind's operation"
    );
    assert_eq!(MAX_ORDINAL, (1 << 29) - 1);
}

/// `answers()` NEVER CROSSES KINDS: a loader fetch round closed Timeout and a page send of the SAME ordinal that was
/// answered are two operations -- the send is `Once`, not LATE (what the loader handover found in one recording).
#[test]
fn answers_never_cross_kinds() {
    use instrument::vocab::Site;
    use instrument::{Answered, Dir, Event, Kind, Label, Outcome, Probe, Record, Recorder};
    let rec = Recorder::with_capacity(16);
    let (fetch, req) = (
        Label::new(Kind::Fetch, 1).unwrap(),
        Label::new(Kind::Request, 1).unwrap(),
    );
    let site = Site::of("test::kinds");
    rec.event(Event::Edge {
        site,
        dir: Dir::Request,
        id: fetch,
    });
    rec.event(Event::Exit {
        site,
        op: fetch.op(),
        outcome: Outcome::Timeout,
    });
    rec.event(Event::Edge {
        site,
        dir: Dir::Request,
        id: req,
    });
    rec.event(Event::Edge {
        site,
        dir: Dir::Response,
        id: req,
    });
    let answers = rec.recording().answers();
    assert_eq!(
        answers.iter().find(|(l, _)| *l == req).map(|(_, a)| *a),
        Some(Answered::Once),
        "req#1 was judged by fetch#1's close: {answers:?}"
    );
    assert_eq!(
        answers.iter().find(|(l, _)| *l == fetch).map(|(_, a)| *a),
        Some(Answered::Never)
    );
}

/// The HTTP classification is its TABLE (`HTTP_CLASSES`), which a generator copies to the SDK's JS loader: pinned,
/// and `of_http` computed from it, so the two cannot disagree.
#[test]
fn http_classification_is_its_table() {
    use instrument::vocab::{StatusClass, HTTP_CLASSES};
    assert_eq!(
        HTTP_CLASSES,
        [
            (200, 299, StatusClass::Ok),
            (404, 404, StatusClass::NotFound),
            (500, 599, StatusClass::ServerError)
        ]
    );
}
