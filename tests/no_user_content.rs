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
    Entry, Event, OpId, Probe, Recorder,
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
    let op = OpId(1);
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
            entry: Entry {
                key: Key::Reads,
                value: 1,
            },
        });
        // The SIZE of the secret, as its padded class — never the length.
        rec.event(Event::Counter {
            site: SITE,
            entry: Entry {
                key: Key::BytesClass,
                value: SizeClass::of(SECRET.len()) as u64,
            },
        });
    }
    // A count derived from user data, bucketed.
    rec.event(Event::Counter {
        site: SITE,
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
    assert_eq!(over.ordinal, Labels::<u32>::CAP);
}
