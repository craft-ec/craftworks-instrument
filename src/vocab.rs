//! The vocabulary: every word an event may contain.
//!
//! **Redaction is by VOCABULARY, not by type.** A fixed-size, `Copy`, strongly
//! typed value can still be sensitive — `domain = "medical"` is all three. So
//! the guarantee this crate offers is not "the payload is small" but "every key
//! and every enumerated value came from this file, which is reviewed".
//!
//! A site therefore cannot emit a value DERIVED from user data, however small.
//! The three shapes that would otherwise leak are each given a lawful form:
//!
//! - **Foreign ids** are LABELLED per bundle (`peer#3`), never truncated. A
//!   truncated id drawn from an enumerable population is not anonymous — a
//!   few thousand candidates are trivially re-identified — so truncation is
//!   not offered at all. The label→id table lives with whoever recorded it and
//!   is never part of a bundle.
//! - **Sizes of sealed data** are reported as a PADDED CLASS, because the exact
//!   length of a ciphertext is a property of the plaintext.
//! - **Counts derived from user data** are BUCKETED, and times are COARSENED
//!   offsets from the start of the recording.

/// Where an event happened.
///
/// A newtype so it cannot be built from a runtime string: the only way to make
/// one is [`Site::of`], which takes a `&'static str` — a compile-time literal
/// in the emitting crate, never anything a user supplied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Site(&'static str);

impl Site {
    /// `&'static str` is the whole guard: a value derived from user data cannot
    /// have that lifetime without being leaked deliberately.
    pub const fn of(name: &'static str) -> Site {
        Site(name)
    }
    pub const fn name(self) -> &'static str {
        self.0
    }
}

/// What a payload entry is ABOUT. Closed, and every addition is reviewed.
///
/// # The test every key must pass
///
/// **Observability is DERIVED where the fact is a property of the DATA, and
/// INSTRUMENTED only where it is a property of an EXECUTION.**
///
/// Derived — never a key here:
/// - how much a tree stores: already in every node's aggregate (ARCHITECTURE §5);
/// - which blocks a write rewrote: a `diff` of two roots, read only where they
///   differ;
/// - what an operation SHOULD cost: a pure function of the tree's shape, since
///   node boundaries are deterministic.
///
/// Instrumented — what these keys are for:
/// - time, and anything measured against a clock the data does not have;
/// - bytes ACTUALLY transferred, which is not what the data says they should be;
/// - hops, attempts, retries;
/// - where an operation died, and **what did not happen at all**.
///
/// A key that reports a derivable fact is DELETED, not maintained: it is a
/// second account of something the data already answers, and two accounts of
/// one fact disagree. Three were removed by that test —
/// [`Record::outstanding`](crate::Record::outstanding) already derives
/// outstanding work from the edges, [`Record::dropped`](crate::Record::dropped)
/// already reads the ring's own counter, and a tree's depth is a property of
/// its root.
///
/// The test has a cost when it is not applied. A 1 KiB block was measured
/// costing 240-395 KB to fetch (F46) and it took six rejected instruments and a
/// night to establish, because nothing said what it SHOULD have cost. Against a
/// derived expectation the same run reads as a ratio on the first attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Key {
    /// Blocks asked for.
    Reads,
    /// Blocks asked for that the source did not have.
    Misses,
    /// Bytes handed back, as a padded class — see [`SizeClass`].
    BytesClass,
    /// Requests sent on a connection.
    Sent,
    /// Responses received.
    Received,
    /// A bucketed count derived from user data — see [`Bucket`].
    CountBucket,
    /// A coarsened offset from the start of the recording, in milliseconds.
    OffsetMs,
    /// Retries, re-puts, re-sends.
    Attempts,
    /// Answers a caller gave up waiting for and is still OWED.
    ///
    /// A bounded wait that expires does not cancel anything: the node still
    /// owes that answer, and it arrives later on a connection that carries no
    /// correlation id. Until something can say WHICH request an answer
    /// settles, a transport that pairs by position is shifted by one from the
    /// moment this is non-zero — which is the defect that made a node look
    /// like it had refused fifteen puts it had in fact accepted
    /// (freenet-harness#38).
    ///
    /// It does not go down. Nothing can prove which later answer settled an
    /// owed one, so a decrement would be a guess written as a fact; this
    /// counts how many times pairing-by-position lost its footing.
    Owed,
    /// Effects the core returned in one delegate call.
    ///
    /// These six are the delegate's PER-CALL REPORT. They exist because a
    /// delegate prints nothing and the node says nothing about it, so five
    /// different breaks in the write path all presented as one symptom — a
    /// write that stops at `Accepted` — and these counts are what separated
    /// them. Every one is a number the engine already had; none is derived
    /// from user data.
    Effects,
    /// Node operations issued in one delegate call.
    Ops,
    /// Blocks put and not yet read back.
    Awaiting,
    /// Puts confirmed by reading them back.
    ///
    /// The read-back, not the acknowledgement: `durable` has always meant the
    /// block can be SERVED, never that an operation finished (F22/F31).
    ReadBack,
    /// Effects still queued when the call ended, and therefore LOST.
    ///
    /// Must be zero. It is recorded rather than asserted so that a non-zero one
    /// is visible in a dump without anybody doing arithmetic.
    Stranded,
    /// Inbound messages this build could not use, by reason.
    ///
    /// The reason is a closed vocabulary — see [`DropReason`] — never a string.
    DroppedMsgs,
    /// Bytes offered to the socket for one operation, counted at OUR boundary.
    ///
    /// A byte COUNT is not derived from content — it is the size of what was
    /// sent, which the transport already knows — so it is exact rather than
    /// bucketed. The size of SEALED data is different and goes through
    /// [`SizeClass`]: a ciphertext's length is a property of its plaintext.
    ///
    /// This measures what WE cost, not what a node sends peer-to-peer. Six
    /// external instruments were rejected trying to infer the latter from
    /// outside (freenet-contracts#39); only the node can count that, and this
    /// is the half we are positioned to count honestly.
    BytesOut,
    /// Bytes read from the socket for one operation, counted at OUR boundary.
    BytesIn,
    /// Answers received while [`Owed`](Key::Owed) was non-zero.
    ///
    /// Counted, and deliberately NOT attributed to any operation: an answer
    /// that might belong to an abandoned request must not close a running one.
    /// A reader seeing this above zero knows the pairing in that recording is
    /// no longer trustworthy, which is exactly what the healthy-looking line
    /// over a shifted stream failed to say.
    Ambiguous,
}

/// Why an inbound message was discarded.
///
/// Closed, and mirroring the protocol's own `Dropped` — a reason is a
/// vocabulary value, never a string. A free-text reason is the easiest place
/// for user data to arrive by accident, and this one crosses into a support
/// bundle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum DropReason {
    /// Not a message this build can read at all.
    Unparseable,
    /// Trailing bytes: the prefix parsed, and a prefix is not a message.
    TrailingBytes,
    /// Bigger than this build will decode.
    TooLarge,
    /// A response about something nobody asked for.
    Unexpected,
    /// A message kind this side has no use for.
    NotForUs,
}

impl DropReason {
    /// A small stable integer, so a reason can ride in a `Counter` without a
    /// second event shape.
    pub const fn code(self) -> u64 {
        match self {
            DropReason::Unparseable => 0,
            DropReason::TrailingBytes => 1,
            DropReason::TooLarge => 2,
            DropReason::Unexpected => 3,
            DropReason::NotForUs => 4,
        }
    }
}

/// How an operation ended.
///
/// `Refused(code)` carries a small stable integer, never a string: a reason
/// string is the easiest place for user data to arrive by accident.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Ok,
    Missing,
    Refused(u16),
    Blocked,
    Timeout,
}

/// Which way an [`Edge`](crate::Event::Edge) points.
///
/// The pair is what makes OUTSTANDING a subtraction rather than a consumer-side
/// guess — the distinction that cost four harness runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Request,
    Response,
}

/// A size reported as the class it falls in, never exactly.
///
/// The exact length of sealed bytes is a property of the plaintext, so a probe
/// that ships in production must not carry it. The classes are the ones the
/// storage layer already pads to, so this loses nothing a reader had.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum SizeClass {
    Empty,
    UpTo1K,
    UpTo4K,
    UpTo16K,
    UpTo64K,
    UpTo256K,
    Over256K,
}

impl SizeClass {
    pub const fn of(bytes: usize) -> SizeClass {
        match bytes {
            0 => SizeClass::Empty,
            1..=1024 => SizeClass::UpTo1K,
            1025..=4096 => SizeClass::UpTo4K,
            4097..=16384 => SizeClass::UpTo16K,
            16385..=65536 => SizeClass::UpTo64K,
            65537..=262144 => SizeClass::UpTo256K,
            _ => SizeClass::Over256K,
        }
    }
}

/// A count reported as the bucket it falls in.
///
/// "This person has 3 contacts" is user data; "this person has between 1 and 9"
/// is what an operator needs to read a trace.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Bucket {
    Zero,
    One,
    UpTo9,
    UpTo99,
    UpTo999,
    Over999,
}

impl Bucket {
    pub const fn of(n: u64) -> Bucket {
        match n {
            0 => Bucket::Zero,
            1 => Bucket::One,
            2..=9 => Bucket::UpTo9,
            10..=99 => Bucket::UpTo99,
            100..=999 => Bucket::UpTo999,
            _ => Bucket::Over999,
        }
    }
}

/// Milliseconds since the recording started, coarsened.
///
/// Not a clock: a wall-clock timestamp is both unavailable in a delegate (F32)
/// and a correlation handle across recordings. A coarse offset says how long
/// something took without saying when it happened.
pub const fn coarsen_ms(ms: u64) -> u64 {
    if ms < 1_000 {
        (ms / 10) * 10
    } else if ms < 60_000 {
        (ms / 100) * 100
    } else {
        (ms / 1_000) * 1_000
    }
}
