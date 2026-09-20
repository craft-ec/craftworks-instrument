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
    /// Sent minus received: the number four voided harness runs could not see.
    Outstanding,
    /// Events the recorder dropped because its ring was full.
    Dropped,
    /// Depth in a tree walk.
    Depth,
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
    /// Answers received while [`Owed`](Key::Owed) was non-zero.
    ///
    /// Counted, and deliberately NOT attributed to any operation: an answer
    /// that might belong to an abandoned request must not close a running one.
    /// A reader seeing this above zero knows the pairing in that recording is
    /// no longer trustworthy, which is exactly what the healthy-looking line
    /// over a shifted stream failed to say.
    Ambiguous,
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
