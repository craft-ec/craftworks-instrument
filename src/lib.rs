//! Permanent instrumentation: a frozen four-event spine, a trait that can never
//! become an input, a recorder that drops rather than grows, and a dump that
//! prints itself when a test fails.
//!
//! # Why it is shaped like this
//!
//! Every constraint here was bought by a failure.
//!
//! - **`Edge` pairs a request with its response by id**, so *outstanding* is a
//!   subtraction rather than a consumer-side guess. Four harness runs were
//!   voided in one day for want of that number: a reader that had sent
//!   thousands of requests nobody would ever answer looked exactly like a
//!   reader doing its job.
//! - **`fn event(&self, e: Event)` returns unit and the trait has no read-back
//!   method.** Instrumented code therefore cannot branch on the probe, so the
//!   probe cannot become an input. That is the failure mode that turns a
//!   measurement into a story about itself.
//! - **A full ring DROPS and counts the drop.** It never grows (an unbounded
//!   buffer is a leak in a long run) and never panics (a probe that fails a
//!   passing test is the worst kind of behaviour change).
//! - **A per-recorder SEQUENCE, never a clock.** A delegate has no clock (F32),
//!   and a wall-clock stamp is a correlation handle across recordings.
//! - **No user content by VOCABULARY** — see [`vocab`]. Not "the payload is
//!   small": every key and enumerated value comes from a reviewed list, because
//!   the probes ship in production as the support tool.

pub mod dump;
pub mod label;
pub mod recorder;
pub mod vocab;

pub use label::{Kind, Label, Labels};
pub use recorder::{Recorder, Recording};
pub use vocab::{Bucket, Dir, Key, Outcome, Site, SizeClass};

/// The stream's version. ONE integer, at the stream level.
///
/// Not per event: a version on every event is a cost paid forever for a change
/// made rarely. An unknown PAYLOAD entry is skippable; an unknown SPINE variant
/// is not — which is why the spine is frozen and small, and everything that
/// churns rides in the payload. The same append-only rule ARCHITECTURE §19
/// already imposes on record encodings.
pub const STREAM_VERSION: u16 = 1;

/// Correlates the parts of one operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct OpId(pub u32);

/// One payload entry: a reviewed key and a number. That is the whole open part.
///
/// No strings, no bytes, no generics. A site that wants to say something the
/// [`Key`] list cannot express adds a key to that list, in a reviewed change —
/// which is exactly the friction that keeps user data out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub key: Key,
    pub value: u64,
}

/// The spine. Closed, frozen, four variants.
///
/// `Copy` and borrow-free on purpose: an event that borrows is an event that
/// can keep user bytes alive, and an event that allocates is a probe with a
/// cost that depends on what it is looking at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// An operation began.
    Enter { site: Site, op: OpId },
    /// An operation ended, and how.
    Exit {
        site: Site,
        op: OpId,
        outcome: Outcome,
    },
    /// A number, from the reviewed vocabulary.
    Counter { site: Site, entry: Entry },
    /// A request or a response carrying a LABELLED foreign id.
    ///
    /// The label, never the id — see [`label`].
    Edge { site: Site, dir: Dir, id: Label },
}

impl Event {
    pub const fn site(&self) -> Site {
        match self {
            Event::Enter { site, .. }
            | Event::Exit { site, .. }
            | Event::Counter { site, .. }
            | Event::Edge { site, .. } => *site,
        }
    }
}

/// Where events go.
///
/// **There is no method to read events back.** That is the guarantee the rest
/// of this crate is built on: instrumented code holds a `&dyn Probe` and can
/// do exactly one thing with it. A test that wants to READ a recording holds a
/// [`Recording`] handle instead, which the instrumented code never sees.
pub trait Probe {
    fn event(&self, e: Event);
}

/// The default: records nothing, costs a call the optimiser can usually see
/// through.
///
/// Its existence is what lets "recording off" be a PARAMETER rather than a
/// rebuild, and what the output differential compares against.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProbe;

impl Probe for NoProbe {
    #[inline(always)]
    fn event(&self, _e: Event) {}
}

/// So `&P` is a probe wherever `P` is — callers should not have to care.
impl<P: Probe + ?Sized> Probe for &P {
    #[inline]
    fn event(&self, e: Event) {
        (**self).event(e)
    }
}

/// Emit an `Enter` now and the matching `Exit` on drop.
///
/// A span whose `Exit` is written by hand is a span that is missing whenever
/// the function returns early — which is precisely when a reader needs it.
pub struct Span<'p, P: Probe + ?Sized> {
    probe: &'p P,
    site: Site,
    op: OpId,
    outcome: Outcome,
}

impl<'p, P: Probe + ?Sized> Span<'p, P> {
    pub fn enter(probe: &'p P, site: Site, op: OpId) -> Self {
        probe.event(Event::Enter { site, op });
        Span {
            probe,
            site,
            op,
            // Nothing said otherwise, so it ended by falling off the end. A
            // span that vanished mid-flight is `Blocked`, set by the caller.
            outcome: Outcome::Ok,
        }
    }

    /// Say how it ended. The `Exit` is still emitted by the drop.
    pub fn finish(mut self, outcome: Outcome) {
        self.outcome = outcome;
    }
}

impl<P: Probe + ?Sized> Drop for Span<'_, P> {
    fn drop(&mut self) {
        self.probe.event(Event::Exit {
            site: self.site,
            op: self.op,
            outcome: self.outcome,
        });
    }
}
