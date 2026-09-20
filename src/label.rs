//! Foreign ids, labelled.
//!
//! A block id, a peer key, a contract instance — anything drawn from a
//! population someone else can enumerate — is never written into a recording.
//! It is replaced by a LABEL: a kind and a small ordinal, `peer#3`, assigned in
//! the order the recorder first saw it.
//!
//! **Not truncated.** A prefix of an id drawn from an enumerable population is
//! not anonymous: with a few thousand candidates, a 32-bit prefix identifies
//! one of them. Truncation looks like redaction and is not, which is worse than
//! doing nothing, so this crate does not offer it.
//!
//! The label→id table is held by whoever is recording and is NEVER part of a
//! bundle. An operator reading a support bundle sees that `peer#3` was slow;
//! only the person who recorded it can say which peer that was.

use crate::vocab::Site;

/// What kind of foreign thing a label stands for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Kind {
    Block,
    Peer,
    Contract,
    Request,
}

impl Kind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Kind::Block => "block",
            Kind::Peer => "peer",
            Kind::Contract => "contract",
            Kind::Request => "req",
        }
    }
}

/// `peer#3` — fixed size, `Copy`, and carrying nothing of the id itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Label {
    pub kind: Kind,
    pub ordinal: u32,
}

impl Label {
    /// The operation this label denotes.
    ///
    /// Every tool that has needed this derived it the same way and separately
    /// (`OpId(label.ordinal)`), which is two definitions of one fact waiting to
    /// disagree. It is stated once here so a recording can cross-reference an
    /// `Edge` with the `Exit` of the operation it belongs to — which is what
    /// makes "answered LATE" expressible at all.
    pub const fn op(self) -> crate::OpId {
        crate::OpId(self.ordinal)
    }
}

impl core::fmt::Display for Label {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}#{}", self.kind.prefix(), self.ordinal)
    }
}

/// Assigns labels, and keeps the only copy of the mapping.
///
/// Bounded like everything else here: past `CAP` distinct ids of a kind, new
/// ones all become `#CAP` rather than growing the table. A support bundle that
/// could be made to allocate without limit by a peer sending many ids is a
/// denial of service with extra steps.
pub struct Labels<Id> {
    seen: Vec<(Kind, Id)>,
    cap: u32,
}

impl<Id: PartialEq + Clone> Labels<Id> {
    pub const CAP: u32 = 512;

    pub fn new() -> Self {
        Labels {
            seen: Vec::with_capacity(64),
            cap: Self::CAP,
        }
    }

    /// The label for this id, assigning one on first sight.
    pub fn label(&mut self, kind: Kind, id: &Id) -> Label {
        if let Some(i) = self.seen.iter().position(|(k, x)| *k == kind && x == id) {
            return Label {
                kind,
                ordinal: i as u32,
            };
        }
        if (self.seen.len() as u32) < self.cap {
            self.seen.push((kind, id.clone()));
            Label {
                kind,
                ordinal: (self.seen.len() - 1) as u32,
            }
        } else {
            // Saturated rather than grown. Everything beyond the cap shares one
            // label, which a reader can see is a saturation and not a peer.
            Label {
                kind,
                ordinal: self.cap,
            }
        }
    }

    /// How many distinct ids this table holds — for the recorder's own report,
    /// never for a bundle.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Resolve a label back to its id. Held by the recorder's owner ONLY; this
    /// is the half a bundle must never contain.
    pub fn resolve(&self, label: Label) -> Option<&Id> {
        self.seen
            .iter()
            .filter(|(k, _)| *k == label.kind)
            .nth(label.ordinal as usize)
            .map(|(_, id)| id)
    }
}

impl<Id: PartialEq + Clone> Default for Labels<Id> {
    fn default() -> Self {
        Self::new()
    }
}

/// The site a label was first seen at, for the recorder's own diagnostics.
pub const LABELLED_AT: Site = Site::of("instrument::label");
