//! A pre-allocated ring that drops when full, and a separate handle for reading
//! it.
//!
//! The split is the point. [`Recorder`] implements [`Probe`] and is what
//! instrumented code holds — write-only, by the shape of the trait.
//! [`Recording`] is what a test holds, and it is the only way to look. Nothing
//! that has a `&dyn Probe` can read.

use core::cell::RefCell;

use crate::{
    vocab::{Dir, Key, Outcome},
    Entry, Event, Label, OpId, Probe, Site,
};

/// Events kept, and events dropped.
///
/// Interior mutability because [`Probe::event`] takes `&self` — it has to, or
/// instrumented code would need a `&mut` it cannot have while the thing it is
/// instrumenting is borrowed.
pub struct Recorder {
    inner: RefCell<Ring>,
}

struct Ring {
    slots: Vec<Event>,
    /// Next write position.
    at: usize,
    /// Total events offered, so `seq` is the sequence the spine promises.
    seq: u64,
    /// Events the ring refused because it was full. COUNTED: a silent drop and
    /// a quiet system look identical in a dump.
    dropped: u64,
    full: bool,
}

impl Recorder {
    /// A ring of `capacity` events, allocated once, here and nowhere else.
    pub fn with_capacity(capacity: usize) -> Recorder {
        let cap = capacity.max(1);
        Recorder {
            inner: RefCell::new(Ring {
                slots: Vec::with_capacity(cap),
                at: 0,
                seq: 0,
                dropped: 0,
                full: false,
            }),
        }
    }

    /// A handle that can read what this recorder holds.
    pub fn recording(&self) -> Recording<'_> {
        Recording { r: self }
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder::with_capacity(4096)
    }
}

impl Probe for Recorder {
    fn event(&self, e: Event) {
        // A probe must not panic, and `RefCell` can. Reentrancy is possible in
        // principle — a `Drop` that emits while a dump is reading — so a failed
        // borrow drops the event rather than taking the process down.
        let Ok(mut ring) = self.inner.try_borrow_mut() else {
            return;
        };
        ring.seq += 1;
        let cap = ring.slots.capacity();
        if ring.slots.len() < cap {
            ring.slots.push(e);
            ring.at = ring.slots.len() % cap;
            return;
        }
        // Full. Overwrite the oldest — a ring keeps the LAST N, which is what a
        // failure dump needs — and count it. Never grow: an unbounded buffer in
        // a long run is a leak with a nice name.
        ring.full = true;
        ring.dropped += 1;
        let at = ring.at;
        ring.slots[at] = e;
        ring.at = (at + 1) % cap;
    }
}

/// The read side. A test holds this; instrumented code never does.
pub struct Recording<'a> {
    r: &'a Recorder,
}

impl Recording<'_> {
    /// Events in the order they were offered, oldest first.
    pub fn events(&self) -> Vec<Event> {
        let ring = self.r.inner.borrow();
        if !ring.full {
            return ring.slots.clone();
        }
        let mut out = Vec::with_capacity(ring.slots.len());
        out.extend_from_slice(&ring.slots[ring.at..]);
        out.extend_from_slice(&ring.slots[..ring.at]);
        out
    }

    /// How many events were offered in total, kept or not.
    pub fn offered(&self) -> u64 {
        self.r.inner.borrow().seq
    }

    /// How many the ring had to drop.
    pub fn dropped(&self) -> u64 {
        self.r.inner.borrow().dropped
    }

    /// Requests with no matching response, by label.
    ///
    /// The number four voided harness runs could not see. It is a SUBTRACTION
    /// because `Edge` pairs the two directions by id — if the two were
    /// unrelated event types, this would be a heuristic.
    pub fn outstanding(&self) -> Vec<Label> {
        let mut open: Vec<Label> = Vec::new();
        for e in self.events() {
            if let Event::Edge { dir, id, .. } = e {
                match dir {
                    Dir::Request => open.push(id),
                    Dir::Response => {
                        if let Some(i) = open.iter().position(|l| *l == id) {
                            open.remove(i);
                        }
                    }
                }
            }
        }
        open
    }

    /// Spans that were entered and never exited.
    pub fn unfinished(&self) -> Vec<(Site, OpId)> {
        let mut open: Vec<(Site, OpId)> = Vec::new();
        for e in self.events() {
            match e {
                Event::Enter { site, op } => open.push((site, op)),
                Event::Exit { site, op, .. } => {
                    if let Some(i) = open.iter().position(|x| *x == (site, op)) {
                        open.remove(i);
                    }
                }
                _ => {}
            }
        }
        open
    }

    /// The sum of one counter across the recording.
    pub fn total(&self, key: Key) -> u64 {
        self.events()
            .iter()
            .filter_map(|e| match e {
                Event::Counter {
                    entry: Entry { key: k, value },
                    ..
                } if *k == key => Some(*value),
                _ => None,
            })
            .sum()
    }

    /// How many spans ended each way.
    pub fn outcomes(&self) -> Vec<(Outcome, usize)> {
        let mut out: Vec<(Outcome, usize)> = Vec::new();
        for e in self.events() {
            if let Event::Exit { outcome, .. } = e {
                match out.iter_mut().find(|(o, _)| *o == outcome) {
                    Some((_, n)) => *n += 1,
                    None => out.push((outcome, 1)),
                }
            }
        }
        out
    }
}
