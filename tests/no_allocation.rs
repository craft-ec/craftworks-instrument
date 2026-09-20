//! The recorder allocates nothing once built.
//!
//! ALONE in this binary on purpose. The counter is a global allocator, so it
//! sees every thread — and cargo runs the tests within one binary in PARALLEL.
//! A second test here would have its allocations attributed to the recording
//! loop, which is the process-global-counter flaw this project already fixed
//! once in prolly's proof counters (#44). One test per binary is how a global
//! allocator is made honest.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use instrument::{
    vocab::{Key, Outcome, Site},
    Entry, Event, OpId, Probe, Recorder,
};

/// Counts allocations while armed. Armed only around the region under test, so
/// the harness's own allocations are not attributed to the recorder.
struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

const SITE: Site = Site::of("test::alloc");

/// The hot path allocates NOTHING.
///
/// It is carried by the types — events are `Copy` and borrow-free, the ring is
/// pre-allocated — but "carried by the types" is a claim until a counter
/// disagrees or does not.
#[test]
fn recording_allocates_nothing_after_construction() {
    let rec = Recorder::with_capacity(1024);
    // Warm anything lazy before arming, so the measurement is of the loop.
    rec.event(Event::Counter {
        site: SITE,
        entry: Entry {
            key: Key::Sent,
            value: 0,
        },
    });

    ALLOCS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    for i in 0..5_000u64 {
        rec.event(Event::Counter {
            site: SITE,
            entry: Entry {
                key: Key::Sent,
                value: i,
            },
        });
        rec.event(Event::Enter {
            site: SITE,
            op: OpId(i as u32),
        });
        rec.event(Event::Exit {
            site: SITE,
            op: OpId(i as u32),
            outcome: Outcome::Ok,
        });
    }
    ARMED.store(false, Ordering::Relaxed);
    let n = ALLOCS.load(Ordering::Relaxed);
    assert_eq!(n, 0, "{n} allocation(s) on the recording path");

    // The control: the counter CAN see an allocation, so the zero above is a
    // measurement and not a broken instrument. `black_box` because an
    // allocation the optimiser can prove is unused is an allocation that does
    // not happen — and a control that silently does nothing is worse than none.
    ALLOCS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let v: Vec<u64> = std::hint::black_box((0..64).collect());
    std::hint::black_box(&v);
    ARMED.store(false, Ordering::Relaxed);
    assert!(
        ALLOCS.load(Ordering::Relaxed) > 0,
        "the allocation counter never fires, so it proves nothing"
    );
    assert_eq!(v.len(), 64);
}
