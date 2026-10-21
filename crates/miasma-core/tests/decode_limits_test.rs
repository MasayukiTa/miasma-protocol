//! A record value that declares a huge string length in a few dozen bytes must
//! be refused without sizing an allocation from the declared length.
//!
//! The test binary installs a counting allocator that remembers the largest
//! single allocation requested while a decode runs. It is a single test so no
//! other test thread can disturb the measurement.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use miasma_core::transfer::manifest::decode_record_value;

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn note(size: usize) {
    if ARMED.load(Ordering::Relaxed) {
        LARGEST.fetch_max(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// A `DhtRecord` (fixed-width little-endian integers) with one location whose
/// first address string declares `declared` bytes but supplies only a few.
fn crafted_record(declared: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x11u8; 32]); // mid_digest
    v.extend_from_slice(&[2, 3, 1]); // data_shards, total_shards, version
    v.extend_from_slice(&1u64.to_le_bytes()); // locations: 1
    v.extend_from_slice(&0u64.to_le_bytes()); // peer_id_bytes: empty
    v.extend_from_slice(&0u16.to_le_bytes()); // shard_index
    v.extend_from_slice(&0u32.to_le_bytes()); // segment_index
    v.extend_from_slice(&1u64.to_le_bytes()); // addrs: 1 string
    v.extend_from_slice(&declared.to_le_bytes()); // string length (a lie)
    v.extend_from_slice(b"/ip4/127.0.0.1"); // far fewer bytes than declared
    v
}

#[test]
fn a_declared_length_never_sizes_an_allocation() {
    const DECLARED: u64 = 64 * 1024 * 1024;
    let value = crafted_record(DECLARED);
    assert!(value.len() < 200);

    LARGEST.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let result = decode_record_value(&value);
    ARMED.store(false, Ordering::Relaxed);
    let largest = LARGEST.load(Ordering::Relaxed);

    assert!(result.is_err(), "a truncated record must be rejected");
    assert!(
        largest < 1024 * 1024,
        "decoding a {}-byte value requested a single allocation of {largest} bytes",
        value.len()
    );
}
