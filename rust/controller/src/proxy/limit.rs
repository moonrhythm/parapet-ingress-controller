//! Per-key concurrency limiting, port of parapet's ConcurrentStrategy /
//! ConcurrentQueueStrategy (Phase-0 design):
//!
//! - `size == 0`: cap `capacity` in-flight per key, reject above (no queue).
//! - `size > 0`: cap `capacity` in-flight; up to `size` extra requests wait;
//!   reject only when the queue is also full.
//!
//! The returned [`Guard`] releases the slot on drop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct HostConcurrency {
    capacity: usize,
    size: usize,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
}

struct Slot {
    count: AtomicUsize,
    sem: Option<Arc<Semaphore>>, // present only for the queueing strategy
}

pub struct Guard {
    slot: Arc<Slot>,
    key: String,
    limiter: Weak<HostConcurrency>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Release the in-flight slot. If this was the last holder, evict the now
        // idle slot from the map so it can't accumulate one entry per distinct
        // key forever — notably `host|country` keys, where the country comes from
        // a request header and is otherwise unbounded. `count` is mutated only
        // under the `slots` lock (in `acquire`), so re-checking it under that lock
        // here makes the evict race-free: a slot at count 0 under the lock has no
        // live or pending holders.
        if self.slot.count.fetch_sub(1, Ordering::Relaxed) == 1 {
            if let Some(limiter) = self.limiter.upgrade() {
                let mut slots = limiter.slots.lock().unwrap();
                if let Some(existing) = slots.get(&self.key) {
                    if Arc::ptr_eq(existing, &self.slot)
                        && self.slot.count.load(Ordering::Relaxed) == 0
                    {
                        slots.remove(&self.key);
                    }
                }
            }
        }
    }
}

impl HostConcurrency {
    /// Returns `None` when limiting is disabled (capacity == 0).
    pub fn new(capacity: usize, size: usize) -> Option<Arc<Self>> {
        if capacity == 0 {
            return None;
        }
        Some(Arc::new(Self {
            capacity,
            size,
            slots: Mutex::new(HashMap::new()),
        }))
    }

    /// Acquire a slot for `key`, waiting if queueing is enabled. Returns `None`
    /// when the limit (capacity, plus the bounded queue) is exceeded.
    pub async fn acquire(self: &Arc<Self>, key: &str) -> Option<Guard> {
        let (slot, n) = {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots
                .entry(key.to_string())
                .or_insert_with(|| {
                    Arc::new(Slot {
                        count: AtomicUsize::new(0),
                        sem: (self.size > 0).then(|| Arc::new(Semaphore::new(self.capacity))),
                    })
                })
                .clone();
            // Increment under the lock (paired with the evict check in `Guard::drop`)
            // so a slot observed at count 0 under the lock is truly idle.
            let n = slot.count.fetch_add(1, Ordering::Relaxed) + 1;
            (slot, n)
        };

        // Tie the count decrement to a guard immediately, so it is released even
        // if this future is dropped while awaiting the permit (client disconnect).
        let mut guard = Guard {
            slot: slot.clone(),
            key: key.to_string(),
            limiter: Arc::downgrade(self),
            _permit: None,
        };

        let limit = self.capacity + self.size; // size == 0 => just capacity
        if n > limit {
            return None; // guard drops here -> count decremented
        }

        if let Some(sem) = &slot.sem {
            match sem.clone().acquire_owned().await {
                Ok(p) => guard._permit = Some(p),
                Err(_) => return None,
            }
        }
        Some(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_strategy_caps_inflight() {
        let lc = HostConcurrency::new(2, 0).unwrap();
        let _g1 = lc.acquire("h").await.unwrap();
        let _g2 = lc.acquire("h").await.unwrap();
        // third concurrent acquire is rejected (no queue)
        assert!(lc.acquire("h").await.is_none());
        // a different key is independent
        assert!(lc.acquire("other").await.is_some());
        drop(_g1);
        // slot freed -> can acquire again
        assert!(lc.acquire("h").await.is_some());
    }

    #[tokio::test]
    async fn queue_strategy_waits_then_serves() {
        // capacity 1, queue 1: one active + one allowed to wait.
        let lc = HostConcurrency::new(1, 1).unwrap();
        let g1 = lc.acquire("h").await.unwrap(); // takes the only permit

        // a queued waiter (count -> 2 == capacity+size, waits for the permit)
        let lc2 = lc.clone();
        let waiter = tokio::spawn(async move { lc2.acquire("h").await.is_some() });

        // give the waiter time to register its count and park on the semaphore
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // queue is now full (1 active + 1 waiting); a further acquire is rejected
        assert!(lc.acquire("h").await.is_none());

        // releasing the active slot lets the waiter through
        drop(g1);
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn idle_slots_are_evicted() {
        let lc = HostConcurrency::new(2, 0).unwrap();
        // distinct keys (e.g. host|country) come and go; each must leave no trace
        for i in 0..100 {
            let g = lc.acquire(&format!("country-{i}")).await.unwrap();
            drop(g); // last holder drops -> slot evicted
        }
        assert_eq!(lc.slots.lock().unwrap().len(), 0, "no idle slots retained");

        // a slot with a live holder is NOT evicted, and is reclaimed once idle
        let g1 = lc.acquire("h").await.unwrap();
        let g2 = lc.acquire("h").await.unwrap();
        assert_eq!(lc.slots.lock().unwrap().len(), 1);
        drop(g1);
        assert_eq!(lc.slots.lock().unwrap().len(), 1, "still one holder");
        drop(g2);
        assert_eq!(lc.slots.lock().unwrap().len(), 0, "evicted when last drops");
    }
}
