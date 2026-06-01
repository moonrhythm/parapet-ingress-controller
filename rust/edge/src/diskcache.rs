//! Disk-backed cache `Storage` for the edge's HTTP response cache.
//!
//! Pingora 0.8 ships only an in-memory `MemCache` (labelled "testing"); there is
//! no disk Storage in the OSS release (cloudflare/pingora#210), so we implement
//! the `pingora::cache::Storage` trait against the filesystem. A disk cache (vs
//! MemCache) survives restarts and isn't bounded by RSS — important given the
//! edge's memory-pressure history (see the jemalloc notes in main.rs).
//!
//! Layout (sharded by the first hash byte so no directory grows unbounded):
//! ```text
//!   <root>/<aa>/<hash>.body   response body bytes
//!   <root>/<aa>/<hash>.meta   framed sidecar: CacheMeta + CompactCacheKey
//!   <root>/tmp/<hash>.<seq>.* in-progress writes, atomically renamed on commit
//! ```
//! `hash` = `CacheHashKey::combined()` (32 hex chars); `aa` = its first two.
//!
//! Durability: a miss is buffered in memory and committed in `finish()` as
//! temp-file + fsync + atomic `rename`, and the `.meta` is written **last** so
//! that the presence of a `.meta` implies a complete `.body`. A crash mid-write
//! leaves only an orphan temp/body file, which the startup scan reaps.
//!
//! Fail-static: IO errors on the read path degrade to a cache miss (serve from
//! origin) rather than erroring the client request.

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::cache::key::{CacheHashKey, CompactCacheKey, HashBinary};
use pingora::cache::storage::{HandleHit, HandleMiss, MissFinishType};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{CacheKey, CacheMeta, HitHandler, MissHandler, PurgeType, Storage};
use pingora::{Error, ErrorType, Result};

/// Magic + version prefix for the `.meta` sidecar framing (bumped if the layout
/// changes; an unrecognised prefix is treated as an orphan and reaped).
const META_MAGIC: &[u8; 8] = b"PEDGEC\x01\x00";

/// A single asset reconstructed from a `.meta` sidecar plus its `.body` size:
/// everything the eviction manager needs to (re-)admit the entry on startup.
pub struct ScannedEntry {
    pub key: CompactCacheKey,
    pub size: usize,
    pub fresh_until: SystemTime,
}

/// Filesystem-backed cache storage. Leaked to `&'static` in `main` (Pingora's
/// `Storage` methods take `&'static self`), like the cert store is a long-lived
/// process-global.
pub struct DiskCache {
    root: PathBuf,
    /// Cap on a cached body buffered in memory during admission. A miss whose
    /// body exceeds this is abandoned (not cached) so a single chunked response
    /// can't blow up RSS. Responses with a `Content-Length` over the cap are
    /// already rejected earlier in `response_cache_filter`.
    max_body_bytes: usize,
    /// Monotonic suffix for temp files so concurrent writers never collide.
    seq: AtomicU64,
}

impl DiskCache {
    /// Create the store rooted at `root`, ensuring `root/` and `root/tmp/` exist.
    pub fn new(root: impl Into<PathBuf>, max_body_bytes: usize) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            root,
            max_body_bytes,
            seq: AtomicU64::new(0),
        })
    }

    fn shard_dir(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[..2])
    }
    fn body_path(&self, hash: &str) -> PathBuf {
        self.shard_dir(hash).join(format!("{hash}.body"))
    }
    fn meta_path(&self, hash: &str) -> PathBuf {
        self.shard_dir(hash).join(format!("{hash}.meta"))
    }
    fn tmp_path(&self, hash: &str, what: &str) -> PathBuf {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        self.root.join("tmp").join(format!("{hash}.{n}.{what}"))
    }

    /// Walk the cache dir, returning every complete, parseable entry so the
    /// caller can re-admit them into the eviction manager (whose accounting is
    /// in-memory and otherwise resets across restarts). Orphans — a `.meta`
    /// without its `.body`, an unreadable/unrecognised sidecar, or a stray
    /// `.body`/temp file — are deleted. Best-effort: IO errors are logged and
    /// skipped, never fatal.
    pub fn scan(&self) -> Vec<ScannedEntry> {
        let mut out = Vec::new();
        let Ok(shards) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for shard in shards.flatten() {
            let dir = shard.path();
            // skip the tmp/ working dir: any file there is an aborted write.
            if !dir.is_dir() || dir.file_name().is_some_and(|n| n == "tmp") {
                if dir.file_name().is_some_and(|n| n == "tmp") {
                    reap_dir(&dir);
                }
                continue;
            }
            let Ok(files) = std::fs::read_dir(&dir) else {
                continue;
            };
            for f in files.flatten() {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "meta") {
                    match self.scan_one(&p) {
                        Some(entry) => out.push(entry),
                        None => {
                            // unparseable/incomplete -> drop both sides
                            let _ = std::fs::remove_file(&p);
                            let _ = std::fs::remove_file(p.with_extension("body"));
                        }
                    }
                } else if p.extension().is_some_and(|e| e == "body") {
                    // a body whose meta is gone is unusable; reaped if orphaned.
                    if !p.with_extension("meta").exists() {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
        }
        out
    }

    /// Synchronously delete an asset's files. Used by the startup eviction scan,
    /// which runs before the tokio runtime is serving. Returns whether anything
    /// was removed.
    pub fn remove_blocking(&self, key: &CompactCacheKey) -> bool {
        let hash = key.combined();
        let m = std::fs::remove_file(self.meta_path(&hash)).is_ok();
        let b = std::fs::remove_file(self.body_path(&hash)).is_ok();
        m || b
    }

    fn scan_one(&self, meta_path: &Path) -> Option<ScannedEntry> {
        let bytes = std::fs::read(meta_path).ok()?;
        let (meta, key) = decode_sidecar(&bytes)?;
        let body = meta_path.with_extension("body");
        let size = std::fs::metadata(&body).ok()?.len() as usize;
        Some(ScannedEntry {
            key,
            size,
            fresh_until: meta.fresh_until(),
        })
    }
}

/// Best-effort removal of every file in a directory (used to reap `tmp/`).
fn reap_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

fn internal_err(msg: &'static str, e: std::io::Error) -> Box<Error> {
    Error::because(ErrorType::InternalError, msg, e)
}

#[async_trait]
impl Storage for DiskCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let hash = key.combined();
        let meta_bytes = match tokio::fs::read(self.meta_path(&hash)).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            // a transient read error becomes a miss (serve from origin), not a
            // hard error to the client.
            Err(e) => {
                tracing::warn!(error = %e, hash, "edge cache: meta read failed; treating as miss");
                return Ok(None);
            }
        };
        let Some((meta, _key)) = decode_sidecar(&meta_bytes) else {
            tracing::warn!(hash, "edge cache: corrupt meta sidecar; treating as miss");
            return Ok(None);
        };
        let body = match tokio::fs::read(self.body_path(&hash)).await {
            Ok(b) => Bytes::from(b),
            // meta without body (mid-rotation/torn) -> miss.
            Err(_) => return Ok(None),
        };
        let hit = DiskHitHandler {
            body: Some(body),
            weight: meta_bytes.len(),
        };
        Ok(Some((meta, Box::new(hit))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let hash = key.combined();
        let sidecar =
            encode_sidecar(meta, &key.to_compact()).map_err(|e| internal_err("encode meta", e))?;
        Ok(Box::new(DiskMissHandler {
            storage: self,
            hash,
            sidecar,
            buf: Vec::new(),
            too_big: false,
            committed: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = key.combined();
        // remove meta first so a concurrent lookup never sees meta-without-body.
        let meta_gone = remove_if_exists(&self.meta_path(&hash)).await;
        let body_gone = remove_if_exists(&self.body_path(&hash)).await;
        Ok(meta_gone || body_gone)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = key.combined();
        if !self.body_path(&hash).exists() {
            return Ok(false);
        }
        let sidecar =
            encode_sidecar(meta, &key.to_compact()).map_err(|e| internal_err("encode meta", e))?;
        let tmp = self.tmp_path(&hash, "meta");
        atomic_write(&tmp, &self.meta_path(&hash), &sidecar)
            .await
            .map_err(|e| internal_err("update meta", e))?;
        Ok(true)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

/// Serves a fully-read body from memory in a single chunk. The body file is read
/// whole in `lookup` (bounded by the per-file size cap), so the handler holds no
/// file descriptor across awaits — streaming straight off disk is a future
/// optimization.
struct DiskHitHandler {
    body: Option<Bytes>,
    weight: usize,
}

#[async_trait]
impl HandleHit for DiskHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        Ok(self.body.take())
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn get_eviction_weight(&self) -> usize {
        // body + meta, so the eviction cap accounts for sidecar overhead too.
        self.weight + self.body.as_ref().map_or(0, |b| b.len())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

/// Buffers a cacheable response in memory, then commits it atomically in
/// `finish()`. Dropped without `finish()` → the write is abandoned (no temp/dest
/// files were created yet), matching the trait's "drop == failed write" contract.
struct DiskMissHandler {
    storage: &'static DiskCache,
    hash: String,
    sidecar: Vec<u8>,
    buf: Vec<u8>,
    /// Set once the buffered body exceeds the cap; the entry is then abandoned.
    too_big: bool,
    committed: bool,
}

#[async_trait]
impl HandleMiss for DiskMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        // Never error here: the body is also being streamed to the client, so an
        // error would abort the client response. Oversize just stops caching.
        if !self.too_big {
            if self.buf.len() + data.len() > self.storage.max_body_bytes {
                self.too_big = true;
                self.buf = Vec::new(); // release the partial buffer
            } else {
                self.buf.extend_from_slice(&data);
            }
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        if self.too_big {
            // Abandon admission; the client already got the full body upstream.
            return Error::e_explain(
                ErrorType::InternalError,
                "edge cache: body exceeded max file size, not cached",
            );
        }
        let size = self.buf.len();
        let body_dst = self.storage.body_path(&self.hash);
        let meta_dst = self.storage.meta_path(&self.hash);
        if let Some(parent) = body_dst.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| internal_err("mkdir shard", e))?;
        }
        // body first, then meta — meta presence implies a complete body.
        let body_tmp = self.storage.tmp_path(&self.hash, "body");
        atomic_write(&body_tmp, &body_dst, &self.buf)
            .await
            .map_err(|e| internal_err("write body", e))?;
        let meta_tmp = self.storage.tmp_path(&self.hash, "meta");
        if let Err(e) = atomic_write(&meta_tmp, &meta_dst, &self.sidecar).await {
            // roll back the body so we never leave an orphan.
            let _ = tokio::fs::remove_file(&body_dst).await;
            return Err(internal_err("write meta", e));
        }
        self.committed = true;
        Ok(MissFinishType::Created(size))
    }
}

/// Write `data` to `tmp`, fsync, then atomically rename onto `dst`.
async fn atomic_write(tmp: &Path, dst: &Path, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::File::create(tmp).await?;
    f.write_all(data).await?;
    f.sync_all().await?;
    drop(f);
    match tokio::fs::rename(tmp, dst).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = tokio::fs::remove_file(tmp).await;
            Err(e)
        }
    }
}

async fn remove_if_exists(p: &Path) -> bool {
    tokio::fs::remove_file(p).await.is_ok()
}

// ---- sidecar framing -------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}

/// Frame the `CacheMeta` (its two serialized blobs) together with the
/// `CompactCacheKey` fields, so a restart scan can re-admit the entry into the
/// eviction manager (which needs the key, not just the on-disk hash).
fn encode_sidecar(meta: &CacheMeta, key: &CompactCacheKey) -> std::io::Result<Vec<u8>> {
    let (internal, header) = meta
        .serialize()
        .map_err(|_| std::io::Error::other("meta serialize"))?;
    let mut out = Vec::with_capacity(internal.len() + header.len() + key.user_tag.len() + 64);
    out.extend_from_slice(META_MAGIC);
    put_u32(&mut out, internal.len());
    out.extend_from_slice(&internal);
    put_u32(&mut out, header.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&key.primary);
    match &key.variance {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(v.as_ref());
        }
        None => out.push(0),
    }
    let tag = key.user_tag.as_bytes();
    put_u32(&mut out, tag.len());
    out.extend_from_slice(tag);
    Ok(out)
}

/// Inverse of `encode_sidecar`. Returns `None` on any framing mismatch (treated
/// by callers as a corrupt/foreign file to reap).
fn decode_sidecar(b: &[u8]) -> Option<(CacheMeta, CompactCacheKey)> {
    let mut i = 0;
    let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
        let s = b.get(*i..*i + n)?;
        *i += n;
        Some(s)
    };
    let take_u32 = |i: &mut usize| -> Option<usize> {
        let s = take(i, 4)?;
        Some(u32::from_le_bytes(s.try_into().ok()?) as usize)
    };
    if take(&mut i, 8)? != META_MAGIC {
        return None;
    }
    let n = take_u32(&mut i)?;
    let internal = take(&mut i, n)?.to_vec();
    let n = take_u32(&mut i)?;
    let header = take(&mut i, n)?.to_vec();
    let meta = CacheMeta::deserialize(&internal, &header).ok()?;

    let primary: HashBinary = take(&mut i, 16)?.try_into().ok()?;
    let variance = match take(&mut i, 1)?[0] {
        0 => None,
        1 => {
            let v: HashBinary = take(&mut i, 16)?.try_into().ok()?;
            Some(Box::new(v))
        }
        _ => return None,
    };
    let n = take_u32(&mut i)?;
    let user_tag = std::str::from_utf8(take(&mut i, n)?).ok()?.into();
    Some((
        meta,
        CompactCacheKey {
            primary,
            variance,
            user_tag,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::cache::trace::Span;
    use pingora::http::ResponseHeader;

    fn span() -> SpanHandle {
        Span::inactive().handle()
    }

    fn meta(max_age: u64) -> CacheMeta {
        let now = SystemTime::now();
        let mut h = ResponseHeader::build(200, None).unwrap();
        h.append_header("cache-control", format!("max-age={max_age}"))
            .unwrap();
        CacheMeta::new(now + std::time::Duration::from_secs(max_age), now, 0, 0, h)
    }

    // Each test leaks a DiskCache to satisfy the `&'static self` Storage methods,
    // rooted in a unique tempdir.
    fn store(tag: &str) -> (&'static DiskCache, PathBuf) {
        let dir = std::env::temp_dir().join(format!("pedge-cache-test-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        let dc = Box::leak(Box::new(DiskCache::new(&dir, 1 << 20).unwrap()));
        (dc, dir)
    }

    #[tokio::test]
    async fn miss_then_finish_then_hit_roundtrips() {
        let (s, _dir) = store("roundtrip");
        let key = CacheKey::new("acme.com", "GET https /x", "");

        assert!(s.lookup(&key, &span()).await.unwrap().is_none());

        let mut miss = s.get_miss_handler(&key, &meta(60), &span()).await.unwrap();
        miss.write_body(Bytes::from_static(b"hello "), false)
            .await
            .unwrap();
        miss.write_body(Bytes::from_static(b"world"), true)
            .await
            .unwrap();
        assert!(matches!(
            miss.finish().await.unwrap(),
            MissFinishType::Created(11)
        ));

        let (m, mut hit) = s.lookup(&key, &span()).await.unwrap().unwrap();
        assert!(m.is_fresh(SystemTime::now()));
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(&body[..], b"hello world");
        assert!(hit.read_body().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_removes_the_entry() {
        let (s, _dir) = store("purge");
        let key = CacheKey::new("acme.com", "GET https /p", "");
        let mut miss = s.get_miss_handler(&key, &meta(60), &span()).await.unwrap();
        miss.write_body(Bytes::from_static(b"data"), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();

        assert!(s.lookup(&key, &span()).await.unwrap().is_some());
        assert!(s
            .purge(&key.to_compact(), PurgeType::Eviction, &span())
            .await
            .unwrap());
        assert!(s.lookup(&key, &span()).await.unwrap().is_none());
        // purging a missing key is a no-op false.
        assert!(!s
            .purge(&key.to_compact(), PurgeType::Eviction, &span())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn update_meta_rewrites_meta_keeps_body() {
        let (s, _dir) = store("updatemeta");
        let key = CacheKey::new("acme.com", "GET https /u", "");
        let mut miss = s.get_miss_handler(&key, &meta(1), &span()).await.unwrap();
        miss.write_body(Bytes::from_static(b"abc"), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();

        // bump freshness via update_meta (revalidation path).
        assert!(s.update_meta(&key, &meta(3600), &span()).await.unwrap());
        let (m, mut hit) = s.lookup(&key, &span()).await.unwrap().unwrap();
        assert!(m.fresh_sec() >= 3000, "freshness extended");
        assert_eq!(&hit.read_body().await.unwrap().unwrap()[..], b"abc");

        // update_meta on an absent body returns false.
        let other = CacheKey::new("acme.com", "GET https /missing", "");
        assert!(!s.update_meta(&other, &meta(60), &span()).await.unwrap());
    }

    #[tokio::test]
    async fn oversize_body_is_not_cached() {
        let dir = std::env::temp_dir().join("pedge-cache-test-oversize");
        let _ = std::fs::remove_dir_all(&dir);
        let s: &'static DiskCache = Box::leak(Box::new(DiskCache::new(&dir, 8).unwrap()));
        let key = CacheKey::new("acme.com", "GET https /big", "");
        let mut miss = s.get_miss_handler(&key, &meta(60), &span()).await.unwrap();
        miss.write_body(Bytes::from_static(b"0123456789"), true)
            .await
            .unwrap(); // 10 > 8 cap
        assert!(miss.finish().await.is_err(), "oversize admission abandoned");
        assert!(s.lookup(&key, &span()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn scan_reseeds_and_reaps_orphans() {
        let (s, dir) = store("scan");
        let key = CacheKey::new("acme.com", "GET https /s", "");
        let mut miss = s.get_miss_handler(&key, &meta(60), &span()).await.unwrap();
        miss.write_body(Bytes::from_static(b"payload"), true)
            .await
            .unwrap();
        miss.finish().await.unwrap();

        // an orphan body (no meta) should be reaped by the scan.
        let orphan = s.shard_dir(&CacheKey::new("a", "b", "").combined());
        std::fs::create_dir_all(&orphan).unwrap();
        let orphan_body = orphan.join("deadbeef.body");
        std::fs::write(&orphan_body, b"x").unwrap();

        let entries = s.scan();
        assert_eq!(entries.len(), 1, "one complete entry re-seeded");
        assert_eq!(entries[0].size, 7);
        assert_eq!(entries[0].key, key.to_compact());
        assert!(!orphan_body.exists(), "orphan body reaped");
        let _ = dir;
    }
}
