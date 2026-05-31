# Heap profiling the Rust controller (jemalloc + jeprof)

When `jemalloc_allocated_bytes` (the live-heap gauge from `proxy/allocmetrics.rs`)
climbs without bound, a jemalloc heap profile names the exact allocation site in
one shot. This is a **debug build** — never the prod image.

## 1. Build the profiling image

GitHub → Actions → **Rust Build (heap profiling)** → *Run workflow*. It pushes:

```
…/parapet-ingress-controller:rust-prof-<sha>
```

It differs from the prod image only in: jemalloc built with `--enable-prof`
(the `jemalloc-prof` feature), symbols kept (`release-prof` profile, unstripped),
and a `debian:trixie-slim` runtime (so `kubectl cp`/`exec` work — distroless has
no shell/tar). Prof stays **inactive** until the env below is set, so the build
allocates like prod.

To build locally instead:

```sh
docker build rust \
  --build-arg CARGO_PROFILE=release-prof \
  --build-arg EXTRA_FEATURES=,jemalloc-prof \
  --build-arg RUNTIME_IMAGE=debian:trixie-slim \
  --build-arg TARGET_CPU=x86-64-v3 \
  -t parapet-prof
```

## 2. Deploy ONE pod with profiling active

Point a single replica (or a separate Deployment) at the `rust-prof-<sha>` image
and add — keep everything else identical to prod so the leak reproduces:

```yaml
        env:
        # The Linux build is unprefixed (unprefixed_malloc_on_supported_platforms),
        # so jemalloc reads MALLOC_CONF — NOT _RJEM_MALLOC_CONF (that name only
        # applies to a prefixed build, e.g. local macOS). Set both to be safe; the
        # wrong one is silently ignored, so a wrong name = no dumps and no error.
        - name: MALLOC_CONF
          value: "prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:28,prof_prefix:/tmp/jeprof"
        - name: _RJEM_MALLOC_CONF
          value: "prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:28,prof_prefix:/tmp/jeprof"
        volumeMounts:
        - { name: prof, mountPath: /tmp }
      volumes:
      - { name: prof, emptyDir: {} }
```

Confirm it took, instead of waiting:

```sh
kubectl exec POD -- ls -la /tmp        # jeprof.<pid>.<seq>.heap appears within ~1 min
kubectl logs POD | grep -i jemalloc    # "Invalid conf pair: prof:true" => prof not
                                       #   compiled in (wrong image, not rust-prof-<sha>)
```
Use a small `lg_prof_interval` (e.g. `25` ≈ 32 MiB) for a near-instant first dump
while confirming, then raise it.

- `lg_prof_sample:19` → sample ~every 512 KiB allocated (low overhead, good detail).
- `lg_prof_interval:30` → auto-dump a profile every 2^30 B (1 GiB) of **allocation
  activity** to `/tmp/jeprof.<pid>.<seq>.heap`. This is *gross* bytes allocated
  (every per-request buffer), **not** net live-heap growth — so under real traffic
  it fires fast: the **first dump lands within a couple of minutes**, then one
  every minute-or-two. (Raise to `33`≈8 GiB for fewer files if it's too chatty.)

Each `.heap` is a snapshot of the *currently live* sampled allocations, so the
leak shows up by diffing an early dump against a much-later one (step 4) — let
the pod run ~20–30 min of wall-clock so the later dump has accumulated clearly
more leaked heap, even though many interval dumps exist by then.

## 3. Capture

Let it run until at least 2–3 dumps exist (so the *diff* shows what's growing),
then pull them plus the (unstripped) binary:

```sh
kubectl exec POD -- ls -la /tmp                       # see jeprof.*.heap
kubectl cp POD:/tmp/jeprof.<pid>.<N>.heap   ./N.heap
kubectl cp POD:/tmp/jeprof.<pid>.<M>.heap   ./M.heap   # a later one
kubectl cp POD:/usr/local/bin/parapet-ingress-controller ./parapet.bin
```

## 4. Analyse

```sh
# Top allocation sites by live bytes:
jeprof --text --show_bytes ./parapet.bin ./M.heap | head -40

# What GREW between two dumps (the leak, isolated from steady-state):
jeprof --text --show_bytes --base=./N.heap ./parapet.bin ./M.heap | head -40

# Or a visual call graph:
jeprof --svg ./parapet.bin ./M.heap > heap.svg
```

`jeprof` ships with `google-perftools` (`brew install google-perftools` /
`apt-get install google-perftools`). The `--base` diff is the decisive view:
its top frame is the leaking call path. Send that output (or the `.heap` +
`parapet.bin`) and we pinpoint the fix.

## 5. Tear down

Delete the profiling pod/Deployment; the prod stream is untouched (separate tag).
