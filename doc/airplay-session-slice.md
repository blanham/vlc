# AirPlay session slice (file-backed)

## Status

Design for the vertical slice after `doc/airplay-foundation.md` on
`feature/airplay-foundation`. Foundation (discovery, stable id, empty sout) is
done; this tranche makes an Apple TV connectable and playable from VLC on
Windows without FairPlay.

## Goals

1. Select an Apple TV in VLC.
2. Enter pairing PIN once via interactive dialog; store identity in VLC keystore.
3. Serve the **current local** H.264/AAC MP4 over tokenized HTTP.
4. Instruct the receiver to play; support pause / seek / stop / EOF / teardown /
   reconnect.
5. Restart VLC and reconnect without re-pairing.

## Non-goals

- FairPlay / Apple private keys, certs, or protected-media circumvention
- Live remux / Chromecast-style FIFO streaming (follow-up)
- RAOP RTP audio streaming as the primary path
- AirPlay 2 multiroom sync, display mirroring, receiver mode
- Qt / Win32 UI modules owning protocol code
- Full hardware model matrix

## Approach

**Thin URL caster** (not a full Chromecast clone):

- Discovery publishes a connectable `airplay://host:port` URI and stable id.
- Portable `modules/stream_out/airplay/` handles pairing, keystore, local HTTP
  file serving, and receiver control.
- Extract only needed patterns from Chromecast: `vlc_http_HostNew` / httpd
  lifetime tied to sout Open/Close, renderer URI → sout options, clear
  Open/Close lifecycle. Do **not** copy Cast protobuf, proxy mux chain, or
  `cc_demux` unless EOF/pacing later proves necessary.

## Module layout

```
modules/stream_out/airplay/
  airplay.c       # sout output Open/Close; options; wire session
  pairing.c/.h    # HAP-style pair FSM; vlc_dialog PIN; keystore I/O
  session.c/.h    # control HTTP: play/pause/seek/stop/teardown
  http_media.c/.h # local httpd; tokenized GET of current file path
  plist.c/.h      # minimal plist encode/decode for control payloads
```

Build: Meson `subdir('airplay')` under `modules/stream_out/`, gated by
`stream_outputs`, portable (Windows-friendly), `socket_libs`. Autotools mirror
if the tree still expects it for sout plugins.

## Discovery → sout wiring

`airplay_publish` (microdns) changes from `uri = NULL` to:

- `uri = airplay://host:port` — prefer the `_airplay._tcp` endpoint; fall back
  carefully if only RAOP is present
- `type = "airplay"`, `id = stable_id` (unchanged)
- No demux_filter in this tranche
- Existing `item_set_sout_from_uri` yields `airplay{ip=…,port=…,…}`
- Set `desc.extra_sout` to `device-id=<stable_id>` (API already supports this).
  Open uses that private option for keystore lookup. Stable id is identity,
  not a secret; still never put PIN/LTK material in sout/URI.

Qt continues to key rows by `type#id`. IP/port changes do not invalidate
keystore entries.

## Media path (file-backed)

On sout Open:

1. Resolve the **current local input** to a filesystem path (`file://` or native
   path).
2. If missing, not local, or unreadable → fail with a clear error (no silent
   remux).
3. Serve that path via tokenized HTTP (see below).
4. Tell the receiver to play the LAN URL.

Validation assets: episodes under `E:\Connections\` (sampled files are already
H.264 + AAC LC in MP4). Re-encode via ffmpeg only if a specific file fails on
hardware.

## HTTP media server

- `vlc_http_HostNew` on configured `http-port` (default chosen to avoid
  Chromecast collision if both can run).
- URL shape: `http://<lan-ip>:<port>/airplay/<token>/media.mp4`
- High-entropy token; reject GET without valid token.
- Prefer file-backed httpd serving (not live FIFO) for this tranche.
- Host lifetime tied to sout session Close/teardown.

## Session FSM

```
Idle → Pairing → Ready → Playing ⇄ Paused
                         ↓
                      Stopping → Idle
                         ↓
                      Dead (error / teardown)
```

| Event            | Behavior |
|------------------|----------|
| Play             | Announce tokenized Content-Location + Start-Position via control `/play` (plist) |
| Pause / Resume   | Control rate / pause / play as required by receiver |
| Seek             | Scrub + resume from new Start-Position |
| Stop / Close     | Stop + teardown; **keep** keystore identity |
| EOF              | Clean stop → Ready/Idle (reconnectable) |
| Reconnect / restart | Keystore hit → skip Pairing → Ready → Play |

## Pairing & keystore

Clean-room HAP-style AirPlay pairing (behavioral reference only; no GPL copy):

1. **Pair-setup:** PIN via `vlc_dialog_*`; SRP-6a; exchange/verify Ed25519
   long-term keys.
2. **Pair-verify:** Curve25519 ephemeral + Ed25519 using stored keys; derive
   session keys for encrypted control HTTP (ChaCha20-Poly1305 as required).
3. Crypto: use existing VLC/contrib primitives where possible; smallest portable
   helpers under `airplay/` if a primitive is missing — no new large dependency.

Keystore mapping:

| Key            | Value |
|----------------|-------|
| `KEY_PROTOCOL` | `"airplay"` |
| `KEY_SERVER`   | renderer stable id |
| secret         | versioned blob: our LTK + peer LTK (+ minimal verify metadata) |

- Label: `VLC AirPlay <display name>`
- PIN is never stored; never placed in sout/URI/id
- Wrong PIN / cancel → no partial store
- Verify failure after device reset → remove/replace entry and re-prompt

## Security boundaries

- No FairPlay, no Apple private material
- No secrets in discovery URI, sout string, or renderer id
- HTTP media obscurity via token (LAN trust model; not end-user auth)
- Pairing material only in VLC keystore backends

## Testing

### Unit / fake

- Pairing FSM transitions
- Keystore store/find/remove helpers (memory keystore where possible)
- HTTP token accept/reject
- Plist encode/decode for control payloads used
- Existing discovery tests remain green; add URI-publish coverage when wired

### Real hardware (required)

Against a real Apple TV with a known-good local MP4 (e.g. Connections S01E01):

1. Discover → select → PIN dialog → pair
2. Playback via tokenized HTTP (receiver can fetch LAN URL)
3. Pause / seek / resume / stop / EOF / teardown
4. Quit and relaunch VLC → no PIN → play again
5. Optional HomePod / audio-only path — not a gate
6. Do not block on multiroom or every hardware variant

### Build

Run airplay unit tests and build/run what the Windows environment allows.
Small reviewable commits; do not push unless asked.

## Implementation commit slices (suggested)

1. Scaffold `stream_out/airplay` + Meson/autotools + empty Open/Close
2. Plist + unit tests
3. HTTP token media server + unit tests
4. Pairing FSM + keystore + dialog + unit tests
5. Session control play/pause/seek/stop/teardown
6. Discovery publish connectable URI + `device-id` wiring
7. Hardware validation fixes as needed

## References

- `doc/airplay-foundation.md` — discovery / identity foundation
- `modules/stream_out/chromecast/` — httpd + sout lifecycle patterns only
- `include/vlc_keystore.h` — credential persistence API
