# AirPlay renderer foundation

## Scope and terminology

This document covers the foundation tranche for AirPlay support in VLC:
DNS-SD discovery of `_airplay._tcp` and `_raop._tcp`, stable renderer
identity, and protocol-neutral renderer item extensions.

**Out of scope here:** pairing, FairPlay, media transport, RAOP streaming,
AirPlay 2 sync, display mirroring, and AirPlay *receiver* mode.

**Terminology**

- *AirPlay service* (`_airplay._tcp`): video/control-oriented advertisement.
- *RAOP service* (`_raop._tcp`): AirTunes/audio advertisement.
- *Physical receiver*: one logical device that may advertise both services.
- *Stable renderer id*: protocol identity that survives IP/port changes.
- *Not connectable*: a discovered renderer with an empty sout (no stream-output
  chain yet).

## Why `_airplay` and `_raop` are aggregated

Apple receivers commonly advertise both services for one box. Publishing two
UI rows (one “AirPlay”, one “RAOP”) is wrong for users and for session setup.
Aggregation uses identity evidence only (device id / RAOP hardware prefix /
public key), never shared hostname, friendly name, or model alone.

## Stable identity rules

Preference order:

1. Normalized AirPlay `deviceid`
2. Normalized RAOP instance hardware-id prefix (`AABBCCDDEEFF@Name`)
3. Fingerprint of advertised `pk`
4. Temporary `dnssd:` fallback from the DNS-SD instance name

IP addresses are never used as persistent identity.

## Discovery data flow

```
libmicrodns callbacks
        |
        v
 record collection (PTR/SRV/TXT/A/AAAA)
        |
        +-- Chromecast TXT handler --> publish chromecast renderer (unchanged sout)
        |
        +-- AirPlay/RAOP TXT parse --> airplay_discovered_device table
                                      merge by stable identity
                                      publish type=airplay, id=..., uri=NULL
```

Chromecast-specific fields (`fn`, `ca`, `md`, `ic`) stay in the Chromecast
handler. AirPlay feature masks remain private to discovery for future session
negotiation; only conservative audio/video flags are exported on the renderer
item.

IPv4 continues to work. AAAA is accepted when libmicrodns provides it (same as
before). mdns_init still binds `MDNS_ADDR_IPV4`; dual-stack listen remains a
follow-up if libmicrodns/API work makes it clean.

## Renderer API additions

- `struct vlc_renderer_item_desc` + `vlc_renderer_item_new_ex()`
- `vlc_renderer_item_id()` / `vlc_renderer_item_capabilities()`
- Legacy `vlc_renderer_item_new()` remains a compatibility wrapper
- `vlc_renderer_item_t` stays opaque
- Empty sout means “not connectable”; input refuses to build `#` sout chains
- Qt keys prefer `type#id`, falling back to `type-sout` for legacy items

Secrets, PINs, and pairing material must never appear in uri/sout/id.

## Security boundaries

- No FairPlay, no Apple private keys/certs, no protected-media circumvention
- No new large dependency in this tranche
- Pairing credentials (next tranche) go through VLC keystore, not sout strings

## Planned portable module layout

```
modules/services_discovery/
  microdns.c              # DNS-SD collector + protocol dispatch
  airplay_discovery.[ch]  # parse + aggregate (testable without multicast)

modules/stream_out/airplay/   # NEXT TRANCHE
  airplay.c               # sout module boundary
  pairing.c               # PIN / HAP-style pairing state machine
  session.c               # play/pause/seek/stop/teardown
  http_media.c            # tokenized local HTTP for direct video
```

Protocol and session code stay out of Qt/Win32 UI modules.

## Licensing / clean-room constraints

Implementation is independent LGPL code. OwnTone, Shairport Sync, UxPlay, and
public docs are behavioral references only — no GPL code copied into VLC.

## Known gaps

- No pairing or streaming yet (intentional)
- Per-endpoint independent expiry is coarse (device-level last_seen)
- Avahi/Bonjour modules not yet taught AirPlay (microdns path first; Windows)
- libvlc public wrappers for id/capabilities not added yet
- mdns still IPv4 listen socket; AAAA answers still handled when present

## Next implementation tranche

End-to-end on Windows:

1. Select Apple TV in VLC
2. Enter pairing code once; store identity in VLC keystore
3. Serve a known-good local H.264/AAC MP4 via tokenized HTTP
4. Instruct receiver to play; support pause/seek/stop/EOF/teardown/reconnect
5. Restart VLC and reconnect without pairing again

### Testing strategy (real hardware available)

The developer has actual AirPlay receivers. Use them deliberately:

- **Fake / unit tests first** for TXT/aggregation regressions, pairing FSM
  transitions, HTTP token auth, and control plist encode/decode without
  multicast.
- **Real devices required** for pairing crypto/PIN flow, keystore reuse after
  VLC restart, play/pause/seek/stop/EOF/teardown, and LAN reachability of the
  tokenized HTTP URL from the receiver.
- Prefer one Apple TV for the end-to-end video demo; add a HomePod (or other
  audio-only receiver) when validating audio-only capability mapping.
- Do not block the tranche on multiroom sync or every hardware variant.

### Next-agent prompt

```
Continue AirPlay on branch feature/airplay-foundation (after ae32222765 /
doc/airplay-foundation.md). Foundation is done: stable renderer id API, Qt
type#id keys, microdns protocol descriptors, AirPlay/RAOP aggregation
publishing type=airplay with empty sout.

Implement the next vertical slice on Windows:
- modules/stream_out/airplay/ (portable; keep out of Qt/Win32 UI)
- Pairing once; store identity in VLC keystore (no secrets in sout/URI)
- Serve local H.264/AAC MP4 via tokenized HTTP; instruct receiver to play
- pause/seek/stop/EOF/teardown/reconnect; restart VLC without re-pairing
- Extract only what is needed from Chromecast session bridge patterns
- No FairPlay / Apple private material

Testing (real AirPlay hardware is available):
- Keep fake/unit coverage for parsers, FSM, HTTP token, plist
- Must validate pairing, keystore reuse, playback controls, and HTTP
  reachability against a real Apple TV
- Optionally validate audio-only path on a HomePod / audio accessory
- Do not require multiroom or full model matrix for this tranche

Run airplay unit tests; build/run whatever the environment allows.
Small reviewable commits; do not push unless asked.
```
