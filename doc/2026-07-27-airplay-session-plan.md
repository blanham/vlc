# AirPlay File-Backed Session Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a discovered Apple TV connectable from VLC on Windows: pair once (PIN dialog + keystore), serve the current local H.264/AAC MP4 over tokenized HTTP, and drive play/pause/seek/stop/teardown/reconnect without FairPlay.

**Architecture:** Thin URL caster. Discovery publishes `airplay://host:port` plus `extra_sout=device-id=<stable_id>`. Portable `modules/stream_out/airplay/` resolves the current player media to a local path, pairs via HAP-style `/pair-setup` + `/pair-verify`, serves the file from `vlc_http_HostNew`, and instructs the receiver with `/play` (plist). Chromecast is a lifecycle/httpd reference only.

**Tech Stack:** C (VLC sout plugin), Meson (+ Autotools mirror), libgcrypt (SRP/Ed25519/X25519/ChaCha20-Poly1305), VLC httpd, `vlc_dialog_wait_login`, `vlc_keystore_*`, `vlc_player_HoldCurrentMedia`.

**Spec:** `doc/airplay-session-slice.md` (committed). Foundation: `doc/airplay-foundation.md`.

## Global Constraints

- No FairPlay / Apple private keys, certs, or protected-media circumvention
- No secrets in sout, URI, or renderer id (PIN never stored; LTKs only in keystore)
- Protocol code stays in `modules/stream_out/airplay/` (not Qt/Win32 UI)
- Clean-room LGPL; OwnTone/Shairport/UxPlay are behavioral references only — do not copy GPL code
- File-backed only this tranche (no live remux / `cc_demux`)
- Small reviewable commits; do not push unless asked
- Real Apple TV validation is required before calling the tranche done; unit tests are not a substitute

## File structure

| Path | Responsibility |
|------|----------------|
| `modules/stream_out/airplay/airplay.c` | Sout module boundary, options, Open/Close orchestration |
| `modules/stream_out/airplay/airplay.h` | Shared session types / opaque handles |
| `modules/stream_out/airplay/plist.c` / `plist.h` | Minimal binary plist encode/decode |
| `modules/stream_out/airplay/http_media.c` / `http_media.h` | Tokenized local file HTTP (+ Range) |
| `modules/stream_out/airplay/path.c` / `path.h` | Resolve current player media → local path |
| `modules/stream_out/airplay/keystore_id.c` / `keystore_id.h` | Versioned identity blob store/find/remove |
| `modules/stream_out/airplay/crypto.c` / `crypto.h` | GCCrypt wrappers: SRP-6a, Ed25519, X25519, ChaCha20-Poly1305, HKDF |
| `modules/stream_out/airplay/pairing.c` / `pairing.h` | Pair-setup / pair-verify FSM + PIN dialog |
| `modules/stream_out/airplay/session.c` / `session.h` | Control HTTP client + play/pause/seek/stop/teardown |
| `modules/stream_out/airplay/meson.build` | Module registration |
| `modules/stream_out/Makefile.am` | Autotools plugin list |
| `modules/services_discovery/microdns.c` | Publish connectable URI + `device-id` |
| `test/modules/stream_out/airplay/*.c` | Unit tests (plist, token, FSM, keystore blob, path helpers) |
| `test/modules/meson.build` | Register tests |
| `doc/airplay-foundation.md` | Point next-agent at this plan when done |

---

### Task 1: Scaffold `stream_out_airplay` module

**Files:**
- Create: `modules/stream_out/airplay/airplay.c`
- Create: `modules/stream_out/airplay/airplay.h`
- Create: `modules/stream_out/airplay/meson.build`
- Modify: `modules/stream_out/meson.build` (add `subdir('airplay')`)
- Modify: `modules/stream_out/Makefile.am` (add sources + `sout_PLUGINS`)

**Interfaces:**
- Produces: sout shortcut `airplay`, capability `sout output`, Open returns success with drop ops (ES discarded this tranche)

- [ ] **Step 1: Add headers and stub module**

Create `modules/stream_out/airplay/airplay.h`:

```c
#ifndef VLC_AIRPLAY_SOUT_H
#define VLC_AIRPLAY_SOUT_H

#include <vlc_common.h>
#include <vlc_sout.h>

#define SOUT_CFG_PREFIX "sout-airplay-"
#define AIRPLAY_DEFAULT_HTTP_PORT 8090  /* avoid Chromecast 8010 */

struct airplay_sys
{
    char *ip;
    uint16_t port;
    uint16_t http_port;
    char *device_id;   /* stable renderer id; not a secret */
    char *device_name;
};

#endif
```

Create `modules/stream_out/airplay/airplay.c` modeled on `modules/stream_out/dummy.c`: parse options `ip`, `port`, `http-port`, `device-id`, `device-name`; store in `sout_stream_sys_t`; Add/Del/Send drop blocks; Close frees strings.

```c
static const char *const ppsz_sout_options[] = {
    "ip", "port", "http-port", "device-id", "device-name", NULL
};
```

Module:

```c
vlc_module_begin()
    set_shortname(N_("AirPlay"))
    set_description(N_("AirPlay stream output"))
    set_capability("sout output", 0)
    add_shortcut("airplay")
    add_string(SOUT_CFG_PREFIX "ip", NULL, IP_TEXT, IP_LONGTEXT)
        change_private()
    add_integer(SOUT_CFG_PREFIX "port", 7000, PORT_TEXT, PORT_LONGTEXT)
        change_private()
    add_integer(SOUT_CFG_PREFIX "http-port", AIRPLAY_DEFAULT_HTTP_PORT,
                HTTP_PORT_TEXT, HTTP_PORT_LONGTEXT)
    add_string(SOUT_CFG_PREFIX "device-id", NULL, ID_TEXT, ID_LONGTEXT)
        change_private()
    add_string(SOUT_CFG_PREFIX "device-name", NULL, NAME_TEXT, NAME_LONGTEXT)
        change_private()
    set_callback(Open)
vlc_module_end()
```

- [ ] **Step 2: Wire Meson**

`modules/stream_out/airplay/meson.build`:

```meson
vlc_modules += {
    'name' : 'stream_out_airplay',
    'sources' : files('airplay.c'),
    'dependencies' : [socket_libs, gcrypt_dep],
    'enabled' : get_option('stream_outputs') and gcrypt_dep.found(),
    'shortname' : 's_o_airp',
}
```

Append to `modules/stream_out/meson.build`:

```meson
subdir('airplay')
```

- [ ] **Step 3: Wire Autotools**

In `modules/stream_out/Makefile.am`, add `libstream_out_airplay_plugin_la_SOURCES`, `LIBADD = $(SOCKET_LIBS) $(GCRYPT_LIBS)`, and append to `sout_PLUGINS` under `ENABLE_SOUT` (mirror HLS/chromecast gating style; require gcrypt like other crypto plugins).

- [ ] **Step 4: Commit**

```bash
git add modules/stream_out/airplay modules/stream_out/meson.build modules/stream_out/Makefile.am
git commit -m "$(cat <<'EOF'
sout: scaffold AirPlay stream output module

Add a portable airplay sout stub with option parsing so later
pairing/HTTP/session pieces have a module boundary to hang on.
EOF
)"
```

---

### Task 2: Binary plist encode/decode + unit tests

**Files:**
- Create: `modules/stream_out/airplay/plist.h`
- Create: `modules/stream_out/airplay/plist.c`
- Create: `test/modules/stream_out/airplay/plist.c`
- Modify: `modules/stream_out/airplay/meson.build` (add `plist.c`)
- Modify: `test/modules/meson.build`

**Interfaces:**
- Produces:
  - `typedef struct airplay_plist airplay_plist;`
  - `airplay_plist *airplay_plist_new(void);`
  - `void airplay_plist_release(airplay_plist *);`
  - `int airplay_plist_set_string(airplay_plist *, const char *key, const char *val);`
  - `int airplay_plist_set_real(airplay_plist *, const char *key, double val);`
  - `int airplay_plist_set_data(airplay_plist *, const char *key, const void *data, size_t len);`
  - `int airplay_plist_get_string(const airplay_plist *, const char *key, char **out);`
  - `int airplay_plist_get_data(const airplay_plist *, const char *key, uint8_t **out, size_t *len);`
  - `int airplay_plist_serialize(const airplay_plist *, uint8_t **out, size_t *len);` /* binary plist */
  - `airplay_plist *airplay_plist_parse(const uint8_t *data, size_t len);`

- [ ] **Step 1: Write failing tests**

`test/modules/stream_out/airplay/plist.c` (same assert/failures style as `test/modules/services_discovery/airplay.c`):

1. Build dict `{ Content-Location = "http://10.0.0.1/x"; Start-Position = 0.25 }` → serialize → parse → round-trip strings/reals.
2. Reject truncated / non-bplist headers.
3. Data value round-trip (32-byte key material).

- [ ] **Step 2: Run test to verify it fails**

```bash
# From Meson build dir once test is registered; or compile smoke:
# Expected: missing symbols / link failure before implementation
```

Register in `test/modules/meson.build`:

```meson
vlc_tests += {
    'name' : 'test_modules_airplay_plist',
    'sources' : files(
        'stream_out/airplay/plist.c',
        '../../modules/stream_out/airplay/plist.c'),
    'suite' : ['modules', 'test_modules'],
}
```

- [ ] **Step 3: Implement minimal binary plist**

Support only what AirPlay control needs: dict, string (ASCII/UTF-8), real (float64), data, integer (used by pairing TLV wrappers if needed). Magic `bplist00`. No XML writer required this tranche (binary only). Keep under ~400 lines; reject unsupported object types cleanly.

- [ ] **Step 4: Run tests — expect PASS**

```bash
meson test -C <builddir> test_modules_airplay_plist --print-errorlogs
```

- [ ] **Step 5: Commit**

```bash
git commit -m "sout/airplay: add minimal binary plist helper"
```

---

### Task 3: Tokenized HTTP media server + unit tests

**Files:**
- Create: `modules/stream_out/airplay/http_media.h`
- Create: `modules/stream_out/airplay/http_media.c`
- Create: `test/modules/stream_out/airplay/http_token.c`
- Modify: meson sources + `test/modules/meson.build`

**Interfaces:**
- Produces:
  - `typedef struct airplay_http_media airplay_http_media;`
  - `airplay_http_media *airplay_http_media_start(vlc_object_t *obj, uint16_t http_port, const char *filepath);`
  - `void airplay_http_media_stop(airplay_http_media *);`
  - `const char *airplay_http_media_token(const airplay_http_media *);`
  - `char *airplay_http_media_url(const airplay_http_media *, const char *lan_ip);` /* returns malloc'd URL */
  - `bool airplay_http_token_valid(const char *expected, const char *got);` /* testable pure helper */
  - `char *airplay_http_generate_token(void);` /* 16+ random bytes, hex or base64url */

URL shape (exact): `http://<lan-ip>:<port>/airplay/<token>/media.mp4`

Implementation notes:
- `vlc_http_HostNew(obj)` then `httpd_UrlNew` + `httpd_UrlCatch` for GET/HEAD.
- Reject unauthorized GETs: core httpd exact-path match yields **404** for
  unknown tokens (accepted); callback returns empty **403** only if a
  mismatch reaches it.
- Serve file with `Accept-Ranges: bytes` and honor `Range` (206) — Apple TV scrubbing needs this.
- MIME `video/mp4`.
- Token from `vlc_rand_bytes` / gcrypt strong random.

- [ ] **Step 1: Write failing token unit tests** (no httpd required)

```c
/* test_modules_airplay_http_token */
expect_true(airplay_http_token_valid("abcd", "abcd"), "equal ok");
expect_true(!airplay_http_token_valid("abcd", "abce"), "mismatch");
expect_true(!airplay_http_token_valid("abcd", NULL), "null rejected");
expect_true(!airplay_http_token_valid("abcd", "abc"), "length mismatch");
/* generate_token: non-NULL, length >= 32 hex chars, two calls differ */
```

- [ ] **Step 2: Implement token helpers + httpd file server**

- [ ] **Step 3: Run `test_modules_airplay_http_token` — PASS**

- [ ] **Step 4: Commit**

```bash
git commit -m "sout/airplay: serve local MP4 behind HTTP token path"
```

---

### Task 4: Resolve current local media path

**Files:**
- Create: `modules/stream_out/airplay/path.h`
- Create: `modules/stream_out/airplay/path.c`
- Create: `test/modules/stream_out/airplay/path.c`

**Interfaces:**
- Produces:
  - `char *airplay_path_from_uri(const char *uri);` /* vlc_uri2path + reject non-file */
  - `char *airplay_resolve_local_path(vlc_object_t *obj);`
    - Walk `vlc_object_parent` starting at `obj`.
    - For each parent, treat as `vlc_player_t *` only when `vlc_player_HoldCurrentMedia` is usable: call under `vlc_player_Lock`/`Unlock`. Document that renderer sout parent is the player (`input_resource_New(VLC_OBJECT(player))` → `sout_NewInstance(p_parent)`).
    - If cast/lock is unsafe on a non-player, detect via NULL media and continue walking.
    - `input_item_GetURI` → `airplay_path_from_uri` → `access(path, R_OK)`.
    - On failure return NULL (caller shows `vlc_dialog_display_error`).

- [ ] **Step 1: Unit-test `airplay_path_from_uri`**

```c
/* file:///C:/foo/bar.mp4 → Windows path (vlc_uri2path behavior) */
/* http://example.com/x → NULL */
/* NULL → NULL */
```

- [ ] **Step 2: Implement path helpers**

- [ ] **Step 3: Tests PASS; commit**

```bash
git commit -m "sout/airplay: resolve current player media to local path"
```

---

### Task 5: Keystore identity blob

**Files:**
- Create: `modules/stream_out/airplay/keystore_id.h`
- Create: `modules/stream_out/airplay/keystore_id.c`
- Create: `test/modules/stream_out/airplay/keystore_id.c`

**Interfaces:**
- Produces:

```c
#define AIRPLAY_ID_BLOB_VERSION 1
struct airplay_identity
{
    uint8_t our_ed25519_sk[64];
    uint8_t our_ed25519_pk[32];
    uint8_t peer_ed25519_pk[32];
    uint8_t has_peer;
};

int airplay_identity_store(vlc_object_t *obj, const char *device_id,
                           const char *label, const struct airplay_identity *id);
int airplay_identity_load(vlc_object_t *obj, const char *device_id,
                          struct airplay_identity *out);
int airplay_identity_remove(vlc_object_t *obj, const char *device_id);
```

Keystore values:
- `KEY_PROTOCOL = "airplay"`
- `KEY_SERVER = device_id` (stable id string)
- Secret = little-endian version `uint32_t` + packed identity fields

- [ ] **Step 1: Test encode/decode of blob round-trip in-memory (no keystore module required)** via pack/unpack helpers exported for tests:

```c
int airplay_identity_pack(const struct airplay_identity *, uint8_t **out, size_t *len);
int airplay_identity_unpack(const uint8_t *in, size_t len, struct airplay_identity *out);
```

- [ ] **Step 2: Implement pack/unpack + store/load/remove using `vlc_keystore_create/store/find/remove/release`**

- [ ] **Step 3: If memory keystore available in test harness, store/find/remove; otherwise pack tests only**

- [ ] **Step 4: Commit**

```bash
git commit -m "sout/airplay: persist pairing identity in VLC keystore"
```

---

### Task 6: Crypto primitives (gcrypt)

**Files:**
- Create: `modules/stream_out/airplay/crypto.h`
- Create: `modules/stream_out/airplay/crypto.c`
- Create: `test/modules/stream_out/airplay/crypto.c`

**Interfaces:**
- Produces (clean-room; HAP/RFC primitives):

```c
void airplay_crypto_init(void); /* vlc_gcrypt_init once */

int airplay_ed25519_keypair(uint8_t sk[64], uint8_t pk[32]);
int airplay_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t len,
                         const uint8_t sk[64]);
int airplay_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t len,
                           const uint8_t pk[32]);

int airplay_x25519(uint8_t shared[32], const uint8_t sk[32], const uint8_t pk[32]);
int airplay_x25519_keypair(uint8_t sk[32], uint8_t pk[32]);

int airplay_chacha_encrypt(uint8_t *out, size_t *out_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *ad, size_t ad_len);
int airplay_chacha_decrypt(...); /* inverse */

int airplay_hkdf_sha512(uint8_t *out, size_t out_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len);

/* SRP-6a with HAP 3072-bit group; username "Pair-Setup" */
typedef struct airplay_srp_ctx airplay_srp_ctx;
airplay_srp_ctx *airplay_srp_client_new(const char *pin);
void airplay_srp_client_release(airplay_srp_ctx *);
int airplay_srp_client_start(airplay_srp_ctx *, uint8_t **A, size_t *A_len);
int airplay_srp_client_finish(airplay_srp_ctx *,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *B, size_t B_len,
                              uint8_t **M1, size_t *M1_len,
                              uint8_t shared_key[32]);
int airplay_srp_client_verify_proof(airplay_srp_ctx *,
                                    const uint8_t *M2, size_t M2_len);
```

- [ ] **Step 1: Unit tests with known vectors** where practical (Ed25519 RFC 8032 first vector; ChaCha20-Poly1305 RFC 8439 §2.8.2; HKDF-SHA512 RFC 5869 style). SRP: start/finish self-consistency against a fixture salt/B if available; otherwise test PIN rejection path with malformed B.

- [ ] **Step 2: Implement with libgcrypt** (`#include <vlc_gcrypt.h>`, `<gcrypt.h>`). If a primitive is missing from the linked gcrypt, implement the smallest portable helper in this file (document which).

- [ ] **Step 3: Tests PASS; commit**

```bash
git commit -m "sout/airplay: add gcrypt-backed pairing crypto helpers"
```

---

### Task 7: Pairing FSM + PIN dialog

**Files:**
- Create: `modules/stream_out/airplay/pairing.h`
- Create: `modules/stream_out/airplay/pairing.c`
- Create: `test/modules/stream_out/airplay/pairing_fsm.c`

**Interfaces:**
- Consumes: crypto, keystore_id, plist
- Produces:

```c
enum airplay_pair_state {
    AIRPLAY_PAIR_IDLE,
    AIRPLAY_PAIR_NEED_PIN,
    AIRPLAY_PAIR_SETUP,
    AIRPLAY_PAIR_VERIFY,
    AIRPLAY_PAIR_READY,
    AIRPLAY_PAIR_FAILED,
};

typedef struct airplay_pairing airplay_pairing;

airplay_pairing *airplay_pairing_new(vlc_object_t *obj, const char *ip,
                                     uint16_t port, const char *device_id,
                                     const char *device_name);
void airplay_pairing_release(airplay_pairing *);

/* Loads keystore; if missing runs dialog+setup; then verify.
 * Returns VLC_SUCCESS and leaves state READY, or error. */
int airplay_pairing_ensure(airplay_pairing *);

enum airplay_pair_state airplay_pairing_state(const airplay_pairing *);

/* Test seam: inject PIN without dialog */
void airplay_pairing_set_pin_for_tests(airplay_pairing *, const char *pin);

/* Encrypt/decrypt control HTTP bodies after READY */
int airplay_pairing_encrypt(airplay_pairing *, ...);
int airplay_pairing_decrypt(airplay_pairing *, ...);
```

PIN UX:
```c
char *user = NULL, *pin = NULL;
bool store = false;
int d = vlc_dialog_wait_login(obj, &user, &pin, &store, "",
    _("AirPlay Pairing"),
    _("Enter the pairing PIN shown on %s"), device_name);
free(user);
/* use pin; free on all paths; never store pin */
```

Control transport: TCP HTTP to `ip:port` for `/pair-setup` and `/pair-verify` (POST, `Content-Type: application/octet-stream` or `application/x-apple-binary-plist` as required by observed HAP pairing). Implement TLV or plist per public HAP pair-setup steps M1–M6 / verify M1–M2 — behavioral clean-room only.

On success: `airplay_identity_store`. On verify fail after load: `airplay_identity_remove` then retry setup once with new PIN prompt.

- [ ] **Step 1: FSM unit tests without network**

Drive states with a test double for “send/recv” injected via function pointers in `airplay_pairing` (set in tests):

```c
typedef int (*airplay_pair_transport_cb)(void *opaque, const char *path,
    const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
void airplay_pairing_set_transport_for_tests(airplay_pairing *,
    airplay_pair_transport_cb cb, void *opaque);
```

Cases: idle→need PIN→setup fail; setup ok→verify ok→READY; load identity→verify ok skips PIN; verify fail→remove→NEED_PIN.

- [ ] **Step 2: Implement pairing.c**

- [ ] **Step 3: Tests PASS; commit**

```bash
git commit -m "sout/airplay: implement HAP-style pairing with keystore reuse"
```

---

### Task 8: Session control (play/pause/seek/stop/teardown)

**Files:**
- Create: `modules/stream_out/airplay/session.h`
- Create: `modules/stream_out/airplay/session.c`
- Create: `test/modules/stream_out/airplay/session_plist.c` (payload builders)

**Interfaces:**
- Consumes: pairing (encrypt), plist, http_media URL
- Produces:

```c
typedef struct airplay_session airplay_session;

airplay_session *airplay_session_new(vlc_object_t *obj, airplay_pairing *pair,
                                     const char *ip, uint16_t port);
void airplay_session_release(airplay_session *);

int airplay_session_play(airplay_session *, const char *content_location,
                         double start_position /* 0.0–1.0 */);
int airplay_session_rate(airplay_session *, double rate); /* 0 pause, 1 play */
int airplay_session_scrub(airplay_session *, double position);
int airplay_session_stop(airplay_session *);
int airplay_session_teardown(airplay_session *);
```

Control requests (headers as required by AirPlay reverse HTTP): `/play`, `/rate`, `/scrub`, `/stop` — bodies via plist where applicable (`Content-Location`, `Start-Position`). Use pairing encryption once READY.

- [ ] **Step 1: Unit-test plist payloads for `/play` contain exact keys**

- [ ] **Step 2: Implement session HTTP client** (blocking sockets ok for tranche; reuse VLC `vlc_tls` only if ATV requires HTTPS — prefer plain HTTP on port 7000 first; adjust if hardware shows otherwise)

- [ ] **Step 3: Commit**

```bash
git commit -m "sout/airplay: add receiver play/pause/seek/stop control"
```

---

### Task 9: Wire Open/Close orchestration in `airplay.c`

**Files:**
- Modify: `modules/stream_out/airplay/airplay.c`
- Modify: `modules/stream_out/airplay/airplay.h`
- Modify: `modules/stream_out/airplay/meson.build` (all sources)

**Interfaces:**
- Consumes: path, http_media, pairing, session

Open sequence:
1. `config_ChainParse` options; require `ip` + `device-id`.
2. `path = airplay_resolve_local_path(VLC_OBJECT(stream))`; on NULL → `vlc_dialog_display_error` + fail.
3. `pair = airplay_pairing_new(...); airplay_pairing_ensure(pair)`.
4. `http = airplay_http_media_start(..., http_port, path)`.
5. Build LAN IP for URL: `httpd_ServerIP` after first client **or** pick host interface toward `ip` (use existing VLC net helpers / `net_GetIP` patterns from Chromecast `renderer` code). Must be reachable from Apple TV — not `127.0.0.1`.
6. `session_play(url, 0.0)`.
7. Store handles in `airplay_sys`.

Close / teardown:
1. `airplay_session_stop` + `teardown`
2. `airplay_http_media_stop`
3. `airplay_pairing_release` (does **not** remove keystore)
4. Free path/options

Add/Del/Send: continue discarding ES (file-backed; demux still runs into sout).

**Pause/seek bridge (no Chromecast demux_filter):** after resolving the
player parent in Open, register `vlc_player_AddListener` with:
- `on_state_changed` → PLAYING/PAUSED/STOPPED → `airplay_session_rate` /
  `stop`
- `on_position_changed` (or seek completion path) → `airplay_session_scrub`
  with normalized 0–1 position when the user seeks
Remove the listener in Close. This is the minimal Chromecast-inspired
“session bridge” without copying `cc_demux`.

Also implement optional `ops.control` / `ops.close` as needed for cleanup.

- [ ] **Step 1: Implement orchestration**

- [ ] **Step 2: Build module in available Windows/Meson env**

- [ ] **Step 3: Commit**

```bash
git commit -m "sout/airplay: wire pairing, HTTP media, and session on Open"
```

---

### Task 10: Discovery publishes connectable URI

**Files:**
- Modify: `modules/services_discovery/microdns.c` (`airplay_publish`)
- Modify: `modules/services_discovery/meson.build` if needed (no)
- Modify: `test/modules/services_discovery/airplay.c` **or** add publish helper test if URI builder extracted

**Interfaces:**
- Change `airplay_publish` to set:

```c
char *uri = NULL;
char *extra = NULL;
const struct airplay_endpoint *ep =
    dev->airplay.valid ? &dev->airplay : NULL;
if (ep == NULL)
    goto no_uri; /* keep unconnectable if only RAOP and no airplay port */

if (asprintf(&uri, "airplay://%s%s%s:%u",
             ep->ipv6 ? "[" : "", ep->host, ep->ipv6 ? "]" : "",
             ep->port) < 0)
    ...
if (asprintf(&extra, "device-id=%s", dev->stable_id) < 0)
    ...

desc.uri = uri;
desc.extra_sout = extra;
desc.id = dev->stable_id;
/* demux_filter stays NULL */
```

Prefer `_airplay` endpoint only this tranche (video/control). Free `uri`/`extra` after `vlc_renderer_item_new_ex` (it copies into sout).

Also set protocol table `psz_sout_module` for airplay entries from `NULL` to `"airplay"` if still NULL so URI scheme matches.

- [ ] **Step 1: Update `airplay_publish` + protocol table**

- [ ] **Step 2: Extend discovery unit tests** if a pure helper is extracted (`airplay_build_renderer_uri`); otherwise manual review of publish path + keep existing tests green

```bash
meson test -C <builddir> test_modules_airplay_discovery --print-errorlogs
```

- [ ] **Step 3: Commit**

```bash
git commit -m "mdns: publish connectable AirPlay renderer URIs"
```

---

### Task 11: Run all AirPlay unit tests + hardware checklist

**Files:**
- Modify: `doc/airplay-foundation.md` (replace next-agent prompt with pointer to this plan + remaining hardware steps)
- Optionally: `doc/airplay-session-slice.md` status line → “Implementation in progress / done”

- [ ] **Step 1: Run unit tests**

```bash
meson test -C <builddir> \
  test_modules_airplay_discovery \
  test_modules_airplay_plist \
  test_modules_airplay_http_token \
  test_modules_airplay_path \
  test_modules_airplay_keystore_id \
  test_modules_airplay_crypto \
  test_modules_airplay_pairing_fsm \
  --print-errorlogs
```

Expected: all PASS.

- [ ] **Step 2: Hardware validation (manual, required)**

Using Apple TV + e.g. `E:\Connections\Season 1\Connections S01E01 - The Trigger Effect.mp4` (already H.264+AAC):

1. Open file in VLC → select AirPlay renderer → PIN dialog → pair
2. Confirm ATV fetches tokenized LAN URL and plays
3. Pause / seek / resume / stop / EOF / teardown
4. Quit VLC entirely → relaunch → same device → **no PIN** → play
5. Optional HomePod audio-only — not a gate

Log failures and fix in small follow-up commits on this branch.

- [ ] **Step 3: Final doc commit**

```bash
git commit -m "doc: mark AirPlay session slice implementation status"
```

---

## Self-review (spec coverage)

| Spec requirement | Task |
|------------------|------|
| `modules/stream_out/airplay/` layout | 1, 2–9 |
| Pair once + `vlc_dialog` PIN | 7 |
| Keystore identity, no secrets in sout | 5, 7, 10 (`device-id` only) |
| Current local H.264/AAC MP4 via tokenized HTTP | 3, 4, 9 |
| play/pause/seek/stop/EOF/teardown/reconnect | 8, 9 |
| Restart without re-pair | 5, 7, 11 |
| Chromecast patterns only (httpd lifecycle) | 3, 9 |
| No FairPlay | Global + 6/7 clean-room |
| Discovery connectable URI | 10 |
| Unit tests parsers/FSM/HTTP/plist | 2, 3, 5, 6, 7 |
| Real Apple TV validation | 11 |
| Small commits, no push | each task commit step |

**Type consistency:** `device_id` string = discovery `stable_id` = keystore `KEY_SERVER` = sout `device-id` option. HTTP URL builder uses `airplay_http_media_url`. Pairing READY required before `airplay_session_play`.
