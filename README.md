<p align="center">
  <h1 align="center">TEESimulator-RS</h1>
  <p align="center"><b>Pass hardware security checks on a rooted Android phone</b></p>
  <p align="center">
    <a href="https://github.com/1vivy/TEESimulator/actions/workflows/build.yml"><img src="https://github.com/1vivy/TEESimulator/actions/workflows/build.yml/badge.svg" alt="Build"></a>
    <img src="https://img.shields.io/badge/Android-10%2B-green?logo=android" alt="Android 10+">
    <a href="https://t.me/superpowers9"><img src="https://img.shields.io/badge/Telegram-community-blue?logo=telegram" alt="Telegram"></a>
  </p>
</p>

---

> [!NOTE]
> This beta continues [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS), itself based on [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator). It adds certificate generation written in Rust, persistent keys, and donor-backed RKA in which one donor phone serves several candidate phones.

## What it does

Some Android apps refuse to run on a rooted phone. They ask the phone to prove it still has a genuine security chip, a check called hardware attestation. A rooted phone normally fails that check.

TEESimulator makes it pass. Android runs a system process named `keystore2` that answers these proof requests. TEESimulator sits in front of `keystore2`, watches for the requests apps make to create keys and read their certificates, and builds the proof itself: a full chain of certificates signed by your `keybox.xml`. To the app, the phone looks genuine.

The module keeps the `tricky_store` module ID and its familiar configuration files. Installing it therefore upgrades an existing TrickyStore/TEESimulator installation in place instead of creating a second colliding module. The added KernelSU WebUI exposes RKA controls while the original Action button and local configuration remain available.

## Requirements

> [!IMPORTANT]
> Local mode needs a valid `keybox.xml`. Experimental RKA mode can instead obtain a short-lived attestation lease from a separate, valid donor device.

1. Android 10 or newer
2. A root manager: KernelSU, Magisk, or APatch
3. Zygisk for the keystore interception path
4. Either a local `keybox.xml` or the donor-backed RKA setup described below, which needs one donor phone plus one or more candidate phones

## Local keybox quick start

1. Download the latest ZIP from [Releases](https://github.com/1vivy/TEESimulator/releases).
2. Install it with your root manager, then reboot.
3. Put your `keybox.xml` at `/data/adb/tricky_store/keybox.xml`.
4. List the apps you want to cover in `/data/adb/tricky_store/target.txt`.
5. Check that it works with Play Integrity or the Key Attestation Demo app.

## How it works

```
   App
    |  asks the phone to prove it has real security hardware
    v
+----------------------------------------------------+
| keystore2  (the Android process that answers)      |
|                                                    |
|   ioctl  <- TEESimulator hooks the call here       |
|     |                                              |
|     v                                              |
|   builds a certificate chain and signs it          |
|   with your keybox.xml                             |
+----------------------------------------------------+
    |  the signed chain goes back to the app
    v
   App  ->  sees a genuine, hardware-backed device
```

**Certificate generation in Rust.** A native library, `libcertgen.so`, builds the X.509 certificate chains in Rust with the `ring` crypto library, encoding the bytes by hand in DER, the standard certificate format. Three key types fall outside `ring`'s support (the P-224, P-521, and Curve25519 curves); for those it falls back to Java's BouncyCastle.

**Hooking keystore2.** Inside the `keystore2` process, TEESimulator redirects `ioctl`, the low-level system call Android uses to pass messages between processes. It does this with `lsplt`, a hooking library. From there it can read and answer three kinds of request: creating a key, importing a key, and fetching a key's certificate.

**Matching stock Android.** The output matches what a real device produces. Keys that are not attested get self-signed certificates. The fields inside the attestation record keep the same order. Fields that only exist on certain Android versions appear only on those versions. The same usage checks run before a key is used.

**Keys that survive reboots.** Generated keys are written to disk and stay valid after a restart. File locking stops two writers from corrupting the store.

**Per-app rate limit.** Each app may request at most 2 hardware-backed keys per 30 seconds, and only 2 at a time. Past that, it receives a software-only certificate.

## Donor-backed RKA mode

The experimental RKA beta uses one rooted arm64 **donor** phone and one or more
rooted arm64 **candidate** phones. Every device runs the same role-neutral
module ZIP; pairing assigns the roles at runtime.

```text
                      donor phone
              fresh Google RKP keys, real TEE
                            |
        +-------------------+-------------------+
        |                   |                   |
        |  each candidate's lease key is imported as a TEE ATTEST_KEY,
        |  certified beneath a fresh RKP key, then the temporary
        |  imported blob is deleted
        |                   |                   |
   pinned TLS 1.3      pinned TLS 1.3      pinned TLS 1.3
    (TCP 37373)         (TCP 37373)         (TCP 37373)
        |                   |                   |
        v                   v                   v
  candidate 1         candidate 2         candidate N
  own lease +         own lease +         own lease +
  own key space       own key space       own key space
        |                   |                   |
        +-------------------+-------------------+
                            |
        each candidate attests locally for 7 days,
        with the donor offline
```

Each candidate creates its own synthetic lease key and sends the bounded PKCS#8
material to the donor over mutually authenticated TLS. The donor imports it as a
TEE `ATTEST_KEY`, certifies it beneath a freshly provisioned RKP key, deletes the
temporary imported KeyMint blob, and returns the chain. The candidate validates
and stores the resulting lease. The donor is needed for issuance and renewal, not
for each application operation. Current leases are valid for seven days.

**How the donor tells candidates apart.** Nothing on the wire names the
candidate. The public v2 wire protocol did not change. When a candidate
connects, the donor takes the TLS peer key it just verified (its SPKI) plus the
selected profile and looks that pair up in a pairing catalog to find the
candidate identity. One authenticated TLS credential maps to exactly one
candidate, and the catalog rejects a duplicate pin when it is admitted, using a
constant-time comparison. Each candidate then gets its own identity, its own
pinned trust, its own activation record, and its own isolated lease and key
namespace. A handle that belongs to another candidate is rejected the same way
an unknown handle is.

**Doing several candidates at once.** Each candidate is served by its own actor,
and all of their work funnels through a single donor-wide fair round-robin
scheduler that runs exactly one physical TEE command at a time. That buys fair
interleaving and network progress that does not block, not parallel TEE
throughput. The real security chip still does one thing at a time.

**Limits.** The catalog holds 32 paired candidates. Donor-wide there are at most
4 live sessions and 16 keys; per candidate, at most 4 keys and 1 live operation.
Exactly 1 physical TEE command is in flight at any moment.

**Configuration on each side.** The donor reads one profile per candidate from
`profiles/direct.d/<candidate>.conf`. Each candidate phone keeps its existing
single `profiles/direct.conf`, so from a candidate's own point of view nothing
changed. On a candidate, an explicit `?` entry in `target.txt` selects the active
synthetic lease. Add or remove applications locally without re-pairing. The
candidate preserves its native application key and signature operations; the
lease supplies the attestation chain. StrongBox, unlisted callers, and
unsupported requests stay on the normal platform path.

On a donor, the WebUI shows one pairing-status card per candidate. Lease renewal
runs from the candidate's own WebUI, where the local lease state is observable.
When a donor has candidate-indexed profiles, its WebUI network form is read-only;
rerun the host CLI bind/deploy workflow to update each candidate's routed address.

The beta's automatic network path uses direct routed Wi-Fi: the donor dials each
candidate on TCP 37373. ADB is used to install and configure the devices but is
not the RKA data path. See the [RKA beta guide](docs/RKA_BETA_GUIDE.md) for
installation, pairing, renewal, verification, and recovery, and the
[beta release notes](docs/RKA_BETA_RELEASE_NOTES.md) for validated scope and
known limitations. Note that the multi-candidate paths are covered by automated
tests only and have not yet been exercised on physical hardware.

## Configuration

All config files live in `/data/adb/tricky_store/`. TEESimulator reloads them the moment you save, so a reboot is not needed.

### target.txt

Lists the apps TEESimulator handles, one package name per line. A suffix sets how each app is handled.

| Suffix | What it does |
|--------|--------------|
| `!` | Always make a software key |
| `?` | Keep the real hardware key, patch only its certificate |
| none | Decide automatically |

To use more than one keybox, add a `[filename.xml]` header above the apps that should use that file:

```
com.google.android.gms!
io.github.vvb2060.keyattestation?

[aosp_keybox.xml]
com.google.android.gsf
```

### security_patch.txt

Sets the security patch dates reported in the attestation certificates. Global defaults go at the top. Override them for one app with a `[package.name]` header.

| Key | What it sets |
|-----|--------------|
| `system` | OS patch level |
| `vendor` | Vendor patch level |
| `boot` | Boot and kernel patch level |
| `all` | All three at once |

Accepted values: `today`, a `YYYY-MM-DD` template, `no` to omit the field, `device_default`, or `prop` to read the value from a system property.

```
system=YYYY-MM-05
vendor=device_default
boot=no

[com.google.android.gms]
system=2025-10-01
```

### boot_props_mode

Controls global `ro.boot.*` property spoofing. Values: `auto` (default), `force`, or `disable`.

In `auto`, Oplus-family devices (OnePlus/OPPO/realme/Oplus) skip boot-state prop spoofing to avoid conflicts with vendor TEE services such as ultrasonic fingerprint calibration. Create `/data/adb/tricky_store/boot_props_mode` with `force` to restore the old behavior, or `disable` to turn it off on any device.

## Building from source

You need JDK 21, the Android SDK and NDK 29, Rust (stable) with the `aarch64-linux-android` target, and `cargo-ndk`.

```bash
git clone --recursive https://github.com/1vivy/TEESimulator.git
cd TEESimulator
./gradlew zipRelease zipDebug
```

The ZIPs land in `out/`. Gradle runs `cargo ndk` for you to cross-compile `libcertgen.so`. To build on CI instead, push to `main` or run Actions > Build > Run workflow.

## Compatibility

| Root manager | Status |
|---|---|
| KernelSU | Tested, including the Action button and lifecycle scripts |
| Magisk | Supported |
| APatch | Supported |

The RKA beta is physically validated on KernelSU/Zygisk only, and only for one
donor paired with one candidate. The multi-candidate paths are covered by
automated tests only. The compatibility table otherwise describes the original
local module path.

## Community

<p align="center">
  <a href="https://t.me/superpowers9">
    <img src="https://img.shields.io/badge/SuperPowers_Telegram-Join-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
</p>

## Credits

- [JingMatrix](https://github.com/JingMatrix/TEESimulator) for the original TEESimulator and its interception design
- [ring](https://github.com/briansmith/ring) for the Rust cryptography
- [fatalcoder524](https://github.com/fatalcoder524) for contributions and collaboration
- [huguangares](https://github.com/huguangares) for collaboration and testing

## License

[GNU General Public License v3.0](LICENSE)
