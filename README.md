# AnDivert

[![CI](https://github.com/bmjubairdadu/AnDivert/actions/workflows/ci.yml/badge.svg)](https://github.com/bmjubairdadu/AnDivert/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bmjubairdadu/AnDivert)](https://github.com/bmjubairdadu/AnDivert/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![API](https://img.shields.io/badge/API-24%2B-brightgreen.svg)](https://developer.android.com/about/versions/nougat)

**WinDivert-style user-mode packet interception for Android.**

AnDivert lets an Android app capture / inspect / filter / drop / modify /
re-inject network packets — the same thing [WinDivert](https://github.com/basil00/WinDivert)
does on Windows, re-imagined for the Android platform. No root required.

```c
// The C API reads exactly like WinDivert's:
ad_handle_t *h = AnDivertOpen(tun_fd, "outbound and tcp.DstPort == 443",
                              AN_LAYER_NETWORK, 0, AN_FLAG_DEFAULT);
AnDivertRecv(h, buf, sizeof(buf), &addr, &recv_len, 1000);
/* ... inspect / modify ... */
AnDivertSend(h, buf, recv_len, &addr, &sent_len);
AnDivertClose(h);
```

```kotlin
// And the Kotlin API:
val divert = AnDivert.open(tunFd, "outbound and udp.DstPort == 53")
val packet = divert.recv(timeoutMs = 1000) ?: return
divert.send(packet.bytes)   // release, or send a modified copy
divert.close()
```

---

## Why it exists

Android does not allow apps to install kernel drivers, so there was no way
to do WinDivert-style packet work in a normal app. AnDivert fills that gap
using the platform-sanctioned VpnService/TUN mechanism — the same approach
as NetGuard and PCAPdroid — but exposes it through a **WinDivert-shaped API**
so existing WinDivert knowledge transfers directly.

### Legitimate uses

✅ per-app firewalls · DNS/ad filtering · traffic monitors & loggers
✅ VPN & tunneling apps · network debugging & research · parental controls

❌ Not for cheating in online games, attacking, or surveilling others —
see [CONTRIBUTING.md](CONTRIBUTING.md).

| | WinDivert (Windows) | AnDivert (Android) |
|---|---|---|
| Interception point | `WinDivert.sys` WFP callout driver | VpnService-created TUN interface |
| Requires admin/root | yes (driver install) | **no** (user consent dialog once) |
| Loopback traffic | yes | no (TUN never sees loopback) |
| API | `WinDivertOpen/Recv/Send/Close` | `AnDivertOpen/Recv/Send/Close` |
| Filter language | full WinDivert language | practical subset (below) |
| License | LGPLv3 / GPLv2 | MIT (independent reimplementation) |

Android does not allow apps to install kernel drivers. The platform-sanctioned
equivalent is `android.net.VpnService`: once the user grants consent, the app
receives a virtual network interface (TUN) through which **every** IP packet
from the device flows in user space. AnDivert attaches its engine to that fd
and gives you WinDivert semantics on top:

```
        app traffic (all apps, or a per-app subset)
                          │
                    ┌─────▼─────┐
                    │ TUN (fd)  │
                    └─────┬─────┘
              ┌───────────▼───────────┐
              │ AnDivert engine (C)   │
              │  filter match?        │
              │  yes ─► ring ─► AnDivertRecv()   your code decides:
              │              ▲        │           drop / modify / release
              │              └─ AnDivertSend() ◄─┘
              │  no  ─► forwarding stack (UDP NAT + TCP mini proxy +
              │         ICMP echo), re-injected toward the real network
              └───────────────────────┘
```

The forwarding stack is the part most people miss: unlike Windows, where
non-matching packets simply continue past the driver, the TUN **swallows
everything**, so AnDivert itself must push non-matching traffic to the real
network. That is built in and transparent — your filter only sees what you
asked to see.

## Getting it

Two consumption paths, both on the [Releases](../../releases) page — they
contain the same engine, packaged for two different audiences:

1. **`andivert-1.0.0.aar`** — for app developers (Gradle/Android Studio).

   ```gradle
   dependencies {
       implementation files('libs/andivert-1.0.0.aar')
   }
   ```

   The AAR bundles `libandivert.so` for **arm64-v8a, armeabi-v7a, x86_64, x86**
   plus the compiled Kotlin API.
   > **Plain-Java apps:** the library uses Kotlin types in its public API, so
   > also add `implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.24'`
   > (Kotlin apps get it automatically).

2. **`andivert-1.0.0-release.zip`** — for NDK developers / vendors: the
   WinDivert.dll-style raw package:
   `prebuilt/<abi>/libandivert.so`, `include/andivert.h`, full C source,
   Kotlin sources and the example app. Use it when you want to vendor the
   C engine into your own NDK build instead of consuming an AAR.

You only need one of the two — pick by how you build your app.

## Integration (10 minutes)

### 1. Declare the service in your manifest

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

<application>
    <service
        android:name=".MyGate"
        android:exported="false"
        android:foregroundServiceType="specialUse"
        android:permission="android.permission.BIND_VPN_SERVICE">
        <property
            android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
            android:value="packet diversion" />
        <intent-filter>
            <action android:name="android.net.VpnService" />
        </intent-filter>
    </service>
</application>
```

### 2. Subclass `AnDivertVpnService`

```kotlin
class MyGate : AnDivertVpnService() {

    // Which packets you want to see (WinDivert filter syntax).
    override fun divertFilter(): String = "outbound and udp.DstPort == 53"

    // Called on a worker thread for every matching packet.
    override fun onPacket(packet: AnDivert.DivertedPacket, divert: AnDivert) {
        Log.i("MyGate", "DNS -> ${packet.meta.dstAddressString()}")
        divert.send(packet.bytes)      // release unchanged
        // not calling send() = DROP (that's a firewall)
        // editing bytes, then send() = MODIFY (fix checksums: ADCalcChecksums
        // in C, or recompute before sending)
    }
}
```

### 3. Start it from an Activity

```kotlin
val prepare = VpnService.prepare(this)      // system consent dialog, once
if (prepare != null) startActivityForResult(prepare, 1) else actuallyStart()

fun actuallyStart() = startForegroundService(
    Intent(this, MyGate::class.java).setAction(AnDivertVpnService.ACTION_START)
)
```

A complete runnable sample is in [`examples/sample-app`](examples/sample-app)
(a DNS query logger — the smallest useful AnDivert app).

### Using the C API directly (NDK apps)

Copy `include/andivert.h` + `prebuilt/<abi>/libandivert.so` into your NDK
project, or add the sources from `src/` to your `CMakeLists.txt`. You must
create the TUN yourself (via VpnService) and pass its fd to `AnDivertOpen`.
If you also want the built-in pass-through forwarding stack, either use the
JNI layer (it wires `VpnService.protect()` for you) or call
`AnDivertSetProtectFn()` with your own JNI shim.

## Filter language

```
true | false
outbound | inbound
ip | ipv4 | ipv6 | tcp | udp | icmp | icmpv6
ip.SrcAddr == 10.0.0.1      ip.DstAddr != 8.8.8.8
ip.Protocol == 6            ip.TTL > 1        ip.Length >= 100
tcp.SrcPort == 443          tcp.DstPort >= 1024
tcp.Syn | tcp.Ack | tcp.Fin | tcp.Rst | tcp.Psh
udp.SrcPort == 53           udp.DstPort == 5353
icmp.Type == 8              icmp.Code == 0
```

Combined with `and`, `or`, `not`, and parentheses:

```
outbound and udp and ip.DstAddr == 8.8.8.8
tcp and (tcp.Syn or tcp.Fin)
not (udp.DstPort == 5353 or udp.DstPort == 1900)
```

Unknown fields are a **compile error at open time** (a typo never silently
matches nothing). Validate user-supplied filters with `AnDivert.isValidFilter()`.

## Public API surface

### Kotlin (`com.andivert.library`)

| Member | WinDivert equivalent | Purpose |
|---|---|---|
| `AnDivert.open(tunFd, filter, flags)` | `WinDivertOpen` | attach engine to a TUN fd |
| `AnDivert.recv(timeoutMs)` | `WinDivertRecv` | next matching packet (null on timeout) |
| `AnDivert.send(bytes)` | `WinDivertSend` | (re-)inject a packet |
| `AnDivert.close()` | `WinDivertClose` | stop and free |
| `AnDivert.stats()` | — | diverted / passed / dropped / bytes counters |
| `AnDivert.isValidFilter(f)` | — | compile check without opening |
| `AnDivertVpnService` | — | base class owning the TUN + per-app routes |
| `AnDivert.FLAG_SNIFF` | `WINDIVERT_FLAG_SNIFF` | observe, let packet continue |
| `AnDivert.FLAG_DROP` | `WINDIVERT_FLAG_DROP` | drop every match |
| `AnDivert.FLAG_READONLY` | `WINDIVERT_FLAG_READONLY` | recv only |

### C (`andivert.h`)

`AnDivertOpen`, `AnDivertRecv`, `AnDivertSend`, `AnDivertClose`,
`AnDivertGetStats`, `AnDivertSetProtectFn`, `ADParsePacket`,
`ADCalcChecksums`, `ADVerifyChecksum`, `ADFilterCompile/Match/Free`,
`AnDivertStrError` — full signatures and docs in
[`andivert/src/main/cpp/andivert.h`](andivert/src/main/cpp/andivert.h).

## Building from source

```bash
# native engine + live tests (any Linux/WSL with gcc)
cd andivert
gcc -O2 -Wall -Isrc/main/cpp -shared -fPIC -o libandivert.so \
    src/main/cpp/{andivert,ad_packet,ad_filter,ad_checksum,ad_ring,ad_forward,ad_log,ad_jni}.c \
    -lpthread

# run the 29-test live suite (engine runs against a fake TUN)
gcc -O1 -Isrc/main/cpp -o /tmp/ad_test test/ad_test.c src/main/cpp/*.c -lpthread
/tmp/ad_test
```

For Android ABIs, build with the NDK (or open the repo in Android Studio —
the `andivert` module builds via CMake automatically):

```bash
for abi in aarch64-linux-android24 armv7a-linux-androideabi24 \
           x86_64-linux-android24 i686-linux-android24; do
  $NDK/toolchains/llvm/prebuilt/<host>/bin/$abi-clang \
    -O2 -shared -fPIC -o libandivert.so andivert/src/main/cpp/*.c
done
```

Release artifacts are rebuilt with `python tools/build_release.py`.

## Test status

The engine is validated by a live test suite (not just compilation):
`29 passed, 0 failed` — covering filter compilation/matching (incl. error
cases), checksum round-trips, a real UDP NAT round-trip through the engine,
the `AnDivertRecv`/`AnDivertSend` divert loop, and a full TCP handshake +
echo through the mini proxy. See `andivert/test/ad_test.c`.

```
RESULT: 29 passed, 0 failed
```

**On-device verification** — the release AAR was installed on a real phone
(Mi A2 Lite, Android 11, arm64-v8a) driving a real VPN session:

```
filter compiled: outbound and udp.DstPort == 53
engine started
DNS -> 8.8.8.8    DNS -> 1.1.1.1    DNS -> 4.4.8.8   ... (68 diverted)
stats: diverted=68 passed=560 dropped=0 in=99KB out=366KB
ping 8.8.8.8 → 0% packet loss   (internet fully functional during diversion)
```

Every DNS query from every app on the device surfaced at `onPacket()` and
was released unchanged — non-matching traffic flowed through the built-in
forwarding stack with zero drops.

## Limitations (read before filing issues)

- **No loopback**: Android never routes 127.0.0.1 traffic through a TUN, so
  localhost packets cannot be captured (same restriction as NetGuard /
  PCAPdroid).
- **Performance**: user-mode TUN copy vs. in-kernel interception. Fine for
  filtering/monitoring/VPN-grade workloads; not for line-rate sniffing.
- **TCP through the forwarder** is a minimal proxy (handshake, data, FIN/RST),
  enough for pass-through; it is not a full TCP stack. Matching (diverted)
  TCP packets are entirely your responsibility.
- **IPv6 forwarding**: diverted/matched IPv6 works with the filter engine;
  the pass-through forwarder currently handles IPv4 (UDP/TCP/ICMP) and
  answers ICMPv6 echo only — extend `ad_forward.c` for full v6 pass-through.
- **VPN consent**: the user sees Android's standard "connection request"
  dialog once per app — that is the platform's price for no-root, and it is
  exactly what NetGuard/PCAPdroid users already expect.

## Roadmap

- [x] Filter engine, checksums, divert loop, UDP NAT, TCP mini-proxy
- [x] On-device verification (real phone, real VPN session)
- [x] CI: 29-test live suite + Gradle AAR build on every push
- [ ] Full IPv6 pass-through forwarding (filter/capture already work)
- [ ] Javadoc/ Dokka published API docs
- [ ] Maven Central publishing (`io.github.bmjubairdadu:andivert`)
- [ ] Performance: batched TUN I/O, larger rings, optional relay thread pool
- [ ] Runtime filter reload without reopening the handle

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). AnDivert shares no code with WinDivert; the
filter language and API shapes are public interfaces documented by that
project. You can use AnDivert in any app, commercial or not.

## Credits

- [WinDivert](https://github.com/basil00/WinDivert) by basil — the original
  concept and API this library mirrors.
- [NetGuard](https://github.com/M66B/NetGuard) and
  [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) — proved the
  VpnService/TUN pattern for no-root packet processing on Android.
