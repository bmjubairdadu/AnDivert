# Changelog

All notable changes to AnDivert are documented here.

## [1.0.0] - 2026-10-12

Initial release.

### Added
- Native C engine (`libandivert.so`): WinDivert-style open/recv/send/close API
  attached to a VpnService TUN fd.
- Filter language subset compiler: `tcp.DstPort == 443 and outbound`, `or`,
  `not`, parentheses, unknown-field compile errors.
- Forwarding stack for non-matching traffic: per-flow UDP NAT, minimal TCP
  proxy (handshake/data/FIN/RST), ICMP echo replies.
- Checksum utilities: `ADCalcChecksums`, `ADVerifyChecksum` (IPv4/IPv6,
  TCP/UDP/ICMP/ICMPv6).
- Kotlin API (`AnDivert`, `AnDivertNative`) with `PacketMeta`, `Stats`,
  filter validation.
- `AnDivertVpnService` base class: TUN lifecycle, per-app allow/deny lists,
  socket protection wiring, foreground notification, consent handling.
- JNI bridge with automatic `VpnService.protect()` integration.
- Prebuilt libraries for arm64-v8a, armeabi-v7a, x86_64, x86 (NDK r27c,
  API 24+, zero warnings).
- AAR packaging + raw release zip (WinDivert.dll-style).
- Live test suite: 29/29 passing (filter, checksum, UDP NAT round-trip,
  divert loop, TCP proxy round-trip).
- Example app: DNS query logger (`examples/sample-app`).
