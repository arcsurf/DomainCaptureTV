# Domain Capture TV

**English** | [Español](README.es.md)

An **Android TV** app that captures the **domains** another app (Netflix, Disney+, Prime Video, YouTube…) uses to reach its content, and generates a **downloadable report** (TXT + CSV) in the TV's `Download/DomainCapture` folder.

No root required.

## How it works

```
 Target app (e.g. Netflix)
        │  DNS query
        ▼
 ┌──────────────────────────────┐
 │ Local VPN (that app only)    │  Fake DNS 10.111.222.1
 │  - logs the domain           │──► Real router/ISP DNS (protected socket)
 │  - logs CNAMEs and IPs       │◄── response
 └──────────────────────────────┘
        │ all other traffic (video, API) does NOT go through the VPN
        ▼
     Regular Internet
```

- Uses `VpnService` with `addAllowedApplication()`: **only the selected app** goes through the VPN; the rest of the TV is untouched.
- The VPN only has `/32` routes to the fake DNS and to well-known public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, OpenDNS). Video traffic goes direct, with no speed loss.
- If the app tries DNS-over-TLS / DNS-over-HTTPS / DNS over TCP against those resolvers, it gets an immediate TCP RST and falls back to classic DNS, which gets captured.
- For each domain it stores: query count, record types (A/AAAA/HTTPS…), first/last seen, **CNAME chain** (e.g. `www.netflix.com → *.dradis.netflix.com`), **resolved IPs** and **which DNS server answered** (router, ISP, or a public resolver the app queried directly).
- **Auto-stop**: with the *Usage access* permission, the app detects when the target app leaves the foreground (you went back to the launcher or opened another app) for more than 8 s, then stops the capture and saves the report on its own.

## Usage

1. Install the APK (see below).
2. Open **Domain Capture TV**.
3. *(One time only)* grant **Usage access** with the "Permiso datos de uso" button. If your TV doesn't have that screen, from a PC:
   ```bash
   adb shell appops set com.acouso.domaincapture GET_USAGE_STATS allow
   ```
4. Pick the app from the list on the left.
5. *(Recommended)* "Info app (forzar detención)" → **Force stop** the target app, so it doesn't reuse connections opened before the capture.
6. **Iniciar captura y abrir app** (start capture and open app) → accept the VPN dialog (first time) → the target app opens automatically.
7. Use the app normally (browse, play content).
8. Leave the app (Home/Back button). After ~8 s the capture stops and the report is saved. You can also stop it manually from the app or from the notification ("Detener y guardar").

## Report

Saved to `/sdcard/Download/DomainCapture/`:

| File | Contents |
|---|---|
| `dominios_<App>_<date>.txt` | Summary, **DNS servers queried** (IP, type, responses, failures, domains each one resolved), **domain list**, grouping by base domain (e.g. `nflxvideo.net: 23 subdominios`), **network blocks / CDN** (ASN, holder, BGP prefixes) with the minimal and full CIDR lists, and details with CNAMEs/IPs/networks |
| `dominios_<App>_<date>.csv` | `dominio, dominio_base, origen, consultas, primera_vez, ultima_vez, tipos, ips, cname_destino, alias_de, servidores_dns, redes` |
| `redes_<App>_<date>.txt` | **Full CIDR list**, one block per line (IPv4 first, then IPv6), ready to import into a VPN/router policy: every prefix originated by each CDN ASN seen, losslessly summarized |
| `redes_<App>_<date>_min.txt` | **Minimal CIDR list**: only the BGP prefixes that contain the IPs seen in this capture, summarized |

### Network blocks (CIDR)

When the capture stops, each resolved public IP is looked up in [RIPEstat](https://stat.ripe.net) (RIPE RIS BGP data): IP → announced prefix + origin ASN → all prefixes originated by that ASN → lossless summarization (covered blocks removed, contiguous halves merged, e.g. `45.57.40.0/24 + 45.57.41.0/24 → 45.57.40.0/23`).

- If the ASN belongs to **your own ISP** (CDN caches embedded in the ISP: Netflix OCA, Google GGC, Akamai…), the ASN is not expanded — that would be the ISP's whole network; `/24` (IPv4) or `/64` (IPv6) per IP is used instead.
- Without Internet access to RIPEstat, each IP is widened to `/24` or `/48`.
- Apps hosted on general-purpose clouds (AWS, Google, Azure) pull in **all** of that cloud's prefixes in the full list (thousands of blocks); use the minimal list if you only want what was actually seen.

To copy it to a PC:
```bash
adb pull /sdcard/Download/DomainCapture/ .
```
(or with any file explorer on the TV / X-plore / Send Files to TV).

If the system doesn't allow writing to Download, the report is saved to `/sdcard/Android/data/com.acouso.domaincapture/files/DomainCapture/`.

## Installation

Download `DomainCaptureTV.apk` from **Releases** and:
```bash
adb connect <TV_IP>:5555          # with "Network/USB debugging" enabled on the TV
adb install -r DomainCaptureTV.apk
```

## Building

Requirements: JDK 17+ and Android SDK (platform 35).
```bash
echo "sdk.dir=$HOME/Android/Sdk" > local.properties
./gradlew testDebugUnitTest assembleRelease
# APK: app/build/outputs/apk/release/app-release.apk
```

## Limitations

- It only sees what the app resolves via **DNS**. If an app uses hardcoded IPs or DoH against its own server (not the blocked public resolvers), those destinations won't show up.
- If **Private DNS** is enabled in strict mode (hostname) on the TV, it's best to disable it during the capture.
- Only one VPN can be active on the system: if you use another VPN, it will be disconnected while capturing.
- IPv4 only for intercepted DNS; the app's IPv6 traffic goes through the regular network (its DNS queries still go through the VPN).
- Requires Android 7.0+ (API 24).

## Structure

```
app/src/main/java/com/acouso/domaincapture/
├── MainActivity.kt        Remote-control UI (app list, start/stop, live domains)
├── CaptureVpnService.kt   Per-app DNS-only VPN, DNS forwarding, RST for DoT/DoH, auto-stop
├── DnsCodec.kt            DNS parser (questions, A, AAAA, CNAME, compression)
├── IpPacket.kt            IPv4/UDP and TCP RST packet building with checksums
├── CaptureState.kt        Shared state: domains, IPs, CNAMEs
├── NetBlocks.kt           CIDR math/summarization, IP → prefix/ASN lookup via RIPEstat
├── ReportWriter.kt        Writes TXT + CSV + CIDR lists to Download/DomainCapture
└── UsageAccess.kt         Usage access permission check
```
