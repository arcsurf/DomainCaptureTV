# Domain Capture TV

App para **Android TV** que captura los **dominios** que usa otra app (Netflix, Disney+, Prime Video, YouTube…) para llegar a su contenido, y genera un **reporte descargable** (TXT + CSV) en la carpeta `Download/DomainCapture` del TV.

No necesita root.

## Cómo funciona

```
 App objetivo (p.ej. Netflix)
        │  consulta DNS
        ▼
 ┌──────────────────────────────┐
 │ VPN local (solo esa app)     │  DNS ficticio 10.111.222.1
 │  - registra el dominio       │──► DNS real del router/ISP (socket protegido)
 │  - registra CNAME e IPs      │◄── respuesta
 └──────────────────────────────┘
        │ el resto del tráfico (video, API) NO pasa por la VPN
        ▼
     Internet normal
```

- Usa `VpnService` con `addAllowedApplication()`: **solo la app elegida** pasa por la VPN; el resto del TV no se toca.
- La VPN tiene únicamente rutas `/32` hacia el DNS ficticio y hacia resolvers públicos conocidos (8.8.8.8, 1.1.1.1, 9.9.9.9, OpenDNS). El tráfico de video va directo, sin pérdida de velocidad.
- Si la app intenta DNS-over-TLS / DNS-over-HTTPS / DNS por TCP contra esos resolvers, recibe un TCP RST inmediato y vuelve al DNS clásico, que queda capturado.
- Por cada dominio guarda: cantidad de consultas, tipos (A/AAAA/HTTPS…), primera/última vez, **cadena CNAME** (ej. `www.netflix.com → *.dradis.netflix.com`) e **IPs resueltas**.
- **Auto-detención**: con el permiso *Acceso a datos de uso*, la app detecta cuando la app objetivo deja de estar en primer plano (volviste al launcher o abriste otra app) durante más de 8 s, detiene la captura y guarda el reporte sola.

## Uso

1. Instalar el APK (ver abajo).
2. Abrir **Domain Capture TV**.
3. *(Una sola vez)* conceder **Acceso a datos de uso** con el botón "Permiso datos de uso". Si tu TV no tiene esa pantalla, desde una PC:
   ```bash
   adb shell appops set com.acouso.domaincapture GET_USAGE_STATS allow
   ```
4. Elegir la app en la lista de la izquierda.
5. *(Recomendado)* "Info app (forzar detención)" → **Forzar detención** de la app objetivo, para que no reutilice conexiones abiertas antes de la captura.
6. **Iniciar captura y abrir app** → aceptar el diálogo de VPN (la primera vez) → la app objetivo se abre sola.
7. Usar la app normalmente (navegar, reproducir contenido).
8. Salir de la app (botón Home/Atrás). A los ~8 s la captura se detiene y se guarda el reporte. También se puede detener a mano desde la app o desde la notificación ("Detener y guardar").

## Reporte

Se guarda en `/sdcard/Download/DomainCapture/`:

| Archivo | Contenido |
|---|---|
| `dominios_<App>_<fecha>.txt` | Resumen, **lista de dominios**, agrupación por dominio base (ej. `nflxvideo.net: 23 subdominios`) y detalle con CNAME/IPs |
| `dominios_<App>_<fecha>.csv` | `dominio, dominio_base, origen, consultas, primera_vez, ultima_vez, tipos, ips, cname_destino, alias_de` |

Para bajarlo a la PC:
```bash
adb pull /sdcard/Download/DomainCapture/ .
```
(o con cualquier explorador de archivos del TV / X-plore / Send Files to TV).

Si el sistema no permitiera escribir en Download, el reporte cae en `/sdcard/Android/data/com.acouso.domaincapture/files/DomainCapture/`.

## Instalación

Descargar `DomainCaptureTV.apk` desde **Releases** y:
```bash
adb connect <IP_DEL_TV>:5555          # con "Depuración por red/USB" activada en el TV
adb install -r DomainCaptureTV.apk
```

## Compilar

Requisitos: JDK 17+ y Android SDK (platform 35).
```bash
echo "sdk.dir=$HOME/Android/Sdk" > local.properties
./gradlew testDebugUnitTest assembleRelease
# APK: app/build/outputs/apk/release/app-release.apk
```

## Limitaciones

- Solo ve lo que la app resuelve por **DNS**. Si una app usa IPs fijas o DoH contra un servidor propio (no los resolvers públicos bloqueados), esos destinos no aparecen.
- Si en el TV está activado **DNS privado** en modo estricto (hostname), conviene desactivarlo durante la captura.
- Solo puede haber una VPN activa en el sistema: si usás otra VPN, se desconecta mientras capturás.
- IPv4 para el DNS interceptado; el tráfico IPv6 de la app sigue por la red normal (sus consultas DNS igualmente pasan por la VPN).
- Requiere Android 7.0+ (API 24).

## Estructura

```
app/src/main/java/com/acouso/domaincapture/
├── MainActivity.kt        UI para control remoto (lista de apps, iniciar/detener, dominios en vivo)
├── CaptureVpnService.kt   VPN solo-DNS por app, reenvío DNS, RST a DoT/DoH, auto-detención
├── DnsCodec.kt            Parser DNS (preguntas, A, AAAA, CNAME, compresión)
├── IpPacket.kt            Construcción de paquetes IPv4/UDP y TCP RST con checksums
├── CaptureState.kt        Estado compartido: dominios, IPs, CNAME
├── ReportWriter.kt        Genera TXT + CSV en Download/DomainCapture
└── UsageAccess.kt         Verificación del permiso de datos de uso
```
