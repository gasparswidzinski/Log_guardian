![Python 3.11](https://img.shields.io/badge/python-3.11-blue)
![CI](https://github.com/gasparswidzinski/Log_guardian/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

# Log Guardian

Análisis **defensivo** de logs (Windows y Linux) con detección de:
- **Ráfagas de fallos de login** (Windows `4625`, Linux `Failed password`)
- **Logins exitosos inusuales** (Windows `4624`, Linux `Accepted …`)
- **Escalada de privilegios** (Linux `sudo` / `su`, Windows `4672/4688` si están en el CSV)

Incluye **configuración por archivo**, **reporte CSV**, y **alertas por correo** (Mailtrap/Gmail) para mostrar **automatización + lógica de detección** en un proyecto profesional y simple de ejecutar.

---

## Características
- Parsers:
  - **Windows (CSV)** exportado del *Security Log*.
  - **Linux (`/var/log/auth.log`)** estilo Debian/Ubuntu.
- Reglas:
  - `failed_login_burst`: N fallos dentro de T minutos por `(usuario, IP)`.
  - `unusual_success`: login exitoso fuera de horario y/o desde IP no permitida.
  - `privilege_escalation`: `sudo`/`su` (Linux) y 4672/4688 (Windows, si aplica).
- **Configurable** con `config.toml`.
- **Reporte CSV** de hallazgos.
- **Alertas por correo** (desactivadas por defecto para evitar envíos accidentales).
- **Tests + CI (GitHub Actions)**.

---

## Estructura
Log_guardian/
├─ main.py
├─ config.toml
├─ samples/
│ ├─ security_sample.csv # Windows
│ └─ auth_sample.log # Linux
├─ tests/
│ └─ test_detectors.py
└─ .github/workflows/
   └─ ci.yml


## Requisitos
- **Python 3.11+**
- Windows para generar CSV del *Security Log* (o usar `samples/`).
- (Opcional) Linux/WSL/VM para `auth.log`.
- Entorno virtual recomendado.

**Entorno virtual (PowerShell)**
```powershell
py -3 -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
python --version

## Configuracion(config.toml)
[general]
business_hours = "08:00-20:00"        # Soporta ventanas nocturnas (p.ej., 22:00-06:00)

[rules.failed_login_burst]
threshold = 5                         # cantidad de fallos en la ventana
window_minutes = 10                   # ancho de ventana deslizante

[rules.unusual_success]
allowed_cidrs = ["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12"]
enforce_business_hours = true

[alerts.email]
enabled = false                       # activar manualmente para pruebas
smtp_host = "sandbox.smtp.mailtrap.io"  # para Gmail: smtp.gmail.com
smtp_port = 587                       # Mailtrap: 587 o 2525
use_tls = true
username = "TU_USER_MAILTRAP"         # para Gmail: tu_email@gmail.com
from_addr = "logguardian@example.com" # en Gmail suele ser = username
to_addrs = ["test@local.test"]        # uno o más destinatarios
min_severity = "HIGH"                 # LOW | MEDIUM | HIGH
cooldown_seconds = 3                  # evita rate limit al probar seguido

## USO
Windows (CSV) ---> python .\main.py --input .\samples\security_sample.csv --platform windows --config .\config.toml --out .\out\findings.csv

Linux (/var/log/auth.log) ---> python .\main.py --input .\samples\auth_sample.log --platform linux --config .\config.toml --out .\out\findings_linux.csv

## Alertas por correo

$env:LOGGUARDIAN_SMTP_PASS="TU_PASSWORD_MAILTRAP"
python -c "import os; print(bool(os.getenv('LOGGUARDIAN_SMTP_PASS')))"  # True
# activar en config.toml:
# [alerts.email] enabled = true, min_severity = "LOW" (si querés forzar envío)

##Gmail (producción personal):
-Requiere 2FA y App Password.
-smtp_host = "smtp.gmail.com", smtp_port = 587, use_tls = true.
-username/from_addr = tu_email@gmail.com y LOGGUARDIAN_SMTP_PASS = <app password>.

## Salida esperada
Eventos: 7  |  Hallazgos: 2
Resumen de hallazgos:
  Por regla: failed_login_burst=1, unusual_success=1
  Por severidad: HIGH=2
CSV generado: .\out\findings.csv

##CSV (findings.csv):
timestamp,rule,severity,user,src_ip,host,message
2025-09-28T10:08:00,failed_login_burst,HIGH,gaspar,203.0.113.5,PC-01,"5 fails en 10 min"
2025-09-28T23:30:00,unusual_success,HIGH,gaspar,198.51.100.7,PC-01,"ok_ip=False, ok_hours=False"

##Lógica de detección
1)failed_login_burst (fuerza bruta / spraying)
-Fuente: Windows 4625 / Linux Failed password (SSH).
-Agrupa por (usuario, IP).
-Ventana deslizante de window_minutes; si el conteo alcanza threshold → HIGH.
-message: "{n} fails en {window_minutes} min".

2) unusual_success (acceso exitoso anómalo)
-Fuente: Windows 4624 / Linux Accepted ….
-Chequeos:
    IP ∈ allowed_cidrs → OK IP
    Si enforce_business_hours = true, timestamp ∈ business_hours → OK horario
-Severidad:
    HIGH si IP no permitida
    MEDIUM si sólo fuera de horario

3) privilege_escalation (aumento de privilegios)
-Fuente: Linux sudo/su (y opcional Windows 4672/4688 si el CSV lo trae).
-Severidad por defecto: MEDIUM (ajustable).

