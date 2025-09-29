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