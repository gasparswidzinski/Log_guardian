import csv
import datetime as dt
from collections import defaultdict, deque, Counter
import argparse
import os
import smtplib, ssl
from email.message import EmailMessage
import re

# Python 3.11+: tomllib
import tomllib
# Si usás 3.10: descomentá abajo y comentá el import tomllib
# import tomli as tomllib

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# ------------------------------------------------------------

def summarize(findings: list[dict]) -> str:
    if not findings:
        return "Sin hallazgos."
    by_rule = Counter(f["rule"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    lines = ["Resumen de hallazgos:"]
    lines.append("  Por regla: " + ", ".join(f"{r}={c}" for r,c in sorted(by_rule.items())))
    lines.append("  Por severidad: " + ", ".join(
        f"{s}={c}" for s,c in sorted(by_sev.items(), key=lambda x: SEV_ORDER.get(x[0], 0))
    ))
    return "\n".join(lines)

MONTHS = {m:i for i,m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1
)}

_failed_re   = re.compile(r"(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)")
_accepted_re = re.compile(r"(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src>\S+)")
_sudo_re     = re.compile(r"(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo:")

def _ts_from_syslog(mon: str, day: str, timestr: str, year: int | None = None) -> str:
    y = year or dt.datetime.now().year
    month = MONTHS.get(mon, 1)
    hh, mm, ss = map(int, timestr.split(":"))
    return dt.datetime(y, month, int(day), hh, mm, ss).isoformat()

def parse_auth_log(path: str):
    """Parsea /var/log/auth.log estilo Debian/Ubuntu."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = _failed_re.search(line)
            if m:
                yield {
                    "timestamp": _ts_from_syslog(m["mon"], m["day"], m["time"]),
                    "event_id": "LINUX_FAILED",           # normalizamos para nuestras reglas
                    "event_type": "failed_login",
                    "user": m["user"], "src_ip": m["src"], "host": m["host"], "raw": line.strip()
                }
                continue
            m = _accepted_re.search(line)
            if m:
                yield {
                    "timestamp": _ts_from_syslog(m["mon"], m["day"], m["time"]),
                    "event_id": "LINUX_ACCEPTED",
                    "event_type": "login_success",
                    "user": m["user"], "src_ip": m["src"], "host": m["host"], "raw": line.strip()
                }
                continue
            m = _sudo_re.search(line)
            if m:
                yield {
                    "timestamp": _ts_from_syslog(m["mon"], m["day"], m["time"]),
                    "event_id": "LINUX_SUDO",
                    "event_type": "sudo",
                    "user": None, "src_ip": None, "host": m["host"], "raw": line.strip()
                }

def send_email(findings: list[dict], cfg: dict, attach_csv: str | None = None) -> None:
    if not cfg or not cfg.get("enabled"):
        return

    # Umbral de severidad
    min_sev = cfg.get("min_severity", "HIGH")
    mins = SEV_ORDER.get(min_sev, SEV_ORDER["HIGH"])
    eligible = [f for f in findings if SEV_ORDER.get(f["severity"], 0) >= mins]
    if not eligible:
        return

    import ssl, smtplib, os, time, tempfile

    host = cfg.get("smtp_host")
    port = int(cfg.get("smtp_port", 587))
    if not host:
        print("[email] smtp_host no configurado. Salteando envío.")
        return

    password = cfg.get("password") or os.getenv("LOGGUARDIAN_SMTP_PASS", "")
    if not password:
        print("[email] Faltó LOGGUARDIAN_SMTP_PASS o 'password' en config. No se envía.")
        return

    # --- Cooldown anti-rate-limit (ej. Mailtrap free) ---
    cooldown = int(cfg.get("cooldown_seconds", 3))
    stamp_path = os.path.join(tempfile.gettempdir(), "logguardian_last_email.ts")
    last_ts = 0.0
    try:
        with open(stamp_path, "r", encoding="utf-8") as fp:
            last_ts = float(fp.read().strip() or "0")
    except Exception:
        pass
    now = time.time()
    if now - last_ts < cooldown:
        wait = cooldown - (now - last_ts)
        print(f"[email] Enfriando {wait:.1f}s para evitar rate limit...")
        time.sleep(wait)

    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = "[LogGuardian] Resumen de hallazgos"
    msg["From"] = cfg.get("from_addr", cfg.get("username", "logguardian@example.com"))
    msg["To"] = ", ".join(cfg.get("to_addrs", []))
    msg.set_content(summarize(eligible))

    if attach_csv and os.path.exists(attach_csv):
        with open(attach_csv, "rb") as f:
            msg.add_attachment(f.read(), maintype="text", subtype="csv",
                               filename=os.path.basename(attach_csv))

    context = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                time.sleep(2)  # margen extra
                server.login(cfg["username"], password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                if cfg.get("use_tls", True):
                    server.starttls(context=context)
                server.login(cfg["username"], password)
                time.sleep(2)  # margen extra
                server.send_message(msg)

        # Guardar timestamp del último envío exitoso
        with open(stamp_path, "w", encoding="utf-8") as fp:
            fp.write(str(time.time()))
        print("[email] Envío OK.")
    except Exception as e:
        print(f"[email] No se pudo enviar el correo: {e}")



def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)

def parse_csv(path: str):
    """Lee Security.csv exportado del Visor de Eventos de Windows.
    Columnas esperadas: TimeCreated, EventID, AccountName, IpAddress, Computer
    """
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            ts = row.get("TimeCreated") or row.get("Timestamp")
            timestamp = ts if ts else dt.datetime.now().isoformat()
            yield {
                "timestamp": timestamp,
                "event_id": str(row.get("EventID", "")).strip(),
                "user": (row.get("AccountName") or "").strip(),
                "src_ip": (row.get("IpAddress") or "").strip(),
                "host": (row.get("Computer") or "").strip(),
                "raw": row
            }

def detect_failed_login_burst(events, threshold: int, window_minutes: int):
    """Regla 1: múltiples 4625 por (usuario, ip) en ventana deslizante."""
    findings = []
    wdelta = dt.timedelta(minutes=window_minutes)
    buckets = defaultdict(deque)  # (user, ip) -> deque[timestamps]

    for e in events:
        if e["event_id"] not in ("4625", "LINUX_FAILED"):

            continue
        user = e["user"] or "-"
        ip = e["src_ip"] or "-"
        ts = dt.datetime.fromisoformat(e["timestamp"])
        key = (user, ip)
        dq = buckets[key]
        dq.append(ts)
        # Limpiar fuera de la ventana
        while dq and (ts - dq[0]) > wdelta:
            dq.popleft()
        if len(dq) >= threshold:
            findings.append({
                "timestamp": e["timestamp"],
                "rule": "failed_login_burst",
                "severity": "HIGH",
                "user": user,
                "src_ip": ip,
                "host": e["host"],
                "message": f"{len(dq)} fails en {window_minutes} min"
            })
    return findings

# ------------------------------------------------------------

import ipaddress

def ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False

def parse_business_hours(s: str):
    start, end = s.split("-")
    s_h, s_m = map(int, start.split(":"))
    e_h, e_m = map(int, end.split(":"))
    return (s_h, s_m), (e_h, e_m)

def within_hours(ts: dt.datetime, start_hm, end_hm) -> bool:
    start = dt.time(*start_hm)
    end = dt.time(*end_hm)
    if start <= end:
        return start <= ts.time() <= end
    # ventana nocturna (ej. 22:00-06:00)
    return ts.time() >= start or ts.time() <= end

def detect_unusual_success(events, allowed_cidrs, enforce_business_hours, business_hours):
    findings = []
    start_hm, end_hm = parse_business_hours(business_hours)
    for e in events:
        if e["event_id"] not in ("4624", "LINUX_ACCEPTED"):
            continue
        ts = dt.datetime.fromisoformat(e["timestamp"])
        src = e["src_ip"] or ""
        ok_ip = ip_in_cidrs(src, allowed_cidrs) if src else False
        ok_hours = True if not enforce_business_hours else within_hours(ts, start_hm, end_hm)
        if (src and not ok_ip) or (enforce_business_hours and not ok_hours):
            sev = "HIGH" if src and not ok_ip else "MEDIUM"
            findings.append({
                "timestamp": e["timestamp"],
                "rule": "unusual_success",
                "severity": sev,
                "user": e["user"],
                "src_ip": src,
                "host": e["host"],
                "message": f"ok_ip={ok_ip}, ok_hours={ok_hours}"
            })
    return findings
# ------------------------------------------------------------

def detect_privilege_escalation(events):
    """Marca escaladas de privilegios (sudo/su en Linux, 4672/4688 en Windows)."""
    findings = []
    for e in events:
        eid = e.get("event_id")
        et  = e.get("event_type", "")
        if et in {"sudo", "su"} or eid in {"4672", "4688"}:
            findings.append({
                "timestamp": e["timestamp"],
                "rule": "privilege_escalation",
                "severity": "MEDIUM",
                "user": e.get("user"),
                "src_ip": e.get("src_ip"),
                "host": e.get("host"),
                "message": e.get("raw") or e.get("message") or str(e)
            })
    return findings


def write_csv(findings: list[dict], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp","rule","severity","user","src_ip","host","message"])
        for x in findings:
            w.writerow([
                x["timestamp"], x["rule"], x["severity"],
                x.get("user",""), x.get("src_ip",""), x.get("host",""), x.get("message","")
            ])


def main():
    ap = argparse.ArgumentParser(description="Log Guardian - CSV Windows + reglas 4625/4624")
    ap.add_argument("--input", required=True, help="Ruta CSV exportado (Security)")
    ap.add_argument("--config", required=True, help="Ruta config.toml")
    ap.add_argument("--out", default="findings.csv", help="Salida CSV (default: findings.csv)")
    ap.add_argument("--platform", required=True, choices=["windows", "linux"], help="Origen del log")
    args = ap.parse_args()

    cfg = load_config(args.config)
    rule_burst = cfg.get("rules", {}).get("failed_login_burst", {})
    threshold = int(rule_burst.get("threshold", 5))
    window = int(rule_burst.get("window_minutes", 10))

    if args.platform == "windows":
        events = list(parse_csv(args.input))
    else:
        events = list(parse_auth_log(args.input)) 


    findings = detect_failed_login_burst(events, threshold=threshold, window_minutes=window)

    ru = cfg.get("rules", {}).get("unusual_success", {})
    findings += detect_unusual_success(
        events,
        allowed_cidrs=ru.get("allowed_cidrs", []),
        enforce_business_hours=bool(ru.get("enforce_business_hours", False)),
        business_hours=cfg.get("general", {}).get("business_hours", "08:00-20:00"),
    )
    
    findings += detect_privilege_escalation(events)

    print(f"Eventos: {len(events)}  |  Hallazgos: {len(findings)}")
    print(summarize(findings))

    write_csv(findings, args.out)
    print(f"CSV generado: {args.out}")

    email_cfg = cfg.get("alerts", {}).get("email", {})
    send_email(findings, email_cfg, attach_csv=args.out)
  


if __name__ == "__main__":
    main()
