"""
web_ui.py — SentinelWatch Flask Dashboard
Serves the Apple Glass web dashboard at http://localhost:8888
"""

import json
import os
import queue
import threading
import time
import platform
import psutil
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response, stream_with_context
from flask_cors import CORS

from tail_detector import TailDetector, get_recent_alerts

# ──────────────────────────────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
app = Flask(__name__)
CORS(app)

# Global detector instance
detector = TailDetector(config_path=CONFIG_PATH)

# SSE subscriber queues
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()

# Background mode thread handle
_bg_thread: threading.Thread | None = None
_bg_stop_event = threading.Event()


# ──────────────────────────────────────────────
#  SSE alert pusher
# ──────────────────────────────────────────────
def _alert_pusher():
    """Watch alert queue and push new items to all SSE subscribers."""
    last_count = 0
    while not _bg_stop_event.is_set():
        alerts = get_recent_alerts(limit=200)
        if len(alerts) > last_count:
            new_alerts = alerts[last_count:]
            last_count = len(alerts)
            payload = json.dumps(new_alerts[-1])  # push latest
            with _sse_lock:
                dead = []
                for q in _sse_clients:
                    try:
                        q.put_nowait(payload)
                    except queue.Full:
                        dead.append(q)
                for q in dead:
                    _sse_clients.remove(q)
        time.sleep(0.5)


threading.Thread(target=_alert_pusher, daemon=True).start()


# ──────────────────────────────────────────────
#  Background mode runner
# ──────────────────────────────────────────────
def _run_mode_background(mode: str):
    global _bg_thread, _bg_stop_event
    _bg_stop_event.set()
    if _bg_thread and _bg_thread.is_alive():
        _bg_thread.join(timeout=3)
    _bg_stop_event = threading.Event()

    def _target():
        if mode == "HOME":
            detector.run_home_mode()
        elif mode == "ROAM":
            detector.run_roam_mode(continuous=True)
        elif mode == "DOORBELL":
            detector.run_doorbell_mode()
        elif mode == "WATCHLIST":
            detector.run_watchlist_mode()

    _bg_thread = threading.Thread(target=_target, daemon=True, name=f"sw-{mode.lower()}")
    _bg_thread.start()


# ──────────────────────────────────────────────
#  Kismet connection check
# ──────────────────────────────────────────────
def _kismet_status() -> dict:
    try:
        import requests
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        api = cfg.get("kismet_api", {})
        r = requests.get(f"{api.get('base_url','http://localhost:2501')}/system/status.json",
                        auth=(api.get("username", "kismet"), api.get("password", "")),
                        timeout=2)
        if r.ok:
            return {"connected": True, "data": r.json()}
    except Exception:
        pass
    return {"connected": False}


# ══════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    kismet = _kismet_status()
    return jsonify({
        "mode": detector.current_mode,
        "kismet_connected": kismet["connected"],
        "total_devices": len(detector.devices),
        "unknown_devices": sum(1 for p in detector.devices.values()
                               if not p.label and "HOME" not in p.modes_seen_in),
        "watchlist_count": len(detector.get_watchlist()),
        "present_count": len(detector.present_macs),
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/whitelist")
def api_whitelist():
    return jsonify({
        "devices": [p.to_dict() | {"display_name": p.display_name(),
                                    "signal_latest": p.signal_history[-1] if p.signal_history else None}
                    for p in sorted(detector.devices.values(),
                                    key=lambda x: x.encounter_score, reverse=True)]
    })


@app.route("/api/top_visitors")
def api_top_visitors():
    limit = int(request.args.get("limit", 20))
    return jsonify({
        "visitors": [p.to_dict() | {"display_name": p.display_name(),
                                     "signal_latest": p.signal_history[-1] if p.signal_history else None}
                     for p in detector.get_top_visitors(limit)]
    })


@app.route("/api/persons")
def api_persons():
    limit = int(request.args.get("limit", 20))
    return jsonify({
        "persons": [p.to_dict() | {"display_name": p.display_name(),
                                    "signal_latest": p.signal_history[-1] if p.signal_history else None}
                    for p in detector.get_persons_of_interest(limit)]
    })


@app.route("/api/watchlist")
def api_watchlist():
    return jsonify({
        "watchlist": [p.to_dict() | {"display_name": p.display_name()}
                      for p in detector.get_watchlist()]
    })


@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify({"alerts": get_recent_alerts(limit)})


@app.route("/api/label", methods=["POST"])
def api_label():
    data = request.get_json(force=True)
    mac = data.get("mac", "").strip()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    detector.label_device(
        mac,
        data.get("label", ""),
        data.get("group", "unknown"),
        data.get("notes", "")
    )
    return jsonify({"ok": True, "mac": mac})


@app.route("/api/watchlist/add", methods=["POST"])
def api_watchlist_add():
    data = request.get_json(force=True)
    mac = data.get("mac", "").strip()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    detector.add_to_watchlist(mac, data.get("reason", ""))
    return jsonify({"ok": True, "mac": mac})


@app.route("/api/watchlist/remove", methods=["POST"])
def api_watchlist_remove():
    data = request.get_json(force=True)
    mac = data.get("mac", "").strip()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    detector.remove_from_watchlist(mac)
    return jsonify({"ok": True, "mac": mac})


@app.route("/api/mode", methods=["POST"])
def api_mode():
    data = request.get_json(force=True)
    mode = data.get("mode", "").upper()
    valid = {"HOME", "ROAM", "DOORBELL", "WATCHLIST"}
    if mode not in valid:
        return jsonify({"error": f"mode must be one of {valid}"}), 400
    _run_mode_background(mode)
    return jsonify({"ok": True, "mode": mode})


@app.route("/api/notifications/config", methods=["GET", "POST"])
def api_notifications_config():
    """Get or update notification settings (Resend / Twilio)."""
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    if request.method == "POST":
        data = request.get_json(force=True)
        alerts = cfg.setdefault("alerts", {})
        if "resend" in data:
            alerts["resend"].update(data["resend"])
        if "twilio" in data:
            alerts["twilio"].update(data["twilio"])
        if "known_device_arrival_notify" in data:
            alerts["known_device_arrival_notify"] = data["known_device_arrival_notify"]
        if "unknown_ssid_linger_notify" in data:
            alerts["unknown_ssid_linger_notify"] = data["unknown_ssid_linger_notify"]
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        # Reload detector config
        detector.config = cfg
        detector.alert_cfg = cfg["alerts"]
        return jsonify({"ok": True})
    return jsonify({"alerts": cfg.get("alerts", {})})


@app.route("/api/export/csv")
def api_export_csv():
    filename = f"data/sentinel_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    detector.export_to_csv(filename)
    return jsonify({"ok": True, "file": filename})


@app.route("/api/export/json")
def api_export_json():
    filename = f"data/sentinel_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    detector.export_to_json(filename)
    return jsonify({"ok": True, "file": filename})


# ─── SSE Stream ───────────────────────────────
@app.route("/api/stream")
def api_stream():
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def _generate():
        # Send buffered recent alerts on connect
        for alert in get_recent_alerts(10):
            yield f"data: {json.dumps(alert)}\n\n"

        try:
            while True:
                try:
                    data = q.get(timeout=30)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


# ──────────────────────────────────────────────
@app.route("/api/stalkers")
def api_stalkers():
    """Multi-location stalker ranking from GPS-correlated Kismet data."""
    try:
        from multi_location_tracker import MultiLocationTracker
        mlt = MultiLocationTracker(config_path=CONFIG_PATH)
        mlt.scan_and_correlate(
            whitelist_path=detector.config["paths"]["whitelist"]
        )
        limit = int(request.args.get("limit", 20))
        ranked = mlt.get_ranked_stalkers(limit=limit)
        return jsonify({"stalkers": [r.to_dict() for r in ranked]})
    except Exception as e:
        return jsonify({"stalkers": [], "error": str(e)})


@app.route("/api/checkpoint", methods=["POST"])
def api_add_checkpoint():
    """Add a GPS checkpoint for multi-location tracking."""
    data = request.get_json(force=True)
    lat = data.get("lat"); lon = data.get("lon"); label = data.get("label", "")
    if lat is None or lon is None:
        return jsonify({"error": "lat and lon required"}), 400
    try:
        from multi_location_tracker import MultiLocationTracker
        mlt = MultiLocationTracker(config_path=CONFIG_PATH)
        cp = mlt.add_checkpoint(float(lat), float(lon), label)
        return jsonify({"ok": True, "checkpoint": cp.to_dict()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sys_stats")
def api_sys_stats():
    """Return system health metrics (CPU, RAM, Disk, Temp)."""
    try:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        
        # Temperature (RPi/Linux specific)
        temp = None
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if "cpu_thermal" in temps:
                temp = temps["cpu_thermal"][0].current
            elif "coretemp" in temps:
                temp = temps["coretemp"][0].current
        
        return jsonify({
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "temp": temp,
            "platform": platform.system(),
            "node": platform.node()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/create_launcher", methods=["POST"])
def api_create_launcher():
    """Create a double-clickable macOS .command desktop launcher."""
    import stat
    from pathlib import Path
    repo = os.path.dirname(os.path.abspath(__file__))
    venv = os.path.join(repo, "venv", "bin", "activate")
    desktop = Path.home() / "Desktop" / "SentinelWatch.command"
    script = f"""#!/bin/bash
# SentinelWatch — Double-click to start
cd "{repo}"
if [ -f "{venv}" ]; then source "{venv}"; fi
echo "🛡  Starting SentinelWatch..."
(sleep 1.5 && open "http://localhost:8888") &
python3 web_ui.py
"""
    try:
        with open(desktop, "w") as f:
            f.write(script)
        desktop.chmod(desktop.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        return jsonify({"ok": True, "path": str(desktop)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
if __name__ == "__main__":

    print("\n🛡  SentinelWatch Web Dashboard")
    print("   http://localhost:8888\n")
    app.run(host="0.0.0.0", port=8888, debug=False, threaded=True)
