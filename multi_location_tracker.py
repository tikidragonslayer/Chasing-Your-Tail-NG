"""
multi_location_tracker.py — SentinelWatch GPS Stalker Ranker
Tracks devices/SSIDs seen across multiple GPS checkpoints and ranks
the most likely persons surveilling/stalking the user.
🔒 SECURE MODE: Uses SecureKismetDB for SQL injection prevention.
"""

import json
import os
import sqlite3
import glob
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from secure_database import SecureKismetDB


# ──────────────────────────────────────────────
#  GPS helpers
# ──────────────────────────────────────────────
def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Return distance in km between two GPS coordinates."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@dataclass
class GPSCheckpoint:
    timestamp: str           # ISO timestamp of when we were at this location
    lat: float
    lon: float
    location_label: str = "" # e.g. "home", "work", "coffee shop"

    def to_dict(self):
        return asdict(self)


@dataclass
class MultiLocationHit:
    """Records one observation of a device at a particular GPS checkpoint."""
    mac: str
    ssids: list = field(default_factory=list)
    checkpoint_label: str = ""
    checkpoint_lat: float = 0.0
    checkpoint_lon: float = 0.0
    timestamp: str = ""
    signal: Optional[int] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class StalkerProfile:
    mac: str
    label: str = ""
    manufacturer: str = ""
    ssids: list = field(default_factory=list)
    # All unique GPS checkpoint locations this device was seen at
    locations_seen: list = field(default_factory=list)   # list of dict {lat,lon,label,timestamp}
    unique_location_count: int = 0
    total_hits: int = 0
    # Stalker score: weighted by unique locations + frequency
    stalker_score: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    notes: str = ""

    def to_dict(self):
        return asdict(self)


# ──────────────────────────────────────────────
#  MultiLocationTracker
# ──────────────────────────────────────────────
class MultiLocationTracker:
    def __init__(self, config_path: str = "config.json",
                 data_path: str = "data/multi_location.json"):
        with open(config_path) as f:
            self.config = json.load(f)
        self.data_path = data_path
        os.makedirs(os.path.dirname(data_path), exist_ok=True)

        # mac → StalkerProfile
        self.profiles: dict[str, StalkerProfile] = {}
        # Our saved GPS checkpoints (user's own locations over time)
        self.our_checkpoints: list[GPSCheckpoint] = []
        # Minimum km between two checkpoints to count as "different location"
        self.min_location_separation_km = 0.5

        self._load()

    # ─── Persistence ──────────────────────────
    def _load(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path) as f:
                    raw = json.load(f)
                for mac, d in raw.get("profiles", {}).items():
                    self.profiles[mac] = StalkerProfile(**{
                        k: v for k, v in d.items()
                        if k in StalkerProfile.__dataclass_fields__
                    })
                for cp in raw.get("our_checkpoints", []):
                    self.our_checkpoints.append(GPSCheckpoint(**cp))
            except Exception as e:
                print(f"[MLT] Load error: {e}")

    def save(self):
        with open(self.data_path, "w") as f:
            json.dump({
                "profiles": {mac: p.to_dict() for mac, p in self.profiles.items()},
                "our_checkpoints": [cp.to_dict() for cp in self.our_checkpoints],
                "updated": datetime.now().isoformat(),
            }, f, indent=2)

    def add_checkpoint(self, lat: float, lon: float, label: str = ""):
        """Record our current GPS location as a named checkpoint."""
        cp = GPSCheckpoint(
            timestamp=datetime.now().isoformat(),
            lat=lat, lon=lon,
            location_label=label or f"loc_{len(self.our_checkpoints)+1}"
        )
        self.our_checkpoints.append(cp)
        self.save()
        print(f"[MLT] Checkpoint added: {cp.location_label} ({lat:.5f}, {lon:.5f})")
        return cp

    def _is_new_location(self, mac: str, lat: float, lon: float) -> bool:
        """True if this lat/lon is far enough from all previously recorded locations for this device."""
        if mac not in self.profiles:
            return True
        for loc in self.profiles[mac].locations_seen:
            dist = haversine_km(lat, lon, loc["lat"], loc["lon"])
            if dist < self.min_location_separation_km:
                return False
        return True

    # ─── Kismet DB scan ───────────────────────
    def _get_kismet_files(self) -> list[str]:
        files = glob.glob(self.config["paths"]["kismet_logs"])
        if not files:
            files = glob.glob(os.path.join(str(Path.home()), "*.kismet"))
        return sorted(files)

    def scan_and_correlate(self, whitelist_path: str = "data/home_whitelist.json"):
        """
        Scan all Kismet databases and correlate devices seen at multiple
        of the user's GPS checkpoints. Updates StalkerProfiles ranked by score.
        """
        if not self.our_checkpoints:
            print("[MLT] No GPS checkpoints recorded yet. Run with GPS or add checkpoints manually.")
            return []

        # Load whitelist so we can skip labeled home devices
        home_macs: set = set()
        try:
            with open(whitelist_path) as f:
                wl = json.load(f)
            home_macs = {mac for mac, d in wl.items()
                         if "HOME" in d.get("modes_seen_in", [])}
        except Exception:
            pass

        for db_path in self._get_kismet_files():
            self._process_db(db_path, home_macs)

        self._compute_scores()
        self.save()
        return self.get_ranked_stalkers()

    def _process_db(self, db_path: str, skip_macs: set):
        """🔒 Secure: parameterized SecureKismetDB — no raw SQL concatenation."""
        try:
            with SecureKismetDB(db_path) as db:
                if not db.validate_connection():
                    return
                rows = db.execute_safe_query(
                    "SELECT devmac, device, first_time, last_time, "
                    "avg_lat, avg_lon, strongest_signal "
                    "FROM devices WHERE avg_lat != 0 AND avg_lon != 0"
                )
            for row in rows:
                mac = row["devmac"]
                if mac in skip_macs:
                    continue
                lat, lon = row["avg_lat"] or 0.0, row["avg_lon"] or 0.0
                if lat == 0.0 and lon == 0.0:
                    continue

                # Find nearest user checkpoint
                nearest_cp = self._nearest_checkpoint(lat, lon)
                if nearest_cp is None:
                    continue

                dist = haversine_km(lat, lon, nearest_cp.lat, nearest_cp.lon)
                # Only count if within 1km of one of our checkpoints
                if dist > 1.0:
                    continue

                # Parse SSIDs from device blob
                ssids = []
                try:
                    blob = json.loads(row["device"])
                    for key in ["dot11.device.probed_ssid_map", "dot11.device.advertised_ssid_map"]:
                        mp = blob.get("dot11.device", {}).get(key, {})
                        if isinstance(mp, dict):
                            for v in mp.values():
                                s = (v.get("dot11.probedssid.ssid")
                                     or v.get("dot11.advertisedssid.ssid", ""))
                                if s and s not in ssids:
                                    ssids.append(s)
                    mfr = blob.get("kismet.device.base.manuf", "Unknown")
                except Exception:
                    mfr = "Unknown"

                ts_last = datetime.fromtimestamp(row["last_time"]).isoformat() if row["last_time"] else ""
                ts_first = datetime.fromtimestamp(row["first_time"]).isoformat() if row["first_time"] else ""

                if mac not in self.profiles:
                    self.profiles[mac] = StalkerProfile(
                        mac=mac, manufacturer=mfr, ssids=ssids,
                        first_seen=ts_first, last_seen=ts_last
                    )
                p = self.profiles[mac]
                p.total_hits += 1
                p.last_seen = ts_last
                for s in ssids:
                    if s and s not in p.ssids:
                        p.ssids.append(s)

                # Record new unique location
                if self._is_new_location(mac, lat, lon):
                    p.locations_seen.append({
                        "lat": lat, "lon": lon,
                        "label": nearest_cp.location_label,
                        "timestamp": ts_last,
                        "signal": row["strongest_signal"],
                    })
                    p.unique_location_count = len(p.locations_seen)
        except Exception as e:
            print(f"[MLT] DB error {db_path}: {e}")

    def _nearest_checkpoint(self, lat: float, lon: float) -> Optional[GPSCheckpoint]:
        if not self.our_checkpoints:
            return None
        return min(self.our_checkpoints,
                   key=lambda cp: haversine_km(lat, lon, cp.lat, cp.lon))

    def _compute_scores(self):
        """
        Stalker score formula:
          score = unique_location_count^2 * log(total_hits + 1) * recency_weight
        Higher weight for devices seen at many distinct locations frequently.
        """
        import math
        now = datetime.now()
        for p in self.profiles.values():
            if p.unique_location_count < 2:
                p.stalker_score = 0.0
                continue
            try:
                last = datetime.fromisoformat(p.last_seen)
                days_ago = max(0, (now - last).total_seconds() / 86400)
                recency = 1.0 / (1 + days_ago)
            except Exception:
                recency = 0.5
            p.stalker_score = (
                (p.unique_location_count ** 2)
                * math.log(p.total_hits + 1)
                * recency
            )

    def get_ranked_stalkers(self, min_locations: int = 2, limit: int = 20) -> list[StalkerProfile]:
        """Return devices seen at 2+ distinct GPS locations, ranked by stalker score."""
        candidates = [
            p for p in self.profiles.values()
            if p.unique_location_count >= min_locations
        ]
        return sorted(candidates, key=lambda p: p.stalker_score, reverse=True)[:limit]

    def print_report(self):
        """Pretty-print the stalker ranking to terminal."""
        ranked = self.get_ranked_stalkers()
        if not ranked:
            print("\n[MLT] No multi-location suspects found yet. Build up GPS data first.")
            return

        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            c = Console()
            t = Table(title="📍 SentinelWatch — Multi-Location Stalker Ranking",
                      box=box.ROUNDED, header_style="bold red", border_style="red")
            t.add_column("Rank", width=5)
            t.add_column("MAC / Label")
            t.add_column("Score", justify="right")
            t.add_column("Locations", justify="right")
            t.add_column("Total Hits", justify="right")
            t.add_column("SSIDs")
            t.add_column("Locations Seen")
            for i, p in enumerate(ranked, 1):
                locs = " → ".join(l["label"] for l in p.locations_seen[:4])
                name = p.label or p.mac
                t.add_row(
                    f"#{i}", name,
                    f"[red]{p.stalker_score:.2f}[/red]",
                    str(p.unique_location_count),
                    str(p.total_hits),
                    ", ".join(p.ssids[:2]) or "—",
                    locs
                )
            c.print(t)
        except ImportError:
            print(f"\n{'─'*90}")
            print("  📍 MULTI-LOCATION STALKER RANKING")
            print(f"{'─'*90}")
            for i, p in enumerate(ranked, 1):
                locs = " → ".join(l["label"] for l in p.locations_seen[:4])
                print(f"  #{i} {p.label or p.mac:<22} Score:{p.stalker_score:.2f}  "
                      f"Locations:{p.unique_location_count}  Hits:{p.total_hits}")
                print(f"     SSIDs: {', '.join(p.ssids[:3]) or '(none)'}  Path: {locs}")
            print(f"{'─'*90}\n")


# ── CLI ───────────────────────────────────────
if __name__ == "__main__":
    import sys
    tracker = MultiLocationTracker()

    if len(sys.argv) >= 2:
        cmd = sys.argv[1]
        if cmd == "add-checkpoint" and len(sys.argv) >= 4:
            label = sys.argv[4] if len(sys.argv) >= 5 else ""
            tracker.add_checkpoint(float(sys.argv[2]), float(sys.argv[3]), label)
        elif cmd == "scan":
            tracker.scan_and_correlate()
            tracker.print_report()
        elif cmd == "report":
            tracker.print_report()
        else:
            print("Usage: python multi_location_tracker.py [scan|report|add-checkpoint <lat> <lon> <label>]")
    else:
        tracker.scan_and_correlate()
        tracker.print_report()
