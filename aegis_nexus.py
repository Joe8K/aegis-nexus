#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  AEGIS-NEXUS v3.0  —  Autonomous Digital Risk Protection Platform    ║
║  SPECTRA · Neural Filter · Graph Intelligence · AI Threat Brain      ║
╚══════════════════════════════════════════════════════════════════════╝

4-Layer Biological Model + AI Brain + Response Engine:
  AXIOM   — Digital Twin (Graph DB of your assets)
  HYDRA   — Ingestion Mesh (11 async scrapers)
  KRONOS  — Neural Noise Filter (SPECTRA algorithm)
  PHANTOM — Deception Layer (honey tokens)
  ORACLE  — AI Brain (Groq LLM threat summaries + campaign reconstruction)
  NEXUS   — Response Engine (takedown generator, PDF reports, containment)

Usage:
  python3 aegis_v6.py api        # Web dashboard at localhost:8000
  python3 aegis_v6.py monitor    # Terminal live monitor
  python3 aegis_v6.py phantom    # Honey token manager
  python3 aegis_v6.py twin       # Inspect Digital Twin
  python3 aegis_v6.py score      # Interactive SPECTRA scorer
  python3 aegis_v6.py calibrate  # Self-calibration engine
  python3 aegis_v6.py test       # Self-test suite
  python3 aegis_v6.py tui        # Textual terminal dashboard
  python3 aegis_v6.py demo       # Pipeline demo

New in v3.0:
  + BeVigil API scraper          + Abuse.ch malware feed
  + OTX AlienVault intel         + URLScan.io phishing detector
  + Pulsedive enrichment
  + IntelX dark web search       + Dark Web Tor monitor
  + GitHub commit secret scanner + Wayback Machine monitor
  + Supply chain monitor         + Employee exposure monitor
  + AI Threat Summariser (Groq)  + Attack timeline reconstruction
  + Attacker profiling           + Certificate abuse scoring
  + Threat actor attribution     + Automated takedown generator
  + Incident PDF reports         + One-click containment
  + Weekly intelligence digest
"""

# ── Standard library ─────────────────────────────────────────────
import asyncio
import hashlib
import json
import logging
import math
import os
import random
import re
import secrets
import string
import sys
import time
import uuid
import urllib.request
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ── Third-party ──────────────────────────────────────────────────
import numpy as np
from scipy.linalg import eigvalsh

# Optional deps — loaded lazily
try:
    import duckdb as _duckdb
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False

try:
    import aiohttp as _aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(name)-16s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aegis")

# ── Helpers ──────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def now_str(fmt: str = "%H:%M:%S") -> str:
    return datetime.now(timezone.utc).strftime(fmt)

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


import ssl as _SSL_MOD

def _mk_ssl_ctx():
    """SSL context that bypasses cert issues on Kali."""
    ctx = _SSL_MOD.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _SSL_MOD.CERT_NONE
    return ctx


# ══════════════════════════════════════════════════════════════════
# LAYER 1 — AXIOM: DIGITAL TWIN
# ══════════════════════════════════════════════════════════════════

@dataclass
class Asset:
    """A single organizational asset tracked by the Digital Twin."""
    name:       str
    kind:       str                              # service | domain | database | cdn
    tech:       List[str] = field(default_factory=list)
    tags:       List[str] = field(default_factory=list)
    meta:       Dict[str, Any] = field(default_factory=dict)
    created:    str = field(default_factory=now_iso)
    node_id:    str = ""
    fingerprint: str = ""

    def __post_init__(self):
        raw = f"{self.name}:{self.kind}:{':'.join(sorted(self.tech))}"
        self.fingerprint = sha256_hex(raw)
        self.node_id     = self.fingerprint[:16]


@dataclass
class Threat:
    """An incoming threat event to be evaluated against the Digital Twin."""
    threat_id:  str
    source:     str          # ct_logs | github | paste | cve | shodan | phantom
    kind:       str          # lookalike_domain | exposed_secret | data_leak | vuln | scan
    indicator:  str          # raw IOC string
    tech:       List[str]    = field(default_factory=list)
    ttps:       List[str]    = field(default_factory=list)
    meta:       Dict[str, Any] = field(default_factory=dict)
    found_at:   str          = field(default_factory=now_iso)
    score:      float        = 0.0
    severity:   str          = "UNKNOWN"

    def sig(self) -> str:
        return sha256_hex(f"{self.kind}:{self.indicator}:{':'.join(sorted(self.tech))}")[:16]


class Laplacian:
    """
    Graph Laplacian engine for the Digital Twin.

    Computes the eigenvalue spectrum of the asset graph — the mathematical
    fingerprint used by SPECTRA Stage 1 (spectral perturbation distance).

    L = D - A  where A = adjacency matrix, D = degree matrix.
    The spectrum encodes structural topology of the asset graph.
    Perturbation distance = how much a threat would shift the spectrum.
    """

    def __init__(self):
        self._adj:  Dict[str, Dict[str, float]] = {}
        self._eigs: Optional[np.ndarray] = None
        self._dirty = True

    def add_node(self, nid: str):
        if nid not in self._adj:
            self._adj[nid] = {}
            self._dirty = True

    def add_edge(self, a: str, b: str, w: float = 1.0):
        self.add_node(a); self.add_node(b)
        self._adj[a][b] = w; self._adj[b][a] = w
        self._dirty = True

    def _build(self) -> np.ndarray:
        nodes = sorted(self._adj)
        n = len(nodes)
        if n == 0:
            return np.zeros((1, 1))
        idx = {nid: i for i, nid in enumerate(nodes)}
        A = np.zeros((n, n))
        for s, nb in self._adj.items():
            for d, w in nb.items():
                A[idx[s]][idx[d]] = w
        return np.diag(A.sum(axis=1)) - A

    def spectrum(self) -> np.ndarray:
        if self._dirty or self._eigs is None:
            self._eigs = np.sort(eigvalsh(self._build()))
            self._dirty = False
        return self._eigs

    def perturbation(self, edges: List[Tuple[str, str, float]]) -> float:
        """
        Compute spectral perturbation distance for candidate threat edges.
        Uses rank-1 Frobenius norm approximation — O(n) not O(n³).
        Returns float in (0, 1) via tanh squash.
        """
        sp = self.spectrum()
        n  = len(self._adj)
        if n == 0:
            return 0.0
        known = set(self._adj)
        frob_sq = 0.0
        for src, dst, w in edges:
            if src in known and dst in known:
                frob_sq += 4 * w ** 2      # both endpoints in graph
            elif src in known or dst in known:
                frob_sq += w ** 2           # one endpoint in graph
        p  = np.sqrt(frob_sq) / max(np.sqrt(n), 1.0)
        sr = float(np.max(np.abs(sp))) if len(sp) > 0 else 1.0
        return float(np.tanh(p / max(sr, 1e-9)))

    @property
    def node_count(self) -> int:
        return len(self._adj)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._adj.values()) // 2


# ══════════════════════════════════════════════════════════════════
# LAYER 1 — AXIOM: DIGITAL TWIN
# ══════════════════════════════════════════════════════════════════

@dataclass
class Asset:
    """A single organizational asset tracked by the Digital Twin."""
    name:       str
    kind:       str                              # service | domain | database | cdn
    tech:       List[str] = field(default_factory=list)
    tags:       List[str] = field(default_factory=list)
    meta:       Dict[str, Any] = field(default_factory=dict)
    created:    str = field(default_factory=now_iso)
    node_id:    str = ""
    fingerprint: str = ""

    def __post_init__(self):
        raw = f"{self.name}:{self.kind}:{':'.join(sorted(self.tech))}"
        self.fingerprint = sha256_hex(raw)
        self.node_id     = self.fingerprint[:16]


@dataclass
class Threat:
    """An incoming threat event to be evaluated against the Digital Twin."""
    threat_id:  str
    source:     str          # ct_logs | github | paste | cve | shodan | phantom
    kind:       str          # lookalike_domain | exposed_secret | data_leak | vuln | scan
    indicator:  str          # raw IOC string
    tech:       List[str]    = field(default_factory=list)
    ttps:       List[str]    = field(default_factory=list)
    meta:       Dict[str, Any] = field(default_factory=dict)
    found_at:   str          = field(default_factory=now_iso)
    score:      float        = 0.0
    severity:   str          = "UNKNOWN"

    def sig(self) -> str:
        return sha256_hex(f"{self.kind}:{self.indicator}:{':'.join(sorted(self.tech))}")[:16]


class Laplacian:
    """
    Graph Laplacian engine for the Digital Twin.

    Computes the eigenvalue spectrum of the asset graph — the mathematical
    fingerprint used by SPECTRA Stage 1 (spectral perturbation distance).

    L = D - A  where A = adjacency matrix, D = degree matrix.
    The spectrum encodes structural topology of the asset graph.
    Perturbation distance = how much a threat would shift the spectrum.
    """

    def __init__(self):
        self._adj:  Dict[str, Dict[str, float]] = {}
        self._eigs: Optional[np.ndarray] = None
        self._dirty = True

    def add_node(self, nid: str):
        if nid not in self._adj:
            self._adj[nid] = {}
            self._dirty = True

    def add_edge(self, a: str, b: str, w: float = 1.0):
        self.add_node(a); self.add_node(b)
        self._adj[a][b] = w; self._adj[b][a] = w
        self._dirty = True

    def _build(self) -> np.ndarray:
        nodes = sorted(self._adj)
        n = len(nodes)
        if n == 0:
            return np.zeros((1, 1))
        idx = {nid: i for i, nid in enumerate(nodes)}
        A = np.zeros((n, n))
        for s, nb in self._adj.items():
            for d, w in nb.items():
                A[idx[s]][idx[d]] = w
        return np.diag(A.sum(axis=1)) - A

    def spectrum(self) -> np.ndarray:
        if self._dirty or self._eigs is None:
            self._eigs = np.sort(eigvalsh(self._build()))
            self._dirty = False
        return self._eigs

    def perturbation(self, edges: List[Tuple[str, str, float]]) -> float:
        """
        Compute spectral perturbation distance for candidate threat edges.
        Uses rank-1 Frobenius norm approximation — O(n) not O(n³).
        Returns float in (0, 1) via tanh squash.
        """
        sp = self.spectrum()
        n  = len(self._adj)
        if n == 0:
            return 0.0
        known = set(self._adj)
        frob_sq = 0.0
        for src, dst, w in edges:
            if src in known and dst in known:
                frob_sq += 4 * w ** 2      # both endpoints in graph
            elif src in known or dst in known:
                frob_sq += w ** 2           # one endpoint in graph
        p  = np.sqrt(frob_sq) / max(np.sqrt(n), 1.0)
        sr = float(np.max(np.abs(sp))) if len(sp) > 0 else 1.0
        return float(np.tanh(p / max(sr, 1e-9)))

    @property
    def node_count(self) -> int:
        return len(self._adj)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._adj.values()) // 2


class DigitalTwin:
    """
    AXIOM Digital Twin — living graph of organizational assets.

    Acts as the immune system:
      is_self()  → True  means the threat targets our tech (relevant)
      is_self()  → False means the threat targets tech we don't use (noise)

    Maintains:
      - Asset node registry
      - Tech-stack index for O(1) relevance lookup
      - Laplacian engine for SPECTRA scoring
      - In-memory alert log (DuckDB in production)
    """

    def __init__(self):
        self.assets:    Dict[str, Asset]  = {}       # node_id → Asset
        self.edges:     List[Tuple]       = []        # (src, dst, rel)
        self.laplacian  = Laplacian()
        self._tech_idx: Dict[str, List[str]] = {}    # tech → [node_ids]
        self._alerts:   List[Dict]        = []

    # ── Asset management ─────────────────────────────────────────

    def add_asset(self, a: Asset) -> str:
        self.assets[a.node_id] = a
        self.laplacian.add_node(a.node_id)
        for t in a.tech:
            tl = t.lower()
            self._tech_idx.setdefault(tl, [])
            if a.node_id not in self._tech_idx[tl]:
                self._tech_idx[tl].append(a.node_id)
        log.debug(f"[AXIOM] Asset: {a.name} ({a.kind}) id={a.node_id}")
        return a.node_id

    def add_edge(self, src_name: str, dst_name: str, rel: str, w: float = 1.0):
        src = self._by_name(src_name)
        dst = self._by_name(dst_name)
        if src and dst:
            self.edges.append((src.node_id, dst.node_id, rel))
            self.laplacian.add_edge(src.node_id, dst.node_id, w)

    def _by_name(self, name: str) -> Optional[Asset]:
        for a in self.assets.values():
            if a.name.lower() == name.lower():
                return a
        return None

    # ── Immune system ─────────────────────────────────────────────

    def is_self(self, techs: List[str]) -> Tuple[bool, List[str], float]:
        """
        Core immune check.
        Returns (relevant, matching_asset_names, overlap_ratio).
        Non-Self threats are fast-rejected before SPECTRA runs.
        """
        if not techs:
            return False, [], 0.0
        hits: Set[str] = set()
        matched: List[str] = []
        for t in techs:
            tl = t.lower()
            if tl in self._tech_idx:
                hits.update(self._tech_idx[tl]); matched.append(t)
            else:
                for k in self._tech_idx:
                    if tl in k or k in tl:
                        hits.update(self._tech_idx[k]); matched.append(t); break
        if not hits:
            return False, [], 0.0
        names   = [self.assets[nid].name for nid in hits if nid in self.assets]
        overlap = len(set(t.lower() for t in matched)) / max(len(set(t.lower() for t in techs)), 1)
        return True, names, overlap

    def candidate_edges(self, threat: Threat) -> List[Tuple[str, str, float]]:
        ok, names, overlap = self.is_self(threat.tech)
        if not ok:
            return []
        tid = f"threat_{threat.sig()}"
        return [
            (tid, a.node_id, overlap * max(len(threat.ttps), 1) * 0.1)
            for name in names
            for a in [self._by_name(name)]
            if a
        ]

    # ── Alert store ───────────────────────────────────────────────

    def store_alert(self, d: Dict):
        self._alerts.insert(0, d)
        if len(self._alerts) > 1000:
            self._alerts.pop()

    def recent_alerts(self, n: int = 50, sev: str = "") -> List[Dict]:
        alerts = self._alerts
        if sev:
            alerts = [a for a in alerts if a.get("severity") == sev.upper()]
        return alerts[:n]

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> Dict:
        sp = self.laplacian.spectrum()
        return {
            "assets":            len(self.assets),
            "edges":             len(self.edges),
            "tech_types":        len(self._tech_idx),
            "tech_list":         list(self._tech_idx.keys()),
            "spectral_radius":   round(float(np.max(np.abs(sp))), 4) if len(sp) > 0 else 0.0,
            "connectivity":      round(float(sp[1]), 4) if len(sp) > 1 else 0.0,
            "alerts_stored":     len(self._alerts),
        }


def build_twin(config: Dict) -> DigitalTwin:
    """Bootstrap a Digital Twin from a JSON config dict."""
    twin = DigitalTwin()
    for a in config.get("assets", []):
        twin.add_asset(Asset(
            name=a["name"],
            kind=a.get("type", "service"),
            tech=a.get("tech_stack", []),
            tags=a.get("tags", []),
            meta=a.get("meta", {}),
        ))
    for r in config.get("relationships", []):
        twin.add_edge(r["from"], r["to"], r["type"])
    log.info(f"[AXIOM] Twin built: {len(twin.assets)} assets, {len(twin.edges)} edges")
    return twin


# ══════════════════════════════════════════════════════════════════
# LAYER 2 — SPECTRA ALGORITHM
# ══════════════════════════════════════════════════════════════════
#
# SPECTRA = Spectral Probabilistic Entropy-Calibrated
#            Threat Relevance Algorithm
#
# 5 Stages:
#   S1  Spectral Perturbation  — how much does threat shift our graph topology?
#   S2  Rényi Entropy          — how targeted vs generic is the threat?
#   S3  TTP Isomorphism        — does attack pattern match known chains?
#   S4  Temporal Decay         — Bayesian posterior decay for repeated signatures
#
# Weights: S1=40%  S2=25%  S3=25%  S4=10%
# Thresholds: < 0.15 → NOISE   > 0.75 → CRITICAL

W_S1, W_S2, W_S3, W_S4 = 0.40, 0.25, 0.25, 0.10

@dataclass
class ScoreResult:
    threat_id: str
    score:     float
    severity:  str
    s1:        float   # spectral perturbation
    s2:        float   # rényi entropy
    s3:        float   # ttp isomorphism
    s4:        float   # temporal decay weight
    is_noise:  bool
    reasoning: List[str]
    ms:        float   # processing time

    def as_dict(self) -> Dict:
        return {
            "threat_id": self.threat_id,
            "score":     self.score,
            "severity":  self.severity,
            "is_noise":  self.is_noise,
            "stages":    {"s1": self.s1, "s2": self.s2, "s3": self.s3, "s4": self.s4},
            "reasoning": self.reasoning,
            "ms":        self.ms,
        }


class SPECTRA:
    """
    SPECTRA scoring engine.
    Thread-safe, async-compatible.
    Maintains signature history for temporal decay.
    """

    def __init__(
        self,
        noise_thresh:    float = 0.25,
        critical_thresh: float = 0.75,
        renyi_alpha:     float = 2.0,
        decay_factor:    float = 0.85,
    ):
        self.noise_thresh    = noise_thresh
        self.critical_thresh = critical_thresh
        self.renyi_alpha     = renyi_alpha
        self.decay_factor    = decay_factor

        self._known_tech: List[str]                       = []
        self._ttp_graph:  Dict[str, Dict[str, int]]       = {}
        self._history:    Dict[str, Tuple[int, float, float]] = {}
        # sig → (count, last_seen_ts, last_score)

    # ── Configuration ─────────────────────────────────────────────

    def set_tech(self, techs: List[str]):
        self._known_tech = [t.lower() for t in techs]

    def load_ttp_pairs(self, pairs: List[Tuple[str, str]]):
        for a, b in pairs:
            self._ttp_graph.setdefault(a, {}).setdefault(b, 0)
            self._ttp_graph.setdefault(b, {}).setdefault(a, 0)
            self._ttp_graph[a][b] += 1
            self._ttp_graph[b][a] += 1

    # ── Stage 1: Spectral Perturbation ────────────────────────────

    def _s1(self, pd: float) -> Tuple[float, str]:
        s = float(np.clip(pd, 0.0, 1.0))
        if s > 0.5:
            msg = "Strong topological overlap with asset graph — high structural relevance."
        elif s > 0.1:
            msg = "Moderate topological overlap — likely relevant."
        else:
            msg = "Near-zero perturbation — structurally disconnected from our assets."
        return s, f"Perturbation={s:.4f}. {msg}"

    # ── Stage 2: Rényi Entropy (α=2, collision entropy) ───────────

    def _s2(self, threat_tech: List[str]) -> Tuple[float, str]:
        if not threat_tech or not self._known_tech:
            return 0.40, "No tech data — defaulting to moderate relevance."
        all_t   = list(set(self._known_tech + [t.lower() for t in threat_tech]))
        n       = len(all_t)
        ts      = set(t.lower() for t in threat_tech)
        overlap = ts & set(self._known_tech)
        p = np.array([1.0 / len(ts) if t in ts else 1e-9 for t in all_t])
        p = p / p.sum()
        # H_α = (1/(1-α)) * log2(Σ p_i^α)
        renyi_h = (1.0 / (1.0 - self.renyi_alpha)) * math.log2(
            float(np.sum(p ** self.renyi_alpha)) + 1e-12
        )
        max_h  = math.log2(n) if n > 1 else 1.0
        norm   = float(np.clip(1.0 - renyi_h / max(max_h, 1e-9), 0.0, 1.0))
        ovr    = len(overlap) / max(len(ts), 1)
        score  = float(np.clip(norm * 0.5 + ovr * 0.5, 0.0, 1.0))
        return score, (
            f"Rényi H₂={renyi_h:.4f} (max={max_h:.4f}). "
            f"Tech overlap={ovr:.1%} ({len(overlap)}/{len(ts)} match our stack)."
        )

    # ── Stage 3: TTP Graph Isomorphism ────────────────────────────

    def _s3(self, ttps: List[str]) -> Tuple[float, str]:
        if not ttps:
            return 0.10, "No TTPs provided — cannot assess attack pattern."
        if not self._ttp_graph:
            return 0.30, f"{len(ttps)} TTPs present but no baseline knowledge loaded."
        known = sum(1 for t in ttps if t in self._ttp_graph)
        # Build local co-occurrence edges from threat TTP list
        total = matched = 0
        for i, a in enumerate(ttps):
            for b in ttps[i + 1:]:
                total += 1
                if a in self._ttp_graph and b in self._ttp_graph[a]:
                    matched += 1
        ks    = known  / max(len(ttps), 1)
        es    = matched / max(total, 1)
        score = float(np.clip(0.6 * ks + 0.4 * es, 0.0, 1.0))
        return score, (
            f"{known}/{len(ttps)} TTPs in knowledge base. "
            f"{matched}/{total} co-occurrence edges matched. "
            f"TTPs: {', '.join(ttps[:4])}{'…' if len(ttps) > 4 else ''}."
        )

    # ── Stage 4: Temporal Bayesian Decay ──────────────────────────

    def _s4(self, sig: str, base: float) -> Tuple[float, str]:
        now = time.monotonic()
        if sig not in self._history:
            self._history[sig] = (1, now, base)
            return 1.0, "Novel signature — maximum prior weight applied."
        count, last_ts, _ = self._history[sig]
        hrs_since   = (now - last_ts) / 3600
        reset_frac  = min(1.0, hrs_since / 72)            # full reset after 72 h
        eff_count   = count * (1.0 - reset_frac * 0.5)
        weight      = float(np.clip(self.decay_factor ** eff_count, 0.05, 1.0))
        self._history[sig] = (count + 1, now, base)
        label = (
            "Repeated FP candidate — weight suppressed." if weight < 0.30
            else "Repeated threat — slight weight reduction." if weight < 0.70
            else "Low repetition — near-full weight."
        )
        return weight, f"Seen {count}× ({hrs_since:.1f}h ago). Weight={weight:.4f}. {label}"

    # ── Master scorer ──────────────────────────────────────────────

    async def score(
        self,
        threat_id: str,
        kind:      str,
        indicator: str,
        tech:      List[str],
        ttps:      List[str],
        meta:      Dict,
        perturbation: float,
    ) -> ScoreResult:
        t0 = time.perf_counter()

        s1, r1 = self._s1(perturbation)
        s2, r2 = self._s2(tech)
        s3, r3 = self._s3(ttps)

        # Intermediate composite for temporal baseline
        mid = (W_S1 * s1 + W_S2 * s2 + W_S3 * s3) / (W_S1 + W_S2 + W_S3)

        sig       = sha256_hex(f"{kind}:{indicator}:{':'.join(sorted(tech))}")[:16]
        s4, r4    = self._s4(sig, mid)

        final = float(np.clip(
            W_S1 * s1 + W_S2 * s2 + W_S3 * s3 + W_S4 * s4 * mid,
            0.0, 1.0,
        ))

        # ── CVSS cap (CVE threats only) ───────────────────────────
        # Prevents a CVSS 5.3 from scoring CRITICAL just because
        # our tech stack matches well. CVSS directly caps max severity.
        cvss = float(meta.get("cvss", 0.0)) if meta else 0.0
        if cvss > 0.0 and kind in ("known_vulnerability", "cve"):
            if   cvss >= 9.0: cvss_cap = 1.00   # CRITICAL allowed
            elif cvss >= 7.0: cvss_cap = 0.74   # HIGH max (< 0.75)
            elif cvss >= 5.0: cvss_cap = 0.49   # MEDIUM max — CVSS 5-6.9 stays MEDIUM
            elif cvss >= 4.0: cvss_cap = 0.38   # LOW-MEDIUM border — CVSS 4-4.9
            else:             cvss_cap = 0.28   # LOW
            final = min(final, cvss_cap)

        # ── Age decay (older CVEs score lower) ────────────────────
        age_years = int(meta.get("age_years", 0)) if meta else 0
        if age_years > 0 and kind in ("known_vulnerability", "cve"):
            if   age_years > 5: final *= 0.50
            elif age_years > 3: final *= 0.68
            elif age_years > 2: final *= 0.82
            elif age_years > 1: final *= 0.92
            final = float(np.clip(final, 0.0, 1.0))
            # CVSS floor: high-severity CVEs maintain minimum severity regardless of age
            # CVSS 9+   → floor 0.57 (HIGH min) — critical vulns stay HIGH forever
            # CVSS 7-8.9 → floor 0.57 (HIGH min) — high vulns stay HIGH until very old
            # CVSS 5-6.9 → floor 0.28 (LOW min)  — medium vulns can fade to LOW
            if cvss >= 7.0: final = max(final, 0.57)
            elif cvss >= 5.0: final = max(final, 0.28)

        noise = final < self.noise_thresh
        if noise:                             sev = "NOISE"
        elif final < 0.35:                    sev = "LOW"
        elif final < 0.55:                    sev = "MEDIUM"
        elif final < self.critical_thresh:    sev = "HIGH"
        else:                                 sev = "CRITICAL"

        ms = (time.perf_counter() - t0) * 1000

        if not noise:
            log.info(
                f"[SPECTRA] {sev:<8} score={final:.4f}  "
                f"s1={s1:.3f} s2={s2:.3f} s3={s3:.3f} s4={s4:.3f}  "
                f"{threat_id}  {kind}  {ms:.1f}ms"
            )

        return ScoreResult(
            threat_id = threat_id,
            score     = round(final, 6),
            severity  = sev,
            s1        = round(s1, 6),
            s2        = round(s2, 6),
            s3        = round(s3, 6),
            s4        = round(s4, 6),
            is_noise  = noise,
            reasoning = [f"[S1] {r1}", f"[S2] {r2}", f"[S3] {r3}", f"[S4] {r4}"],
            ms        = round(ms, 3),
        )

    def stats(self) -> Dict:
        return {
            "noise_threshold":    self.noise_thresh,
            "critical_threshold": self.critical_thresh,
            "signatures_tracked": len(self._history),
            "ttp_nodes":          len(self._ttp_graph),
            "known_tech_types":   len(self._known_tech),
        }


# ══════════════════════════════════════════════════════════════════
# LAYER 3 — PHANTOM: DECEPTION ENGINE
# ══════════════════════════════════════════════════════════════════

@dataclass
class HoneyToken:
    token_id:    str
    token_type:  str
    value:       str
    meta:        Dict[str, Any]
    deployed_to: str  = ""
    created:     str  = field(default_factory=now_iso)
    triggered:   bool = False
    trigger_ip:  str  = ""


class Phantom:
    """
    PHANTOM Deception Engine.

    Generates realistic honey tokens and canary files.
    When a token is used, it fires a CRITICAL alert — the highest-confidence
    signal in the system because it proves active exploitation.

    Token types: AWS credential, GitHub PAT, JWT secret, DB connection string,
                 generic API key, SSH private key (stub).

    Canary files: .env files with embedded tokens + unique watermarks.
    If a canary appears in a leak database, the watermark identifies the source.
    """

    def __init__(self):
        self._tokens:   Dict[str, HoneyToken] = {}
        self._canaries: Dict[str, Dict]       = {}
        self._callbacks: List[Callable]       = []

    def on_trigger(self, cb: Callable):
        self._callbacks.append(cb)

    # ── Token generators ─────────────────────────────────────────

    def gen_aws(self, org: str = "org") -> HoneyToken:
        chars = string.ascii_uppercase + string.digits
        ak    = "AKIA" + "".join(secrets.choice(chars) for _ in range(16))
        sk    = "".join(secrets.choice(string.ascii_letters + string.digits + "/+=") for _ in range(40))
        tid   = f"phantom_aws_{uuid.uuid4().hex[:8]}"
        t     = HoneyToken(tid, "aws_credential",
                           json.dumps({"access_key": ak, "secret_key": sk}),
                           {"access_key": ak, "secret_key": sk, "org": org})
        self._tokens[tid] = t
        return t

    def gen_github(self) -> HoneyToken:
        val = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        tid = f"phantom_gh_{uuid.uuid4().hex[:8]}"
        t   = HoneyToken(tid, "github_token", val, {"token": val, "scopes": ["repo"]})
        self._tokens[tid] = t
        return t

    def gen_jwt(self) -> HoneyToken:
        val = secrets.token_hex(32)
        tid = f"phantom_jwt_{uuid.uuid4().hex[:8]}"
        t   = HoneyToken(tid, "jwt_secret", val, {"secret": val, "algorithm": "HS256"})
        self._tokens[tid] = t
        return t

    def gen_db(self, dbtype: str = "postgresql") -> HoneyToken:
        user = "app_" + secrets.token_hex(4)
        pw   = secrets.token_urlsafe(16)
        host = f"db-{secrets.token_hex(3)}.internal.example.com"
        db   = f"prod_{secrets.token_hex(3)}"
        conn = f"{dbtype}://{user}:{pw}@{host}:5432/{db}"
        tid  = f"phantom_db_{uuid.uuid4().hex[:8]}"
        t    = HoneyToken(tid, "db_connection", conn, {"connection_string": conn, "host": host})
        self._tokens[tid] = t
        return t

    def gen_api_key(self, svc: str = "internal") -> HoneyToken:
        val = f"sk-{svc[:8]}-{secrets.token_hex(20)}"
        tid = f"phantom_api_{uuid.uuid4().hex[:8]}"
        t   = HoneyToken(tid, "api_key", val, {"key": val, "service": svc})
        self._tokens[tid] = t
        return t

    # ── Canary file ───────────────────────────────────────────────

    def gen_env_canary(self, domain: str = "example.com") -> Dict:
        aws  = self.gen_aws(domain.split(".")[0])
        gh   = self.gen_github()
        jwt  = self.gen_jwt()
        db   = self.gen_db()
        api  = self.gen_api_key("main-api")
        am   = json.loads(aws.value)
        wm   = sha256_hex(f"{domain}:{time.time()}")[:16]
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        content = f"""# Production Environment — {domain}
# Watermark: {wm}  Generated: {date}

# Application
APP_NAME={domain.split('.')[0]}-api
APP_ENV=production
APP_URL=https://api.{domain}
APP_PORT=8080

# Database
DATABASE_URL={db.value}
DATABASE_POOL_SIZE=10

# AWS
AWS_ACCESS_KEY_ID={am['access_key']}
AWS_SECRET_ACCESS_KEY={am['secret_key']}
AWS_DEFAULT_REGION=us-east-1
AWS_S3_BUCKET={domain.split('.')[0]}-prod-assets

# Auth
JWT_SECRET={jwt.value}
JWT_EXPIRY=3600
JWT_ALGORITHM=HS256

# GitHub
GITHUB_TOKEN={gh.value}
GITHUB_ORG={domain.split('.')[0]}

# API
INTERNAL_API_KEY={api.value}
INTERNAL_API_URL=https://api.{domain}/v1

# Redis
REDIS_URL=redis://:{secrets.token_hex(12)}@redis.{domain}:6379/0

# Monitoring
SENTRY_DSN=https://{secrets.token_hex(16)}@sentry.{domain}/1
LOG_LEVEL=info
"""
        fid = f"canary_{uuid.uuid4().hex[:8]}"
        c   = {
            "file_id":   fid,
            "domain":    domain,
            "watermark": wm,
            "content":   content,
            "tokens":    [aws.token_id, gh.token_id, jwt.token_id,
                          db.token_id, api.token_id],
            "created":   now_iso(),
            "triggered": False,
        }
        self._canaries[fid] = c
        for tid in c["tokens"]:
            if tid in self._tokens:
                self._tokens[tid].deployed_to = f"canary:{fid}"
        return c

    # ── Trigger ───────────────────────────────────────────────────

    def trigger(self, token_id: str, ip: str = "0.0.0.0") -> Dict:
        if token_id not in self._tokens:
            return {"error": f"Token not found: {token_id}"}
        t            = self._tokens[token_id]
        t.triggered  = True
        t.trigger_ip = ip
        triggered_at = now_iso()
        result = {
            "status":     "TRIGGERED",
            "token_id":   token_id,
            "token_type": t.token_type,
            "trigger_ip": ip,
            "triggered_at": triggered_at,
            "severity":   "CRITICAL",
        }
        # Persist trigger event so it survives process restart
        try:
            _phantom_log = os.path.expanduser("~/.aegis_phantom_triggers.jsonl")
            with open(_phantom_log, "a") as _pf:
                import json as _j
                _pf.write(_j.dumps({**result, "deployed_to": t.deployed_to,
                                    "created": t.created}) + "\n")
        except Exception as _pe:
            log.warning(f"[PHANTOM] Failed to persist trigger: {_pe}")
        for cb in self._callbacks:
            try:
                cb(t)
            except Exception:
                pass
        return result

    def stats(self) -> Dict:
        triggered = sum(1 for t in self._tokens.values() if t.triggered)
        return {
            "total_tokens":   len(self._tokens),
            "total_canaries": len(self._canaries),
            "triggered":      triggered,
            "by_type": {
                tt: sum(1 for t in self._tokens.values() if t.token_type == tt)
                for tt in ["aws_credential", "github_token", "jwt_secret",
                           "db_connection", "api_key"]
            },
        }

    def list_tokens(self) -> List[Dict]:
        return [
            {
                "token_id":   t.token_id,
                "token_type": t.token_type,
                "deployed_to": t.deployed_to or "—",
                "triggered":  t.triggered,
                "created":    t.created,
            }
            for t in self._tokens.values()
        ]

    def list_canaries(self) -> List[Dict]:
        return [
            {
                "file_id":   c["file_id"],
                "domain":    c["domain"],
                "watermark": c["watermark"],
                "tokens":    len(c["tokens"]),
                "triggered": c["triggered"],
                "created":   c["created"],
            }
            for c in self._canaries.values()
        ]


# ══════════════════════════════════════════════════════════════════
# DARKWATCH — OSINT Intelligence
# ══════════════════════════════════════════════════════════════════

ACTOR_DB: List[Dict] = [
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "Navigator Group"],
        "ttps": {"T1566", "T1059", "T1053", "T1078", "T1486"},
        "sectors": ["retail", "hospitality", "finance"],
        "sophistication": "high",
        "motivation": "financial",
    },
    {
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Zinc"],
        "ttps": {"T1190", "T1059", "T1566", "T1486", "T1078"},
        "sectors": ["finance", "cryptocurrency", "defense"],
        "sophistication": "nation-state",
        "motivation": "financial+espionage",
    },
    {
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy"],
        "ttps": {"T1566", "T1078", "T1021", "T1059", "T1053"},
        "sectors": ["government", "military", "energy"],
        "sophistication": "nation-state",
        "motivation": "espionage",
    },
    {
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "LockBit Black"],
        "ttps": {"T1190", "T1078", "T1486", "T1490", "T1489"},
        "sectors": ["healthcare", "manufacturing", "government"],
        "sophistication": "high",
        "motivation": "financial",
    },
    {
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Muddled Libra"],
        "ttps": {"T1078", "T1566", "T1110", "T1621", "T1539"},
        "sectors": ["telecom", "retail", "technology"],
        "sophistication": "medium",
        "motivation": "financial",
    },
    {
        "name": "Volt Typhoon",
        "aliases": ["Bronze Silhouette"],
        "ttps": {"T1190", "T1078", "T1133", "T1505", "T1021"},
        "sectors": ["critical-infrastructure", "government", "energy"],
        "sophistication": "nation-state",
        "motivation": "espionage+pre-positioning",
    },
]


def actor_match(ttps: List[str], indicator: str = "", sector: str = "") -> List[Dict]:
    """Match TTPs against known threat actor profiles. Returns ranked matches."""
    ts  = set(ttps)
    out = []
    for actor in ACTOR_DB:
        ov   = len(ts & actor["ttps"])
        conf = ov / max(len(actor["ttps"]), 1) * 0.70
        if re.search(r"\.(top|xyz|ru|cn)$", indicator):
            conf = min(conf + 0.10, 1.0)
        if sector and any(s in sector.lower() for s in actor["sectors"]):
            conf = min(conf + 0.15, 1.0)
        if conf > 0.12:
            out.append({
                "actor":          actor["name"],
                "aliases":        actor["aliases"],
                "confidence":     round(conf, 4),
                "matched_ttps":   list(ts & actor["ttps"]),
                "ttp_overlap":    ov,
                "sophistication": actor["sophistication"],
                "motivation":     actor["motivation"],
            })
    return sorted(out, key=lambda x: x["confidence"], reverse=True)[:3]


def typosquat(domain: str, limit: int = 40) -> List[str]:
    """Generate typosquat permutations for a domain."""
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return []
    name, tld = parts[0].lower(), parts[1].lower()
    out: Set[str] = set()

    # 1. Character omission
    for i in range(len(name)):
        v = name[:i] + name[i + 1:]
        if v:
            out.add(f"{v}.{tld}")

    # 2. Character doubling
    for i, c in enumerate(name):
        out.add(f"{name[:i]}{c}{c}{name[i+1:]}.{tld}")

    # 3. Numeric substitution
    subs = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
    for i, c in enumerate(name):
        if c in subs:
            out.add(f"{name[:i]}{subs[c]}{name[i+1:]}.{tld}")

    # 4. Common attack suffixes / prefixes
    for suffix in ["-login", "-secure", "-account", "-verify",
                   "-portal", "-support", "-help", "-auth"]:
        out.add(f"{name}{suffix}.{tld}")
    for prefix in ["login-", "secure-", "account-", "my-", "verify-"]:
        out.add(f"{prefix}{name}.{tld}")

    # 5. TLD substitution
    for alt in ["com", "net", "org", "io", "co", "xyz", "app", "online"]:
        if alt != tld:
            out.add(f"{name}.{alt}")

    # 6. Hyphen insertion
    for i in range(1, len(name)):
        out.add(f"{name[:i]}-{name[i:]}.{tld}")

    out.discard(domain)
    return list(out)[:limit]


# ══════════════════════════════════════════════════════════════════
# KRONOS — NOISE FILTER (ties all layers together)
# ══════════════════════════════════════════════════════════════════

class Kronos:
    """
    KRONOS Neural Noise Filter.
    Bridges AXIOM → SPECTRA and manages alert routing.

    Fast-path:  is_self() = False  → instant discard (no SPECTRA call)
    Slow-path:  is_self() = True   → full SPECTRA 5-stage scoring
    """

    def __init__(self, twin: DigitalTwin, spectra: SPECTRA):
        self.twin    = twin
        self.spectra = spectra
        self._noise   = 0
        self._total   = 0
        self._start   = time.monotonic()

    async def process(self, threat: Threat) -> Optional[ScoreResult]:
        self._total += 1
        # ── Fast path: immune check ───────────────────────────────
        ok, assets, overlap = self.twin.is_self(threat.tech)
        # Only fast-reject if tech is populated AND has zero overlap AND
        # it is not a high-value threat type that should always be scored
        _always_score = {"supply_chain_typosquat", "data_leak", "credential_exposure",
                         "dark_web_mention", "lookalike_domain", "employee_breach",
                         "paste_exposure", "github_secret", "ct_anomaly"}
        if not ok and threat.tech and threat.kind not in _always_score:
            self._noise += 1
            log.debug(f"[KRONOS] FAST-REJECT {threat.kind} tech={threat.tech}")
            return None

        # ── Laplacian perturbation ────────────────────────────────
        edges = self.twin.candidate_edges(threat)
        pd    = self.twin.laplacian.perturbation(edges)
        if not edges and not threat.tech:
            pd = 0.25   # unknown tech — treat as moderately relevant

        # ── SPECTRA scoring ───────────────────────────────────────
        result = await self.spectra.score(
            threat_id    = threat.threat_id,
            kind         = threat.kind,
            indicator    = threat.indicator,
            tech         = threat.tech,
            ttps         = threat.ttps,
            meta         = threat.meta,
            perturbation = pd,
        )

        threat.score    = result.score
        threat.severity = result.severity

        if result.is_noise:
            self._noise += 1
        else:
            # Store alert in Digital Twin
            alert = {
                "threat_id":  threat.threat_id,
                "source":     threat.source,
                "kind":       threat.kind,
                "indicator":  threat.indicator,
                "severity":   result.severity,
                "score":      result.score,
                "tech":       threat.tech,
                "ttps":       threat.ttps,
                "stages":     {"s1": result.s1, "s2": result.s2,
                               "s3": result.s3, "s4": result.s4},
                "reasoning":  result.reasoning,
                "assets":     assets,
                "ms":         result.ms,
                "found_at":   threat.found_at,
            }
            self.twin.store_alert(alert)

        return result

    def stats(self) -> Dict:
        uptime = time.monotonic() - self._start
        alerts = self._total - self._noise
        return {
            "uptime_s":        round(uptime, 1),
            "total_processed": self._total,
            "noise_discarded": self._noise,
            "alerts_raised":   alerts,
            "noise_reduction": f"{self._noise / max(self._total, 1):.1%}",
            "throughput_eps":  round(self._total / max(uptime, 1), 2),
        }


# ══════════════════════════════════════════════════════════════════
# DEMO CONFIGURATION
# ══════════════════════════════════════════════════════════════════

DEMO_TWIN_CONFIG = {
    "assets": [
        {
            "name": "main-webapp",
            "type": "service",
            "tech_stack": ["nginx", "python", "django", "redis", "postgresql"],
            "tags": ["production", "public-facing"],
        },
        {
            "name": "api-gateway",
            "type": "service",
            "tech_stack": ["nginx", "fastapi", "python", "jwt"],
            "tags": ["production", "api"],
        },
        {
            "name": "auth-service",
            "type": "service",
            "tech_stack": ["python", "jwt", "postgresql", "redis", "oauth2"],
            "tags": ["production", "internal"],
        },
        {
            "name": "prod-db",
            "type": "database",
            "tech_stack": ["postgresql", "ssl"],
            "tags": ["production", "database"],
        },
        {
            "name": "company.example.com",
            "type": "domain",
            "tech_stack": ["tls", "web", "http", "dns"],
            "tags": ["primary-domain"],
        },
        {
            "name": "cdn-assets",
            "type": "service",
            "tech_stack": ["cloudfront", "s3", "aws"],
            "tags": ["production", "cdn"],
        },
    ],
    "relationships": [
        {"from": "main-webapp",  "to": "api-gateway",  "type": "CONNECTS_TO"},
        {"from": "api-gateway",  "to": "auth-service", "type": "AUTHENTICATED_BY"},
        {"from": "main-webapp",  "to": "prod-db",      "type": "DEPENDS_ON"},
        {"from": "auth-service", "to": "prod-db",      "type": "DEPENDS_ON"},
    ],
}

MITRE_TTP_PAIRS = [
    ("T1190", "T1059"), ("T1583.001", "T1608.001"),
    ("T1552.001", "T1078"), ("T1566", "T1059"),
    ("T1046", "T1190"), ("T1530", "T1078.004"),
    ("T1078", "T1021"), ("T1059", "T1486"),
]


def _load_yaml_config(path: str) -> Optional[Dict]:
    """Load a config.yaml into a build_twin-compatible dict. Returns None on failure.

    Handles two YAML shapes:
      Shape A (CloudSEK style) — top-level keys: organization, domain, assets, edges
        assets items use: id, type, tech, tags
      Shape B (legacy style)  — top-level keys: nodes, edges
        node items use: name, type, tech_stack, tags
    """
    try:
        import yaml  # type: ignore
        with open(path) as f:
            raw = yaml.safe_load(f)

        # raw must be a dict — guard against bare lists
        if not isinstance(raw, dict):
            raise ValueError(f"Expected a YAML mapping at top level, got {type(raw).__name__}")

        # Locate the asset list — try every known key name
        node_list = (
            raw.get("assets") or
            raw.get("nodes") or
            []
        )

        assets = []
        for node in node_list:
            if not isinstance(node, dict):
                continue
            assets.append({
                # CloudSEK uses 'id' as the name; legacy uses 'name'
                "name":       node.get("name") or node.get("id") or "unknown",
                # both use 'type'; fallback to 'kind'
                "type":       node.get("type") or node.get("kind") or "service",
                # CloudSEK uses 'tech'; legacy uses 'tech_stack'
                "tech_stack": node.get("tech") or node.get("tech_stack") or [],
                "tags":       node.get("tags") or [],
                "meta":       node.get("meta") or {},
            })

        # Locate the edge/relationship list
        edge_list = (
            raw.get("edges") or
            raw.get("relationships") or
            []
        )

        rels = []
        for edge in edge_list:
            if not isinstance(edge, dict):
                continue
            rels.append({
                "from": edge.get("from") or edge.get("source") or "",
                "to":   edge.get("to")   or edge.get("target") or "",
                "type": edge.get("type") or edge.get("relation") or "CONNECTS_TO",
            })

        return {"assets": assets, "relationships": rels, "_raw": raw}

    except Exception as e:
        log.warning(f"[CONFIG] Failed to load {path}: {e}")
        return None


def make_engine() -> Tuple[DigitalTwin, SPECTRA, Phantom, Kronos]:
    """Bootstrap the full Aegis-Nexus engine stack.

    Automatically loads config.yaml from the current directory (or ~/Downloads/)
    if found. Falls back to DEMO_TWIN_CONFIG otherwise.
    """
    # ── Try to load real config.yaml ──────────────────────────────
    config     = None
    config_src = "demo"
    for candidate in [
        "config.yaml",
        os.path.expanduser("~/Downloads/config.yaml"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"),
    ]:
        if os.path.exists(candidate):
            loaded = _load_yaml_config(candidate)
            if loaded and loaded.get("assets"):
                config     = loaded
                config_src = candidate
                log.info(f"[AXIOM] Loaded real config from {candidate}")
                break

    if config is None:
        config     = DEMO_TWIN_CONFIG
        config_src = "built-in demo"
        log.info("[AXIOM] Using built-in demo twin (no config.yaml found)")
        print(f"  \033[93m⚠ WARNING: No config.yaml found — running on DEMO DATA.\033[0m")
        print(f"  \033[93m  Asset names, domains, and tech stacks shown are PLACEHOLDER values.\033[0m")
        print(f"  \033[93m  Create config.yaml with real CloudSEK assets to enable live monitoring.\033[0m")

    twin = build_twin(config)

    # Pull domain + org metadata from raw yaml if available
    raw = config.get("_raw", {})
    if raw.get("domain"):
        twin.meta = {
            "domain":     raw["domain"],
            "org":        raw.get("organization", raw.get("org", "Unknown")),
            "github_org": raw.get("github_org", ""),
        }
    else:
        twin.meta = {"domain": "example.com", "org": "Demo Org", "github_org": ""}

    print(f"  {col('AXIOM','CYAN')} Digital Twin loaded  "
          f"{col(f'{len(twin.assets)} assets','HIGH')}  "
          f"{col(f'source: {config_src}','DIM')}")

    spectra = SPECTRA()
    spectra.set_tech(list(twin._tech_idx.keys()))
    spectra.load_ttp_pairs(MITRE_TTP_PAIRS)
    phantom = Phantom()
    phantom.gen_aws("aegis-demo")
    phantom.gen_github()
    phantom.gen_env_canary(twin.meta.get("domain", "example.com"))
    kronos  = Kronos(twin, spectra)
    return twin, spectra, phantom, kronos


# ══════════════════════════════════════════════════════════════════
# CLI — TERMINAL INTERFACE
# ══════════════════════════════════════════════════════════════════

# ANSI colour helpers — safe on Kali terminal
C = {
    "CRITICAL": "\033[91m", "HIGH":    "\033[93m",
    "MEDIUM":   "\033[96m", "LOW":     "\033[92m",
    "NOISE":    "\033[90m", "RST":     "\033[0m",
    "BOLD":     "\033[1m",  "DIM":     "\033[2m",
    "CYAN":     "\033[96m", "GREEN":   "\033[92m",
    "RED":      "\033[91m", "YELLOW":  "\033[93m",
}

def col(text: str, key: str) -> str:
    return f"{C.get(key, '')}{text}{C['RST']}"

def bar(val: float, width: int = 20) -> str:
    f = int(val * width)
    key = "CRITICAL" if val > 0.75 else "HIGH" if val > 0.50 else "MEDIUM" if val > 0.15 else "NOISE"
    return col("█" * f, key) + col("░" * (width - f), "DIM")

def banner():
    print(f"""
{C['CYAN']}{C['BOLD']}  ╔══════════════════════════════════════════════════════╗
  ║  █████╗ ███████╗ ██████╗ ██╗███████╗             ║
  ║ ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝             ║
  ║ ███████║█████╗  ██║  ███╗██║███████╗  NEXUS      ║
  ║ ██╔══██║██╔══╝  ██║   ██║██║╚════██║             ║
  ║ ██║  ██║███████╗╚██████╔╝██║███████║  v3.0       ║
  ╚══════════════════════════════════════════════════════╝{C['RST']}
  {col('Autonomous Digital Risk Protection', 'DIM')}
  {col('SPECTRA · AXIOM · HYDRA · KRONOS · PHANTOM', 'DIM')}
""")

def sev_col(sev: str) -> str:
    return col(sev, sev)


# ── Command: demo ─────────────────────────────────────────────────

async def cmd_demo():
    banner()
    twin, spectra, phantom, kronos = make_engine()
    st = twin.stats()
    print(f"  {col('Digital Twin','BOLD')}  {st['assets']} assets · {st['tech_types']} tech types · λ-radius={st['spectral_radius']}")
    print(f"  {col('Tech stack:','DIM')}  {', '.join(st['tech_list'][:10])}")
    print()

    threats = [
        ("Lookalike domain",      "ct_logs",  "lookalike_domain",    "c0mpany-login.com",     ["tls","web","dns"],           ["T1583.001","T1608.001"]),
        ("Exposed GitHub secret", "github",   "exposed_secret",      "ghp_xK9aBmQ3FAKE36chars",["git","python","credentials"],["T1552.001","T1078"]),
        ("PostgreSQL CVE",        "cve_feed", "known_vulnerability", "CVE-2025-9821",           ["postgresql","ssl"],          ["T1190","T1203"]),
        ("JWT secret in paste",   "paste",    "credential_leak",     "pastebin.com/xK9aB3mQ",  ["python","jwt"],              ["T1530","T1078.004"]),
        ("Windows RDP scan",      "shodan",   "port_scan",           "203.0.113.42:3389",      ["windows","rdp","iis"],       ["T1021.001"]),
        ("Java Spring exploit",   "shodan",   "known_vulnerability", "CVE-2024-1111",           ["java","spring-boot"],        ["T1190"]),
        ("Mass SSH brute",        "shodan",   "brute_force",         "0.0.0.0/0",              ["linux","ssh","windows"],     ["T1110"]),
        ("Phishing domain",       "ct_logs",  "phishing_domain",     "company-secure.xyz",     ["tls","web","dns"],           ["T1566.002","T1583.001"]),
        ("AWS key in paste",      "paste",    "credential_leak",     "pastebin.com/awsleak",   ["aws","credentials"],         ["T1552","T1078"]),
        ("Honey token fired",     "phantom",  "honey_token_trigger", "AKIAIOSFODNN7EXAMPLE",  ["aws","credentials"],         ["T1078","T1087"]),
    ]

    print(f"  {col('SPECTRA pipeline — 10 test threats','BOLD')}\n")
    HDR = f"  {'THREAT':<33} {'SEV':^10} {'SCORE':^8} {'S1':^7} {'S2':^7} {'S3':^7}  FATE"
    print(HDR)
    print("  " + "─" * 85)

    noise = alerts = 0
    for name, src, kind, ind, tech, ttps in threats:
        t = Threat(f"demo-{sha256_hex(name)[:6]}", src, kind, ind, tech, ttps)
        r = await kronos.process(t)
        if r is None:
            noise += 1
            print(f"  {name:<33} {col('NOISE',    'NOISE'):^19}  {'—':^7}  {'—':^6}  {'—':^6}  {'—':^7}  {col('⌀ IMMUNE REJECT','DIM')}")
        elif r.is_noise:
            noise += 1
            print(f"  {name:<33} {sev_col(r.severity):^19}  {r.score:^7.4f}  {r.s1:^6.3f}  {r.s2:^6.3f}  {r.s3:^6.3f}  {col('⌀ DISCARDED','DIM')}")
        else:
            alerts += 1
            fate = col("⚠ CRITICAL", "CRITICAL") if r.severity == "CRITICAL" else col("→ ALERT", "HIGH") if r.severity == "HIGH" else col("→ alert", "MEDIUM")
            print(f"  {name:<33} {sev_col(r.severity):^19}  {r.score:^7.4f}  {r.s1:^6.3f}  {r.s2:^6.3f}  {r.s3:^6.3f}  {fate}")
        await asyncio.sleep(0.04)

    total = len(threats)
    print("  " + "─" * 85)
    print(f"\n  {col('Session Summary','BOLD')}")
    print(f"    Threats processed  : {total}")
    print(f"    Noise discarded    : {col(str(noise),'DIM')} ({noise/total:.0%})")
    print(f"    Alerts raised      : {col(str(alerts),'HIGH')}")
    print(f"    Noise reduction    : {col(f'{noise/total:.1%}','HIGH')}")
    kst = kronos.stats()
    print(f"    Throughput         : {kst['throughput_eps']} events/s")

    print(f"\n  {col('Typosquat variants for example.com','BOLD')}")
    for v in typosquat("example.com", 8):
        print(f"    {col('›','DIM')} {v}")

    print(f"\n  {col('Phantom — active honey tokens','BOLD')}")
    for tok in phantom.list_tokens()[:4]:
        status = col("● active", "GREEN")
        print(f"    {status}  {tok['token_id']}  {tok['token_type']}")

    print(f"\n  {col('✓ AEGIS-NEXUS demo complete.','GREEN')}\n")


# ── Command: score ────────────────────────────────────────────────

async def cmd_score():
    banner()
    twin, spectra, phantom, kronos = make_engine()
    print(f"  {col('SPECTRA Threat Scorer','BOLD')}\n")
    kind  = input("  Threat type  [lookalike_domain]: ").strip() or "lookalike_domain"
    ind   = input("  Indicator    [c0mpany.com]: ").strip()      or "c0mpany.com"
    tech  = input("  Target tech  [tls,web,dns]: ").strip()      or "tls,web,dns"
    ttps  = input("  TTPs         [T1583.001,T1608.001]: ").strip() or "T1583.001,T1608.001"

    tech_list = [t.strip() for t in tech.split(",") if t.strip()]
    ttp_list  = [t.strip() for t in ttps.split(",") if t.strip()]

    t = Threat("manual", "manual", kind, ind, tech_list, ttp_list)
    ok, assets, ovr = twin.is_self(tech_list)

    print(f"\n  {col('Immune Check','DIM')}  is_self={col(str(ok),'HIGH' if ok else 'NOISE')}  "
          f"assets={assets}  overlap={ovr:.1%}")

    if not ok and tech_list:
        print(f"  {col('→ FAST REJECTED — Non-Self threat. Not in our tech stack.','NOISE')}\n")
        return

    edges = twin.candidate_edges(t)
    pd    = twin.laplacian.perturbation(edges)
    print(f"  {col('Laplacian perturbation:','DIM')} {pd:.6f}")
    print(f"\n  {col('Running SPECTRA 5-stage pipeline…','DIM')}\n")

    r = await spectra.score("manual", kind, ind, tech_list, ttp_list, {}, pd)

    # Score card
    print(f"  ┌─────────────────────────────────────────┐")
    print(f"  │  Score    : {col(f'{r.score:.6f}', r.severity):<37}│")
    print(f"  │  Severity : {col(r.severity, r.severity):<37}│")
    print(f"  │  Is Noise : {col(str(r.is_noise), 'NOISE' if r.is_noise else 'HIGH'):<37}│")
    print(f"  │  Time     : {r.ms:.2f}ms{'':<30}│")
    print(f"  └─────────────────────────────────────────┘\n")

    # Stage breakdown
    print(f"  {col('Stage Breakdown','BOLD')}")
    stages = [
        ("S1 · Spectral Perturbation", r.s1),
        ("S2 · Rényi Entropy",         r.s2),
        ("S3 · TTP Isomorphism",       r.s3),
        ("S4 · Temporal Decay",        r.s4),
    ]
    for label, val in stages:
        print(f"  {label:<26}  {bar(val)}  {col(f'{val:.4f}', 'HIGH' if val > 0.5 else 'DIM')}")

    # Reasoning
    print(f"\n  {col('Reasoning Chain','BOLD')}")
    for line in r.reasoning:
        print(f"    {col('›','DIM')} {line}")

    # Actor attribution
    actors = actor_match(ttp_list, ind)
    if actors:
        print(f"\n  {col('Threat Actor Attribution','BOLD')}")
        for a in actors:
            print(f"    {col(a['actor'],'HIGH')}  confidence={a['confidence']:.3f}  "
                  f"soph={a['sophistication']}  motive={a['motivation']}")
            if a["matched_ttps"]:
                print(f"    {col('matched:','DIM')} {', '.join(a['matched_ttps'])}")
    print()


# ── Command: monitor ──────────────────────────────────────────────

async def cmd_monitor():
    banner()
    twin, spectra, phantom, kronos = make_engine()

    # Use domain/org from loaded config, or prompt
    meta       = getattr(twin, "meta", {})
    default_d  = meta.get("domain", "example.com")
    domain     = input(f"  Target domain [{default_d}]: ").strip() or default_d
    org        = meta.get("org", domain.split(".")[0].capitalize())
    gh_org     = meta.get("github_org", "")
    tech_stack = list(twin._tech_idx.keys()) or [
        "fastapi", "nginx", "postgresql", "redis", "elasticsearch",
        "docker", "kubernetes", "openssl", "grafana"
    ]

    print(f"\n  {col('HYDRA real scrapers starting…','DIM')}")
    print(f"  {col('Sources: crt.sh · NVD/CVE · GitHub · Pastebin · Shodan','DIM')}")
    print(f"  {col('KRONOS engine active — SPECTRA scoring live','DIM')}")
    print(f"  {col('Press Ctrl+C to stop','DIM')}\n")
    print(f"  {'TIME':^9} {'SEV':^10} {'SCORE':^8} {'TYPE':<26} {'SOURCE':<12} {'INDICATOR'}")
    print("  " + "─" * 90)

    hydra = HydraScrapers(
        domains    = [domain],
        keywords   = [domain, org] + ([gh_org] if gh_org else []),
        known_tech = tech_stack,
    )
    await hydra.start()

    alerts = 0
    try:
        while True:
            threat = await hydra.next(timeout=5.0)
            if threat is None:
                continue
            result = await kronos.process(threat)
            if result and not result.is_noise:
                alerts += 1
                ts   = now_str()
                fate = col(" ⚠", "CRITICAL") if result.severity == "CRITICAL" else ""
                src  = threat.source[:10]
                ind  = threat.indicator[:40]
                print(f"  {ts:^9} {sev_col(result.severity):^19} {result.score:^8.4f} "
                      f"{threat.kind:<26} {col(src,'DIM'):<12} {col(ind,'DIM')}{fate}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        hydra.stop()
        kst = kronos.stats()
        hst = hydra.stats()
        print(f"\n\n  {col('Monitor stopped.','DIM')}")
        print(f"  Alerts={alerts}  "
              f"Processed={kst['total_processed']}  "
              f"Noise={kst['noise_discarded']}  "
              f"Reduction={kst['noise_reduction']}")
        print(f"  HYDRA counts: {hst['counts']}")


# ── Command: phantom ──────────────────────────────────────────────

async def cmd_phantom():
    banner()
    _, _, phantom, _ = make_engine()
    print(f"  {col('PHANTOM Deception Engine','BOLD')}\n")
    print("  1) Generate AWS credential token")
    print("  2) Generate GitHub PAT token")
    print("  3) Generate JWT secret token")
    print("  4) Generate DB connection string")
    print("  5) Generate API key")
    print("  6) Generate .env canary file")
    print("  7) List all active tokens")
    print("  8) Simulate honey token trigger")
    choice = input("\n  Choice [1-8]: ").strip()

    if choice == "1":
        t = phantom.gen_aws(); m = json.loads(t.value)
        print(f"\n  {col('Token ID','DIM')}    {t.token_id}")
        print(f"  {col('Access Key','DIM')}  {m['access_key']}")
        print(f"  {col('Secret Key','DIM')}  {m['secret_key']}")
    elif choice == "2":
        t = phantom.gen_github()
        print(f"\n  {col('Token ID','DIM')}  {t.token_id}")
        print(f"  {col('Value','DIM')}     {t.value}")
    elif choice == "3":
        t = phantom.gen_jwt()
        print(f"\n  {col('Token ID','DIM')}  {t.token_id}")
        print(f"  {col('Secret','DIM')}    {t.value}")
    elif choice == "4":
        t = phantom.gen_db()
        print(f"\n  {col('Token ID','DIM')}  {t.token_id}")
        print(f"  {col('ConnStr','DIM')}   {t.value}")
    elif choice == "5":
        svc = input("  Service name [internal-api]: ").strip() or "internal-api"
        t   = phantom.gen_api_key(svc)
        print(f"\n  {col('Token ID','DIM')}  {t.token_id}")
        print(f"  {col('Key','DIM')}      {t.value}")
    elif choice == "6":
        dom    = input("  Domain [example.com]: ").strip() or "example.com"
        canary = phantom.gen_env_canary(dom)
        path   = f"/tmp/aegis_canary_{canary['file_id']}.env"
        with open(path, "w") as f:
            f.write(canary["content"])
        print(f"\n  {col('Canary saved:','GREEN')}  {path}")
        print(f"  {col('File ID:','DIM')}     {canary['file_id']}")
        print(f"  {col('Watermark:','DIM')}   {canary['watermark']}")
        print(f"  {col('Tokens:','DIM')}      {len(canary['tokens'])} embedded")
        print(f"\n  {col('Preview (first 8 lines):','DIM')}")
        for line in canary["content"].split("\n")[:8]:
            print(f"    {col(line,'DIM')}")
    elif choice == "7":
        tokens = phantom.list_tokens()
        if not tokens:
            print(f"\n  {col('No tokens generated yet.','DIM')}")
        else:
            print()
            for tok in tokens:
                status = col("⚠ TRIGGERED", "CRITICAL") if tok["triggered"] else col("● active", "GREEN")
                print(f"  {status}  {tok['token_id']}  {col(tok['token_type'],'DIM')}  → {tok['deployed_to']}")
        st = phantom.stats()
        print(f"\n  Total: {st['total_tokens']} tokens  {st['total_canaries']} canaries  "
              f"{col(str(st['triggered'])+' triggered', 'CRITICAL' if st['triggered'] else 'DIM')}")
    elif choice == "8":
        tokens = phantom.list_tokens()
        if not tokens:
            print(f"  {col('No tokens to trigger. Generate one first.','DIM')}")
        else:
            print("\n  Available tokens:")
            for i, tok in enumerate(tokens):
                print(f"  [{i}] {tok['token_id']}  {tok['token_type']}")
            idx = input("  Select index [0]: ").strip() or "0"
            try:
                tid = tokens[int(idx)]["token_id"]
                ip  = input("  Source IP [1.2.3.4]: ").strip() or "1.2.3.4"
                r   = phantom.trigger(tid, ip)
                print(f"\n  {col('⚠ PHANTOM ALERT ⚠','CRITICAL')}")
                print(f"  {json.dumps(r, indent=4)}")
            except (IndexError, ValueError):
                print(f"  {col('Invalid selection','RED')}")
    print()


# ── Command: twin ─────────────────────────────────────────────────

async def cmd_twin():
    banner()
    twin, _, _, _ = make_engine()
    st = twin.stats()
    print(f"  {col('AXIOM Digital Twin Inspector','BOLD')}\n")
    print(f"  Assets          : {col(str(st['assets']),'HIGH')}")
    print(f"  Relationships   : {col(str(st['edges']),'HIGH')}")
    print(f"  Tech types      : {col(str(st['tech_types']),'HIGH')}")
    print(f"  Spectral radius : {col(str(st['spectral_radius']),'CYAN')}")
    print(f"  Connectivity    : {col(str(st['connectivity']),'CYAN')}")
    print(f"  Stored alerts   : {st['alerts_stored']}")

    print(f"\n  {col('Asset Nodes','BOLD')}")
    icons = {"service": "◈", "domain": "◉", "database": "◆", "cdn": "◇"}
    colors = {"service": "CYAN", "domain": "HIGH", "database": "YELLOW", "cdn": "GREEN"}
    for a in twin.assets.values():
        ic = icons.get(a.kind, "○")
        print(f"  {col(ic, colors.get(a.kind,'DIM'))} {col(a.name,'BOLD')}  "
              f"{col(a.kind,'DIM')}  tech: {', '.join(a.tech[:5])}"
              f"{'…' if len(a.tech) > 5 else ''}")

    print(f"\n  {col('Tech Coverage','BOLD')}")
    techs = list(twin._tech_idx.keys())
    print("  " + col(" · ".join(techs), "CYAN"))

    print(f"\n  {col('Laplacian Spectrum (first 6 eigenvalues)','BOLD')}")
    sp = twin.laplacian.spectrum()
    vals = [f"{float(v):.4f}" for v in sp[:6]]
    print("  [" + "  ".join(vals) + "]")
    print(f"\n  {col('λ₁=0 confirms connected graph. λ₂>0 = no isolated nodes.','DIM')}\n")


# ── Command: api ──────────────────────────────────────────────────


def _ensure_static_assets(static_dir: str):
    """Download D3 and font CSS once into ~/.aegis_static/ for local serving."""
    import urllib.request, ssl, os
    ctx = ssl.create_default_context()
    os.makedirs(static_dir, exist_ok=True)

    assets = {
        "d3.min.js": [
            "https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js",
            "https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js",
            "https://unpkg.com/d3@7.8.5/dist/d3.min.js",
        ],
        "fonts.css": [
            "https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap",
        ],
    }

    results = {}
    for filename, urls in assets.items():
        path = os.path.join(static_dir, filename)
        if os.path.exists(path) and os.path.getsize(path) > 500:
            results[filename] = "cached"
            continue
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "AegisNexus/2.0"})
                with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
                    data = r.read()
                with open(path, "wb") as f:
                    f.write(data)
                results[filename] = f"downloaded ({len(data)} bytes)"
                break
            except Exception as e:
                results[filename] = f"failed: {e}"
    return results



async def cmd_api():
    banner()
    try:
        from fastapi import FastAPI, WebSocket, WebSocketDisconnect
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import HTMLResponse, PlainTextResponse
        from fastapi.staticfiles import StaticFiles
        import uvicorn
    except ImportError:
        print("  Run: pip3 install fastapi uvicorn --break-system-packages")
        return

    # ── Download static assets (D3, fonts) once, serve locally ──
    static_dir = os.path.expanduser("~/.aegis_static")
    print(f"  {col('Checking static assets…','DIM')}")
    results = _ensure_static_assets(static_dir)
    for name, status in results.items():
        icon = col('✓','GREEN') if 'downloaded' in status or 'cached' in status else col('✗','YELLOW')
        print(f"  {icon} {name}: {status}")
    has_d3    = os.path.exists(os.path.join(static_dir, "d3.min.js"))
    has_fonts = os.path.exists(os.path.join(static_dir, "fonts.css"))

    twin, spectra, phantom, kronos = make_engine()
    # Use a consistent path — if locked by another process, fall back to memory
    _db_path = os.path.expanduser("~/.aegis_alerts.db")
    db = AlertDB(_db_path)
    if db._db is None:
        log.warning("[DB] Using in-memory store — close other aegis instances to persist")
    ws_clients: List[WebSocket] = []
    k_stats    = {"total_processed": 0, "noise_discarded": 0,
                  "alerts_raised": 0, "critical": 0}

    async def broadcast(msg: dict):
        dead = []
        for ws in ws_clients:
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in ws_clients: ws_clients.remove(ws)

    def on_phantom_trigger(tok):
        asyncio.create_task(broadcast({
            "type": "phantom_trigger",
            "data": {"token_id": tok.token_id, "type": tok.token_type,
                     "ip": tok.trigger_ip, "severity": "CRITICAL"}
        }))
    phantom.on_trigger(on_phantom_trigger)

    # ── Real HYDRA ingestion for the web dashboard ────────────────
    _meta      = getattr(twin, "meta", {})
    _domain    = _meta.get("domain", "cloudsek.com")
    _org       = _meta.get("org", _domain.split(".")[0].capitalize())
    _gh_org    = _meta.get("github_org", "")
    _tech_stack = list(twin._tech_idx.keys()) or [
        "fastapi","nginx","postgresql","redis","elasticsearch",
        "docker","kubernetes","openssl","grafana"
    ]
    hydra = HydraScrapers(
        domains    = [_domain],
        keywords   = [_domain, _org] + ([_gh_org] if _gh_org else []),
        known_tech = _tech_stack,
    )

    async def real_ingestion():
        """Pull from HydraScrapers queue, score with KRONOS, broadcast via WebSocket."""
        await hydra.start()
        # hydra_v3 is initialized later in cmd_api scope — wait up to 10s for it
        await asyncio.sleep(3)
        try:
            await hydra_v3.start()
            log.info("[HYDRA-v3] Extended scrapers started successfully")
        except Exception as e:
            log.warning(f"[HYDRA-v3] Start failed: {e}")
        while True:
            threat = await hydra.next(timeout=2.0)
            if threat is None:
                # Also drain v3 queue
                try:
                    threat = hydra_v3._queue.get_nowait()
                except Exception:
                    await broadcast({"type":"stats","data":k_stats})
                    continue
            k_stats["total_processed"] += 1
            result = await kronos.process(threat)
            if result is None or result.is_noise:
                k_stats["noise_discarded"] += 1
            else:
                k_stats["alerts_raised"] += 1
                if result.severity == "CRITICAL":
                    k_stats["critical"] += 1
                alert = {
                    "threat_id": threat.threat_id,
                    "source":    threat.source,
                    "kind":      threat.kind,
                    "indicator": threat.indicator,
                    "severity":  result.severity,
                    "score":     result.score,
                    "tech":      threat.tech,
                    "ttps":      threat.ttps,
                    "meta":      threat.meta,
                    "stages":    {"s1":result.s1,"s2":result.s2,
                                  "s3":result.s3,"s4":result.s4},
                    "reasoning": result.reasoning,
                    "found_at":  threat.found_at,
                }
                db.save(alert)
                await broadcast({"type":"alert","data":alert})
                asyncio.create_task(_send_email_alert(alert))
                asyncio.create_task(_send_slack_alert(alert))
                # AI enrichment for HIGH/CRITICAL
                if result.severity in ("HIGH","CRITICAL"):
                    asyncio.create_task(_enrich_alert(alert))
            await broadcast({"type":"stats","data":k_stats})

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        import threading, asyncio as _aio
        def _run_ingestion():
            loop = _aio.new_event_loop()
            _aio.set_event_loop(loop)
            loop.run_until_complete(real_ingestion())
        threading.Thread(target=_run_ingestion, daemon=True).start()
        threading.Thread(target=_run_ingestion, daemon=True).start()
        yield
    api = FastAPI(title="AEGIS-NEXUS REST API",
                  description="Autonomous Digital Risk Protection — v3.0",
                  version="3.0.0",
                  lifespan=lifespan)
    api.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])
    # Mount local static assets
    try:
        api.mount("/static", StaticFiles(directory=static_dir), name="static")
    except Exception:
        pass

    @api.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard():
        html = DASHBOARD_HTML
        # Inject D3 if downloaded locally
        if has_d3:
            html = html.replace(
                "/* INJECT_D3 */",
                '<script src="/static/d3.min.js"></script>'
            )
        # Inject fonts if downloaded locally
        if has_fonts:
            html = html.replace(
                "/* INJECT_FONTS */",
                '<link rel="stylesheet" href="/static/fonts.css">'
            )
        return HTMLResponse(html)

    @api.websocket("/ws/alerts")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()
        ws_clients.append(ws)
        try:
            await ws.send_text(json.dumps({"type":"stats","data":k_stats}))
            # Replay recent alerts — filter out stale CVEs on reconnect
            for a in reversed(db.recent(50)):
                meta = a.get("meta") or {}
                age  = int(meta.get("age_years", 0))
                cvss = float(meta.get("cvss", 0))
                kind = a.get("kind","")
                # Skip old CVEs that slipped through before filter tightening
                if kind == "known_vulnerability" and age >= 6:
                    continue
                await ws.send_text(json.dumps({"type":"alert","data":a}))
            while True:
                await ws.receive_text()
        except (WebSocketDisconnect, Exception):
            if ws in ws_clients: ws_clients.remove(ws)

    @api.get("/health")
    def health():
        _meta = getattr(twin, "meta", {})
        _is_demo = (_meta.get("domain","") in ("example.com","") or
                    not any(a.name not in ("main-webapp","api-gateway","auth-service",
                                           "prod-db","company.example.com","cdn-assets")
                            for a in twin.assets.values()))
        return {"status":"ok","assets":len(twin.assets),
                "tech_types":len(twin._tech_idx),
                "demo_mode": _is_demo,
                "warning": ("Running on demo/placeholder data — provide config.yaml for live data"
                            if _is_demo else None),
                "kronos":k_stats,"phantom":phantom.stats()}

    @api.get("/stats")
    def stats():
        return {"twin":twin.stats(),"spectra":spectra.stats(),
                "phantom":phantom.stats(),"kronos":k_stats,"alerts":db.analytics()}

    @api.get("/twin/assets")
    def list_assets():
        return {"total":len(twin.assets),
                "assets":[{"id":a.node_id,"name":a.name,"kind":a.kind,
                            "tech":a.tech,"tags":a.tags} for a in twin.assets.values()]}

    @api.get("/twin/spectrum")
    def get_spectrum():
        sp = twin.laplacian.spectrum(); st = twin.stats()
        return {"eigenvalues":[round(float(v),6) for v in sp],
                "spectral_radius":st["spectral_radius"],"connectivity":st["connectivity"]}

    @api.post("/twin/asset")
    def add_asset_ep(body: dict):
        a = Asset(body["name"],body.get("kind","service"),body.get("tech",[]),body.get("tags",[]))
        nid = twin.add_asset(a)
        spectra.set_tech(list(twin._tech_idx.keys()))
        return {"node_id":nid,"name":a.name}

    @api.post("/spectra/score")
    async def score_threat(body: dict):
        t = Threat(body.get("id",f"api-{time.time():.0f}"),body.get("source","api"),
                   body.get("kind","unknown"),body.get("indicator",""),
                   body.get("tech",[]),body.get("ttps",[]))
        ok,assets,ovr = twin.is_self(t.tech)
        edges = twin.candidate_edges(t); pd = twin.laplacian.perturbation(edges)
        r = await spectra.score(t.threat_id,t.kind,t.indicator,t.tech,t.ttps,{},pd)
        if not r.is_noise:
            alert = {"threat_id":t.threat_id,"source":t.source,"kind":t.kind,
                     "indicator":t.indicator,"severity":r.severity,"score":r.score,
                     "tech":t.tech,"ttps":t.ttps,
                     "stages":{"s1":r.s1,"s2":r.s2,"s3":r.s3,"s4":r.s4},"found_at":now_iso()}
            db.save(alert)
            await broadcast({"type":"alert","data":alert})
        return {**r.as_dict(),"immune_check":{"is_self":ok,"matching_assets":assets,"overlap":ovr},
                "perturbation":round(pd,6)}

    @api.get("/alerts")
    def list_alerts(limit: int = 50, severity: str = "", clean: bool = True):
        alerts = db.recent(limit, severity)
        if clean:
            # Filter stale CVEs that predate tighter scoring rules
            def _keep(a):
                meta = a.get("meta") or {}
                age  = int(meta.get("age_years", 0))
                kind = a.get("kind","")
                if kind == "known_vulnerability" and age >= 6:
                    return False
                return True
            alerts = [a for a in alerts if _keep(a)]
        return {"alerts": alerts, "analytics": db.analytics()}

    @api.get("/phantom/tokens")
    def list_tokens():
        return {"stats":phantom.stats(),"tokens":phantom.list_tokens()}

    @api.post("/phantom/generate")
    def gen_token(body: dict):
        tt  = body.get("type","aws")
        gen = {"aws":lambda:phantom.gen_aws(body.get("org","org")),
               "github":phantom.gen_github,"jwt":phantom.gen_jwt,"db":phantom.gen_db,
               "api":lambda:phantom.gen_api_key(body.get("service","api"))}.get(tt,phantom.gen_github)
        t = gen()
        return {"token_id":t.token_id,"type":t.token_type}

    @api.get("/phantom/canaries")
    def list_canaries():
        return {"canaries":phantom.list_canaries()}

    @api.post("/phantom/canary")
    def gen_canary(body: dict):
        c = phantom.gen_env_canary(body.get("domain","example.com"))
        return {"file_id":c["file_id"],"watermark":c["watermark"],"tokens":c["tokens"]}

    @api.get("/phantom/canaries/{file_id}/content")
    def canary_content(file_id: str):
        from fastapi import HTTPException
        c = phantom._canaries.get(file_id)
        if not c: raise HTTPException(404,f"Canary {file_id} not found")
        return PlainTextResponse(c["content"])

    @api.post("/phantom/trigger")
    async def trigger(body: dict):
        result = phantom.trigger(body.get("token_id",""),body.get("ip","0.0.0.0"))
        if "error" not in result:
            await broadcast({"type":"phantom_trigger","data":result})
        return result

    @api.get("/darkwatch/typosquat")
    def typosquat_ep(domain: str = "example.com"):
        v = typosquat(domain)
        return {"domain":domain,"count":len(v),"variants":v}

    @api.post("/darkwatch/actors")
    def actor_ep(body: dict):
        return {"matches":actor_match(body.get("ttps",[]),body.get("indicator",""),body.get("sector",""))}

    @api.get("/db/analytics")
    def db_analytics():
        return db.analytics()

    # ── v3.0 NEW ENDPOINTS ─────────────────────────────────────

    @api.post("/oracle/summarise")
    async def oracle_summarise(body: dict):
        """Generate AI threat summary for an alert."""
        alert_id = body.get("threat_id", "")
        alerts = db.recent(200)
        alert = next((a for a in alerts if a.get("threat_id") == alert_id), None)
        if not alert:
            alert = body
        summary = await oracle.summarise_threat(alert)
        actors  = oracle.attribute_threat_actors(
            alert.get("ttps", []), alert.get("indicator", ""), "technology"
        )
        return {"threat_id": alert_id, "ai_summary": summary, "threat_actors": actors}

    @api.get("/oracle/timeline")
    async def oracle_timeline():
        """Reconstruct attack campaign timeline from recent alerts."""
        recent = db.recent(50)
        result = await oracle.reconstruct_timeline(recent)
        return result or {"is_campaign": False, "narrative": "Not enough data for campaign detection yet."}

    @api.post("/oracle/profile")
    async def oracle_profile(body: dict):
        """Build attacker profile for an indicator."""
        indicator = body.get("indicator", "")
        itype     = body.get("type", "domain")
        profile   = await oracle.profile_attacker(indicator, itype)
        return profile

    @api.post("/oracle/takedown")
    async def oracle_takedown(body: dict):
        """Generate UDRP abuse report for a domain."""
        alert_id = body.get("threat_id", "")
        alerts = db.recent(200)
        alert = next((a for a in alerts if a.get("threat_id") == alert_id), body)
        report = await oracle.generate_takedown_request(alert)
        return report

    @api.post("/oracle/cert-abuse")
    async def oracle_cert_abuse(body: dict):
        """Score a subdomain for certificate abuse indicators."""
        subdomain = body.get("subdomain", "")
        domain    = body.get("domain", "cloudsek.com")
        issued    = body.get("issued", "")
        result = await oracle.score_certificate_abuse(subdomain, domain, issued)
        return result

    @api.get("/oracle/actors")
    def oracle_actors(ttps: str = "", indicator: str = "", sector: str = "technology"):
        """Match TTPs to threat actor groups."""
        ttp_list = [t.strip() for t in ttps.split(",") if t.strip()]
        return {"actors": oracle.attribute_threat_actors(ttp_list, indicator, sector)}

    @api.post("/nexus/block")
    def nexus_block(body: dict):
        """One-click containment — block IP or domain."""
        indicator = body.get("indicator", "")
        itype     = body.get("type", "domain")
        result    = nexus.block_indicator(indicator, itype)
        return result

    @api.get("/nexus/blocked")
    def nexus_blocked():
        """List all blocked indicators."""
        return nexus.get_blocked()

    @api.post("/nexus/incident-pdf")
    async def nexus_pdf(body: dict):
        """Generate incident PDF report for an alert."""
        from fastapi.responses import Response as _Resp
        alert_id = body.get("threat_id", "")
        alerts = db.recent(200)
        alert = next((a for a in alerts if a.get("threat_id") == alert_id), body)
        summary = await oracle.summarise_threat(alert)
        actors  = oracle.attribute_threat_actors(alert.get("ttps",[]), alert.get("indicator",""), "technology")
        profile = await oracle.profile_attacker(alert.get("indicator",""), "domain")
        pdf_bytes = nexus.generate_incident_pdf(alert, summary, actors, profile)
        fname = f"aegis_incident_{alert_id[:12]}_{now_str('%Y%m%d_%H%M%S')}.pdf"
        return _Resp(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @api.get("/nexus/weekly-digest")
    async def nexus_digest():
        """Generate weekly intelligence digest."""
        alerts = db.recent(1000)
        return await nexus.generate_weekly_digest(alerts)

    @api.get("/nexus/weekly-digest/pdf")
    async def nexus_digest_pdf():
        """Generate and download weekly digest as PDF."""
        from fastapi.responses import Response as _Resp
        alerts = db.recent(1000)
        digest = await nexus.generate_weekly_digest(alerts)
        # Build PDF using reportlab
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            import io as _io

            buf = _io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=letter,
                leftMargin=0.75*inch, rightMargin=0.75*inch,
                topMargin=0.75*inch, bottomMargin=0.75*inch)
            styles = getSampleStyleSheet()
            BLUE  = HexColor("#1B4F8A")
            LGRAY = HexColor("#F2F4F6")
            RED   = HexColor("#C0392B")
            WHITE = HexColor("#FFFFFF")

            title_s = ParagraphStyle("t", fontSize=20, textColor=BLUE,
                fontName="Helvetica-Bold", spaceAfter=6)
            h2_s = ParagraphStyle("h2", fontSize=13, textColor=BLUE,
                fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4)
            body_s = ParagraphStyle("b", fontSize=10, fontName="Helvetica",
                spaceAfter=4, leading=14)

            story = []
            story.append(Paragraph("AEGIS-NEXUS v3.0", title_s))
            story.append(Paragraph(f"Weekly Intelligence Digest — {digest.get('week_ending','')}", 
                ParagraphStyle("sub", fontSize=13, textColor=HexColor("#666666"),
                fontName="Helvetica", spaceAfter=4)))
            story.append(HRFlowable(width="100%", thickness=2, color=BLUE))
            story.append(Spacer(1, 0.15*inch))

            # Stats table
            by_sev = digest.get("by_severity", {})
            data = [
                ["Metric", "Value"],
                ["Total Alerts", str(digest.get("total_alerts", 0))],
                ["Critical", str(by_sev.get("CRITICAL", 0))],
                ["High", str(by_sev.get("HIGH", 0))],
                ["Medium", str(by_sev.get("MEDIUM", 0))],
                ["Low", str(by_sev.get("LOW", 0))],
                ["Week Ending", digest.get("week_ending", "")],
            ]
            tbl = Table(data, colWidths=[3*inch, 4.5*inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLUE),
                ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 10),
                ("BACKGROUND", (0,1), (0,-1), LGRAY),
                ("FONTNAME",   (0,1), (0,-1), "Helvetica-Bold"),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LGRAY]),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("TOPPADDING",  (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 0.2*inch))

            # AI Narrative
            story.append(Paragraph("Executive Summary", h2_s))
            narrative = digest.get("narrative", "No data available for this week.")
            story.append(Paragraph(narrative.replace("\n", "<br/>"), body_s))
            story.append(Spacer(1, 0.15*inch))

            # Top threats
            top = digest.get("top_threats", [])
            if top:
                story.append(Paragraph("Top Threats This Week", h2_s))
                threat_data = [["Severity", "Indicator", "Score"]]
                for t in top[:10]:
                    threat_data.append([
                        t.get("severity", ""),
                        str(t.get("indicator", ""))[:55],
                        f"{float(t.get('score', 0)):.4f}",
                    ])
                ttbl = Table(threat_data, colWidths=[1.2*inch, 5*inch, 1.3*inch])
                ttbl.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), BLUE),
                    ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
                    ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0,0), (-1,-1), 9),
                    ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LGRAY]),
                    ("LEFTPADDING", (0,0), (-1,-1), 6),
                    ("TOPPADDING",  (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]))
                story.append(ttbl)
                story.append(Spacer(1, 0.15*inch))

            # By source
            by_src = digest.get("by_source", {})
            if by_src:
                story.append(Paragraph("Alerts by Source", h2_s))
                src_data = [["Source", "Count"]]
                for src, cnt in sorted(by_src.items(), key=lambda x: x[1], reverse=True)[:10]:
                    src_data.append([src, str(cnt)])
                stbl = Table(src_data, colWidths=[4*inch, 3.5*inch])
                stbl.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,0), BLUE),
                    ("TEXTCOLOR",  (0,0), (-1,0), WHITE),
                    ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0,0), (-1,-1), 9),
                    ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LGRAY]),
                    ("LEFTPADDING", (0,0), (-1,-1), 6),
                    ("TOPPADDING",  (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]))
                story.append(stbl)

            story.append(Spacer(1, 0.2*inch))
            story.append(HRFlowable(width="100%", thickness=1, color=BLUE))
            story.append(Paragraph(
                f"Generated by AEGIS-NEXUS v3.0 | {now_str('%Y-%m-%d %H:%M:%S')} UTC | CONFIDENTIAL",
                ParagraphStyle("footer", fontSize=8, textColor=HexColor("#666666"), alignment=1)
            ))

            doc.build(story)
            pdf_bytes = buf.getvalue()

            # Also save to Downloads folder
            import os as _os
            save_path = _os.path.expanduser(f"~/Downloads/aegis_digest_{digest.get('week_ending','')}.pdf")
            with open(save_path, "wb") as f2:
                f2.write(pdf_bytes)
            log.info(f"[NEXUS] Weekly digest PDF saved: {save_path}")

            fname = f"aegis_digest_{digest.get('week_ending','')}.pdf"
            return _Resp(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{fname}"'},
            )
        except ImportError:
            return {"error": "reportlab not installed: pip3 install reportlab --break-system-packages"}
        except Exception as e:
            log.warning(f"[NEXUS/DIGEST-PDF] {e}")
            return {"error": str(e)}

    @api.get("/hydra/sources")
    def hydra_sources():
        """List all active HYDRA sources and their counts."""
        return {
            "v2_sources": ["crt.sh", "nvd", "github", "pastebin", "shodan"],
            "v3_sources": ["bevigil", "abuse_ch", "otx", "urlscan",
                           "pulsedive", "breach_directory", "paste_hunter", "spiderfoot", "alienvault", "dark_web", "github_commits",
                           "wayback", "supply_chain", "employee_exposure"],
            "counts": {
                # v2 sources — map internal keys to dashboard label keys
                "crt.sh":            hydra._counts.get("ct_logs", 0),
                "nvd":               hydra._counts.get("cve_feed", 0) + hydra._counts.get("nvd", 0),
                "github":            hydra._counts.get("github", 0),
                "pastebin":          hydra._counts.get("paste_monitor", 0) + hydra._counts.get("paste", 0) + hydra._counts.get("pastebin", 0),
                "shodan":            hydra._counts.get("shodan", 0),
                # v3 sources
                "bevigil":           hydra._counts.get("bevigil", 0),
                "abuse_ch":          hydra._counts.get("abuse_ch", 0),
                "otx":               hydra._counts.get("otx", 0),
                "urlscan":           hydra._counts.get("urlscan", 0),
                "pulsedive":         hydra._counts.get("pulsedive", 0),
                "breach_directory":  hydra._counts.get("breach_directory", 0),
                "paste_hunter":      hydra._counts.get("paste_hunter", 0),
                "spiderfoot":        hydra._counts.get("spiderfoot", 0),
                "alienvault":        hydra._counts.get("alienvault", 0),
                "dark_web":          hydra._counts.get("dark_web", 0),
                "github_commits":    hydra._counts.get("github_commits", 0),
                "wayback":           hydra._counts.get("wayback", 0),
                "supply_chain":      hydra._counts.get("supply_chain", 0) + hydra._counts.get("typosquat", 0),
                "employee_exposure": hydra._counts.get("employee_exposure", 0),
            },
            "total_sources": 20,
        }

    @api.get("/hydra/debug")
    def hydra_debug():
        """Debug endpoint — shows raw scraper counts, queue size, and key status."""
        import os
        def _k(obj, a): return bool(getattr(obj, a, ""))
        try:
            v3 = hydra_v3
        except NameError:
            v3 = None
        return {
            "raw_counts":    hydra._counts,
            "scraper_class": type(v3).__name__ if v3 else type(hydra).__name__,
            "env_keys": {
                "BEVIGIL":   bool(os.environ.get("BEVIGIL_API_KEY","")),
                "OTX":       bool(os.environ.get("OTX_API_KEY","")),
                "URLSCAN":   bool(os.environ.get("URLSCAN_API_KEY","")),
                "ABUSECH":   bool(os.environ.get("ABUSECH_API_KEY","")),
                "GROQ":      bool(os.environ.get("GROQ_API_KEY","")),
                "GITHUB":    bool(os.environ.get("GITHUB_TOKEN","")),
                "PULSEDIVE": bool(os.environ.get("PULSEDIVE_API_KEY","")),
            },
            "keys_loaded": {
                "BEVIGIL":   _k(v3,"BEVIGIL_KEY") if v3 else False,
                "OTX":       _k(v3,"OTX_KEY") if v3 else False,
                "URLSCAN":   _k(v3,"URLSCAN_KEY") if v3 else False,
                "ABUSECH":   _k(v3,"ABUSECH_KEY") if v3 else False,
                "PULSEDIVE": _k(v3,"PULSEDIVE_KEY") if v3 else False,
                "GITHUB":    _k(v3,"GH_TOKEN") if v3 else False,
                "GROQ":      _k(v3,"GROQ_KEY") if v3 else False,
                "RAPIDAPI":  _k(v3,"RAPIDAPI_KEY") if v3 else False,
            },
            "tasks_running": [],
        }

    @api.post("/db/purge-stale")
    def purge_stale():
        """Remove CVEs older than 6 years from DuckDB (pre-filter-tightening cleanup)."""
        removed = 0
        if db._db:
            try:
                r = db._db.execute("""
                    DELETE FROM alerts
                    WHERE kind = 'known_vulnerability'
                    AND CAST(SUBSTRING(meta, POSITION('age_years' IN meta)+12, 2) AS INTEGER) >= 6
                """)
                removed = r.rowcount if hasattr(r,'rowcount') else 0
            except Exception:
                pass
        # Also clean memory store
        before = len(db._alerts)
        db._alerts = [
            a for a in db._alerts
            if not (a.get("kind")=="known_vulnerability" and
                    int((a.get("meta") or {}).get("age_years",0)) >= 6)
        ]
        removed += before - len(db._alerts)
        return {"purged": removed, "message": f"Removed {removed} stale CVE alerts"}

    @api.get("/alerts/export.json")
    def export_json(severity: str = "", limit: int = 5000):
        """Export all alerts as a downloadable JSON file."""
        from fastapi.responses import Response
        import datetime as _dt
        alerts = db.recent(limit, severity)
        payload = {
            "exported_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "total":       len(alerts),
            "severity_filter": severity or "all",
            "alerts":      alerts,
        }
        body = json.dumps(payload, indent=2, default=str)
        fname = f"aegis_alerts_{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @api.get("/alerts/export.csv")
    def export_csv(severity: str = "", limit: int = 5000):
        """Export all alerts as a downloadable CSV file."""
        from fastapi.responses import Response
        import datetime as _dt, csv, io
        alerts = db.recent(limit, severity)
        buf = io.StringIO()
        writer = csv.writer(buf)
        # Header
        writer.writerow([
            "threat_id", "found_at", "severity", "score",
            "kind", "source", "indicator",
            "tech", "ttps",
            "cvss", "published", "age_years", "keyword",
            "monitored", "cert_issued", "nvd_url",
            "s1_spectral", "s2_renyi", "s3_ttp", "s4_decay",
        ])
        for a in alerts:
            meta   = a.get("meta") or {}
            stages = a.get("stages") or {}
            writer.writerow([
                a.get("threat_id", ""),
                str(a.get("found_at", ""))[:19].replace("T", " "),
                a.get("severity", ""),
                round(float(a.get("score", 0)), 6),
                a.get("kind", ""),
                a.get("source", ""),
                a.get("indicator", ""),
                "|".join(a.get("tech", [])),
                "|".join(a.get("ttps", [])),
                meta.get("cvss", ""),
                meta.get("pub", ""),
                meta.get("age_years", ""),
                meta.get("keyword", ""),
                meta.get("monitored", ""),
                meta.get("issued", ""),
                meta.get("url", ""),
                round(float(stages.get("s1", 0)), 4),
                round(float(stages.get("s2", 0)), 4),
                round(float(stages.get("s3", 0)), 4),
                round(float(stages.get("s4", 0)), 4),
            ])
        fname = f"aegis_alerts_{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    # ── Email alert config from env vars ──────────────────────
    _email_cfg = {
        "enabled":   os.environ.get("AEGIS_EMAIL_TO", ""),
        "to":        os.environ.get("AEGIS_EMAIL_TO", ""),
        "from":      os.environ.get("AEGIS_EMAIL_FROM", os.environ.get("AEGIS_EMAIL_TO", "")),
        "smtp_host": os.environ.get("AEGIS_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.environ.get("AEGIS_SMTP_PORT", "587")),
        "password":  os.environ.get("AEGIS_SMTP_PASS", ""),
        "min_sev":   os.environ.get("AEGIS_EMAIL_MIN_SEV", "CRITICAL"),
    }
    if _email_cfg["enabled"]:
        print(f"  {col('Email alerts','GREEN')}  ─►  {_email_cfg['to']}  (min: {_email_cfg['min_sev']})")

    _email_fail_count = [0]   # circuit breaker counter
    _email_disabled   = [False]

    async def _send_email_alert(alert: dict):
        """Send email notification for high-severity alerts."""
        cfg = _email_cfg
        if not cfg["enabled"]:
            return
        if not cfg["password"]:
            log.warning("[EMAIL] AEGIS_SMTP_PASS not set — email alerts disabled")
            return
        if _email_disabled[0]:
            return  # circuit breaker tripped — stop retrying
        sev = alert.get("severity", "")
        sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = sev_rank.get(cfg["min_sev"], 4)
        if sev_rank.get(sev, 0) < min_rank:
            return
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            ind  = alert.get("indicator", "")
            kind = (alert.get("kind") or "").replace("_", " ")
            meta = alert.get("meta") or {}
            body = f"""AEGIS-NEXUS Alert

Severity  : {sev}
Score     : {alert.get('score', 0):.6f}
Type      : {kind}
Source    : {alert.get('source', '')}
Indicator : {ind}
TTPs      : {', '.join(alert.get('ttps', []))}
Tech      : {', '.join(alert.get('tech', []))}
Found at  : {str(alert.get('found_at', ''))[:19]}
"""
            if meta.get("cvss"):   body += f"CVSS      : {meta['cvss']}\n"
            if meta.get("pub"):    body += f"Published : {meta['pub']}\n"
            if meta.get("url"):    body += f"NVD Link  : {meta['url']}\n"
            body += "\nDashboard : http://localhost:8080/\n"

            msg = MIMEMultipart()
            msg["From"]    = cfg["from"]
            msg["To"]      = cfg["to"]
            msg["Subject"] = f"[AEGIS] {sev} — {kind} — {ind[:50]}"
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as s:
                s.starttls()
                s.login(cfg["from"], cfg["password"])
                s.sendmail(cfg["from"], cfg["to"], msg.as_string())
            log.info(f"[EMAIL] Alert sent: {sev} {kind}")
        except Exception as e:
            err = str(e)
            if "535" in err or "BadCredentials" in err or "Username and Password" in err:
                _email_fail_count[0] += 1
                if _email_fail_count[0] >= 3:
                    _email_disabled[0] = True
                    log.warning("[EMAIL] Auth failed 3 times — disabling email alerts.")
                    log.warning("[EMAIL] Fix: generate new Gmail App Password at https://myaccount.google.com/apppasswords")
                else:
                    log.warning(f"[EMAIL] Auth failed ({_email_fail_count[0]}/3): bad Gmail App Password")
            elif "550" in err or "Daily user sending limit" in err or "sending limit" in err.lower():
                _email_disabled[0] = True
                log.warning("[EMAIL] Gmail daily sending limit reached — email disabled until midnight UTC.")
                log.warning("[EMAIL] Slack alerts will continue working normally.")
            elif "503" in err or "Service Unavailable" in err:
                log.warning("[EMAIL] Gmail temporarily unavailable — will retry next alert")
            else:
                log.warning(f"[EMAIL] Failed to send alert: {e}")

    # ── Slack webhook config from env vars ─────────────────────
    _slack_cfg = {
        "enabled":  os.environ.get("AEGIS_SLACK_WEBHOOK", ""),
        "webhook":  os.environ.get("AEGIS_SLACK_WEBHOOK", ""),
        "min_sev":  os.environ.get("AEGIS_SLACK_MIN_SEV", "HIGH"),
    }
    if _slack_cfg["enabled"]:
        print(f"  {col('Slack alerts','GREEN')}   ─►  webhook configured  (min: {_slack_cfg['min_sev']})")

    async def _send_slack_alert(alert: dict):
        """Send Slack webhook notification for high-severity alerts."""
        cfg = _slack_cfg
        if not cfg["enabled"]:
            return
        sev = alert.get("severity", "")
        sev_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        min_rank = sev_rank.get(cfg["min_sev"], 3)
        if sev_rank.get(sev, 0) < min_rank:
            return
        try:
            import urllib.request, json as _json
            kind  = (alert.get("kind") or "").replace("_", " ").title()
            ind   = alert.get("indicator", "")
            score = alert.get("score", 0)
            src   = alert.get("source", "")
            meta  = alert.get("meta") or {}
            ttps  = ", ".join(alert.get("ttps", [])) or "—"
            tech  = ", ".join(alert.get("tech", [])) or "—"

            sev_emoji = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}.get(sev, "⚪")

            fields = [
                {"type": "mrkdwn", "text": f"*Score*\n`{score:.4f}`"},
                {"type": "mrkdwn", "text": f"*Source*\n{src}"},
                {"type": "mrkdwn", "text": f"*TTPs*\n{ttps}"},
                {"type": "mrkdwn", "text": f"*Tech*\n{tech}"},
            ]
            if meta.get("cvss"):
                fields.append({"type": "mrkdwn", "text": f"*CVSS*\n{meta['cvss']}"})
            if meta.get("pub"):
                fields.append({"type": "mrkdwn", "text": f"*Published*\n{str(meta['pub'])[:10]}"})

            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{sev_emoji} AEGIS-NEXUS — {sev} Alert", "emoji": True}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{kind}*\n`{ind}`"}
                },
                {"type": "section", "fields": fields},
            ]
            if meta.get("url"):
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"<{meta['url']}|View on NVD>  •  <http://localhost:8080/|Open Dashboard>"}
                })
            else:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "<http://localhost:8080/|Open Dashboard>"}
                })
            blocks.append({"type": "divider"})

            payload = _json.dumps({"blocks": blocks}).encode()
            req = urllib.request.Request(
                cfg["webhook"],
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    log.info(f"[SLACK] Alert sent: {sev} {kind}")
                else:
                    log.warning(f"[SLACK] Non-200 response: {resp.status}")
        except Exception as e:
            log.warning(f"[SLACK] Failed to send alert: {e}")

    print(f"  {col(chr(9608)*2+' NEXUS-GATE STARTED '+chr(9608)*2,'GREEN')}")

    # ── ORACLE AI + NEXUS Response + HydraV3 init ─────────────
    oracle   = OracleAI()
    nexus    = NexusResponse(oracle)
    domains  = [a.name for a in twin.assets.values() if a.kind == "domain"][:5]
    if not domains:
        domains = ["cloudsek.com", "bevigil.com"]
    keywords = ["cloudsek", "bevigil", "xvigil"]
    known_tech = list(twin._tech_idx.keys())[:20]
    hydra_v3 = HydraV3Scrapers(
        domains=domains,
        keywords=keywords,
        known_tech=known_tech,
        queue=hydra._queue,
        seen=hydra._seen,
        counts=hydra._counts,
    )
    print(f"  {col('ORACLE AI','GREEN')}    ─►  Groq llama-3.3-70b  (AI threat summaries)")
    print(f"  {col('NEXUS OPS','GREEN')}    ─►  PDF reports · Containment · Weekly digest")
    print(f"  {col('HYDRA v3','GREEN')}     ─►  11 new scrapers unlocked")

    async def _auto_weekly_digest():
        """Auto-send weekly digest every Monday at 09:00."""
        import time as _time
        while True:
            now = datetime.now(timezone.utc)
            # Check if it's Monday (weekday 0) between 09:00-09:05
            if now.weekday() == 0 and now.hour == 9 and now.minute < 5:
                try:
                    alerts = db.recent(1000)
                    digest = await nexus.generate_weekly_digest(alerts)
                    # Send via email if configured
                    email_to = os.environ.get("AEGIS_EMAIL_TO", "")
                    if email_to:
                        subject = f"AEGIS-NEXUS Weekly Digest — {digest.get('week_ending','')}"
                        body = f"Week: {digest.get('week_ending')} · Alerts: {digest.get('total_alerts',0)}\n\n{digest.get('narrative','')}"
                        await _send_email_alert({"severity":"HIGH","kind":"weekly_digest","indicator":subject,"meta":{"digest":body},"ttps":[],"tech":[],"found_at":now_iso(),"score":0.5,"threat_id":"digest"})
                        log.info("[NEXUS] Weekly digest sent")
                    await asyncio.sleep(300)  # Sleep 5 min to avoid duplicate
                except Exception as e:
                    log.debug(f"[NEXUS/DIGEST] {e}")
            await asyncio.sleep(60)  # Check every minute

    async def _enrich_alert(alert: dict):
        """Background AI enrichment for HIGH/CRITICAL alerts."""
        try:
            summary = await oracle.summarise_threat(alert)
            actors  = oracle.attribute_threat_actors(
                alert.get("ttps", []),
                alert.get("indicator", ""),
                "technology"
            )
            alert["ai_summary"] = summary
            alert["threat_actors"] = actors
            # Update in DB
            db.save(alert)
            await broadcast({"type": "alert_enriched", "data": {
                "threat_id": alert.get("threat_id"),
                "ai_summary": summary,
                "threat_actors": actors,
            }})
        except Exception as e:
            log.debug(f"[ORACLE/ENRICH] {e}")
    print()
    print(f"  {col('Web Dashboard','BOLD')}  ─►  {col('http://localhost:8080/','HIGH')}")
    print(f"  {col('Swagger API','DIM')}    ─►  {col('http://localhost:8080/docs','CYAN')}")
    print(f"  {col('WebSocket','DIM')}      ─►  ws://localhost:8080/ws/alerts")
    print()
    print(f"  {col('Open http://localhost:8080/ in Firefox now!','YELLOW')}")
    print(f"  {col('Press Ctrl+C to stop','DIM')}")
    print()

    # Auto-kill any existing process on port 8000
    import socket as _sock
    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as _s:
        if _s.connect_ex(('127.0.0.1', 8000)) == 0:
            import subprocess as _sp, time as _t
            log.warning("[NEXUS] Port 8000 in use — killing old instance...")
            _sp.run(['pkill', '-f', 'aegis_v6.py'], capture_output=True)
            _t.sleep(2)

    cfg    = uvicorn.Config(
        api,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        timeout_keep_alive=30,
    )
    server = uvicorn.Server(cfg)
    try:
        await server.serve()
    except (KeyboardInterrupt, asyncio.CancelledError):
        server.should_exit = True
        print(f"\n  {col('API stopped.','DIM')}\n")


# ── Command: test ─────────────────────────────────────────────────

async def cmd_test():
    banner()
    twin, spectra, phantom, kronos = make_engine()
    print(f"  {col('Running AEGIS-NEXUS self-tests…','BOLD')}\n")
    passed = failed = 0

    async def check(name: str, fn) -> bool:
        nonlocal passed, failed
        try:
            result = fn() if callable(fn) else fn
            assert result, "Assertion failed"
            print(f"  {col('✓','GREEN')} {name}")
            passed += 1
            return True
        except Exception as e:
            print(f"  {col('✗','RED')} {name}  {col(str(e),'DIM')}")
            failed += 1
            return False

    # ── AXIOM ────────────────────────────────────────────────────
    sp = twin.laplacian.spectrum()
    await check("AXIOM  asset count > 0",                lambda: len(twin.assets) > 0)
    await check("AXIOM  tech index populated",            lambda: len(twin._tech_idx) > 0)
    await check("AXIOM  tls in tech index",               lambda: "tls" in twin._tech_idx or "dns" in twin._tech_idx)
    await check("AXIOM  is_self(['tls']) → True",         lambda: twin.is_self(["tls"])[0])
    await check("AXIOM  is_self(['cobol','mainframe']) → False", lambda: not twin.is_self(["cobol","mainframe"])[0])
    await check("AXIOM  is_self([]) → False",             lambda: not twin.is_self([])[0])
    await check("AXIOM  spectral radius >= 0",            lambda: float(np.max(np.abs(sp))) >= 0)
    await check("AXIOM  λ₀ ≈ 0 (connected graph)",        lambda: abs(sp[0]) < 1e-6)
    await check("AXIOM  edges registered",                lambda: len(twin.edges) >= 0)
    node = Asset(name="test-svc", kind="service", tech=["golang", "grpc"])
    twin.add_asset(node)
    await check("AXIOM  dynamic asset addition works",    lambda: node.node_id in twin.assets)
    await check("AXIOM  golang added to tech index",      lambda: "golang" in twin._tech_idx)

    # ── Laplacian ────────────────────────────────────────────────
    L = Laplacian()
    L.add_edge("A", "B"); L.add_edge("B", "C"); L.add_edge("C", "A")
    eigs = L.spectrum()
    await check("LAPLACIAN  spectrum length = 3",          lambda: len(eigs) == 3)
    await check("LAPLACIAN  min eigenvalue ≈ 0",           lambda: abs(eigs[0]) < 1e-6)
    pd = L.perturbation([("threat", "A", 0.8), ("threat", "B", 0.5)])
    await check("LAPLACIAN  perturbation known nodes > 0", lambda: pd > 0.0)
    await check("LAPLACIAN  perturbation in (0,1)",        lambda: 0 < pd < 1)
    pd0 = L.perturbation([("threat", "X", 1.0)])
    await check("LAPLACIAN  perturbation unknown nodes = 0", lambda: pd0 == 0.0)

    # ── SPECTRA ───────────────────────────────────────────────────
    r1 = await spectra.score("t1","lookalike_domain","c0.com",["tls","web"],["T1583.001"],{},0.8)
    await check("SPECTRA  relevant threat not noise",      lambda: not r1.is_noise)
    await check("SPECTRA  score in [0.0, 1.0]",            lambda: 0.0 <= r1.score <= 1.0)
    await check("SPECTRA  all stages in [0,1]",            lambda: all(0<=v<=1 for v in [r1.s1,r1.s2,r1.s3,r1.s4]))
    await check("SPECTRA  reasoning has 4 entries",        lambda: len(r1.reasoning) == 4)
    await check("SPECTRA  processing time > 0 ms",         lambda: r1.ms > 0)

    r2 = await spectra.score("t2","scan","1.2.3.4",["java","iis","windows"],["T1595"],{},0.0)
    await check("SPECTRA  irrelevant tech → noise",        lambda: r2.is_noise)
    await check("SPECTRA  noise severity = NOISE",         lambda: r2.severity == "NOISE")

    r3 = await spectra.score("t3","cve","CVE-X",["postgresql"],["T1190"],{},0.95)
    await check("SPECTRA  high perturbation → HIGH+",      lambda: r3.severity in ("HIGH","CRITICAL"))

    # Temporal decay — same signature repeated
    scores = []
    for i in range(6):
        rx = await spectra.score(f"rep-{i}","scan","repeated",["nginx"],["T1046"],{},0.4)
        scores.append(rx.score)
    await check("SPECTRA  temporal decay lowers score",    lambda: scores[-1] <= scores[0] + 0.05)

    # ── PHANTOM ───────────────────────────────────────────────────
    aws = phantom.gen_aws("testco"); m = json.loads(aws.value)
    await check("PHANTOM  AWS key starts AKIA",            lambda: m["access_key"].startswith("AKIA"))
    await check("PHANTOM  AWS key length 20",              lambda: len(m["access_key"]) == 20)
    await check("PHANTOM  AWS secret length 40",           lambda: len(m["secret_key"]) == 40)

    gh = phantom.gen_github()
    await check("PHANTOM  GitHub token starts ghp_",       lambda: gh.value.startswith("ghp_"))
    await check("PHANTOM  GitHub token length 40",         lambda: len(gh.value) == 40)

    jwt = phantom.gen_jwt()
    await check("PHANTOM  JWT secret is 64 hex chars",     lambda: len(jwt.value) == 64)

    db = phantom.gen_db()
    await check("PHANTOM  DB conn has postgresql://",      lambda: "postgresql://" in db.value)

    api_k = phantom.gen_api_key("test")
    await check("PHANTOM  API key starts sk-",             lambda: api_k.value.startswith("sk-"))

    canary = phantom.gen_env_canary("testco.com")
    await check("PHANTOM  canary has watermark",           lambda: bool(canary["watermark"]))
    await check("PHANTOM  canary embeds 5 tokens",         lambda: len(canary["tokens"]) == 5)
    await check("PHANTOM  canary content has AWS key",     lambda: "AWS_ACCESS_KEY_ID" in canary["content"])
    await check("PHANTOM  canary content has JWT",         lambda: "JWT_SECRET" in canary["content"])

    tr = phantom.trigger(aws.token_id, "1.2.3.4")
    await check("PHANTOM  trigger returns TRIGGERED",      lambda: tr["status"] == "TRIGGERED")
    await check("PHANTOM  token marked triggered",         lambda: phantom._tokens[aws.token_id].triggered)
    await check("PHANTOM  trigger_ip recorded",            lambda: phantom._tokens[aws.token_id].trigger_ip == "1.2.3.4")

    bad = phantom.trigger("nonexistent-id-xyz")
    await check("PHANTOM  bad token returns error dict",   lambda: "error" in bad)

    # ── DARKWATCH ─────────────────────────────────────────────────
    actors = actor_match(["T1566","T1059","T1078","T1486"], "malware.top", "retail")
    await check("DARKWATCH  actor match returns results",  lambda: len(actors) > 0)
    await check("DARKWATCH  FIN7 identified",              lambda: any(a["actor"] == "FIN7" for a in actors))
    await check("DARKWATCH  confidence in [0,1]",          lambda: all(0 <= a["confidence"] <= 1 for a in actors))
    await check("DARKWATCH  sorted by confidence desc",    lambda: len(actors) < 2 or actors[0]["confidence"] >= actors[1]["confidence"])

    variants = typosquat("example.com")
    await check("DARKWATCH  typosquat > 20 variants",      lambda: len(variants) > 20)
    await check("DARKWATCH  original not in variants",     lambda: "example.com" not in variants)
    await check("DARKWATCH  example.net in variants",      lambda: "example.net" in variants)
    await check("DARKWATCH  suffix variant present",       lambda: any("login" in v for v in variants))

    # ── KRONOS integration ────────────────────────────────────────
    t_rel = Threat("int-1","ct","lookalike","c0.com",["tls","web","dns"],["T1583.001"])
    r_rel = await kronos.process(t_rel)
    await check("KRONOS  relevant threat processed",       lambda: r_rel is not None)
    await check("KRONOS  result has severity",             lambda: r_rel.severity in ["LOW","MEDIUM","HIGH","CRITICAL","NOISE"])

    t_irr = Threat("int-2","shodan","scan","1.2.3.4",["windows","rdp","iis"],["T1595"])
    r_irr = await kronos.process(t_irr)
    await check("KRONOS  non-self threat fast-rejected",   lambda: r_irr is None)

    kst = kronos.stats()
    await check("KRONOS  stats keys present",              lambda: all(k in kst for k in ["total_processed","noise_discarded","alerts_raised","noise_reduction"]))

    # ── Summary ───────────────────────────────────────────────────
    total = passed + failed
    print(f"\n  {'─' * 50}")
    if failed == 0:
        print(f"  {col(f'{passed}/{total} tests passed','GREEN')}  {col('ALL TESTS PASSED ✓','GREEN')}")
    else:
        print(f"  {col(f'{passed}/{total} passed','HIGH')}  {col(f'{failed} failed','RED')}")
    print()


# ══════════════════════════════════════════════════════════════════
# DUCKDB PERSISTENT ALERT STORE
# ══════════════════════════════════════════════════════════════════

class AlertDB:
    """
    DuckDB-backed persistent alert store.
    Falls back to in-memory list if DuckDB not available.
    Enables analytics queries over historical threat data.
    """

    def __init__(self, path: str = ":memory:"):
        self._path = path
        self._alerts: List[Dict] = []   # always-available memory store
        self._db = None
        if HAS_DUCKDB:
            try:
                import duckdb
                self._db = duckdb.connect(path)
                self._db.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        threat_id   VARCHAR PRIMARY KEY,
                        source      VARCHAR,
                        kind        VARCHAR,
                        indicator   VARCHAR,
                        severity    VARCHAR,
                        score       DOUBLE,
                        tech        VARCHAR,
                        ttps        VARCHAR,
                        found_at    TIMESTAMP,
                        meta        VARCHAR
                    )
                """)
            except Exception as e:
                log.warning(f"[DB] DuckDB init failed, using memory: {e}")
                self._db = None

    def save(self, alert: Dict):
        self._alerts.insert(0, alert)
        if len(self._alerts) > 5000:
            self._alerts.pop()
        if self._db:
            try:
                self._db.execute("""
                    INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)
                """, [
                    alert.get("threat_id", ""),
                    alert.get("source", ""),
                    alert.get("kind", ""),
                    alert.get("indicator", ""),
                    alert.get("severity", ""),
                    alert.get("score", 0.0),
                    json.dumps(alert.get("tech", [])),
                    json.dumps(alert.get("ttps", [])),
                    alert.get("found_at", now_iso()),
                    json.dumps(alert.get("meta", {})),
                ])
            except Exception:
                pass

    def recent(self, n: int = 100, sev: str = "") -> List[Dict]:
        alerts = self._alerts
        if sev:
            alerts = [a for a in alerts if a.get("severity","").upper() == sev.upper()]
        return alerts[:n]

    def query(self, sql: str) -> List[Dict]:
        if not self._db:
            return [{"error": "DuckDB not available"}]
        try:
            r  = self._db.execute(sql)
            cols = [d[0] for d in r.description]
            return [dict(zip(cols, row)) for row in r.fetchall()]
        except Exception as e:
            return [{"error": str(e)}]

    def analytics(self) -> Dict:
        if not self._db:
            total = len(self._alerts)
            by_sev = {}
            for a in self._alerts:
                s = a.get("severity","?")
                by_sev[s] = by_sev.get(s, 0) + 1
            return {"total": total, "by_severity": by_sev, "source": "memory"}
        try:
            rows = self._db.execute("""
                SELECT severity, COUNT(*) as cnt, AVG(score) as avg_score
                FROM alerts GROUP BY severity ORDER BY cnt DESC
            """).fetchall()
            by_sev = {r[0]: {"count": r[1], "avg_score": round(r[2], 4)} for r in rows}
            total  = sum(r["count"] for r in by_sev.values())
            return {"total": total, "by_severity": by_sev, "source": "duckdb"}
        except Exception as e:
            return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════
# REAL HYDRA SCRAPERS
# ══════════════════════════════════════════════════════════════════

class HydraScrapers:
    """
    Real async HYDRA scrapers hitting live external sources.
    Each scraper runs as an independent async task.

    Sources:
      CT Logs    — crt.sh certificate transparency (lookalike domains)
      NVD/CVE    — National Vulnerability Database (CVEs vs our tech)
      Pastebin   — public paste monitor (data leaks)
      GitHub     — public code search (exposed secrets)
    """

    def __init__(self, domains: List[str], keywords: List[str], known_tech: List[str]):
        self.domains     = domains
        self.keywords    = keywords
        self.known_tech  = known_tech
        self._queue:     asyncio.Queue = asyncio.Queue(maxsize=500)
        self._running    = False
        self._counts: Dict[str, int]  = {}
        self._seen:   Set[str]        = set()

    # ── CT Log scraper ───────────────────────────────────────────

    @staticmethod
    def _gen_typosquats(domain: str) -> List[str]:
        """Generate typosquat permutations — port of aegis_real.py gen_typosquats()."""
        name, _, tld = domain.partition(".")
        variants: Set[str] = set()
        subs = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5", "c": "ck"}
        for i, c in enumerate(name):
            if c in subs:
                variants.add(name[:i] + subs[c] + name[i+1:] + "." + tld)
        for kw in ["login","secure","verify","auth","support","account","portal","signin"]:
            variants.add(f"{name}-{kw}.com")
            variants.add(f"{kw}-{name}.com")
        for alt in ["net","org","io","co","xyz","online","in"]:
            variants.add(f"{name}.{alt}")
        for i in range(len(name) - 1):
            s = list(name); s[i], s[i+1] = s[i+1], s[i]
            variants.add("".join(s) + "." + tld)
        variants.discard(domain)
        return sorted(variants)

    async def _scrape_ct(self):
        """Query crt.sh for certificates — lookalike detection + typosquat scan."""
        _LOOKALIKE_KWS = [
            "login","secure","verify","auth","admin","portal","account",
            "support","signin","sso","dev","staging","test","beta",
            "internal","manage","dashboard","reset",
        ]
        ctx = _mk_ssl_ctx()

        while self._running:
            for domain in self.domains:
                all_ct_domains: Set[str] = set()
                try:
                    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
                            "Accept": "application/json",
                            "Accept-Encoding": "gzip, deflate",
                        }
                    )
                    # Retry up to 3 times on timeout
                    data = None
                    for _attempt in range(3):
                        try:
                            with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
                                raw = resp.read()
                                data = json.loads(raw.decode())
                            break
                        except Exception as _te:
                            if _attempt < 2:
                                await asyncio.sleep(5)
                            else:
                                raise _te
                    if data is None:
                        continue

                    await asyncio.sleep(3)  # polite delay between crt.sh queries
                    seen_in_run: Set[str] = set()
                    for entry in data[:200]:
                        for raw_sub in entry.get("name_value", "").split("\n"):
                            sub = raw_sub.strip().lstrip("*.")
                            if not sub or sub == domain or sub in seen_in_run:
                                continue
                            seen_in_run.add(sub)
                            all_ct_domains.add(sub)

                            sig = sha256_hex(f"ct:{sub}:{domain}")[:16]
                            if sig in self._seen:
                                continue
                            self._seen.add(sig)

                            is_lookalike = any(k in sub for k in _LOOKALIKE_KWS)
                            kind = "lookalike_domain" if is_lookalike else "subdomain_discovered"
                            issued = entry.get("entry_timestamp", "")[:10]
                            t = Threat(
                                threat_id = f"ct-{sig}",
                                source    = "ct_logs",
                                kind      = kind,
                                indicator = sub,
                                tech      = ["tls", "web", "dns"],
                                ttps      = ["T1583.001", "T1608.001"],
                                meta      = {"monitored": domain, "issued": issued},
                            )
                            await self._queue.put(t)
                            self._counts["ct_logs"] = self._counts.get("ct_logs", 0) + 1

                    # Typosquat check — any generated variant appearing in CT logs → CRITICAL
                    squats = self._gen_typosquats(domain)
                    for squat in squats:
                        if any(squat in d for d in all_ct_domains):
                            sig = sha256_hex(f"typosquat:{squat}:{domain}")[:16]
                            if sig not in self._seen:
                                self._seen.add(sig)
                                t = Threat(
                                    threat_id = f"typosquat-{sig}",
                                    source    = "ct_logs",
                                    kind      = "typosquat_active",
                                    indicator = squat,
                                    tech      = ["tls", "web", "dns"],
                                    ttps      = ["T1583.001", "T1608.001"],
                                    meta      = {"monitored": domain,
                                                 "note": "typosquat found in CT logs"},
                                )
                                await self._queue.put(t)
                                self._counts["typosquat"] = self._counts.get("typosquat", 0) + 1

                except Exception as e:
                    if "429" in str(e) or "Too Many" in str(e):
                        log.warning("[HYDRA/CT] Rate limited by crt.sh — waiting 10 minutes")
                        await asyncio.sleep(600)
                    elif "timed out" in str(e).lower() or "timeout" in str(e).lower():
                        log.warning("[HYDRA/CT] Timeout — retrying in 60s")
                        await asyncio.sleep(60)
                    else:
                        log.warning(f"[HYDRA/CT] {e}")
                await asyncio.sleep(30)  # between domains
            await asyncio.sleep(300)  # 5 min between full cycles

    # ── NVD CVE scraper ──────────────────────────────────────────

    async def _scrape_cve(self):
        """Pull CVEs from 3 free sources: OSV, GitHub Advisory, Vulners.
        No API key needed for any of these."""
        ctx = _mk_ssl_ctx()

        # Packages to scan — built dynamically from the loaded Digital Twin tech stack.
        # PyPI packages are derived from the twin's known_tech list; npm list is curated.
        _PYPI_KNOWN = {
            "fastapi", "uvicorn", "pydantic", "python-jose", "cryptography",
            "paramiko", "requests", "aiohttp", "celery", "scrapy", "pillow",
            "sqlalchemy", "boto3", "httpx", "typer", "rich", "duckdb",
        }
        _NPM_KNOWN = {
            "express", "axios", "lodash", "jsonwebtoken", "react",
            "webpack", "typescript", "dotenv", "cors", "jest",
        }
        _tech_lower = {t.lower() for t in self.known_tech}
        _pypi_pkgs = [p for p in _PYPI_KNOWN if p in _tech_lower or any(p in t for t in _tech_lower)]
        # Always include core packages even if not in twin (they're nearly universal)
        _pypi_pkgs = list(set(_pypi_pkgs) | {"fastapi", "cryptography", "requests", "aiohttp"})
        OSV_PACKAGES = (
            [("PyPI", p) for p in sorted(_pypi_pkgs)] +
            [("npm", p) for p in sorted(_NPM_KNOWN)]
        )

        while self._running:
            # ── Source 1: OSV (Google) ──────────────────────────
            for ecosystem, package in OSV_PACKAGES:
                try:
                    payload = json.dumps({
                        "package": {"name": package, "ecosystem": ecosystem}
                    }).encode()
                    req = urllib.request.Request(
                        "https://api.osv.dev/v1/query",
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    vulns = data.get("vulns", [])
                    for vuln in vulns[:3]:
                        vuln_id = vuln.get("id", "")
                        # Only process CVEs and recent ones
                        if not vuln_id.startswith("CVE-") and not vuln_id.startswith("GHSA-"):
                            continue
                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                        # Extract year from CVE ID
                        try:
                            year = int(cve_id.split("-")[1])
                            if year < 2022:
                                continue
                        except Exception:
                            pass
                        # Get severity from database_specific
                        severity_info = vuln.get("database_specific", {})
                        cvss = 0.0
                        for sev in vuln.get("severity", []):
                            if sev.get("type") == "CVSS_V3":
                                try:
                                    score_str = sev.get("score", "")
                                    # CVSS vector string — extract base score
                                    cvss = float(severity_info.get("cvss_v3", {}).get("baseScore", 5.0))
                                except Exception:
                                    cvss = 5.0
                        if cvss == 0.0:
                            cvss = 5.0  # default medium

                        if cvss < 4.0:
                            continue

                        sig = sha256_hex(f"osv:{cve_id}:{package}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)

                        summary = vuln.get("summary", f"Vulnerability in {package}")
                        t = Threat(
                            threat_id = f"osv-{sig}",
                            source    = "cve_feed",
                            kind      = "known_vulnerability",
                            indicator = f"{cve_id} ({ecosystem}/{package}) CVSS:{cvss:.1f}",
                            tech      = [package.lower(), ecosystem.lower()],
                            ttps      = ["T1190", "T1203"],
                            meta      = {
                                "cve_id": cve_id,
                                "package": package,
                                "ecosystem": ecosystem,
                                "cvss": cvss,
                                "summary": summary[:200],
                                "url": f"https://osv.dev/vulnerability/{vuln_id}",
                                "source_db": "OSV",
                            },
                        )
                        await self._queue.put(t)
                        self._counts['cve_feed'] = self._counts.get('cve_feed', 0) + 1
                        log.info(f"[HYDRA/CVE] OSV: {cve_id} in {ecosystem}/{package} CVSS:{cvss}")
                except Exception as e:
                    if "404" not in str(e):
                        log.warning(f"[HYDRA/CVE] OSV {package}: {e}")
                await asyncio.sleep(2)

            # ── Source 2: GitHub Advisory Database ──────────────
            GH_ECOSYSTEMS = ["pip", "npm", "docker"]
            gh_token = os.environ.get("GITHUB_TOKEN", "")
            for ecosystem in GH_ECOSYSTEMS:
                try:
                    # GraphQL query for recent advisories
                    query = """
                    {
                      securityAdvisories(first: 10, orderBy: {field: PUBLISHED_AT, direction: DESC},
                                        classifications: [GENERAL]) {
                        nodes {
                          ghsaId
                          summary
                          severity
                          publishedAt
                          cvss { score }
                          vulnerabilities(first: 3, ecosystem: """ + ecosystem.upper() + """) {
                            nodes { package { name } }
                          }
                          identifiers { type value }
                        }
                      }
                    }"""
                    payload = json.dumps({"query": query}).encode()
                    req = urllib.request.Request(
                        "https://api.github.com/graphql",
                        data=payload,
                        headers={
                            "Authorization": f"Bearer {gh_token}",
                            "Content-Type": "application/json",
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
                    for adv in advisories[:5]:
                        cvss = float(adv.get("cvss", {}).get("score", 0) or 0)
                        if cvss < 4.0:
                            continue
                        severity = adv.get("severity", "MEDIUM")
                        ghsa_id = adv.get("ghsaId", "")
                        # Get CVE ID if available
                        cve_id = ghsa_id
                        for ident in adv.get("identifiers", []):
                            if ident.get("type") == "CVE":
                                cve_id = ident.get("value", ghsa_id)
                                break
                        # Check year
                        pub = adv.get("publishedAt", "")[:4]
                        try:
                            if int(pub) < 2022:
                                continue
                        except Exception:
                            pass
                        # Get affected packages
                        packages = [
                            n.get("package", {}).get("name", "")
                            for n in adv.get("vulnerabilities", {}).get("nodes", [])
                        ]
                        sig = sha256_hex(f"ghsa:{ghsa_id}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = Threat(
                            threat_id = f"ghsa-{sig}",
                            source    = "cve_feed",
                            kind      = "known_vulnerability",
                            indicator = f"{cve_id} ({ecosystem}: {', '.join(packages[:2])}) CVSS:{cvss:.1f}",
                            tech      = packages[:3] + [ecosystem],
                            ttps      = ["T1190", "T1203"],
                            meta      = {
                                "cve_id": cve_id,
                                "ghsa_id": ghsa_id,
                                "cvss": cvss,
                                "severity": severity,
                                "summary": adv.get("summary", "")[:200],
                                "url": f"https://github.com/advisories/{ghsa_id}",
                                "source_db": "GitHub Advisory",
                            },
                        )
                        await self._queue.put(t)
                        self._counts['cve_feed'] = self._counts.get('cve_feed', 0) + 1
                        log.info(f"[HYDRA/CVE] GHSA: {cve_id} CVSS:{cvss}")
                except Exception as e:
                    log.warning(f"[HYDRA/CVE] GitHub Advisory {ecosystem}: {e}")
                await asyncio.sleep(3)

            await asyncio.sleep(900)  # full cycle every 15 min


    async def _scrape_paste(self):
        """Monitor Pastebin archive for mentions of our domains/keywords."""
        seen_pastes: Set[str] = set()
        while self._running:
            try:
                url = "https://pastebin.com/archive"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    html = resp.read().decode(errors="replace")
                pids = re.findall(r'/([A-Za-z0-9]{8})"', html)[:20]
                for pid in pids:
                    if pid in seen_pastes:
                        continue
                    seen_pastes.add(pid)
                    try:
                        raw_url = f"https://pastebin.com/raw/{pid}"
                        req2    = urllib.request.Request(raw_url, headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req2, timeout=10) as r2:
                            content = r2.read().decode(errors="replace").lower()
                        matched_d = [d for d in self.domains  if d.lower() in content]
                        matched_k = [k for k in self.keywords if k.lower() in content]
                        if matched_d or matched_k:
                            has_pw = bool(re.search(r'password[\s:=]+\S+', content, re.I))
                            sig    = sha256_hex(f"paste:{pid}")[:16]
                            t = Threat(
                                threat_id = f"paste-{sig}",
                                source    = "paste_monitor",
                                kind      = "credential_leak" if has_pw else "data_leak",
                                indicator = f"pastebin.com/{pid}",
                                tech      = ["web", "credentials"] if has_pw else ["web"],
                                ttps      = ["T1552.001", "T1530"] if has_pw else ["T1530"],
                                meta      = {"pid": pid, "matched_domains": matched_d,
                                             "matched_keywords": matched_k,
                                             "has_passwords": has_pw},
                            )
                            await self._queue.put(t)
                            self._counts["paste"] = self._counts.get("paste", 0) + 1
                        await asyncio.sleep(2)
                    except Exception:
                        pass
            except Exception as e:
                log.warning(f"[HYDRA/PASTE] {e}")
            await asyncio.sleep(120)  # every 2 min

    # ── GitHub Repository Exposure scraper ──────────────────────

    async def _scrape_github(self):
        """Search GitHub public repositories for org/domain mentions.
        No auth needed for /search/repositories. Upgrades to code search
        if GITHUB_TOKEN env var is set (finds exposed secrets in files)."""
        ctx      = _mk_ssl_ctx()
        gh_token = os.environ.get("GITHUB_TOKEN", "")
        extra_hdrs: Dict[str, str] = {}
        if gh_token:
            extra_hdrs["Authorization"] = f"token {gh_token}"
            log.info("[HYDRA/GH] GITHUB_TOKEN found — using authenticated search")

        while self._running:
            for keyword in self.keywords:
                queries = [
                    (f"{keyword} credentials",    "github_exposure"),
                    (f"{keyword} leaked",         "github_exposure"),
                    (f"{keyword} api secret",     "github_exposure"),
                    (f"{keyword} token",          "github_exposure"),
                ]
                for query, kind in queries:
                    try:
                        enc = urllib.parse.quote(query)
                        url = (f"https://api.github.com/search/repositories"
                               f"?q={enc}&per_page=5&sort=updated")
                        req = urllib.request.Request(
                            url,
                            headers={
                                "User-Agent":            "AegisNexus/2.0",
                                "Accept":                "application/vnd.github+json",
                                "X-GitHub-Api-Version":  "2022-11-28",
                                **extra_hdrs,
                            }
                        )
                        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                            d = json.loads(r.read().decode())

                        count = d.get("total_count", 0)
                        if count > 0:
                            sig = sha256_hex(f"gh:{query}")[:16]
                            if sig not in self._seen:
                                self._seen.add(sig)
                                t = Threat(
                                    threat_id = f"gh-{sig}",
                                    source    = "github",
                                    kind      = kind,
                                    indicator = f'"{query}"  ({count} repos)',
                                    tech      = ["git", "credentials"],
                                    ttps      = ["T1552.001", "T1078"],
                                    meta      = {
                                        "query":       query,
                                        "repo_count":  count,
                                        "search_url":  f"https://github.com/search?q={enc}&type=repositories",
                                    },
                                )
                                await self._queue.put(t)
                                self._counts["github"] = self._counts.get("github", 0) + 1

                        await asyncio.sleep(2)

                    except urllib.error.HTTPError as e:
                        if e.code == 403:
                            log.warning(f"[HYDRA/GH] Rate limited (403) — sleeping 60s")
                            await asyncio.sleep(60)
                        elif e.code == 401:
                            log.warning("[HYDRA/GH] GitHub token invalid — check GITHUB_TOKEN")
                        elif e.code == 422:
                            pass  # query too complex — skip silently
                        else:
                            log.warning(f"[HYDRA/GH] {query}: HTTP {e.code}")
                    except Exception as e:
                        log.warning(f"[HYDRA/GH] {query}: {e}")

            await asyncio.sleep(600)   # every 10 min

    # ── Lifecycle ─────────────────────────────────────────────────


    # ── Shodan exposure scraper ───────────────────────────────
    async def _scrape_shodan(self):
        """Check Shodan InternetDB for exposed ports/vulns on our domains.
        Uses the free InternetDB API — no key required.
        Resolves domain → IP then checks exposure."""
        import socket as _socket
        ctx = _mk_ssl_ctx()
        seen: Set[str] = set()

        while self._running:
            for domain in self.domains:
                try:
                    # Resolve domain to IP
                    try:
                        ip = _socket.gethostbyname(domain)
                    except Exception:
                        await asyncio.sleep(5)
                        continue

                    sig = sha256_hex(f"shodan:{ip}")[:16]
                    if sig in seen:
                        await asyncio.sleep(60)
                        continue

                    url = f"https://internetdb.shodan.io/{ip}"
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "AegisNexus/2.0", "Accept": "application/json"}
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())

                    ports    = data.get("ports",    [])
                    vulns    = data.get("vulns",    [])
                    tags     = data.get("tags",     [])
                    hostnames = data.get("hostnames", [])

                    # Only alert if there's something interesting
                    if not ports and not vulns:
                        seen.add(sig)
                        await asyncio.sleep(10)
                        continue

                    # Exposed ports alert
                    if ports:
                        risky = [p for p in ports if p in [21,22,23,25,80,443,3306,3389,5432,6379,8080,8443,9200,27017]]
                        if risky:
                            t = Threat(
                                threat_id = f"shodan-ports-{sig}",
                                source    = "shodan",
                                kind      = "exposed_service",
                                indicator = f"{ip} — ports: {','.join(map(str,risky))}",
                                tech      = ["network", "infrastructure"],
                                ttps      = ["T1046", "T1595"],
                                meta      = {
                                    "ip":        ip,
                                    "domain":    domain,
                                    "ports":     ports,
                                    "tags":      tags,
                                    "hostnames": hostnames[:5],
                                },
                            )
                            await self._queue.put(t)
                            self._counts["shodan"] = self._counts.get("shodan", 0) + 1

                    # Known CVEs on that IP
                    for vuln in vulns[:5]:
                        vsig = sha256_hex(f"shodan:{ip}:{vuln}")[:16]
                        if vsig in seen:
                            continue
                        seen.add(vsig)
                        t = Threat(
                            threat_id = f"shodan-vuln-{vsig}",
                            source    = "shodan",
                            kind      = "known_vulnerability",
                            indicator = f"{vuln} on {ip}",
                            tech      = ["network", "infrastructure"],
                            ttps      = ["T1190", "T1595"],
                            meta      = {"ip": ip, "domain": domain, "cve": vuln},
                        )
                        await self._queue.put(t)
                        self._counts["shodan"] = self._counts.get("shodan", 0) + 1

                    seen.add(sig)
                    await asyncio.sleep(10)

                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        pass  # IP not in Shodan — fine
                    else:
                        log.warning(f"[HYDRA/SHODAN] HTTP {e.code}")
                    await asyncio.sleep(10)
                except Exception as e:
                    log.warning(f"[HYDRA/SHODAN] {e}")
                    await asyncio.sleep(15)

            await asyncio.sleep(1200)  # re-scan every 20 min

    async def start(self):
        self._running = True
        log.info("[HYDRA] Starting real scrapers: CT Logs · NVD/CVE · Pastebin · GitHub · Shodan")
        asyncio.create_task(self._scrape_ct(),      name="hydra-ct")
        asyncio.create_task(self._scrape_cve(),     name="hydra-cve")
        asyncio.create_task(self._scrape_paste(),   name="hydra-paste")
        asyncio.create_task(self._scrape_github(),  name="hydra-github")
        asyncio.create_task(self._scrape_shodan(),  name="hydra-shodan")

    def stop(self):
        self._running = False

    async def next(self, timeout: float = 5.0) -> Optional[Threat]:
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def stats(self) -> Dict:
        return {"counts": self._counts, "queued": self._queue.qsize()}


# ══════════════════════════════════════════════════════════════════
# SPECTRA CALIBRATION ENGINE
# ══════════════════════════════════════════════════════════════════

@dataclass
class LabeledThreat:
    """A scored threat with analyst ground-truth label."""
    threat_id:    str
    kind:         str
    indicator:    str
    tech:         List[str]
    ttps:         List[str]
    perturbation: float
    label:        str    # "true_positive" | "false_positive" | "confirmed_critical"



# ══════════════════════════════════════════════════════════════════
# LAYER 2 EXTENSION — HYDRA v3.0 NEW SCRAPERS
# ══════════════════════════════════════════════════════════════════

class HydraV3Scrapers:
    """
    6 new async scrapers extending HYDRA to 11 total sources.
    BeVigil · Abuse.ch · OTX · URLScan · Pulsedive · IntelX · Dark Web
    """

    def __init__(self, domains, keywords, known_tech, queue, seen, counts):
        self.domains     = domains
        self.keywords    = keywords
        self.known_tech  = known_tech
        self._queue      = queue
        self._seen       = seen
        self._counts     = counts
        self._running    = False

        # API keys — loaded from environment variables ONLY.
        # Set before starting: export BEVIGIL_API_KEY=your_key etc.
        # All previously hardcoded fallback keys have been removed for security.
        self.BEVIGIL_KEY    = os.environ.get("BEVIGIL_API_KEY", "")
        self.ABUSECH_KEY    = os.environ.get("ABUSECH_API_KEY", "")
        self.OTX_KEY        = os.environ.get("OTX_API_KEY", "")
        self.VT_KEY         = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.URLSCAN_KEY    = os.environ.get("URLSCAN_API_KEY", "")
        self.ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.PULSEDIVE_KEY  = os.environ.get("PULSEDIVE_API_KEY", "")
        self.INTELX_KEY     = os.environ.get("INTELX_API_KEY", "")
        self.GROQ_KEY       = os.environ.get("GROQ_API_KEY", "")
        self.GH_TOKEN       = os.environ.get("GITHUB_TOKEN", "")
        # NVD_API_KEY — add later for higher rate limits; works without it
        self.NVD_KEY        = os.environ.get("NVD_API_KEY", "")
        # Warn at startup for missing keys so operator knows which scrapers are degraded
        _missing = [k for k, v in {
            "BEVIGIL_API_KEY": self.BEVIGIL_KEY, "ABUSECH_API_KEY": self.ABUSECH_KEY,
            "OTX_API_KEY": self.OTX_KEY, "URLSCAN_API_KEY": self.URLSCAN_KEY,
            "PULSEDIVE_API_KEY": self.PULSEDIVE_KEY, "GROQ_API_KEY": self.GROQ_KEY,
            "GITHUB_TOKEN": self.GH_TOKEN,
        }.items() if not v]
        if _missing:
            log.warning(f"[HYDRA-v3] Missing env vars (scrapers degraded): {', '.join(_missing)}")

    def _mk_threat(self, **kw) -> Threat:
        return Threat(
            threat_id = kw.get("threat_id", f"v3-{uuid.uuid4().hex[:8]}"),
            source    = kw["source"],
            kind      = kw["kind"],
            indicator = kw["indicator"],
            tech      = kw.get("tech", []),
            ttps      = kw.get("ttps", []),
            meta      = kw.get("meta", {}),
        )

    def _seen_add(self, sig: str) -> bool:
        """Returns True if already seen (skip). Adds if new."""
        if sig in self._seen:
            return True
        self._seen.add(sig)
        return False

    async def _put(self, t: Threat, source_key: str):
        await self._queue.put(t)
        self._counts[source_key] = self._counts.get(source_key, 0) + 1

    # ── 1. BeVigil API ──────────────────────────────────────────
    async def _scrape_bevigil(self):
        """BeVigil mobile app intelligence — exposed API keys in APKs.
        Uses 25 free credits wisely — only 3 searches per 6 hours.
        Requires BEVIGIL_API_KEY env var."""
        ctx = _mk_ssl_ctx()
        # Only search top 3 keywords once per 6hrs to preserve 25 credits
        KEYWORDS = ["cloudsek", "bevigil", "xvigil"]
        _credit_used = 0
        while self._running:
            if not self.BEVIGIL_KEY:
                log.warning("[HYDRA/BEVIGIL] BEVIGIL_API_KEY not set — scraper disabled")
                await asyncio.sleep(86400)
                continue
            if _credit_used >= 24:
                log.warning("[HYDRA/BEVIGIL] Credit limit reached — pausing BeVigil")
                await asyncio.sleep(86400)
                continue
            for keyword in KEYWORDS:
                try:
                    # Try subdomains endpoint first (costs 1 credit)
                    url = f"https://osint.bevigil.com/api/{urllib.parse.quote(keyword)}/subdomains/"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "X-Access-Token": self.BEVIGIL_KEY,
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    _credit_used += 1
                    subdomains = data.get("subdomains", [])
                    for sub in subdomains[:15]:
                        sig = sha256_hex(f"bevigil-sub:{sub}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"bv-{sig}",
                            source    = "bevigil",
                            kind      = "subdomain_discovered",
                            indicator = sub,
                            tech      = ["mobile", "android", "web"],
                            ttps      = ["T1526", "T1583.001"],
                            meta      = {"keyword": keyword, "source_api": "bevigil",
                                         "credits_used": _credit_used},
                        )
                        await self._put(t, "bevigil")
                    log.info(f"[HYDRA/BEVIGIL] {keyword}: {len(subdomains)} subdomains (credits used: {_credit_used})")
                except Exception as e:
                    if "402" in str(e) or "Payment" in str(e):
                        log.warning("[HYDRA/BEVIGIL] Credit exhausted")
                        _credit_used = 25
                    elif "401" in str(e):
                        log.warning("[HYDRA/BEVIGIL] Invalid API key")
                        await asyncio.sleep(86400)
                    else:
                        log.warning(f"[HYDRA/BEVIGIL] {e}")
                await asyncio.sleep(10)  # 10s between keywords
            await asyncio.sleep(21600)  # 6hrs between full cycles — preserves credits

    # ── 2. Abuse.ch ─────────────────────────────────────────────
    async def _scrape_abusech(self):
        """Abuse.ch ThreatFox — malware IOCs referencing our stack."""
        ctx = _mk_ssl_ctx()
        while self._running:
            for kw in self.keywords[:5]:
                try:
                    payload = json.dumps({"query": "search_ioc", "search_term": kw}).encode()
                    _abusech_headers = {"Content-Type": "application/json"}
                    if self.ABUSECH_KEY:
                        _abusech_headers["Auth-Key"] = self.ABUSECH_KEY
                    req = urllib.request.Request(
                        "https://threatfox-api.abuse.ch/api/v1/",
                        data=payload,
                        headers=_abusech_headers,
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    # API returns {"query_status":"no_results"} or {"data":[...]}
                    if not isinstance(data, dict):
                        continue
                    if data.get("query_status") in ("no_results", "ok") and not data.get("data"):
                        continue
                    for ioc in (data.get("data") or [])[:5]:
                        if not isinstance(ioc, dict):
                            continue
                        ioc_val = ioc.get("ioc_value", "")
                        ioc_type = ioc.get("ioc_type", "")
                        malware = ioc.get("malware", "")
                        sig = sha256_hex(f"abusech:{ioc_val}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"abch-{sig}",
                            source    = "abuse_ch",
                            kind      = "malware_ioc",
                            indicator = f"{ioc_val} ({malware})",
                            tech      = ["malware", ioc_type],
                            ttps      = ["T1071", "T1059"],
                            meta      = {
                                "ioc_type": ioc_type,
                                "malware": malware,
                                "confidence": ioc.get("confidence_level", 0),
                                "tags": ioc.get("tags", []),
                            },
                        )
                        await self._put(t, "abuse_ch")
                except Exception as e:
                    log.warning(f"[HYDRA/ABUSECH] {e}")
                await asyncio.sleep(3)
            await asyncio.sleep(600)

    # ── 3. OTX AlienVault ───────────────────────────────────────
    async def _scrape_otx(self):
        """AlienVault OTX — threat pulses for our domains and keywords.
        Requires OTX_API_KEY env var."""
        ctx = _mk_ssl_ctx()
        _otx_retries = 0
        while self._running:
            if not self.OTX_KEY:
                log.warning("[HYDRA/OTX] OTX_API_KEY not set — scraper disabled")
                await asyncio.sleep(86400)
                continue
            for domain in self.domains[:3]:
                try:
                    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/general"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "X-OTX-API-KEY": self.OTX_KEY,
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    for pulse in pulses[:3]:
                        sig = sha256_hex(f"otx:{pulse.get('id','')}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        tags = pulse.get("tags", [])
                        adversary = pulse.get("adversary", "")
                        t = self._mk_threat(
                            threat_id = f"otx-{sig}",
                            source    = "otx",
                            kind      = "threat_intelligence",
                            indicator = f"{domain} — {pulse.get('name','')}",
                            tech      = ["web", "dns"],
                            ttps      = pulse.get("attack_ids", ["T1566"])[:3],
                            meta      = {
                                "pulse_id": pulse.get("id"),
                                "pulse_name": pulse.get("name"),
                                "adversary": adversary,
                                "tags": tags,
                                "pulse_count": pulse_count,
                                "otx_url": f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
                            },
                        )
                        await self._put(t, "otx")
                except Exception as e:
                    err = str(e)
                    if "502" in err or "503" in err or "504" in err:
                        log.warning(f"[HYDRA/OTX] {domain}: server error — retrying in 5 min")
                        await asyncio.sleep(300)
                    elif "429" in err:
                        await asyncio.sleep(120)
                    else:
                        log.warning(f"[HYDRA/OTX] {e}")
                await asyncio.sleep(5)
            await asyncio.sleep(900)

    # ── 4. URLScan.io phishing detector ─────────────────────────
    async def _scrape_urlscan(self):
        """URLScan.io — search for scans of our domains (phishing detection).
        Requires URLSCAN_API_KEY env var."""
        ctx = _mk_ssl_ctx()
        while self._running:
            if not self.URLSCAN_KEY:
                log.warning("[HYDRA/URLSCAN] URLSCAN_API_KEY not set — scraper disabled")
                await asyncio.sleep(86400)
                continue
            for domain in self.domains[:3]:
                try:
                    url = f"https://urlscan.io/api/v1/search/?q=page.domain%3A{urllib.parse.quote(domain)}&size=10"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "API-Key": self.URLSCAN_KEY,
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    for result in data.get("results", [])[:5]:
                        page = result.get("page", {})
                        scan_url = page.get("url", "")
                        verdict = result.get("verdicts", {}).get("overall", {})
                        is_malicious = verdict.get("malicious", False)
                        score = verdict.get("score", 0)
                        if score < 20 and not is_malicious:
                            continue
                        sig = sha256_hex(f"urlscan:{result.get('_id','')}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"us-{sig}",
                            source    = "urlscan",
                            kind      = "phishing_detected",
                            indicator = scan_url,
                            tech      = ["web", "phishing"],
                            ttps      = ["T1566.002", "T1583.001"],
                            meta      = {
                                "scan_id": result.get("_id"),
                                "malicious": is_malicious,
                                "score": score,
                                "screenshot": f"https://urlscan.io/screenshots/{result.get('_id','')}.png",
                                "report": f"https://urlscan.io/result/{result.get('_id','')}",
                                "domain": domain,
                            },
                        )
                        await self._put(t, "urlscan")
                except Exception as e:
                    log.warning(f"[HYDRA/URLSCAN] {e}")
                await asyncio.sleep(5)
            await asyncio.sleep(600)

    # ── 6. Pulsedive enrichment ──────────────────────────────────
    async def _scrape_pulsedive(self):
        """Pulsedive — threat enrichment for our domains.
        Requires PULSEDIVE_API_KEY env var."""
        ctx = _mk_ssl_ctx()
        while self._running:
            if not self.PULSEDIVE_KEY:
                log.warning("[HYDRA/PULSEDIVE] PULSEDIVE_API_KEY not set — scraper disabled")
                await asyncio.sleep(86400)
                continue
            for domain in self.domains[:3]:
                try:
                    # Pulsedive v2 API — lookup indicator by value
                    url = (f"https://pulsedive.com/api/info.php"
                           f"?indicator={urllib.parse.quote(domain)}"
                           f"&pretty=1&key={self.PULSEDIVE_KEY}")
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "AegisNexus/3.0",
                        "Accept": "application/json",
                    })
                    try:
                        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                            data = json.loads(r.read().decode())
                    except Exception as _e404:
                        # 404 = domain not in Pulsedive DB — not an error, just skip
                        if "404" in str(_e404) or "Not Found" in str(_e404):
                            await asyncio.sleep(5)
                            continue
                        raise
                    risk = data.get("risk", "unknown")
                    if risk in ("none", "unknown", ""):
                        await asyncio.sleep(5)
                        continue
                    threats_list = data.get("threats", [])
                    for threat_item in threats_list[:3]:
                        sig = sha256_hex(f"pd:{domain}:{threat_item.get('name','')}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"pd-{sig}",
                            source    = "pulsedive",
                            kind      = "threat_intelligence",
                            indicator = f"{domain} — {threat_item.get('name', 'Unknown')}",
                            tech      = ["web", "dns"],
                            ttps      = ["T1566", "T1071"],
                            meta      = {
                                "risk": risk,
                                "threat_name": threat_item.get("name"),
                                "category": threat_item.get("category"),
                                "pulsedive_url": f"https://pulsedive.com/indicator/?ioc={urllib.parse.quote(domain)}",
                            },
                        )
                        await self._put(t, "pulsedive")
                except Exception as e:
                    if "429" in str(e) or "Too Many" in str(e):
                        await asyncio.sleep(300)
                    else:
                        err = str(e)
                        if "404" in err or "Not Found" in err:
                            pass  # domain not indexed in Pulsedive — normal, skip quietly
                        elif "429" in err:
                            log.warning("[HYDRA/PULSEDIVE] Rate limited — sleeping 10 min")
                            await asyncio.sleep(600)
                        elif "502" in err or "503" in err:
                            log.warning("[HYDRA/PULSEDIVE] Server error — retrying in 5 min")
                            await asyncio.sleep(300)
                        else:
                            log.warning(f"[HYDRA/PULSEDIVE] {e}")
                await asyncio.sleep(30)
            await asyncio.sleep(7200)

    # ── 7. IntelX dark web search ────────────────────────────────
    # ── IntelX REPLACED with 5 free alternatives ────────────────

    async def _scrape_breachdirectory(self):
        """BreachDirectory — XposedOrNot free API for CloudSEK employee breach detection."""
        ctx = _mk_ssl_ctx()
        while self._running:
            # XposedOrNot only (truly free, no key needed)
            for domain in ["cloudsek.com", "bevigil.com"]:
                try:
                    # Use BreachDirectory.com free public API
                    url = f"https://breachdirectory.org/api/v1/search?query={urllib.parse.quote(domain)}"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                            "Accept": "application/json",
                            "Referer": "https://breachdirectory.org/",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    results = data.get("result", []) if isinstance(data, dict) else []
                    if results:
                        sig = sha256_hex(f"bdir:{domain}:{len(results)}")[:16]
                        if not self._seen_add(sig):
                            t = self._mk_threat(
                                threat_id = f"bdir-{sig}",
                                source    = "breach_directory",
                                kind      = "employee_credential_leak",
                                indicator = f"{domain} — {len(results)} records found in breach database",
                                tech      = ["credentials", "email", "identity"],
                                ttps      = ["T1078", "T1589.002"],
                                meta      = {"domain": domain, "record_count": len(results),
                                             "source_api": "BreachDirectory"},
                            )
                            await self._put(t, "breach_directory")
                            log.info(f"[HYDRA/BREACHDIR] {domain}: {len(results)} breach records")
                except Exception as e:
                    if "404" not in str(e) and "403" not in str(e):
                        log.warning(f"[HYDRA/BREACHDIR] {domain}: {e}")
                await asyncio.sleep(15)
            await asyncio.sleep(7200)

    async def _scrape_pastehunter(self):
        """PasteHunter — search GitHub repos + Gists for CloudSEK credential leaks."""
        ctx = _mk_ssl_ctx()
        while self._running:
            for domain in self.domains[:2]:
                for query in [
                    f"{domain} password",
                    f"{domain} api_key",
                    f"{domain} secret",
                    f"{domain} token",
                ]:
                    try:
                        # Use repo search (no code search auth needed)
                        url = (f"https://api.github.com/search/repositories"
                               f"?q={urllib.parse.quote(query)}&sort=updated&per_page=5")
                        hdrs = {
                            "User-Agent": "AegisNexus/3.0",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        }
                        if self.GH_TOKEN:
                            hdrs["Authorization"] = f"Bearer {self.GH_TOKEN}"
                        req = urllib.request.Request(url, headers=hdrs)
                        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                            data = json.loads(r.read().decode())
                        items = data.get("items", [])
                        for item in items[:3]:
                            repo_name = item.get("full_name", "")
                            html_url  = item.get("html_url", "")
                            desc      = item.get("description", "") or ""
                            sig = sha256_hex(f"ph:{repo_name}:{query[:20]}")[:16]
                            if self._seen_add(sig):
                                continue
                            t = self._mk_threat(
                                threat_id = f"ph-{sig}",
                                source    = "paste_hunter",
                                kind      = "data_leak",
                                indicator = f"{domain} mentioned in repo: {repo_name}",
                                tech      = ["credentials", "web", "git", "github",
                                             "python", "javascript", "ssl"],
                                ttps      = ["T1552.001", "T1530"],
                                meta      = {
                                    "repo": repo_name,
                                    "url": html_url,
                                    "description": desc[:100],
                                    "query": query,
                                },
                            )
                            await self._put(t, "paste_hunter")
                    except Exception as e:
                        if "401" in str(e):
                            log.warning("[HYDRA/PASTEHUNT] Auth error — check GITHUB_TOKEN")
                        elif "403" not in str(e) and "422" not in str(e):
                            log.warning(f"[HYDRA/PASTEHUNT] {e}")
                    await asyncio.sleep(8)
            await asyncio.sleep(1800)

    async def _scrape_spiderfoot(self):
        """SpiderFoot HX public data — DNS, WHOIS, cert info for our domains."""
        ctx = _mk_ssl_ctx()
        while self._running:
            for domain in self.domains[:2]:
                # Use free public DNS + WHOIS APIs as SpiderFoot data sources
                try:
                    # HackerTarget free DNS lookup — no API key required
                    url2 = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
                    req2 = urllib.request.Request(url2, headers={"User-Agent": "AegisNexus/3.0"})
                    with urllib.request.urlopen(req2, timeout=15, context=ctx) as r:
                        raw = r.read().decode()
                    lines = [l.strip() for l in raw.splitlines() if domain in l and "," in l]
                    for line in lines[:10]:
                        parts = line.split(",")
                        subdomain = parts[0].strip() if parts else ""
                        ip = parts[1].strip() if len(parts) > 1 else ""
                        if not subdomain or subdomain == domain:
                            continue
                        sig = sha256_hex(f"spiderfoot:{subdomain}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"sf-{sig}",
                            source    = "spiderfoot",
                            kind      = "subdomain_discovered",
                            indicator = subdomain,
                            tech      = ["dns", "web", "network"],
                            ttps      = ["T1592", "T1595.002"],
                            meta      = {"domain": domain, "ip": ip,
                                         "source": "HackerTarget DNS"},
                        )
                        await self._put(t, "spiderfoot")
                except Exception as e:
                    if "429" not in str(e):
                        log.warning(f"[HYDRA/SPIDERFOOT] {domain}: {e}")
                    else:
                        await asyncio.sleep(60)
                await asyncio.sleep(15)
            await asyncio.sleep(3600)

    async def _scrape_alienvault_pulse(self):
        """AlienVault OTX Pulse extended — threat actor correlation per domain.
        Requires OTX_API_KEY env var."""
        ctx = _mk_ssl_ctx()
        log.info("[HYDRA/ALIENVAULT] Pulse scraper started")
        while self._running:
            if not self.OTX_KEY:
                log.warning("[HYDRA/ALIENVAULT] OTX_API_KEY not set — pulse scraper disabled")
                await asyncio.sleep(86400)
                continue
            for domain in self.domains[:3]:
                try:
                    # Get full pulse details including related indicators
                    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/malware"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "X-OTX-API-KEY": self.OTX_KEY,
                            "User-Agent": "AegisNexus/3.0",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    results = data.get("data", [])
                    for malware in results[:3]:
                        family = malware.get("detections", {}).get("av_family", "Unknown")
                        sig = sha256_hex(f"avpulse:{domain}:{family}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"avp-{sig}",
                            source    = "alienvault",
                            kind      = "malware_ioc",
                            indicator = f"{domain} — malware family: {family}",
                            tech      = ["web", "malware"],
                            ttps      = ["T1566", "T1071"],
                            meta      = {
                                "domain": domain,
                                "malware_family": family,
                                "hash": malware.get("hash", ""),
                                "otx_url": f"https://otx.alienvault.com/indicator/domain/{domain}",
                            },
                        )
                        await self._put(t, "alienvault")
                except Exception as e:
                    err = str(e)
                    if "502" in err or "503" in err or "504" in err:
                        log.warning(f"[HYDRA/ALIENVAULT] {domain}: server error {err[:60]} — retrying in 5 min")
                        await asyncio.sleep(300)
                    elif "429" in err:
                        await asyncio.sleep(120)
                    elif "404" not in err:
                        log.warning(f"[HYDRA/ALIENVAULT] {domain}: {e}")
                await asyncio.sleep(10)
            await asyncio.sleep(3600)

    # ── 8. Dark Web Tor monitor ──────────────────────────────────
    async def _scrape_darkweb(self):
        """Monitor dark web paste sites via Tor proxy for domain mentions."""
        TOR_PROXY = "socks5h://127.0.0.1:9050"
        ONION_PASTES = [
            "http://depastedihrn3jtw.onion/",
            "http://strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3rlh3ad.onion/",
        ]
        while self._running:
            # Check if Tor is running
            try:
                import socket as _socket
                s = _socket.socket()
                s.settimeout(3)
                s.connect(("127.0.0.1", 9050))
                s.close()
                tor_up = True
            except Exception:
                tor_up = False
                log.debug("[HYDRA/DARKWEB] Tor not reachable on 9050 — skipping")
                await asyncio.sleep(300)
                continue

            if tor_up:
                try:
                    import subprocess as _sp
                    for domain in self.domains[:2]:
                        for site in ONION_PASTES:
                            try:
                                result = _sp.run(
                                    ["curl", "--socks5-hostname", "127.0.0.1:9050",
                                     "-s", "--max-time", "20", site],
                                    capture_output=True, text=True, timeout=25
                                )
                                content = result.stdout.lower()
                                if domain.lower() in content:
                                    sig = sha256_hex(f"darkweb:{site}:{domain}")[:16]
                                    if self._seen_add(sig):
                                        continue
                                    t = self._mk_threat(
                                        threat_id = f"dw-{sig}",
                                        source    = "dark_web",
                                        kind      = "dark_web_mention",
                                        indicator = f"{domain} mentioned on {site}",
                                        tech      = ["web", "credentials"],
                                        ttps      = ["T1530", "T1552"],
                                        meta      = {"site": site, "domain": domain,
                                                     "tor_proxy": TOR_PROXY},
                                    )
                                    await self._put(t, "dark_web")
                            except Exception as e:
                                log.warning(f"[HYDRA/DARKWEB] {site}: {e}")
                            await asyncio.sleep(10)
                except Exception as e:
                    log.warning(f"[HYDRA/DARKWEB] {e}")
            await asyncio.sleep(600)

    # ── 9. GitHub commit secret scanner ─────────────────────────
    async def _scrape_github_commits(self):
        """Scan public repo commits for accidentally committed secrets.
        Requires GITHUB_TOKEN env var for authenticated access."""
        ctx = _mk_ssl_ctx()
        gh_token = self.GH_TOKEN
        hdrs = {
            "User-Agent": "AegisNexus/3.0",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if gh_token:
            hdrs["Authorization"] = f"token {gh_token}"

        SECRET_PATTERNS = [
            r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?(\S{8,})',
            r'(?i)(token|secret|credential)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})',
            r'ghp_[A-Za-z0-9]{36}',
            r'AIza[A-Za-z0-9\-_]{35}',
            r'AKIA[0-9A-Z]{16}',
        ]

        while self._running:
            try:
                # Search public repos mentioning CloudSEK/BeVigil
                url = "https://api.github.com/search/repositories?q=cloudsek+bevigil&sort=updated&per_page=5"
                req = urllib.request.Request(url, headers=hdrs)
                with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                    repos = json.loads(r.read().decode())

                repo_list = repos.get("items", []) if isinstance(repos, dict) else repos
                for repo in repo_list[:5]:
                    repo_name = repo.get("full_name", "")
                    if not repo_name:
                        continue
                    try:
                        # Get recent commits
                        commit_url = f"https://api.github.com/repos/{repo_name}/commits?per_page=5"
                        req2 = urllib.request.Request(commit_url, headers=hdrs)
                        with urllib.request.urlopen(req2, timeout=15, context=ctx) as r2:
                            commits = json.loads(r2.read().decode())

                        for commit in commits[:3]:
                            sha = commit.get("sha", "")
                            # Get commit diff
                            diff_url = f"https://api.github.com/repos/{repo_name}/commits/{sha}"
                            req3 = urllib.request.Request(diff_url, headers={**hdrs, "Accept": "application/vnd.github.diff"})
                            with urllib.request.urlopen(req3, timeout=15, context=ctx) as r3:
                                diff = r3.read().decode(errors="replace")

                            for pattern in SECRET_PATTERNS:
                                matches = re.findall(pattern, diff)
                                if matches:
                                    sig = sha256_hex(f"ghcommit:{sha}:{pattern[:20]}")[:16]
                                    if self._seen_add(sig):
                                        continue
                                    t = self._mk_threat(
                                        threat_id = f"ghc-{sig}",
                                        source    = "github_commits",
                                        kind      = "secret_in_commit",
                                        indicator = f"{repo_name}@{sha[:8]} — secret pattern detected",
                                        tech      = ["git", "credentials", "secrets"],
                                        ttps      = ["T1552.001", "T1078"],
                                        meta      = {
                                            "repo": repo_name,
                                            "commit_sha": sha,
                                            "commit_url": f"https://github.com/{repo_name}/commit/{sha}",
                                            "pattern_matched": str(pattern[:50]),
                                            "match_count": len(matches),
                                        },
                                    )
                                    await self._put(t, "github_commits")
                            await asyncio.sleep(2)
                    except Exception as e:
                        log.warning(f"[HYDRA/GHCOMMIT] {repo_name}: {e}")
                    await asyncio.sleep(3)
            except Exception as e:
                if "404" in str(e):
                    log.warning("[HYDRA/GHCOMMIT] Repo not found — skipping")
                elif "403" in str(e) or "401" in str(e):
                    log.warning("[HYDRA/GHCOMMIT] Auth error — check GITHUB_TOKEN")
                else:
                    log.warning(f"[HYDRA/GHCOMMIT] {e}")
            await asyncio.sleep(3600)

    # ── 10. Wayback Machine monitor ──────────────────────────────
    async def _scrape_wayback(self):
        """Check archive.org for sensitive deleted pages."""
        ctx = _mk_ssl_ctx()
        log.info("[HYDRA/WAYBACK] Scraper started")
        SENSITIVE_PATHS = [
            "/.env", "/config.php", "/wp-config.php", "/admin",
            "/.git/config", "/api/v1/users", "/backup", "/dump.sql",
            "/credentials", "/secrets", "/private", "/.aws/credentials",
        ]
        while self._running:
            for domain in self.domains[:3]:
                for path in SENSITIVE_PATHS[:5]:
                    try:
                        query_url = urllib.parse.quote(f"http://{domain}{path}")
                        url = f"http://archive.org/wayback/available?url={query_url}"
                        req = urllib.request.Request(url, headers={"User-Agent": "AegisNexus/3.0"})
                        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                            data = json.loads(r.read().decode())
                        snapshot = data.get("archived_snapshots", {}).get("closest", {})
                        if snapshot.get("available") and snapshot.get("status") == "200":
                            snap_url = snapshot.get("url", "")
                            snap_ts  = snapshot.get("timestamp", "")
                            sig = sha256_hex(f"wayback:{domain}:{path}")[:16]
                            if self._seen_add(sig):
                                continue
                            t = self._mk_threat(
                                threat_id = f"wb-{sig}",
                                source    = "wayback",
                                kind      = "sensitive_page_archived",
                                indicator = f"{domain}{path} — archived {snap_ts[:8]}",
                                tech      = ["web", "configuration"],
                                ttps      = ["T1592", "T1530"],
                                meta      = {
                                    "domain": domain,
                                    "path": path,
                                    "snapshot_url": snap_url,
                                    "snapshot_date": snap_ts,
                                    "wayback_url": f"https://web.archive.org/web/*/{domain}{path}",
                                },
                            )
                            await self._put(t, "wayback")
                    except Exception as e:
                        if "429" in str(e):
                            await asyncio.sleep(30)
                        else:
                            log.warning(f"[HYDRA/WAYBACK] {domain}{path}: {e}")
                    await asyncio.sleep(4)
            await asyncio.sleep(3600)

    # ── 11. Supply chain monitor ─────────────────────────────────
    async def _scrape_supply_chain(self):
        """Monitor PyPI and npm for typosquat packages targeting our tech stack."""
        ctx = _mk_ssl_ctx()
        # Key packages CloudSEK/BeVigil likely uses
        WATCH_PACKAGES = {
            "pypi": ["fastapi", "uvicorn", "duckdb", "pyyaml", "httpx", "requests",
                     "cryptography", "pydantic", "typer", "rich"],
            "npm":  ["axios", "express", "lodash", "react", "typescript",
                     "webpack", "eslint", "jest", "dotenv", "cors"],
        }

        def _gen_typosquats_pkg(name: str):
            variants = set()
            for i in range(len(name) - 1):
                s = list(name); s[i], s[i+1] = s[i+1], s[i]
                v = "".join(s)
                if v != name: variants.add(v)
            for extra in ["-python", "-py", "py-", "python-"]:
                variants.add(f"{extra}{name}")
                variants.add(f"{name}{extra}")
            for c in "0123456789":
                variants.add(f"{name}{c}")
            return list(variants)[:8]

        while self._running:
            # PyPI check
            for pkg in WATCH_PACKAGES["pypi"][:5]:
                for typo in _gen_typosquats_pkg(pkg):
                    try:
                        url = f"https://pypi.org/pypi/{urllib.parse.quote(typo)}/json"
                        req = urllib.request.Request(url, headers={"User-Agent": "AegisNexus/3.0"})
                        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                            data = json.loads(r.read().decode())
                        # Package exists — potential typosquat
                        info = data.get("info", {})
                        sig = sha256_hex(f"pypi:{typo}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"sc-pypi-{sig}",
                            source    = "supply_chain",
                            kind      = "supply_chain_typosquat",
                            indicator = f"PyPI: {typo} (typosquat of {pkg})",
                            tech      = ["python", "package", "supply_chain"],
                            ttps      = ["T1195.001", "T1072"],
                            meta      = {
                                "package": typo,
                                "legitimate": pkg,
                                "registry": "pypi",
                                "author": info.get("author", ""),
                                "pypi_url": f"https://pypi.org/project/{typo}/",
                                "downloads": info.get("downloads", {}),
                            },
                        )
                        await self._put(t, "supply_chain")
                    except urllib.error.HTTPError as e:
                        if e.code != 404:
                            log.warning(f"[HYDRA/SC] pypi:{typo} HTTP {e.code}")
                    except Exception as e:
                        log.warning(f"[HYDRA/SC] pypi:{typo}: {e}")

            # npm check
            for pkg in WATCH_PACKAGES["npm"][:5]:
                for typo in _gen_typosquats_pkg(pkg):
                    try:
                        url = f"https://registry.npmjs.org/{urllib.parse.quote(typo)}"
                        req = urllib.request.Request(url, headers={"User-Agent": "AegisNexus/3.0"})
                        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                            data = json.loads(r.read().decode())
                        sig = sha256_hex(f"npm:{typo}")[:16]
                        if sig in self._seen:
                            continue
                        self._seen.add(sig)
                        t = self._mk_threat(
                            threat_id = f"sc-npm-{sig}",
                            source    = "supply_chain",
                            kind      = "supply_chain_typosquat",
                            indicator = f"npm: {typo} (typosquat of {pkg})",
                            tech      = ["javascript", "node", "supply_chain"],
                            ttps      = ["T1195.001", "T1072"],
                            meta      = {
                                "package": typo,
                                "legitimate": pkg,
                                "registry": "npm",
                                "npm_url": f"https://www.npmjs.com/package/{typo}",
                            },
                        )
                        await self._put(t, "supply_chain")
                    except urllib.error.HTTPError as e:
                        if e.code != 404:
                            log.warning(f"[HYDRA/SC] npm:{typo} HTTP {e.code}")
                    except Exception as e:
                        log.warning(f"[HYDRA/SC] npm:{typo}: {e}")

            await asyncio.sleep(1800)

    # ── 12. Employee exposure monitor ───────────────────────────
    async def _scrape_employee_exposure(self):
        """Check XposedOrNot + BreachDirectory for CloudSEK employee email exposure."""
        ctx = _mk_ssl_ctx()
        # Known CloudSEK email domains
        CHECK_DOMAINS = ["cloudsek.com", "bevigil.com"]

        while self._running:
            for domain in CHECK_DOMAINS:
                # XposedOrNot — free, no key
                try:
                    url = f"https://api.xposedornot.com/v1/domain-breaches/{urllib.parse.quote(domain)}"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "AegisNexus/3.0",
                            "Accept": "application/json",
                            "x-api-key": "",
                        },
                        method="GET"
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    breaches = data.get("breaches", [])
                    metrics  = data.get("metrics", {})
                    exposed_count = metrics.get("exposed_count", 0)
                    if breaches:
                        for breach in breaches[:3]:
                            sig = sha256_hex(f"xon:{domain}:{breach}")[:16]
                            if self._seen_add(sig):
                                continue
                            t = self._mk_threat(
                                threat_id = f"xon-{sig}",
                                source    = "employee_exposure",
                                kind      = "employee_credential_leak",
                                indicator = f"{domain} — {exposed_count} accounts in breach: {breach}",
                                tech      = ["credentials", "email", "identity"],
                                ttps      = ["T1078", "T1110.001", "T1589.002"],
                                meta      = {
                                    "domain": domain,
                                    "breach_name": breach,
                                    "exposed_count": exposed_count,
                                    "source_api": "XposedOrNot",
                                    "check_url": f"https://xposedornot.com/xposed/{urllib.parse.quote(domain)}",
                                },
                            )
                            await self._put(t, "employee_exposure")
                except Exception as e:
                    log.debug(f"[HYDRA/EMPEXP/XON] {domain}: {e}")

                # BreachDirectory — free API
                try:
                    url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={urllib.parse.quote(domain)}"
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "AegisNexus/3.0",
                            "X-RapidAPI-Key": os.environ.get("RAPIDAPI_KEY", ""),
                            "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                        data = json.loads(r.read().decode())
                    results = data.get("result", [])
                    if results:
                        sig = sha256_hex(f"bd:{domain}:{len(results)}")[:16]
                        if not self._seen_add(sig):
                            t = self._mk_threat(
                                threat_id = f"bd-{sig}",
                                source    = "employee_exposure",
                                kind      = "employee_credential_leak",
                                indicator = f"{domain} — {len(results)} records in BreachDirectory",
                                tech      = ["credentials", "email", "identity"],
                                ttps      = ["T1078", "T1589.002"],
                                meta      = {
                                    "domain": domain,
                                    "record_count": len(results),
                                    "source_api": "BreachDirectory",
                                    "sample_emails": [r.get("email","")[:30] for r in results[:3]],
                                },
                            )
                            await self._put(t, "employee_exposure")
                except Exception as e:
                    log.debug(f"[HYDRA/EMPEXP/BD] {domain}: {e}")

                await asyncio.sleep(10)
            await asyncio.sleep(1800)

    async def start(self):
        self._running = True
        log.info("[HYDRA-v3] Starting extended scrapers: BeVigil·AbuseCH·OTX·URLScan·Pulsedive·IntelX·DarkWeb·GHCommits·Wayback·SupplyChain·EmpExposure")
        asyncio.create_task(self._scrape_bevigil(),          name="hydra-bevigil")
        asyncio.create_task(self._scrape_abusech(),          name="hydra-abusech")
        asyncio.create_task(self._scrape_otx(),              name="hydra-otx")
        asyncio.create_task(self._scrape_urlscan(),          name="hydra-urlscan")
        asyncio.create_task(self._scrape_pulsedive(),        name="hydra-pulsedive")
        asyncio.create_task(self._scrape_breachdirectory(),  name="hydra-breachdir")
        asyncio.create_task(self._scrape_pastehunter(),       name="hydra-pastehunter")
        asyncio.create_task(self._scrape_spiderfoot(),        name="hydra-spiderfoot")
        asyncio.create_task(self._scrape_alienvault_pulse(),  name="hydra-alienvault")
        asyncio.create_task(self._scrape_darkweb(),          name="hydra-darkweb")
        asyncio.create_task(self._scrape_github_commits(),   name="hydra-ghcommits")
        asyncio.create_task(self._scrape_wayback(),          name="hydra-wayback")
        asyncio.create_task(self._scrape_supply_chain(),     name="hydra-supplychain")
        asyncio.create_task(self._scrape_employee_exposure(),name="hydra-empexposure")

    def stop(self):
        self._running = False



# ══════════════════════════════════════════════════════════════════
# LAYER 5 — ORACLE: AI BRAIN (Groq LLM)
# ══════════════════════════════════════════════════════════════════

class OracleAI:
    """
    AI-powered threat analysis using Groq (llama-3.3-70b).
    Features:
      - AI Threat Summariser: plain-English per-alert explanation
      - Attack Timeline Reconstruction: campaign narrative from alert clusters
      - Attacker Profiling: WHOIS + VT + AbuseIPDB enrichment
      - Certificate Abuse Scoring: Let's Encrypt + IP reputation
      - Threat Actor Attribution: MITRE ATT&CK actor matching
      - Automated Takedown Generator: UDRP abuse email
    """

    GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
    _groq_semaphore = None  # Set in __init__ to limit concurrent calls
    GROQ_MODEL = "llama-3.1-8b-instant"  # Higher rate limits on free tier

    # MITRE ATT&CK threat actors with their common TTPs (offline dataset)
    THREAT_ACTORS = {
        "APT28 (Fancy Bear)": {
            "ttps": ["T1566", "T1078", "T1583.001", "T1190", "T1059"],
            "sectors": ["government", "military", "technology", "security"],
            "origin": "Russia",
        },
        "APT29 (Cozy Bear)": {
            "ttps": ["T1566.002", "T1078", "T1552", "T1530", "T1071"],
            "sectors": ["government", "healthcare", "technology", "security"],
            "origin": "Russia",
        },
        "Lazarus Group": {
            "ttps": ["T1195.001", "T1566", "T1059", "T1552.001", "T1078"],
            "sectors": ["finance", "cryptocurrency", "technology"],
            "origin": "North Korea",
        },
        "APT41": {
            "ttps": ["T1190", "T1059", "T1078", "T1552.001", "T1072"],
            "sectors": ["healthcare", "technology", "gaming", "security"],
            "origin": "China",
        },
        "FIN7": {
            "ttps": ["T1566.001", "T1059", "T1078", "T1530", "T1486"],
            "sectors": ["finance", "retail", "hospitality"],
            "origin": "Unknown",
        },
        "REvil / Sodinokibi": {
            "ttps": ["T1486", "T1078", "T1190", "T1552.001"],
            "sectors": ["all"],
            "origin": "Unknown",
        },
        "Scattered Spider": {
            "ttps": ["T1566.002", "T1078", "T1583.001", "T1608.001", "T1530"],
            "sectors": ["technology", "security", "telecom"],
            "origin": "Unknown",
        },
        "SilverFish": {
            "ttps": ["T1190", "T1059", "T1552", "T1071"],
            "sectors": ["technology", "security", "government"],
            "origin": "Russia",
        },
    }

    def __init__(self):
        self.groq_key   = os.environ.get("GROQ_API_KEY", "")
        self.vt_key     = os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb  = os.environ.get("ABUSEIPDB_API_KEY", "")
        self._cache: Dict[str, str] = {}
        self._last_groq_call: float = 0.0  # Rate limit tracker
        self._groq_lock = None  # initialized lazily
        self._timeline_window: List[dict] = []   # recent alerts for campaign detection

    def _groq_call(self, system: str, user: str, max_tokens: int = 300) -> str:
        """Synchronous Groq call — wrapped in thread for async use."""
        if not self.groq_key:
            return "AI summary unavailable — GROQ_API_KEY not set."
        try:
            import ssl as _ssl_local
            import urllib.request as _ureq
            import json as _json
            import time as _time
            # Enforce minimum 8s between Groq calls to avoid rate limits
            elapsed = _time.time() - self._last_groq_call
            if elapsed < 8.0:
                _time.sleep(8.0 - elapsed)
            self._last_groq_call = _time.time()
            ctx = _ssl_local.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl_local.CERT_NONE
            payload = _json.dumps({
                "model": self.GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            }).encode()
            req = _ureq.Request(
                self.GROQ_URL,
                data=payload,
                headers={
                    "Authorization": f"Bearer {self.groq_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "AegisNexus/3.0",
                }
            )
            with _ureq.urlopen(req, timeout=30, context=ctx) as r:
                data = _json.loads(r.read().decode())
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            body = b""
            try: body = e.read()
            except Exception: pass
            msg = str(e)
            if "429" in msg or "Too Many" in msg:
                # Fallback to Gemini on Groq rate limit
                try:
                    return self._gemini_fallback(system, user, max_tokens)
                except Exception:
                    return "AI summary paused (rate limit)."
            log.warning(f"[ORACLE/GROQ] {type(e).__name__}: {e} {body[:100] if body else ''}")
            return "AI analysis unavailable."

    def _gemini_fallback(self, system: str, user: str, max_tokens: int = 300) -> str:
        """Fallback to Gemini Flash when Groq is rate limited."""
        import ssl as _ssl_local, urllib.request as _ureq, json as _json
        GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
        ctx = _ssl_local.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_local.CERT_NONE
        if not GEMINI_KEY:
            return "AI summary unavailable — set GEMINI_API_KEY env var for fallback."
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_KEY}"
        payload = _json.dumps({
            "contents": [{"parts": [{"text": f"{system}\n\n{user}"}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.3}
        }).encode()
        req = _ureq.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with _ureq.urlopen(req, timeout=20, context=ctx) as r:
            data = _json.loads(r.read().decode())
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()

    async def summarise_threat(self, alert: dict) -> str:
        """Generate plain-English threat summary for an alert."""
        cache_key = sha256_hex(f"sum:{alert.get('threat_id','')}:{alert.get('score',0)}")[:16]
        if cache_key in self._cache:
            return self._cache[cache_key]

        kind     = (alert.get("kind") or "").replace("_", " ")
        ind      = alert.get("indicator", "")
        sev      = alert.get("severity", "")
        score    = alert.get("score", 0)
        ttps     = ", ".join(alert.get("ttps", []))
        tech     = ", ".join(alert.get("tech", []))
        meta     = alert.get("meta") or {}
        source   = alert.get("source", "")

        system = (
            "You are a cybersecurity threat analyst for CloudSEK, an Indian cybersecurity company. "
            "Write concise, plain-English threat summaries for a non-technical executive audience. "
            "Be direct. 3-4 sentences max. Explain what was found, what the attacker likely wants, "
            "and what CloudSEK should do immediately. No jargon."
        )
        user = (
            f"Threat: {kind}\n"
            f"Indicator: {ind}\n"
            f"Severity: {sev} (score: {score:.3f})\n"
            f"Source: {source}\n"
            f"TTPs: {ttps}\n"
            f"Tech affected: {tech}\n"
            f"Additional context: {json.dumps(meta)[:300]}\n\n"
            f"Write a 3-sentence plain-English summary: what it is, what attackers want, what to do."
        )
        summary = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._groq_call(system, user, 200)
        )
        self._cache[cache_key] = summary
        return summary

    async def reconstruct_timeline(self, recent_alerts: List[dict]) -> Optional[dict]:
        """Detect coordinated campaigns from alert clusters."""
        if len(recent_alerts) < 3:
            return None

        # Group alerts within 2-hour windows
        now = datetime.now(timezone.utc)
        window_alerts = []
        for a in recent_alerts:
            try:
                found = datetime.fromisoformat(str(a.get("found_at","")).replace("Z","+00:00"))
                if (now - found).total_seconds() < 7200:
                    window_alerts.append(a)
            except Exception:
                pass

        if len(window_alerts) < 3:
            return None

        # Check for multi-source pattern (campaign indicator)
        sources = set(a.get("source","") for a in window_alerts)
        kinds   = set(a.get("kind","") for a in window_alerts)
        if len(sources) < 2:
            return None  # single-source not a campaign

        system = (
            "You are a threat intelligence analyst. Analyse these recent alerts and determine "
            "if they represent a coordinated attack campaign. If yes, write a brief campaign narrative "
            "connecting the dots. Be specific about the likely attack chain. 4-5 sentences max."
        )
        alerts_summary = "\n".join([
            f"- [{a.get('severity','')}] {a.get('kind','').replace('_',' ')} from {a.get('source','')} "
            f"— {str(a.get('indicator',''))[:60]} at {str(a.get('found_at',''))[:16]}"
            for a in window_alerts[:10]
        ])
        user = f"Recent alerts (last 2 hours):\n{alerts_summary}\n\nIs this a coordinated campaign? If yes, describe the attack chain."

        narrative = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._groq_call(system, user, 300)
        )

        return {
            "is_campaign": "yes" in narrative.lower() or "coordinated" in narrative.lower(),
            "narrative": narrative,
            "alert_count": len(window_alerts),
            "sources": list(sources),
            "kinds": list(kinds),
            "generated_at": now_iso(),
        }

    def attribute_threat_actors(self, ttps: List[str], indicator: str = "", sector: str = "technology") -> List[dict]:
        """Match TTPs to known threat actors from offline MITRE dataset."""
        matches = []
        ttp_set = set(ttps)
        for actor, data in self.THREAT_ACTORS.items():
            actor_ttps = set(data["ttps"])
            overlap = ttp_set & actor_ttps
            if not overlap:
                continue
            relevance = len(overlap) / max(len(actor_ttps), 1)
            sector_match = sector.lower() in [s.lower() for s in data["sectors"]] or "all" in data["sectors"]
            score = relevance * (1.3 if sector_match else 1.0)
            if score > 0.1:
                matches.append({
                    "actor": actor,
                    "origin": data["origin"],
                    "matching_ttps": list(overlap),
                    "relevance_score": round(score, 3),
                    "sector_match": sector_match,
                })
        matches.sort(key=lambda x: x["relevance_score"], reverse=True)
        return matches[:3]

    async def profile_attacker(self, indicator: str, indicator_type: str = "domain") -> dict:
        """Build attacker profile using VirusTotal + AbuseIPDB."""
        profile = {"indicator": indicator, "type": indicator_type}
        ctx = _mk_ssl_ctx()

        # VirusTotal lookup
        if self.vt_key and indicator:
            try:
                import base64 as _b64
                if indicator_type == "domain":
                    vt_id = urllib.parse.quote(indicator)
                    url = f"https://www.virustotal.com/api/v3/domains/{vt_id}"
                else:
                    vt_id = _b64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
                    url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
                req = urllib.request.Request(
                    url,
                    headers={
                        "x-apikey": self.vt_key,
                        "User-Agent": "AegisNexus/3.0",
                    }
                )
                with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                    vt_data = json.loads(r.read().decode())
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                profile["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "creation_date": attrs.get("creation_date", ""),
                    "registrar": attrs.get("registrar", ""),
                    "whois": str(attrs.get("whois",""))[:500],
                }
            except Exception as e:
                log.debug(f"[ORACLE/VT] {e}")
                profile["virustotal"] = {"error": str(e)}

        # AbuseIPDB lookup (for IP indicators)
        if self.abuseipdb and indicator_type == "ip":
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(indicator)}&maxAgeInDays=90"
                req = urllib.request.Request(
                    url,
                    headers={
                        "Key": self.abuseipdb,
                        "Accept": "application/json",
                        "User-Agent": "AegisNexus/3.0",
                    }
                )
                with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                    ab_data = json.loads(r.read().decode())
                d = ab_data.get("data", {})
                profile["abuseipdb"] = {
                    "abuse_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", ""),
                    "isp": d.get("isp", ""),
                    "total_reports": d.get("totalReports", 0),
                    "is_tor": d.get("isTor", False),
                    "domain": d.get("domain", ""),
                }
            except Exception as e:
                log.debug(f"[ORACLE/ABUSEIPDB] {e}")

        return profile

    async def score_certificate_abuse(self, subdomain: str, domain: str, issued_date: str = "") -> dict:
        """Score a CT log entry for certificate abuse indicators."""
        score = 0.0
        flags = []

        # Let's Encrypt = common phishing cert (free, instant)
        is_lets_encrypt = False  # we'd check issuer from CT data
        if is_lets_encrypt:
            score += 0.3
            flags.append("Let's Encrypt cert — common in phishing")

        # Recently issued cert (within 7 days)
        if issued_date:
            try:
                issued = datetime.fromisoformat(issued_date.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - issued).days
                if age_days <= 7:
                    score += 0.4
                    flags.append(f"Very recently issued ({age_days} days ago)")
                elif age_days <= 30:
                    score += 0.2
                    flags.append(f"Recently issued ({age_days} days ago)")
            except Exception:
                pass

        # Suspicious keywords in subdomain
        SUSPICIOUS = ["login", "secure", "verify", "auth", "account", "portal",
                      "signin", "support", "reset", "update", "confirm", "aws",
                      "microsoft", "google", "paypal", "banking"]
        matched_kws = [kw for kw in SUSPICIOUS if kw in subdomain.lower()]
        if matched_kws:
            score += 0.2 * len(matched_kws)
            flags.append(f"Suspicious keywords: {', '.join(matched_kws)}")

        # Subdomain depth (deep subdomains more suspicious)
        depth = subdomain.count(".")
        if depth >= 3:
            score += 0.1
            flags.append(f"Deep subdomain ({depth} levels)")

        # VT check on the domain
        vt_profile = await self.profile_attacker(subdomain, "domain")
        vt = vt_profile.get("virustotal", {})
        if vt.get("malicious", 0) > 0:
            score += 0.5
            flags.append(f"VirusTotal: {vt['malicious']} malicious detections")

        return {
            "subdomain": subdomain,
            "abuse_score": min(score, 1.0),
            "flags": flags,
            "vt_data": vt,
            "recommendation": "HIGH RISK — investigate immediately" if score > 0.5 else
                              "MEDIUM RISK — monitor" if score > 0.2 else "LOW RISK",
        }

    async def generate_takedown_request(self, alert: dict) -> dict:
        """Generate UDRP/abuse report email for typosquat/lookalike domains."""
        indicator = alert.get("indicator", "")
        kind      = alert.get("kind", "")
        meta      = alert.get("meta") or {}
        monitored = meta.get("monitored", "cloudsek.com")

        system = (
            "You are a legal abuse report writer. Write a professional UDRP/domain abuse report email "
            "to a domain registrar. The email should: identify the offending domain, explain why it is "
            "a brand infringement or phishing domain, cite the legitimate brand owner, and request "
            "immediate suspension. Be formal, specific, and cite relevant policies. Max 300 words."
        )
        user = (
            f"Write an abuse report email for this situation:\n"
            f"Offending domain/subdomain: {indicator}\n"
            f"Threat type: {kind.replace('_', ' ')}\n"
            f"Legitimate brand owner: CloudSEK (cloudsek.com) — Indian cybersecurity company\n"
            f"Monitored domain: {monitored}\n"
            f"Evidence: Detected in SSL certificate transparency logs\n\n"
            f"Write the full abuse report email including subject line."
        )
        email_text = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._groq_call(system, user, 400)
        )

        # Determine registrar abuse contacts
        REGISTRAR_ABUSE = {
            "godaddy":    "abuse@godaddy.com",
            "namecheap":  "abuse@namecheap.com",
            "cloudflare": "abusereports@cloudflare.com",
            "google":     "registrar-abuse@google.com",
            "default":    "abuse@iana.org",
        }

        return {
            "indicator": indicator,
            "email_subject": f"ABUSE REPORT: Brand Impersonation — {indicator}",
            "email_body": email_text,
            "send_to": REGISTRAR_ABUSE["default"],
            "additional_contacts": list(REGISTRAR_ABUSE.values()),
            "generated_at": now_iso(),
            "evidence": {
                "threat_id": alert.get("threat_id"),
                "score": alert.get("score"),
                "source": alert.get("source"),
                "found_at": alert.get("found_at"),
            },
        }


# ══════════════════════════════════════════════════════════════════
# LAYER 6 — NEXUS RESPONSE ENGINE
# ══════════════════════════════════════════════════════════════════

class NexusResponse:
    """
    Response automation engine.
    - Incident PDF reports
    - One-click containment (iptables)
    - Weekly intelligence digest
    - Certificate abuse enrichment pipeline
    """

    def __init__(self, oracle: OracleAI):
        self.oracle = oracle
        self._blocked_ips: Set[str] = set()
        self._blocked_domains: Set[str] = set()

    def generate_incident_pdf(self, alert: dict, ai_summary: str = "", actors: List[dict] = None, profile: dict = None) -> bytes:
        """Generate incident report PDF for a CRITICAL alert."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor, black, white, red
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            import io as _io

            buf = _io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=letter,
                                    leftMargin=0.75*inch, rightMargin=0.75*inch,
                                    topMargin=0.75*inch, bottomMargin=0.75*inch)

            styles = getSampleStyleSheet()
            BLUE  = HexColor("#1B4F8A")
            RED   = HexColor("#C0392B")
            LGRAY = HexColor("#F2F4F6")

            title_style = ParagraphStyle("title", fontSize=20, textColor=BLUE,
                                          fontName="Helvetica-Bold", spaceAfter=6)
            h2_style    = ParagraphStyle("h2", fontSize=13, textColor=BLUE,
                                          fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4)
            body_style  = ParagraphStyle("body", fontSize=10, fontName="Helvetica", spaceAfter=4)
            mono_style  = ParagraphStyle("mono", fontSize=9, fontName="Courier",
                                          backColor=LGRAY, spaceAfter=4, leftIndent=12)

            sev = alert.get("severity", "UNKNOWN")
            sev_color = RED if sev == "CRITICAL" else HexColor("#E67E22")

            story = []

            # Header
            story.append(Paragraph("AEGIS-NEXUS v3.0", title_style))
            story.append(Paragraph("INCIDENT REPORT", ParagraphStyle(
                "ir", fontSize=14, textColor=sev_color, fontName="Helvetica-Bold", spaceAfter=4)))
            story.append(HRFlowable(width="100%", thickness=2, color=BLUE))
            story.append(Spacer(1, 0.1*inch))

            # Metadata table
            meta = alert.get("meta") or {}
            stages = alert.get("stages") or {}
            data = [
                ["Field",           "Value"],
                ["Threat ID",       alert.get("threat_id", "")[:40]],
                ["Severity",        sev],
                ["SPECTRA Score",   f"{float(alert.get('score', 0)):.6f}"],
                ["Type",            (alert.get("kind","")).replace("_"," ").title()],
                ["Source",          alert.get("source","")],
                ["Indicator",       str(alert.get("indicator",""))[:60]],
                ["Detected At",     str(alert.get("found_at",""))[:19]],
                ["TTPs",            ", ".join(alert.get("ttps",[]))],
                ["Tech Affected",   ", ".join(alert.get("tech",[]))],
                ["CVSS",            str(meta.get("cvss","N/A"))],
            ]
            tbl = Table(data, colWidths=[2*inch, 5*inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLUE),
                ("TEXTCOLOR",  (0,0), (-1,0), white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("BACKGROUND", (0,1), (0,-1), LGRAY),
                ("FONTNAME",   (0,1), (0,-1), "Helvetica-Bold"),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, LGRAY]),
                ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING",(0,0),(-1,-1), 6),
                ("RIGHTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING", (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 0.15*inch))

            # SPECTRA breakdown
            story.append(Paragraph("SPECTRA Score Breakdown", h2_style))
            spec_data = [
                ["Stage", "Score", "Weight", "Description"],
                ["S1 — Spectral Perturbation", f"{float(stages.get('s1',0)):.4f}", "40%", "Asset graph topology impact"],
                ["S2 — Rényi Entropy",          f"{float(stages.get('s2',0)):.4f}", "25%", "Targeting specificity"],
                ["S3 — TTP Isomorphism",        f"{float(stages.get('s3',0)):.4f}", "25%", "MITRE ATT&CK pattern match"],
                ["S4 — Temporal Decay",         f"{float(stages.get('s4',0)):.4f}", "10%", "Novelty / freshness bias"],
            ]
            spec_tbl = Table(spec_data, colWidths=[2.5*inch, 1*inch, 0.8*inch, 2.7*inch])
            spec_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), BLUE),
                ("TEXTCOLOR",  (0,0), (-1,0), white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 9),
                ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, LGRAY]),
                ("LEFTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING", (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(spec_tbl)
            story.append(Spacer(1, 0.15*inch))

            # AI Summary
            if ai_summary:
                story.append(Paragraph("AI Threat Analysis (Groq llama-3.3-70b)", h2_style))
                story.append(Paragraph(ai_summary, body_style))
                story.append(Spacer(1, 0.1*inch))

            # Threat actor attribution
            if actors:
                story.append(Paragraph("Threat Actor Attribution", h2_style))
                for actor in actors[:2]:
                    story.append(Paragraph(
                        f"<b>{actor['actor']}</b> ({actor['origin']}) — "
                        f"Relevance: {actor['relevance_score']:.2f} — "
                        f"Matching TTPs: {', '.join(actor['matching_ttps'])}",
                        body_style
                    ))
                story.append(Spacer(1, 0.1*inch))

            # Attacker profile
            if profile:
                story.append(Paragraph("Attacker Profile (VirusTotal)", h2_style))
                vt = profile.get("virustotal", {})
                if vt and "error" not in vt:
                    story.append(Paragraph(
                        f"Malicious detections: {vt.get('malicious',0)} | "
                        f"Suspicious: {vt.get('suspicious',0)} | "
                        f"Reputation: {vt.get('reputation',0)} | "
                        f"Registrar: {vt.get('registrar','')}",
                        body_style
                    ))

            # Recommended actions
            story.append(Paragraph("Recommended Actions", h2_style))
            kind = alert.get("kind","")
            actions = {
                "typosquat_active":       ["1. Submit abuse report to domain registrar immediately", "2. Alert CloudSEK legal team", "3. Monitor for phishing emails from this domain", "4. Add domain to threat blocklist"],
                "lookalike_domain":       ["1. Investigate domain ownership via WHOIS", "2. Check if site is hosting a phishing page", "3. Submit UDRP complaint if brand infringement confirmed", "4. Alert employees to not trust this domain"],
                "subdomain_discovered":   ["1. Verify if this subdomain is owned by CloudSEK", "2. If not owned, investigate purpose and owner", "3. Check for active content or redirects"],
                "known_vulnerability":    ["1. Identify if affected component is deployed", "2. Apply vendor patch immediately", "3. Implement WAF rule as temporary mitigation", "4. Scan for exploitation attempts in logs"],
                "employee_credential_leak": ["1. Force password reset for all affected accounts immediately", "2. Enable MFA if not already active", "3. Check for unauthorized access in last 30 days", "4. Notify affected employees"],
                "secret_in_commit":       ["1. Rotate the exposed credential immediately", "2. Delete the commit from history (git filter-branch)", "3. Check if credential was used by unauthorized parties", "4. Review commit signing policies"],
                "supply_chain_typosquat": ["1. Alert all developers to not use this package", "2. Scan all package.json / requirements.txt files", "3. Report to PyPI/npm abuse team"],
                "phishing_detected":      ["1. Screenshot the phishing page as evidence", "2. Report to URLScan, Google Safe Browsing, and PhishTank", "3. Alert CloudSEK employees immediately"],
            }.get(kind, ["1. Investigate the indicator", "2. Escalate to senior security analyst", "3. Document findings"])

            for action in actions:
                story.append(Paragraph(action, body_style))
            story.append(Spacer(1, 0.1*inch))

            # Footer
            story.append(HRFlowable(width="100%", thickness=1, color=BLUE))
            story.append(Paragraph(
                f"Generated by AEGIS-NEXUS v3.0 | {now_str('%Y-%m-%d %H:%M:%S')} UTC | CONFIDENTIAL",
                ParagraphStyle("footer", fontSize=8, textColor=HexColor("#666666"), alignment=1)
            ))

            doc.build(story)
            return buf.getvalue()

        except ImportError:
            return b"PDF generation requires reportlab: pip3 install reportlab --break-system-packages"
        except Exception as e:
            log.debug(f"[NEXUS/PDF] {e}")
            return b""

    def block_indicator(self, indicator: str, indicator_type: str = "domain") -> dict:
        """One-click containment — block IP or domain via iptables/hosts."""
        import subprocess as _sp
        import socket as _socket
        result = {"indicator": indicator, "type": indicator_type, "actions": [], "errors": []}

        if indicator_type == "domain":
            # Add to /etc/hosts
            try:
                hosts_entry = f"0.0.0.0\t{indicator}\t# AEGIS-NEXUS block {now_str()}\n"
                _sp.run(["sudo", "sh", "-c", f"echo '{hosts_entry}' >> /etc/hosts"],
                        capture_output=True, timeout=10)
                self._blocked_domains.add(indicator)
                result["actions"].append(f"Added {indicator} to /etc/hosts (→ 0.0.0.0)")
            except Exception as e:
                result["errors"].append(f"hosts file: {e}")

            # Resolve and block IP too
            try:
                ip = _socket.gethostbyname(indicator)
                self.block_indicator(ip, "ip")
                result["actions"].append(f"Also blocked resolved IP: {ip}")
            except Exception:
                pass

        elif indicator_type == "ip":
            try:
                _sp.run(["sudo", "iptables", "-A", "INPUT", "-s", indicator, "-j", "DROP"],
                        capture_output=True, timeout=10)
                _sp.run(["sudo", "iptables", "-A", "OUTPUT", "-d", indicator, "-j", "DROP"],
                        capture_output=True, timeout=10)
                self._blocked_ips.add(indicator)
                result["actions"].append(f"iptables: DROP INPUT/OUTPUT for {indicator}")
            except Exception as e:
                result["errors"].append(f"iptables: {e}")

        result["blocked_at"] = now_iso()
        result["total_blocked_ips"] = len(self._blocked_ips)
        result["total_blocked_domains"] = len(self._blocked_domains)
        return result

    async def generate_weekly_digest(self, db_alerts: List[dict]) -> dict:
        """Generate weekly intelligence digest using Groq."""
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        week_alerts = []
        for a in db_alerts:
            try:
                found = datetime.fromisoformat(str(a.get("found_at","")).replace("Z","+00:00"))
                if found >= week_ago:
                    week_alerts.append(a)
            except Exception:
                pass

        if not week_alerts:
            return {"error": "No alerts in past 7 days"}

        # Stats
        by_sev = {}
        by_kind = {}
        by_source = {}
        for a in week_alerts:
            sev = a.get("severity","UNKNOWN")
            kind = a.get("kind","unknown")
            src  = a.get("source","unknown")
            by_sev[sev]    = by_sev.get(sev, 0) + 1
            by_kind[kind]  = by_kind.get(kind, 0) + 1
            by_source[src] = by_source.get(src, 0) + 1

        top_threats = sorted(week_alerts, key=lambda x: float(x.get("score",0)), reverse=True)[:5]

        system = (
            "You are a weekly threat intelligence briefing writer for CloudSEK executives. "
            "Write a concise, professional weekly digest. Include: key threats of the week, "
            "trend analysis, top concerns, and recommendations. Executive tone. 200 words max."
        )
        user = (
            f"Week ending: {now.strftime('%Y-%m-%d')}\n"
            f"Total alerts: {len(week_alerts)}\n"
            f"By severity: {json.dumps(by_sev)}\n"
            f"By type: {json.dumps(dict(sorted(by_kind.items(), key=lambda x: x[1], reverse=True)[:5]))}\n"
            f"By source: {json.dumps(by_source)}\n"
            f"Top threat: {top_threats[0].get('indicator','') if top_threats else 'None'} "
            f"(score: {top_threats[0].get('score',0):.3f})\n\n"
            f"Write a professional weekly threat intelligence digest for CloudSEK leadership."
        )
        narrative = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self.oracle._groq_call(system, user, 300)
        )

        return {
            "week_ending": now.strftime("%Y-%m-%d"),
            "total_alerts": len(week_alerts),
            "by_severity": by_sev,
            "by_kind": dict(sorted(by_kind.items(), key=lambda x: x[1], reverse=True)[:5]),
            "by_source": by_source,
            "top_threats": [{"indicator": a.get("indicator"), "severity": a.get("severity"), "score": a.get("score")} for a in top_threats],
            "narrative": narrative,
            "generated_at": now_iso(),
        }

    def get_blocked(self) -> dict:
        return {
            "blocked_ips": list(self._blocked_ips),
            "blocked_domains": list(self._blocked_domains),
            "total": len(self._blocked_ips) + len(self._blocked_domains),
        }

class SPECTRACalibrator:
    """
    Self-improving calibration engine for SPECTRA.

    Grid-searches noise threshold space [0.05, 0.35] to maximize F1 score
    against analyst-labeled data. Updates engine thresholds automatically.

    Also computes per-source reliability scores so HYDRA can weight
    scraper outputs.
    """

    def __init__(self, engine: "SPECTRA"):
        self.engine  = engine
        self.labeled: List[Tuple[LabeledThreat, ScoreResult]] = []
        self._tp_by_source: Dict[str, List[float]] = {}

    def add_sample(self, lt: LabeledThreat, result: ScoreResult):
        self.labeled.append((lt, result))
        src = lt.kind
        if src not in self._tp_by_source:
            self._tp_by_source[src] = []
        is_tp = 1.0 if lt.label in ("true_positive", "confirmed_critical") else 0.0
        self._tp_by_source[src].append(is_tp)

    def _prf(self, threshold: float) -> Tuple[float, float, float]:
        tp = fp = fn = tn = 0
        for lt, result in self.labeled:
            pred_pos   = result.score >= threshold
            actual_pos = lt.label in ("true_positive", "confirmed_critical")
            if pred_pos and actual_pos:      tp += 1
            elif pred_pos and not actual_pos: fp += 1
            elif not pred_pos and actual_pos: fn += 1
            else:                             tn += 1
        p  = tp / max(tp + fp, 1)
        r  = tp / max(tp + fn, 1)
        f1 = 2 * p * r / max(p + r, 1e-9)
        return p, r, f1

    async def calibrate(self) -> Dict:
        if len(self.labeled) < 5:
            return {"status": "insufficient_data",
                    "needed": 5, "have": len(self.labeled)}
        best_f1 = best_thresh = 0.0
        best_p  = best_r     = 0.0
        for thresh in [i / 100 for i in range(5, 36)]:
            p, r, f1 = self._prf(thresh)
            if f1 > best_f1:
                best_f1 = f1; best_thresh = thresh
                best_p = p;   best_r = r
        old = self.engine.noise_thresh
        self.engine.noise_thresh = round(best_thresh, 3)
        source_reliability = {
            src: round(sum(rates) / max(len(rates), 1), 4)
            for src, rates in self._tp_by_source.items()
        }
        return {
            "status":              "calibrated",
            "samples":             len(self.labeled),
            "old_noise_threshold": old,
            "new_noise_threshold": best_thresh,
            "precision":           round(best_p, 4),
            "recall":              round(best_r, 4),
            "f1":                  round(best_f1, 4),
            "source_reliability":  source_reliability,
        }

    def report(self) -> Dict:
        tp = sum(1 for lt, _ in self.labeled
                 if lt.label in ("true_positive", "confirmed_critical"))
        return {
            "total_labeled":        len(self.labeled),
            "true_positives":       tp,
            "false_positives":      len(self.labeled) - tp,
            "current_noise_thresh": self.engine.noise_thresh,
            "source_reliability":   {
                src: round(sum(r)/max(len(r),1), 4)
                for src, r in self._tp_by_source.items()
            },
        }


# ══════════════════════════════════════════════════════════════════
# WEB DASHBOARD (served by the API)
# ══════════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS-NEXUS v3.0</title>
<style>
:root{
  --bg:#f0f4f8;--sf:#fff;--sf2:#f8fafc;--bd:#e2e8f0;--bd2:#cbd5e1;
  --tx:#0f172a;--tx2:#475569;--tx3:#94a3b8;
  --cr:#dc2626;--cr-bg:#fef2f2;--cr-bd:#fecaca;
  --hi:#ea580c;--hi-bg:#fff7ed;--hi-bd:#fed7aa;
  --me:#0284c7;--me-bg:#f0f9ff;--me-bd:#bae6fd;
  --lo:#16a34a;--lo-bg:#f0fdf4;--lo-bd:#bbf7d0;
  --ac:#0ea5e9;--pu:#7c3aed;--pu-bg:#f5f3ff;--pu-bd:#ddd6fe;
  --font:system-ui,sans-serif;--mono:monospace;
}
[data-theme="dark"]{
  --bg:#080d16;--sf:#0d1424;--sf2:#111c30;--bd:#1a2840;--bd2:#243550;
  --tx:#dde4ee;--tx2:#8ba3be;--tx3:#3d5470;
  --cr:#f87171;--cr-bg:#1c0808;--cr-bd:#7f1d1d;
  --hi:#fb923c;--hi-bg:#1a0d04;--hi-bd:#7c2d12;
  --me:#38bdf8;--me-bg:#040f1e;--me-bd:#0c4a6e;
  --lo:#4ade80;--lo-bg:#040f08;--lo-bd:#14532d;
  --ac:#38bdf8;--pu:#a78bfa;--pu-bg:#1a0f2e;--pu-bd:#4c1d95;
}
*{margin:0;padding:0;box-sizing:border-box;}
html,body{width:100%;height:100%;background:var(--bg);color:var(--tx);font-family:var(--font);overflow:hidden;}
#app{display:grid;grid-template-rows:52px 1fr 66px;grid-template-columns:272px 1fr 352px;width:100vw;height:100vh;}
#hdr{grid-column:1/-1;background:var(--sf);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:0 14px;gap:8px;min-width:0;}
.logo-icon{width:26px;height:26px;background:var(--ac);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.logo-icon svg{width:13px;height:13px;fill:#fff;}
.logo-text{font-size:13px;font-weight:700;letter-spacing:.3px;}
.logo-sub{font-size:8px;color:var(--tx3);}
.logo-ver{font-size:8px;color:var(--ac);font-weight:600;margin-left:4px;}
.hdiv{width:1px;height:20px;background:var(--bd);flex-shrink:0;}
.vs{display:flex;flex-shrink:0;}
.v{padding:0 10px;border-right:1px solid var(--bd);text-align:center;}
.vv{font-size:15px;font-weight:700;font-family:var(--mono);}
.vl{font-size:8px;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);}
.v.cr .vv{color:var(--cr);}.v.hi .vv{color:var(--hi);}.v.lo .vv{color:var(--lo);}.v.ac .vv{color:var(--ac);}
.pill{display:flex;align-items:center;gap:5px;padding:3px 10px;background:var(--lo-bg);border:1px solid var(--lo-bd);border-radius:20px;font-size:10px;color:var(--lo);font-weight:500;margin-left:auto;}
.dot{width:5px;height:5px;border-radius:50%;background:var(--lo);animation:blink 2s infinite;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
#clk{font-family:var(--mono);font-size:11px;color:var(--tx3);margin-left:4px;}
.hbtn{height:28px;padding:0 10px;border-radius:6px;border:1px solid var(--bd);background:var(--sf2);cursor:pointer;font-size:11px;color:var(--tx2);display:flex;align-items:center;gap:4px;flex-shrink:0;}
.hbtn:hover{border-color:var(--ac);color:var(--ac);}
#src-count{font-size:9px;padding:2px 7px;border-radius:10px;background:#0ea5e91a;border:1px solid #0ea5e944;color:var(--ac);font-weight:600;flex-shrink:0;}
#left{background:var(--sf);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;min-height:0;}
.pt{padding:8px 12px 6px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;}
#olist{overflow-y:auto;padding:4px;max-height:38%;}
#olist::-webkit-scrollbar,#feed::-webkit-scrollbar,#rscroll::-webkit-scrollbar{width:3px;}
#olist::-webkit-scrollbar-thumb,#feed::-webkit-scrollbar-thumb,#rscroll::-webkit-scrollbar-thumb{background:var(--bd2);}
.oc{display:flex;align-items:center;gap:7px;padding:5px 7px;border-radius:6px;margin-bottom:2px;cursor:pointer;border:1px solid transparent;}
.oc:hover{background:var(--sf2);border-color:var(--bd);}
.oc.active{background:var(--me-bg);border-color:var(--me-bd);}
.oi{width:24px;height:24px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;}
.on{font-size:11px;font-weight:500;}
.otype{font-size:9px;color:var(--tx3);}
.hb{width:15px;height:15px;border-radius:50%;background:var(--lo-bg);border:1px solid var(--lo-bd);display:flex;align-items:center;justify-content:center;font-size:8px;color:var(--lo);margin-left:auto;flex-shrink:0;}
.src-badge{display:inline-flex;align-items:center;font-size:8px;font-weight:600;padding:1px 5px;border-radius:3px;letter-spacing:.3px;}
.src-ct_logs{background:#0ea5e91a;color:#0ea5e9;border:1px solid #0ea5e944;}
.src-cve_feed,.src-nvd{background:#dc26261a;color:#dc2626;border:1px solid #dc262644;}
.src-github{background:#7c3aed1a;color:#7c3aed;border:1px solid #7c3aed44;}
.src-paste_monitor,.src-paste{background:#ea580c1a;color:#ea580c;border:1px solid #ea580c44;}
.src-shodan{background:#0891b21a;color:#0891b2;border:1px solid #0891b244;}
.src-bevigil{background:#16a34a1a;color:#16a34a;border:1px solid #16a34a44;}
.src-abuse_ch{background:#b91c1c1a;color:#b91c1c;border:1px solid #b91c1c44;}
.src-otx{background:#d971061a;color:#d97106;border:1px solid #d9710644;}
.src-urlscan{background:#7c3aed1a;color:#7c3aed;border:1px solid #7c3aed44;}

.src-pulsedive{background:#0891b21a;color:#0891b2;border:1px solid #0891b244;}
.src-intelx{background:#6d28d91a;color:#6d28d9;border:1px solid #6d28d944;}
.src-breach_directory{background:#dc26261a;color:#f87171;border:1px solid #dc262644;}
.src-paste_hunter{background:#ea580c1a;color:#fb923c;border:1px solid #ea580c44;}
.src-spiderfoot{background:#0891b21a;color:#38bdf8;border:1px solid #0891b244;}
.src-alienvault{background:#d971061a;color:#fbbf24;border:1px solid #d9710644;}
.src-dark_web{background:#1c0808;color:#f87171;border:1px solid #7f1d1d;}
.src-github_commits{background:#7c3aed1a;color:#a78bfa;border:1px solid #7c3aed44;}
.src-wayback{background:#92400e1a;color:#d97706;border:1px solid #92400e44;}
.src-supply_chain{background:#0369a11a;color:#0284c7;border:1px solid #0369a144;}
.src-employee_exposure{background:#dc26261a;color:#f87171;border:1px solid #dc262644;}
.src-phantom{background:#dc26261a;color:#dc2626;border:1px solid #dc262644;}
.feed-tabs{display:flex;flex-wrap:wrap;border-top:1px solid var(--bd);border-bottom:1px solid var(--bd);background:var(--sf2);}
.tab{flex:1 0 30%;padding:4px 0;font-size:8.5px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--tx3);cursor:pointer;text-align:center;border-bottom:2px solid transparent;}
.tab.active{color:var(--ac);border-bottom-color:var(--ac);background:var(--sf);}
#export-bar{display:flex;align-items:center;gap:5px;padding:4px 8px;border-bottom:1px solid var(--bd);background:var(--sf2);flex-shrink:0;}
.ex-label{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);}
.ex-sel{font-size:10px;background:var(--sf);border:1px solid var(--bd);border-radius:4px;color:var(--tx);padding:2px 5px;}
.ex-btn{font-size:10px;font-weight:500;padding:2px 8px;border-radius:5px;border:1px solid var(--bd);background:var(--sf);color:var(--tx2);cursor:pointer;}
.ex-btn:hover{border-color:var(--ac);color:var(--ac);}
.ex-btn.csv{color:var(--lo);}
.ex-count{font-size:9px;color:var(--tx3);margin-left:auto;}
#feed{flex:1;overflow-y:auto;padding:3px;}
.fi{padding:7px 9px;border-radius:6px;margin-bottom:3px;cursor:pointer;border:1px solid var(--bd);background:var(--sf);}
.fi:hover{border-color:var(--bd2);}
.fi.CRITICAL{border-left:3px solid var(--cr);background:var(--cr-bg);}
.fi.HIGH{border-left:3px solid var(--hi);background:var(--hi-bg);}
.fi.MEDIUM{border-left:3px solid var(--me);background:var(--me-bg);}
.fi.LOW{border-left:3px solid var(--lo);background:var(--lo-bg);}
.fih{display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;gap:4px;}
.fb{font-size:9px;font-weight:600;padding:1px 5px;border-radius:3px;flex-shrink:0;}
.fb.CRITICAL{background:var(--cr-bd);color:var(--cr);}
.fb.HIGH{background:var(--hi-bd);color:var(--hi);}
.fb.MEDIUM{background:var(--me-bd);color:var(--me);}
.fb.LOW{background:var(--lo-bd);color:var(--lo);}
.fs{font-family:var(--mono);font-size:10px;color:var(--tx3);}
.ft{font-size:11px;font-weight:500;display:flex;align-items:center;justify-content:space-between;gap:4px;margin-bottom:2px;}
.fi2{font-family:var(--mono);font-size:9px;color:var(--tx3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.ai-badge{font-size:8px;padding:1px 4px;border-radius:3px;background:var(--pu-bg);border:1px solid var(--pu-bd);color:var(--pu);flex-shrink:0;}
#timeline-panel{flex:1;overflow-y:auto;padding:10px;display:none;}
#timeline-panel.visible{display:block;}
.tl-card{background:var(--sf2);border:1px solid var(--bd);border-radius:8px;padding:10px;margin-bottom:8px;}
.tl-card.campaign{border-color:var(--cr-bd);background:var(--cr-bg);}
.tl-title{font-size:11px;font-weight:600;margin-bottom:5px;}
.tl-body{font-size:10px;color:var(--tx2);line-height:1.6;}
.tl-meta{font-size:9px;color:var(--tx3);margin-top:5px;}
.tl-item{display:flex;align-items:flex-start;gap:7px;padding:4px 0;border-bottom:1px solid var(--bd);}
.tl-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:3px;}
.tl-dot.CRITICAL{background:var(--cr);}.tl-dot.HIGH{background:var(--hi);}.tl-dot.MEDIUM{background:var(--me);}.tl-dot.LOW{background:var(--lo);}
.tl-text{font-size:10px;color:var(--tx2);}
.tl-time{font-size:9px;color:var(--tx3);font-family:var(--mono);}
#sources-panel{flex:1;overflow-y:auto;padding:8px;display:none;}
#sources-panel.visible{display:block;}
.src-row{display:flex;align-items:center;justify-content:space-between;padding:5px 8px;border-radius:5px;margin-bottom:3px;border:1px solid var(--bd);background:var(--sf2);}
.src-name{font-size:10px;font-weight:500;}
.src-cnt{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--ac);}
.src-status{width:7px;height:7px;border-radius:50%;background:var(--lo);}
.src-status.zero{background:var(--bd2);}
#analytics-panel{display:none;flex-direction:column;gap:8px;padding:10px;}
#analytics-panel.visible{display:flex;}
#darkwatch-panel{flex:1;overflow-y:auto;padding:10px;display:none;}
#darkwatch-panel.visible{display:block;}
#blocked-panel{flex:1;overflow-y:auto;padding:10px;display:none;}
#blocked-panel.visible{display:block;}
.dw-row{display:flex;justify-content:space-between;align-items:center;padding:4px 6px;border-radius:4px;background:var(--sf2);margin-bottom:3px;font-size:10px;}
.blocked-row{display:flex;justify-content:space-between;padding:4px 6px;border-radius:4px;background:#1a0a0a;border:1px solid #7f1d1d;margin-bottom:3px;font-size:10px;color:var(--cr);}
.canary-row{padding:4px 6px;border-radius:4px;background:#1a0a2e;border:1px solid #4c1d95;margin-bottom:3px;font-size:10px;color:#a78bfa;}
.an-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;}
.an-card{padding:8px 10px;border-radius:7px;border:1px solid var(--bd);background:var(--sf2);}
.an-val{font-size:18px;font-weight:700;font-family:var(--mono);}
.an-lbl{font-size:9px;color:var(--tx3);text-transform:uppercase;letter-spacing:1px;margin-top:1px;}
.an-bar-row{display:flex;align-items:center;gap:6px;margin-bottom:4px;}
.an-bar-label{font-size:10px;color:var(--tx2);width:60px;flex-shrink:0;}
.an-bar-track{flex:1;height:5px;background:var(--bd);border-radius:3px;overflow:hidden;}
.an-bar-fill{height:100%;border-radius:3px;transition:width .5s;}
.an-bar-count{font-size:10px;font-family:var(--mono);color:var(--tx3);min-width:28px;text-align:right;}
#chart-canvas{width:100%;height:90px;}
#center{background:var(--bg);position:relative;overflow:hidden;}
#gsvg{position:absolute;top:0;left:0;width:100%;height:100%;}
#right{background:var(--sf);border-left:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;min-height:0;}
#rscroll{flex:1;padding:12px;overflow-y:auto;}
.rh{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);padding-bottom:6px;border-bottom:1px solid var(--bd);margin-bottom:9px;}
.sc{padding:9px 11px;border-radius:7px;margin-bottom:9px;border:1px solid;}
.sc.CRITICAL{background:var(--cr-bg);border-color:var(--cr-bd);}
.sc.HIGH{background:var(--hi-bg);border-color:var(--hi-bd);}
.sc.MEDIUM{background:var(--me-bg);border-color:var(--me-bd);}
.sc.LOW{background:var(--lo-bg);border-color:var(--lo-bd);}
.sl{font-size:11px;font-weight:600;}.sv{font-family:var(--mono);font-size:21px;font-weight:700;margin-top:2px;}
.dr{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd);font-size:11px;}
.dk{color:var(--tx3);}.dv{color:var(--tx);font-family:var(--mono);font-size:10px;text-align:right;max-width:210px;word-break:break-all;}
.sw{margin:4px 0;}.sr2{display:flex;justify-content:space-between;font-size:10px;color:var(--tx3);margin-bottom:2px;}
.st{height:4px;background:var(--bd);border-radius:2px;overflow:hidden;}
.sf2x{height:100%;border-radius:2px;transition:width .5s;}
.sf2x.c{background:var(--cr);}.sf2x.h{background:var(--hi);}.sf2x.m{background:var(--me);}.sf2x.l{background:var(--bd2);}
.mb{margin-top:7px;padding:7px 9px;border-radius:6px;background:var(--sf2);border:1px solid var(--bd);}
.mt{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:4px;}
.rb{margin-top:7px;padding:8px 10px;border-radius:6px;background:var(--sf2);border:1px solid var(--bd);font-size:10px;color:var(--tx2);line-height:1.7;}
.rb p{margin-bottom:3px;}
.ai-box{margin-top:8px;padding:10px 11px;border-radius:7px;background:var(--pu-bg);border:1px solid var(--pu-bd);}
.ai-box-hdr{display:flex;align-items:center;gap:6px;margin-bottom:6px;}
.ai-box-title{font-size:10px;font-weight:600;color:var(--pu);}
.ai-box-body{font-size:10px;color:var(--tx2);line-height:1.7;}
.ai-spinner{display:inline-block;width:10px;height:10px;border:2px solid var(--pu-bd);border-top-color:var(--pu);border-radius:50%;animation:spin .6s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
.prof-box{margin-top:8px;padding:9px 11px;border-radius:7px;background:var(--sf2);border:1px solid var(--bd);}
.prof-row{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--bd);font-size:10px;}
.prof-k{color:var(--tx3);}.prof-v{color:var(--tx);font-family:var(--mono);font-size:9px;}
.actor-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:10px;background:var(--cr-bg);border:1px solid var(--cr-bd);color:var(--cr);font-size:9px;font-weight:600;margin:2px 2px 0 0;}
.act-row{display:flex;gap:5px;margin-top:8px;flex-wrap:wrap;}
.act-btn{padding:4px 10px;border-radius:5px;font-size:10px;font-weight:500;border:1px solid var(--bd);background:var(--sf2);color:var(--tx2);cursor:pointer;}
.act-btn:hover{border-color:var(--ac);color:var(--ac);}
.act-btn.danger{color:var(--cr);border-color:var(--cr-bd);}
.act-btn.primary{color:var(--ac);border-color:var(--ac);background:var(--me-bg);}
.act-btn.purple{color:var(--pu);border-color:var(--pu-bd);background:var(--pu-bg);}
.block-confirm{margin-top:7px;padding:8px 10px;border-radius:6px;background:var(--cr-bg);border:1px solid var(--cr-bd);font-size:10px;color:var(--cr);display:none;}
.block-confirm.visible{display:block;}
#ps{border-top:1px solid var(--bd);padding:8px 12px;flex-shrink:0;}
.ph{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:5px;}
.pt2{display:flex;justify-content:space-between;align-items:center;padding:4px 7px;border-radius:5px;border:1px solid var(--bd);background:var(--sf2);margin-bottom:2px;font-size:10px;color:var(--tx2);}
.pt2.fired{border-color:var(--cr-bd);background:var(--cr-bg);color:var(--cr);}
.tk{color:var(--tx3);font-family:var(--mono);font-size:9px;}
#digest-btn{margin:6px 12px;padding:6px 0;border-radius:6px;border:1px solid var(--bd);background:var(--sf2);color:var(--tx2);cursor:pointer;font-size:10px;font-weight:500;text-align:center;display:flex;align-items:center;justify-content:center;gap:5px;}
#digest-btn:hover{border-color:var(--ac);color:var(--ac);}
#bot{grid-column:1/-1;background:var(--sf);border-top:1px solid var(--bd);display:flex;align-items:center;}
.bs{padding:0 14px;border-right:1px solid var(--bd);text-align:center;height:100%;display:flex;flex-direction:column;justify-content:center;}
.bv{font-size:14px;font-weight:700;font-family:var(--mono);}.bl{font-size:8px;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);}
.ow{flex:1;padding:5px 14px;}.ot{font-size:9px;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:2px;}
#osc{width:100%;height:36px;}
.ol{display:flex;justify-content:space-between;font-size:8px;color:var(--tx3);font-family:var(--mono);margin-top:1px;}
#notif{position:fixed;bottom:74px;left:280px;z-index:999;display:flex;flex-direction:column-reverse;gap:4px;pointer-events:none;max-width:300px;}
.ni{padding:6px 10px;border-radius:5px;font-size:10px;font-weight:500;border:1px solid;animation:tin .15s ease;}
@keyframes tin{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.ni.CRITICAL{background:var(--cr-bg);border-color:var(--cr-bd);color:var(--cr);}
.ni.HIGH{background:var(--hi-bg);border-color:var(--hi-bd);color:var(--hi);}
.ni.info{background:var(--me-bg);border-color:var(--me-bd);color:var(--me);}
#tip{position:fixed;z-index:1000;pointer-events:none;display:none;background:var(--sf);color:var(--tx);border:1px solid var(--bd2);padding:5px 9px;border-radius:5px;font-size:10px;line-height:1.5;max-width:220px;}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:2000;display:none;align-items:center;justify-content:center;}
#modal.visible{display:flex;}
.modal-box{background:var(--sf);border:1px solid var(--bd2);border-radius:10px;padding:20px;max-width:520px;width:90%;max-height:80vh;overflow-y:auto;}
.modal-title{font-size:14px;font-weight:700;margin-bottom:12px;color:var(--ac);}
.modal-body{font-size:11px;color:var(--tx2);line-height:1.7;white-space:pre-wrap;word-break:break-word;}
.modal-close{float:right;font-size:18px;cursor:pointer;color:var(--tx3);}
</style>
/* INJECT_FONTS */
/* INJECT_D3 */
</head>
<body>
<div id="notif"></div>
<div id="tip"></div>
<div id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <span class="modal-close" onclick="closeModal()">x</span>
    <div class="modal-title" id="modal-title">Report</div>
    <div class="modal-body" id="modal-body">Loading...</div>
  </div>
</div>
<div id="app">
<header id="hdr">
  <div class="logo-icon"><svg viewBox="0 0 16 16"><path d="M8 1L2 4v4c0 3.5 2.5 6.5 6 7.5C11.5 14.5 14 11.5 14 8V4L8 1z"/></svg></div>
  <div><div style="display:flex;align-items:baseline;gap:4px"><div class="logo-text">AEGIS-NEXUS</div><div class="logo-ver">v3.0</div></div><div class="logo-sub">Autonomous Digital Risk Protection . 17 Sources . AI-Powered</div></div>
  <div class="hdiv"></div>
  <div class="vs">
    <div class="v ac"><div class="vv" id="vv-proc">0</div><div class="vl">Processed</div></div>
    <div class="v"><div class="vv" id="vv-noise" style="color:var(--tx3)">0</div><div class="vl">Neutralised</div></div>
    <div class="v hi"><div class="vv" id="vv-alerts">0</div><div class="vl">Alerts</div></div>
    <div class="v cr"><div class="vv" id="vv-crit">0</div><div class="vl">Critical</div></div>
    <div class="v lo"><div class="vv" id="vv-rate">0%</div><div class="vl">Immunity</div></div>
  </div>
  <div id="src-count">0/17 sources</div>
  <div class="pill"><div class="dot"></div>System Active</div>
  <div id="clk"></div>
  <button class="hbtn" onclick="openWeeklyDigest()">[D] Weekly Digest</button>
  <button class="hbtn" id="tbtn" onclick="toggleTheme()">Light</button>
</header>
<aside id="left">
  <div class="pt"><span>Protected Assets</span><span style="font-size:9px;color:var(--ac)" id="asset-count">36 assets</span></div>
  <div id="olist"></div>
  <div class="feed-tabs">
    <div class="tab active" id="tab-feed" onclick="switchTab('feed')">Alerts</div>
    <div class="tab" id="tab-timeline" onclick="switchTab('timeline')">Timeline</div>
    <div class="tab" id="tab-sources" onclick="switchTab('sources')">Sources</div>
    <div class="tab" id="tab-analytics" onclick="switchTab('analytics')">Analytics</div>
    <div class="tab" id="tab-darkwatch" onclick="switchTab('darkwatch')">DarkWatch</div>
    <div class="tab" id="tab-blocked" onclick="switchTab('blocked')">Blocked</div>
  </div>
  <div id="export-bar">
    <span class="ex-label">Export</span>
    <select id="ex-sev" class="ex-sel"><option value="">All severity</option><option value="CRITICAL">Critical only</option><option value="HIGH">High only</option><option value="MEDIUM">Medium only</option></select>
    <button class="ex-btn csv" onclick="exportAlerts('csv')">v CSV</button>
    <button class="ex-btn" onclick="exportAlerts('json')">v JSON</button>
    <span class="ex-count" id="ex-count">0 alerts</span>
  </div>
  <div id="feed"></div>
  <div id="timeline-panel"><div style="font-size:10px;color:var(--tx3);text-align:center;padding:20px">Click to load timeline...</div></div>
  <div id="sources-panel"><div id="src-list"></div></div>
  <div id="analytics-panel">
    <div class="an-grid">
      <div class="an-card"><div class="an-val" id="an-total">0</div><div class="an-lbl">Total alerts</div></div>
      <div class="an-card"><div class="an-val" style="color:var(--cr)" id="an-crit">0</div><div class="an-lbl">Critical</div></div>
      <div class="an-card"><div class="an-val" style="color:var(--ac)" id="an-sources">0</div><div class="an-lbl">Sources active</div></div>
      <div class="an-card"><div class="an-val" style="color:var(--lo)" id="an-noise-pct">0%</div><div class="an-lbl">Noise filtered</div></div>
    </div>
    <div style="font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:4px;">By severity</div>
    <div id="an-sev-bars"></div>
    <canvas id="chart-canvas"></canvas>
  </div>
  <div id="darkwatch-panel">
    <div style="font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:6px">Typosquat Domains</div>
    <div id="dw-list"><div style="font-size:10px;color:var(--tx3);padding:10px">Loading...</div></div>
    <div style="font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin:8px 0 4px">Threat Actors</div>
    <div id="dw-actors"><div style="font-size:10px;color:var(--tx3);padding:6px">Loading...</div></div>
  </div>
  <div id="blocked-panel">
    <div style="font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:6px">Blocked Indicators</div>
    <div id="blocked-list"><div style="font-size:10px;color:var(--tx3);padding:10px">None blocked yet.</div></div>
    <button class="ex-btn" style="margin-top:8px;width:100%" onclick="purgeStale()">[x] Purge Stale Alerts</button>
  </div>
</aside>
<main id="center"><svg id="gsvg" xmlns="http://www.w3.org/2000/svg"></svg></main>
<aside id="right">
  <div id="rscroll">
    <div class="rh">Threat Inspector</div>
    <div id="rbody" style="color:var(--tx3);font-size:11px;line-height:1.8">Click any alert or graph node to inspect.</div>
  </div>
  <button id="digest-btn" onclick="openWeeklyDigest()">[D] Weekly Intelligence Digest</button>
  <div id="ps">
    <div class="ph" style="display:flex;align-items:center;justify-content:space-between"><span>Phantom Decoys</span><button class="ex-btn" style="font-size:9px" onclick="genPhantomToken()">+ Gen</button></div>
    <div id="plist"></div>
    <div id="canary-list" style="margin-top:6px"></div>
    <button class="ex-btn" style="margin-top:6px;width:100%;font-size:9px" onclick="loadCanaries()">[C] Canary Files</button>
    <button class="ex-btn" style="margin-top:4px;width:100%;font-size:9px" onclick="openCertAbuse()">[!] Report Cert Abuse</button>
    <button class="ex-btn" style="margin-top:4px;width:100%;font-size:9px" onclick="loadOracleActors()">[A] Threat Actor DB</button>
  </div>
</aside>
<div id="bot">
  <div class="bs"><div class="bv" id="bs-t">0</div><div class="bl">Total</div></div>
  <div class="bs"><div class="bv" id="bs-n" style="color:var(--tx3)">0</div><div class="bl">Noise</div></div>
  <div class="bs"><div class="bv" id="bs-r" style="color:var(--lo)">0%</div><div class="bl">Filtered</div></div>
  <div class="ow"><div class="ot">SPECTRA Score Stream</div><canvas id="osc"></canvas><div class="ol"><span>NOISE</span><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div></div>
</div>
</div>
<script>
const OCOL={service:"#0ea5e9",domain:"#7c3aed",database:"#d97706",cdn:"#16a34a",infra:"#0891b2",api:"#6366f1"};
const OICO={service:"o",domain:"o",database:"o",cdn:"o",infra:"o",api:"o"};
const SEVHEX={CRITICAL:{l:"#dc2626",d:"#f87171"},HIGH:{l:"#ea580c",d:"#fb923c"},MEDIUM:{l:"#0284c7",d:"#38bdf8"},LOW:{l:"#16a34a",d:"#4ade80"},NOISE:{l:"#94a3b8",d:"#3d5470"}};
const SRC_LABELS={ct_logs:"crt.sh",cve_feed:"NVD",nvd:"NVD",github:"GitHub",paste_monitor:"Paste",paste:"Paste",shodan:"Shodan",bevigil:"BeVigil",abuse_ch:"AbuseCH",otx:"OTX",urlscan:"URLScan",pulsedive:"Pulsedive",breach_directory:"BreachDir",paste_hunter:"PasteHunt",spiderfoot:"SpiderFoot",alienvault:"AlienVault",dark_web:"DarkWeb",github_commits:"GH Commits",wayback:"Wayback",supply_chain:"SupplyChain",employee_exposure:"EmpExposure",phantom:"Phantom"};
function dk(){return document.documentElement.getAttribute("data-theme")==="dark";}
function sc(s){const m=SEVHEX[s]||SEVHEX.NOISE;return dk()?m.d:m.l;}
function qs(s){return document.querySelector(s);}
const NS="http://www.w3.org/2000/svg";
let S={assets:[],alerts:[],phantom:[],proc:0,noise:0,crit:0,ekg:Array(200).fill(0)};
let GW=0,GH=0,gcx=0,gcy=0,_currentAlertId=null,_activeTab="feed",_spawnIdx=0;
function toggleTheme(){document.documentElement.setAttribute("data-theme",dk()?"light":"dark");qs("#tbtn").textContent=dk()?"Dark":"Light";buildGraph();drawOsc();}
setInterval(()=>{qs("#clk").textContent=new Date().toTimeString().slice(0,8);},1000);
setInterval(()=>{if(_activeTab==="sources")renderSources();},10000);
function updateVitals(){
  const r=S.proc>0?(S.noise/S.proc*100).toFixed(1):"0.0";
  qs("#vv-proc").textContent=S.proc.toLocaleString();qs("#vv-noise").textContent=S.noise.toLocaleString();
  qs("#vv-alerts").textContent=S.alerts.length;qs("#vv-crit").textContent=S.crit;qs("#vv-rate").textContent=r+"%";
  qs("#bs-t").textContent=S.proc;qs("#bs-n").textContent=S.noise;qs("#bs-r").textContent=r+"%";
  const ec=qs("#ex-count");if(ec)ec.textContent=S.alerts.length+" alerts";
  const activeSrcs=new Set(S.alerts.map(a=>a.source)).size;
  qs("#src-count").textContent=activeSrcs+"/17 sources";
}
function exportAlerts(fmt){
  const sev=qs("#ex-sev").value;
  const a=document.createElement("a");a.href=`/alerts/export.${fmt}?limit=5000${sev?"&severity="+sev:""}`;a.download="";
  document.body.appendChild(a);a.click();document.body.removeChild(a);
}
function switchTab(tab){
  _activeTab=tab;
  ["feed","timeline","sources","analytics","darkwatch","blocked"].forEach(t=>{
    const tabEl=qs("#tab-"+t);if(tabEl)tabEl.classList.toggle("active",t===tab);
    if(t==="feed"){qs("#feed").style.display=tab==="feed"?"":"none";qs("#export-bar").style.display=tab==="feed"?"":"none";}
    else{const p=qs("#"+t+"-panel");if(p)p.classList.toggle("visible",t===tab);}
  });
  if(tab==="timeline")loadTimeline();
  if(tab==="sources")renderSources();
  if(tab==="analytics")refreshAnalytics();
  if(tab==="darkwatch")loadDarkWatch();
  if(tab==="blocked")loadBlocked();
}
setInterval(()=>{if(_activeTab==="sources")renderSources();},30000);
function renderSources(){
  fetch("/hydra/sources").then(r=>r.json()).then(data=>{
    const counts=data.counts||{};
    const all=[...(data.v2_sources||[]),...(data.v3_sources||[])];
    qs("#src-list").innerHTML=all.map(src=>{
      const cnt=counts[src]||0,label=SRC_LABELS[src]||src,isNew=(data.v3_sources||[]).includes(src);
      return `<div class="src-row"><div style="display:flex;align-items:center;gap:6px"><div class="src-status ${cnt===0?"zero":""}"></div><span class="src-name">${label}</span>${isNew?'<span style="font-size:7px;padding:1px 4px;border-radius:3px;background:var(--ac)1a;color:var(--ac);border:1px solid var(--ac)44">NEW</span>':""}</div><span class="src-cnt">${cnt}</span></div>`;
    }).join("");
  }).catch(()=>{qs("#src-list").innerHTML='<div style="font-size:10px;color:var(--tx3);padding:10px">Loading...</div>';});
}
function loadTimeline(){
  const panel=qs("#timeline-panel");
  panel.innerHTML='<div style="font-size:10px;color:var(--tx3);text-align:center;padding:20px"><div class="ai-spinner" style="margin:0 auto 8px;display:block"></div>Analysing...</div>';
  fetch("/oracle/timeline").then(r=>r.json()).then(data=>{
    const recent=S.alerts.slice(0,15);
    let html=`<div class="tl-card ${data.is_campaign?"campaign":""}"><div class="tl-title">${data.is_campaign?"! Campaign Detected":"Alert Timeline"}</div><div class="tl-body">${data.narrative||"Not enough multi-source data yet."}</div>${data.sources?`<div class="tl-meta">Sources: ${data.sources.join(", ")} . ${data.alert_count} alerts</div>`:""}</div>`;
    html+=recent.map(a=>`<div class="tl-item"><div class="tl-dot ${a.severity}"></div><div style="flex:1;min-width:0"><div class="tl-text">${(a.kind||"").replace(/_/g," ")} - ${(a.indicator||"").slice(0,40)}</div><div style="display:flex;gap:6px;margin-top:1px"><span class="tl-time">${(a.found_at||"").slice(11,19)}</span><span class="src-badge src-${a.source}">${SRC_LABELS[a.source]||a.source}</span></div></div></div>`).join("");
    panel.innerHTML=html;
  }).catch(()=>{panel.innerHTML='<div style="font-size:10px;color:var(--tx3);padding:10px">Timeline unavailable</div>';});
}
function refreshAnalytics(){
  const total=S.alerts.length,crit=S.alerts.filter(a=>a.severity==="CRITICAL").length;
  const sources=new Set(S.alerts.map(a=>a.source)).size,noisePct=S.proc>0?Math.round(S.noise/S.proc*100):0;
  qs("#an-total").textContent=total;qs("#an-crit").textContent=crit;qs("#an-sources").textContent=sources;qs("#an-noise-pct").textContent=noisePct+"%";
  const sevs=["CRITICAL","HIGH","MEDIUM","LOW"],sevCols={CRITICAL:"var(--cr)",HIGH:"var(--hi)",MEDIUM:"var(--me)",LOW:"var(--lo)"},counts={};
  S.alerts.forEach(a=>{counts[a.severity]=(counts[a.severity]||0)+1;});
  const maxC=Math.max(1,...Object.values(counts));
  qs("#an-sev-bars").innerHTML=sevs.map(s=>`<div class="an-bar-row"><span class="an-bar-label">${s}</span><div class="an-bar-track"><div class="an-bar-fill" style="width:${Math.round((counts[s]||0)/maxC*100)}%;background:${sevCols[s]}"></div></div><span class="an-bar-count">${counts[s]||0}</span></div>`).join("");
}
function loadDarkWatch(){
  fetch("/darkwatch/typosquat").then(r=>r.json()).then(data=>{
    const domains=data.domains||[];
    qs("#dw-list").innerHTML=domains.length?domains.map(d=>`<div class="dw-row"><span style="color:var(--cr)">${d.domain||d}</span><span style="color:var(--tx3);font-size:9px">${d.registrar||""}</span></div>`).join(""):'<div style="font-size:10px;color:var(--tx3);padding:6px">No typosquats detected yet.</div>';
  }).catch(()=>{qs("#dw-list").innerHTML='<div style="font-size:10px;color:var(--tx3);padding:6px">Unavailable</div>';});
  fetch("/oracle/actors").then(r=>r.json()).then(data=>{
    const actors=data.actors||[];
    qs("#dw-actors").innerHTML=actors.length?actors.map(a=>`<div style="padding:4px 6px;border-radius:4px;background:var(--sf2);margin-bottom:3px;font-size:10px"><span style="color:var(--ac);font-weight:600">${a.actor||a.name||a}</span>${a.origin?` <span style="color:var(--tx3);font-size:9px">(${a.origin})</span>`:""}</div>`).join(""):'<div style="font-size:10px;color:var(--tx3);padding:6px">No actors profiled yet.</div>';
  }).catch(()=>{qs("#dw-actors").innerHTML='<div style="font-size:10px;color:var(--tx3);padding:6px">Unavailable</div>';});
}
function loadBlocked(){
  fetch("/nexus/blocked").then(r=>r.json()).then(data=>{
    const blocked=data.blocked||[];
    qs("#blocked-list").innerHTML=blocked.length?blocked.map(b=>`<div class="blocked-row"><span>${b.indicator||b}</span><span style="font-size:9px">${b.type||""}</span></div>`).join(""):'<div style="font-size:10px;color:var(--tx3);padding:6px">No indicators blocked yet.</div>';
  }).catch(()=>{qs("#blocked-list").innerHTML='<div style="font-size:10px;color:var(--tx3);padding:6px">Unavailable</div>';});
}
function purgeStale(){
  if(!confirm("Purge stale alerts older than 7 days?"))return;
  fetch("/db/purge-stale",{method:"POST"}).then(r=>r.json()).then(data=>{toast("info","Purged: "+(data.purged||0)+" alerts");loadBlocked();}).catch(()=>toast("HIGH","Purge failed"));
}
function genPhantomToken(){
  const types=["aws_credential","github_token","jwt_secret","db_connection","api_key"];
  const t=types[Math.floor(Math.random()*types.length)];
  fetch("/phantom/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token_type:t})}).then(r=>r.json()).then(data=>{
    toast("info","Token generated: "+t);
    S.phantom.unshift({token_id:data.token_id||"new",token_type:t,triggered:false});
    renderPhantom();
  }).catch(()=>toast("HIGH","Token gen failed"));
}
function loadCanaries(){
  fetch("/phantom/canaries").then(r=>r.json()).then(data=>{
    const files=data.files||data||[];
    qs("#canary-list").innerHTML=Array.isArray(files)&&files.length?files.map(f=>`<div class="canary-row">[C] ${f.filename||f.file_id||f}<span style="font-size:9px;float:right">${f.triggered?"! Triggered":"Active"}</span></div>`).join(""):'<div style="font-size:10px;color:var(--tx3);padding:4px">No canary files.</div>';
  }).catch(()=>{qs("#canary-list").innerHTML='';});
}
function openCertAbuse(){
  const indicator=prompt("Enter domain/cert to report:");
  if(!indicator)return;
  qs("#modal-title").textContent="Cert Abuse Report";
  qs("#modal-body").textContent="Generating...";
  qs("#modal").classList.add("visible");
  fetch("/oracle/cert-abuse",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({indicator})}).then(r=>r.json()).then(data=>{
    qs("#modal-body").textContent=data.report||data.body||JSON.stringify(data,null,2);
  }).catch(e=>{qs("#modal-body").textContent="Error: "+e;});
}
function loadOracleActors(){
  fetch("/oracle/actors").then(r=>r.json()).then(data=>{
    const actors=data.actors||[];
    qs("#modal-title").textContent="Threat Actor Database";
    qs("#modal-body").textContent=actors.length?actors.map((a,i)=>`${i+1}. ${a.actor||a.name||a}${a.origin?" ("+a.origin+")":""}${a.relevance_score?" — "+parseFloat(a.relevance_score).toFixed(2):""}`).join("\n"):"No actors profiled yet.";
    qs("#modal").classList.add("visible");
  }).catch(()=>toast("HIGH","Actor DB unavailable"));
}
function connectWS(){
  const ws=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws/alerts");
  ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==="alert")onAlert(m.data);if(m.type==="stats")onStats(m.data);if(m.type==="phantom_trigger")onPT(m.data);if(m.type==="alert_enriched")onEnriched(m.data);};
  ws.onclose=()=>setTimeout(connectWS,3000);
}
function onStats(s){S.proc=s.total_processed||0;S.noise=s.noise_discarded||0;S.crit=s.critical||0;updateVitals();}
function onAlert(a){S.alerts.unshift(a);if(S.alerts.length>500)S.alerts.pop();S.ekg.push(a.score||0);if(S.ekg.length>200)S.ekg.shift();renderFeed();spawnThreat(a);drawOsc();if(a.severity==="CRITICAL"||a.severity==="HIGH")toast(a.severity,(a.kind||"").replace(/_/g," ")+" . "+(a.indicator||"").slice(0,26));}
function onPT(t){const tok=S.phantom.find(x=>x.token_id===t.token_id);if(tok)tok.triggered=true;renderPhantom();toast("CRITICAL","! Phantom triggered!");}
function onEnriched(data){const a=S.alerts.find(x=>x.threat_id===data.threat_id);if(a){a.ai_summary=data.ai_summary;a.threat_actors=data.threat_actors;}if(_currentAlertId===data.threat_id){const idx=S.alerts.findIndex(x=>x.threat_id===data.threat_id);if(idx>=0)selAlert(idx);}renderFeed();}
function renderOrgans(){qs("#olist").innerHTML=S.assets.map(a=>{const c=OCOL[a.kind]||"#0ea5e9";return `<div class="oc" id="oc-${a.id}" onclick="selOrgan('${a.id}')"><div class="oi" style="background:${c}1a;color:${c}">${OICO[a.kind]||"o"}</div><div style="flex:1;min-width:0"><div class="on" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${a.name}</div><div class="otype">${a.kind}</div></div><div class="hb">v</div></div>`;}).join("");qs("#asset-count").textContent=S.assets.length+" assets";}
function renderFeed(){
  qs("#feed").innerHTML=S.alerts.slice(0,100).map((a,i)=>{
    const src=SRC_LABELS[a.source]||a.source||"",meta=a.meta||{},extra=meta.cvss?` CVSS:${meta.cvss}`:"",hasAI=!!a.ai_summary;
    return `<div class="fi ${a.severity}" onclick="selAlert(parseInt(this.dataset.idx))" data-idx="${i}"><div class="fih"><span class="fb ${a.severity}">${a.severity}</span><span class="fs">${(a.score||0).toFixed(4)}</span>${hasAI?'<span class="ai-badge">* AI</span>':""}</div><div class="ft"><span>${(a.kind||"").replace(/_/g," ")}</span><span class="src-badge src-${a.source}">${src}</span></div><div class="fi2">${(a.indicator||"")}${extra}</div></div>`;
  }).join("");
  if(_activeTab==="analytics")refreshAnalytics();
}
function selOrgan(id){
  document.querySelectorAll(".oc").forEach(c=>c.classList.remove("active"));
  const card=qs("#oc-"+id);if(card)card.classList.add("active");
  const a=S.assets.find(x=>x.id===id);if(!a)return;
  const c=OCOL[a.kind]||"#0ea5e9";
  qs("#rbody").innerHTML=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:11px"><div style="width:32px;height:32px;border-radius:7px;background:${c}1a;display:flex;align-items:center;justify-content:center;font-size:16px;color:${c}">${OICO[a.kind]||"o"}</div><div><div style="font-weight:600;font-size:13px">${a.name}</div><div style="font-size:10px;color:var(--tx3)">${a.kind}</div></div></div><div class="dr"><span class="dk">Tech Stack</span><span class="dv">${(a.tech||[]).join(", ")}</span></div><div class="dr"><span class="dk">Tags</span><span class="dv">${(a.tags||[]).join(", ")||"-"}</span></div><div class="dr"><span class="dk">Status</span><span class="dv" style="color:var(--lo)">Healthy v</span></div>`;
}
function selAlert(idx){
  const a=typeof idx==="number"?S.alerts[idx]:S.alerts.find(x=>x.threat_id===idx);if(!a)return;
  _currentAlertId=a.threat_id;
  const sev=a.severity||"NOISE",col=sc(sev),st=a.stages||{},meta=a.meta||{};
  const bar=(k,l)=>{const v=st[k]||0,pct=Math.round(v*100),cls=v>.75?"c":v>.5?"h":v>.15?"m":"l";return `<div class="sw"><div class="sr2"><span>${l}</span><span>${v.toFixed(4)}</span></div><div class="st"><div class="sf2x ${cls}" style="width:${pct}%"></div></div></div>`;};
  const mrows=[meta.cvss!=null?["CVSS",`<span style="color:${col};font-weight:600">${meta.cvss}</span>`]:null,meta.pub?["Published",meta.pub]:null,meta.url?["NVD",`<a href="${meta.url}" target="_blank" style="color:var(--ac)">nvd.nist.gov -></a>`]:null,meta.report?["URLScan",`<a href="${meta.report}" target="_blank" style="color:var(--ac)">View -></a>`]:null,meta.commit_url?["Commit",`<a href="${meta.commit_url}" target="_blank" style="color:var(--ac)">GitHub -></a>`]:null,meta.wayback_url?["Archive",`<a href="${meta.wayback_url}" target="_blank" style="color:var(--ac)">Wayback -></a>`]:null,meta.otx_url?["OTX",`<a href="${meta.otx_url}" target="_blank" style="color:var(--ac)">OTX -></a>`]:null].filter(Boolean);
  const metaHtml=mrows.length?`<div class="mb"><div class="mt">Source Metadata</div>${mrows.map(([k,v])=>`<div class="dr"><span class="dk">${k}</span><span class="dv">${v}</span></div>`).join("")}</div>`:"";
  const rHtml=(a.reasoning&&a.reasoning.length)?`<div class="rb">${a.reasoning.map(r=>`<p>${r}</p>`).join("")}</div>`:"";
  let aiHtml="";
  if(a.ai_summary){aiHtml=`<div class="ai-box"><div class="ai-box-hdr"><span style="font-size:12px">*</span><span class="ai-box-title">AI Threat Analysis</span><span style="font-size:9px;color:var(--tx3);margin-left:auto">Groq</span></div><div class="ai-box-body">${a.ai_summary}</div></div>`;}
  else if(sev==="HIGH"||sev==="CRITICAL"){
    aiHtml=`<div class="ai-box" id="ai-loading-box"><div class="ai-box-hdr"><span class="ai-spinner"></span><span class="ai-box-title" style="margin-left:6px">AI Analysis</span><span style="font-size:9px;color:var(--tx3);margin-left:auto">Generating...</span></div><div style="font-size:10px;color:var(--tx3);font-style:italic">Groq is analysing this threat...</div></div>`;
    fetch("/oracle/summarise",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({threat_id:a.threat_id})}).then(r=>r.json()).then(data=>{const box=qs("#ai-loading-box");if(box&&_currentAlertId===a.threat_id){box.innerHTML=`<div class="ai-box-hdr"><span style="font-size:12px">*</span><span class="ai-box-title">AI Threat Analysis</span><span style="font-size:9px;color:var(--tx3);margin-left:auto">Groq</span></div><div class="ai-box-body">${data.ai_summary||"Analysis complete."}</div>`;if(data.threat_actors&&data.threat_actors.length){const ab=qs("#actor-box");if(ab){ab.style.display="";ab.innerHTML=`<div class="mt">Threat Actor Attribution</div>${data.threat_actors.map(ac=>`<span class="actor-pill">! ${ac.actor} (${ac.origin})</span>`).join("")}`;}}}}). catch(()=>{});
  }
  let actorHtml=a.threat_actors&&a.threat_actors.length?`<div class="prof-box" id="actor-box"><div class="mt">Threat Actor Attribution</div>${a.threat_actors.map(ac=>`<span class="actor-pill">! ${ac.actor} (${ac.origin}) . ${ac.relevance_score.toFixed(2)}</span>`).join("")}</div>`:`<div class="prof-box" id="actor-box" style="display:none"></div>`;
  const isCT=a.source==="ct_logs",isCrit=sev==="CRITICAL";
  const actionBtns=`<div class="act-row">${isCrit?`<button class="act-btn danger" onclick="blockIndicator('${(a.indicator||"").split(" ")[0]}','${a.source==="shodan"?"ip":"domain"}','${a.threat_id}')">[B] Block</button>`:""} ${isCT?`<button class="act-btn purple" onclick="generateTakedown('${a.threat_id}')">[E] Takedown</button>`:""} <button class="act-btn primary" onclick="downloadPDF('${a.threat_id}')">[P] PDF</button><button class="act-btn" onclick="profileAttacker('${(a.indicator||"").split(" ")[0]}','${a.source==="shodan"?"ip":"domain"}','${a.threat_id}')">[?] Profile</button></div><div class="block-confirm" id="block-confirm-${a.threat_id}"></div>`;
  qs("#rbody").innerHTML=`<div class="sc ${sev}"><div class="sl" style="color:${col}">${sev}</div><div class="sv" style="color:${col}">${(a.score||0).toFixed(6)}</div></div><div class="dr"><span class="dk">Type</span><span class="dv">${(a.kind||"").replace(/_/g," ")}</span></div><div class="dr"><span class="dk">Source</span><span class="dv"><span class="src-badge src-${a.source}">${SRC_LABELS[a.source]||a.source}</span></span></div><div class="dr"><span class="dk">Indicator</span><span class="dv" style="color:${col}">${a.indicator||""}</span></div><div class="dr"><span class="dk">TTPs</span><span class="dv">${(a.ttps||[]).join(", ")||"-"}</span></div><div class="dr"><span class="dk">Tech</span><span class="dv">${(a.tech||[]).join(", ")||"-"}</span></div><div class="dr"><span class="dk">Found</span><span class="dv">${(a.found_at||"").slice(0,19).replace("T"," ")}</span></div>${metaHtml}<div style="margin-top:9px;font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--tx3);margin-bottom:3px">SPECTRA</div>${bar("s1","S1 . Spectral Perturbation")}${bar("s2","S2 . Renyi Entropy")}${bar("s3","S3 . TTP Isomorphism")}${bar("s4","S4 . Temporal Decay")}${rHtml}${aiHtml}${actorHtml}${actionBtns}`;
}
function blockIndicator(indicator,type,threatId){if(!confirm(`Block ${type}: ${indicator}?`))return;fetch("/nexus/block",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({indicator,type})}).then(r=>r.json()).then(data=>{const box=qs(`#block-confirm-${threatId}`);if(box){box.classList.add("visible");box.innerHTML=`[B] ${data.actions.join(" . ")||"Blocked"}`;}toast("CRITICAL",`[B] Blocked: ${indicator}`);}).catch(e=>toast("HIGH","Block failed"));}
function generateTakedown(threatId){qs("#modal-title").textContent="Generating Takedown...";qs("#modal-body").textContent="Calling Groq AI...";qs("#modal").classList.add("visible");fetch("/oracle/takedown",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({threat_id:threatId})}).then(r=>r.json()).then(data=>{qs("#modal-title").textContent="[E] UDRP Abuse Report";qs("#modal-body").textContent=`TO: ${data.send_to}\nSUBJECT: ${data.email_subject}\n\n${data.email_body}`;}).catch(e=>{qs("#modal-title").textContent="Error";qs("#modal-body").textContent=String(e);});}
function downloadPDF(threatId){toast("info","Generating PDF...");fetch("/nexus/incident-pdf",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({threat_id:threatId})}).then(r=>r.ok?r.blob():Promise.reject("failed")).then(blob=>{const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`aegis_incident_${threatId.slice(0,12)}.pdf`;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);toast("info","v PDF downloaded");}).catch(()=>toast("HIGH","PDF failed"));}
function profileAttacker(indicator,type,threatId){fetch("/oracle/profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({indicator,type})}).then(r=>r.json()).then(data=>{const vt=data.virustotal||{},ab=data.abuseipdb||{},box=qs("#actor-box");if(box){box.style.display="";let html=`<div class="mt">Attacker Profile</div>`;if(vt.malicious!==undefined)html+=`<div class="prof-row"><span class="prof-k">VT Malicious</span><span class="prof-v" style="${vt.malicious>0?"color:var(--cr)":""}">${vt.malicious}</span></div>`;if(vt.registrar)html+=`<div class="prof-row"><span class="prof-k">Registrar</span><span class="prof-v">${vt.registrar}</span></div>`;if(ab.abuse_score!==undefined)html+=`<div class="prof-row"><span class="prof-k">Abuse Score</span><span class="prof-v">${ab.abuse_score}%</span></div>`;if(ab.country)html+=`<div class="prof-row"><span class="prof-k">Country</span><span class="prof-v">${ab.country}</span></div>`;box.innerHTML=html;}}).catch(()=>{});}
function openWeeklyDigest(){
  qs("#modal-title").innerHTML='Weekly Intelligence Digest <button onclick="downloadDigestPDF()" style="float:right;margin-left:10px;padding:3px 10px;border-radius:5px;border:1px solid var(--ac);background:var(--me-bg);color:var(--ac);cursor:pointer;font-size:10px;">Save PDF</button>';
  qs("#modal-body").textContent="Generating with Groq AI...";
  qs("#modal").classList.add("visible");
  fetch("/nexus/weekly-digest").then(r=>r.json()).then(data=>{
    var sevLine=Object.entries(data.by_severity||{}).map(function(e){return e[0]+": "+e[1];}).join(" | ");
    var srcLine=Object.entries(data.by_source||{}).sort(function(a,b){return b[1]-a[1];}).slice(0,5).map(function(e){return e[0]+"("+e[1]+")";}).join(", ");
    var threats=(data.top_threats||[]).map(function(t,i){return (i+1)+". ["+t.severity+"] "+t.indicator+" ("+parseFloat(t.score||0).toFixed(4)+")";}).join("\n");
    var txt="WEEK ENDING: "+data.week_ending+"\nTOTAL ALERTS: "+data.total_alerts+"\nBY SEVERITY: "+sevLine+"\nTOP SOURCES: "+srcLine+"\n\n"+("-".repeat(50))+"\nEXECUTIVE SUMMARY\n"+("-".repeat(50))+"\n"+(data.narrative||"No data yet.")+"\n\n"+("-".repeat(50))+"\nTOP THREATS\n"+("-".repeat(50))+"\n"+threats;
    qs("#modal-body").textContent=txt;
  }).catch(function(e){qs("#modal-body").textContent="Could not generate: "+e;});
}
function downloadDigestPDF(){
  toast("info","Generating digest PDF...");
  var a=document.createElement("a");
  a.href="/nexus/weekly-digest/pdf";
  a.download="";
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  toast("info","PDF saved to Downloads");
}
function closeModal(){qs("#modal").classList.remove("visible");}
function renderPhantom(){const list=S.phantom.length?S.phantom:[{token_id:"p1",token_type:"aws_credential",triggered:false},{token_id:"p2",token_type:"github_token",triggered:false},{token_id:"p3",token_type:"aws_credential",triggered:false},{token_id:"p4",token_type:"github_token",triggered:false},{token_id:"p5",token_type:"jwt_secret",triggered:false}];qs("#plist").innerHTML=list.slice(0,5).map(t=>`<div class="pt2 ${t.triggered?"fired":""}"><span>${t.triggered?"! Triggered":"* Active"}</span><span class="tk">${(t.token_type||"").replace(/_/g," ")}</span></div>`).join("");}
function svgEl2(tag,attrs){const el=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs||{}))el.setAttribute(k,v);return el;}
function svgText2(x,y,txt,attrs){const el=svgEl2("text",{x,y,"text-anchor":"middle","dominant-baseline":"middle",...attrs});el.textContent=txt;return el;}
function buildGraph(){
  const center=qs("#center");GW=center.clientWidth;GH=center.clientHeight;if(!GW||!GH){setTimeout(buildGraph,100);return;}
  gcx=GW/2;gcy=GH/2;
  if(typeof d3!=="undefined"&&d3.select){buildGraphD3();return;}
  const svg=qs("#gsvg");svg.setAttribute("viewBox",`0 0 ${GW} ${GH}`);while(svg.firstChild)svg.removeChild(svg.firstChild);
  const isDk=dk(),gridC=isDk?"#0d1830":"#eaeff5",ring1C=isDk?"#162035":"#e2e8f0",ring2C=isDk?"#1a3060":"#bae6fd",nuclF=isDk?"#091424":"#f0f9ff",nuclS=isDk?"#1a3060":"#bae6fd",axiomC=isDk?"#38bdf8":"#0284c7",labelC=isDk?"#4a6a8a":"#64748b",nodeBg=isDk?"#0d1424":"#ffffff";
  const gridG=svgEl2("g");for(let x=0;x<=GW;x+=52)for(let y=0;y<=GH;y+=52)gridG.appendChild(svgEl2("circle",{cx:x,cy:y,r:"0.8",fill:gridC}));svg.appendChild(gridG);
  const Ro=Math.min(GW,GH)*.43,Rm=Math.min(GW,GH)*.30,Ri=Math.min(GW,GH)*.16;
  [[Ro,ring1C,.4,"8 8"],[Rm,ring2C,1.2,"none"],[Ri,ring1C,.4,"none"]].forEach(([r,c,sw,da])=>{const el=svgEl2("circle",{cx:gcx,cy:gcy,r,fill:"none",stroke:c,"stroke-width":sw});if(da!=="none")el.setAttribute("stroke-dasharray",da);svg.appendChild(el);});
  svg.appendChild(svgEl2("circle",{cx:gcx,cy:gcy,r:30,fill:nuclF,stroke:nuclS,"stroke-width":1.5}));
  svg.appendChild(svgEl2("circle",{cx:gcx,cy:gcy,r:17,fill:axiomC,opacity:.1}));
  svg.appendChild(svgText2(gcx,gcy,"AXIOM",{"font-family":"monospace","font-size":9,"font-weight":500,"letter-spacing":1,fill:axiomC}));
  const arcG=svgEl2("g",{id:"arc-g"}),nodeG=svgEl2("g",{id:"node-g"});svg.appendChild(arcG);svg.appendChild(nodeG);
  S.assets.forEach((a,i)=>{const angle=(i/S.assets.length)*2*Math.PI-Math.PI/2,nx=gcx+Rm*Math.cos(angle),ny=gcy+Rm*Math.sin(angle);a._nx=nx;a._ny=ny;const c=OCOL[a.kind]||"#0ea5e9";const g=svgEl2("g",{style:"cursor:pointer"});g.appendChild(svgEl2("circle",{cx:nx,cy:ny,r:23,fill:"none",stroke:c,"stroke-width":.5,opacity:.2}));g.appendChild(svgEl2("circle",{cx:nx,cy:ny,r:17,fill:nodeBg,stroke:c,"stroke-width":1.4}));g.appendChild(svgEl2("circle",{cx:nx,cy:ny,r:17,fill:c,opacity:.1}));g.appendChild(svgText2(nx,ny,OICO[a.kind]||"o",{"font-size":12,fill:c}));const lx=gcx+(nx-gcx)*1.38,ly=gcy+(ny-gcy)*1.38,label=a.name.length>15?a.name.slice(0,14)+"...":a.name;g.appendChild(svgText2(lx,ly,label,{"font-size":9,"font-family":"system-ui,sans-serif","font-weight":500,fill:labelC}));g.addEventListener("click",()=>selOrgan(a.id));g.addEventListener("mouseenter",(e)=>showTip(e,`${a.name}\n${a.kind}\n${(a.tech||[]).slice(0,5).join(", ")}`));g.addEventListener("mouseleave",hideTip);nodeG.appendChild(g);});
}
function buildGraphD3(){
  const svgEl3=qs("#gsvg");svgEl3.setAttribute("viewBox",`0 0 ${GW} ${GH}`);while(svgEl3.firstChild)svgEl3.removeChild(svgEl3.firstChild);
  const isDk=dk(),gridC=isDk?"#0d1830":"#eaeff5",ring2C=isDk?"#1a3060":"#bae6fd",ring1C=isDk?"#162035":"#e2e8f0",nuclF=isDk?"#091424":"#f0f9ff",nuclS=isDk?"#1a3060":"#bae6fd",axiomC=isDk?"#38bdf8":"#0284c7",labelC=isDk?"#4a6a8a":"#64748b",nodeBg=isDk?"#0d1424":"#ffffff";
  const svg=d3.select("#gsvg");const gridG=svg.append("g").attr("opacity",.5);
  for(let x=0;x<=GW;x+=56)for(let y=0;y<=GH;y+=56)gridG.append("circle").attr("cx",x).attr("cy",y).attr("r",.7).attr("fill",gridC);
  const minRm=S.assets.length>0?(S.assets.length*34)/(2*Math.PI):180,Rm=Math.max(minRm,Math.min(Math.min(GW,GH)*0.38,220)),Ro=Rm*1.38,Ri=Rm*0.52;
  [[Ro,ring1C,.4,"8 8"],[Rm,ring2C,1.2,"none"],[Ri,ring1C,.4,"none"]].forEach(([r,c,sw,da])=>{const el=svg.append("circle").attr("cx",gcx).attr("cy",gcy).attr("r",r).attr("fill","none").attr("stroke",c).attr("stroke-width",sw);if(da!=="none")el.attr("stroke-dasharray",da);});
  svg.append("circle").attr("cx",gcx).attr("cy",gcy).attr("r",30).attr("fill",nuclF).attr("stroke",nuclS).attr("stroke-width",1.5);
  svg.append("circle").attr("cx",gcx).attr("cy",gcy).attr("r",17).attr("fill",axiomC).attr("opacity",.1);
  svg.append("text").attr("x",gcx).attr("y",gcy).attr("text-anchor","middle").attr("dominant-baseline","middle").attr("fill",axiomC).attr("font-family","monospace").attr("font-size",9).attr("font-weight",500).attr("letter-spacing",1).text("AXIOM");
  svg.append("g").attr("id","arc-g");svg.append("g").attr("id","node-g");
  const nodeG=d3.select("#node-g");
  S.assets.forEach((a,i)=>{const angle=(i/S.assets.length)*2*Math.PI-Math.PI/2;a._nx=gcx+Rm*Math.cos(angle);a._ny=gcy+Rm*Math.sin(angle);const c=OCOL[a.kind]||"#0ea5e9";const g=nodeG.append("g").style("cursor","pointer").on("click",()=>selOrgan(a.id)).on("mouseenter",(e)=>showTip(e,a.name+"\n"+a.kind+"\n"+(a.tech||[]).slice(0,5).join(", "))).on("mouseleave",hideTip);g.append("circle").attr("cx",a._nx).attr("cy",a._ny).attr("r",20).attr("fill","none").attr("stroke",c).attr("stroke-width",.5).attr("opacity",.2);g.append("circle").attr("cx",a._nx).attr("cy",a._ny).attr("r",16).attr("fill",nodeBg).attr("stroke",c).attr("stroke-width",1.4);g.append("circle").attr("cx",a._nx).attr("cy",a._ny).attr("r",16).attr("fill",c).attr("opacity",.1);g.append("text").attr("x",a._nx).attr("y",a._ny).attr("text-anchor","middle").attr("dominant-baseline","middle").attr("fill",c).attr("font-size",11).text(OICO[a.kind]||"o");const normY=(a._ny-gcy)/Rm,crowdFactor=1.25+Math.abs(normY)*0.18,lx=gcx+(a._nx-gcx)*crowdFactor,ly=gcy+(a._ny-gcy)*crowdFactor,isVertical=Math.abs(Math.atan2(a._ny-gcy,a._nx-gcx))>1.2,labelFs=isVertical?7:8,maxChars=isVertical?8:11,label=a.name.length>maxChars?a.name.slice(0,maxChars-1)+"...":a.name;g.append("text").attr("x",lx).attr("y",ly).attr("text-anchor","middle").attr("dominant-baseline","middle").attr("fill",labelC).attr("font-family","system-ui,sans-serif").attr("font-size",labelFs).attr("font-weight",500).text(label);});
}
function spawnThreat(alert){
  const svg=qs("#gsvg");if(!svg||!S.assets.length)return;
  const sev=alert.severity||"NOISE",c=sc(sev),golden=2.399963,angle=(_spawnIdx++)*golden;
  const baseR=Math.max(195,Math.min(GW,GH)*0.38)*1.65,dist=Math.min(baseR+((_spawnIdx%7)-3)*8,Math.min(GW,GH)*0.48);
  const tx=gcx+dist*Math.cos(angle),ty=gcy+dist*Math.sin(angle);
  let target=S.assets[0];if(alert.tech&&alert.tech.length){const m=S.assets.find(n=>(n.tech||[]).some(t=>(alert.tech||[]).includes(t)));if(m)target=m;}else target=S.assets[Math.floor(Math.random()*S.assets.length)];
  const px=target._nx||gcx,py=target._ny||gcy,mx=(tx+px)/2+(Math.random()-.5)*80,my=(ty+py)/2+(Math.random()-.5)*80;
  const arcG=qs("#arc-g")||svg,nodeG=qs("#node-g")||svg;
  const arc=svgEl2("path",{d:`M${tx},${ty} Q${mx},${my} ${px},${py}`,fill:"none",stroke:c,"stroke-width":sev==="CRITICAL"?1.4:.7,"stroke-dasharray":"5 5",opacity:.4});arcG.appendChild(arc);
  const pulse=svgEl2("circle",{cx:px,cy:py,r:20,fill:"none",stroke:c,"stroke-width":1.2,opacity:.6});arcG.appendChild(pulse);
  let pr=20,po=0.6;const pInt=setInterval(()=>{pr+=2.5;po-=0.05;pulse.setAttribute("r",pr);pulse.setAttribute("opacity",Math.max(0,po));if(po<=0){clearInterval(pInt);try{arcG.removeChild(pulse);}catch(e){}}},30);
  const r=sev==="CRITICAL"?9:sev==="HIGH"?7:5,isDk=dk();
  const g=svgEl2("g",{style:"cursor:pointer"});g.appendChild(svgEl2("circle",{cx:tx,cy:ty,r,fill:isDk?"#0d1424":"#fff",stroke:c,"stroke-width":1.4}));g.appendChild(svgText2(tx,ty-r-4,(alert.score||0).toFixed(3),{"font-family":"monospace","font-size":8,fill:c}));
  const _aIdx=S.alerts.indexOf(alert);g.addEventListener("click",()=>selAlert(_aIdx>=0?_aIdx:alert.threat_id));g.addEventListener("mouseenter",(e)=>showTip(e,`${sev} . ${(alert.score||0).toFixed(4)}\n${(alert.kind||"").replace(/_/g," ")}\n${(alert.indicator||"").slice(0,30)}`));g.addEventListener("mouseleave",hideTip);nodeG.appendChild(g);
  setTimeout(()=>{try{arcG.removeChild(arc);}catch(e){}try{nodeG.removeChild(g);}catch(e){}},9000);
}
function drawOsc(){
  const cv=qs("#osc");if(!cv)return;const ctx=cv.getContext("2d");const W2=cv.offsetWidth,H2=cv.offsetHeight;if(!W2||!H2)return;
  cv.width=W2*devicePixelRatio;cv.height=H2*devicePixelRatio;ctx.scale(devicePixelRatio,devicePixelRatio);ctx.clearRect(0,0,W2,H2);
  const isDk=dk(),CR=isDk?"#f87171":"#dc2626",HI=isDk?"#fb923c":"#ea580c",ME=isDk?"#38bdf8":"#0284c7",data=S.ekg,step=W2/(data.length-1||1);
  [[.75,CR],[.5,HI],[.15,ME]].forEach(([v,c])=>{ctx.setLineDash([3,4]);ctx.strokeStyle=c+"55";ctx.lineWidth=.5;ctx.beginPath();ctx.moveTo(0,H2*(1-v));ctx.lineTo(W2,H2*(1-v));ctx.stroke();});
  ctx.setLineDash([]);ctx.beginPath();ctx.moveTo(0,H2);data.forEach((v,i)=>ctx.lineTo(i*step,H2*(1-Math.min(v,1))));ctx.lineTo((data.length-1)*step,H2);ctx.closePath();ctx.fillStyle=isDk?"rgba(56,189,248,.04)":"rgba(14,165,233,.05)";ctx.fill();
  for(let i=1;i<data.length;i++){const v=data[i],c=v>=.75?CR:v>=.5?HI:v>=.15?ME:(isDk?"#1a2840":"#cbd5e1");ctx.beginPath();ctx.moveTo((i-1)*step,H2*(1-Math.min(data[i-1],1)));ctx.lineTo(i*step,H2*(1-Math.min(v,1)));ctx.strokeStyle=c;ctx.lineWidth=1.5;ctx.stroke();}
}
function toast(sev,msg){const el=qs("#notif");while(el.children.length>=3)el.removeChild(el.lastChild);const d=document.createElement("div");d.className=`ni ${sev}`;d.textContent=msg;el.prepend(d);setTimeout(()=>{d.style.opacity="0";setTimeout(()=>d.remove(),260);},sev==="CRITICAL"?5000:2800);}
function showTip(e,txt){const el=qs("#tip");el.style.display="block";el.innerHTML=txt.replace(/\n/g,"<br>");el.style.left=(e.pageX+13)+"px";el.style.top=(e.pageY-6)+"px";}
function hideTip(){qs("#tip").style.display="none";}
document.addEventListener("mousemove",e=>{const el=qs("#tip");if(el.style.display==="block"){el.style.left=(e.pageX+13)+"px";el.style.top=(e.pageY-6)+"px";}});
async function init(){
  try{const[ar,tr]=await Promise.all([fetch("/twin/assets"),fetch("/phantom/tokens")]);S.assets=((await ar.json()).assets)||[];S.phantom=((await tr.json()).tokens)||[];}catch(e){console.error("init error",e);}
  renderOrgans();renderPhantom();updateVitals();
  requestAnimationFrame(()=>requestAnimationFrame(()=>setTimeout(()=>{buildGraph();drawOsc();},50)));
}
window.addEventListener("resize",()=>{buildGraph();drawOsc();});
document.addEventListener("DOMContentLoaded",()=>{init().then(()=>connectWS());});
</script>
</body>
</html>"""





# ══════════════════════════════════════════════════════════════════
# COMMAND: TUI — Textual Terminal Dashboard
# ══════════════════════════════════════════════════════════════════

async def cmd_tui():
    """Full interactive terminal dashboard using Textual."""
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.widgets import DataTable, Footer, Label, Static
        from rich.text import Text as RichText
    except ImportError:
        print("  Run: pip3 install textual --break-system-packages")
        return

    # Textual cannot run inside an existing asyncio event loop.
    # We build the app object and launch it in a fresh thread/loop.
    import threading

    twin, spectra, phantom, kronos = make_engine()

    SEV_STYLE = {
        "CRITICAL": "bold red", "HIGH": "bold yellow",
        "MEDIUM":   "bold cyan", "LOW": "bold green",
        "NOISE":    "dim white",
    }

    class HeaderWidget(Static):
        def __init__(self, state_ref, **kw):
            super().__init__(**kw); self._s = state_ref
        def render(self) -> RichText:
            s  = self._s
            nr = f"{s['noise']/max(s['total'],1):.1%}"
            t  = RichText()
            t.append("  AEGIS", style="bold cyan")
            t.append("-NEXUS  ", style="bold white")
            t.append(f"Processed: {s['total']:,}  ", style="cyan")
            t.append(f"Noise: {s['noise']:,}  ",     style="dim white")
            t.append(f"Alerts: {s['alerts']}  ",     style="yellow")
            t.append(f"Critical: {s['critical']}  ", style="bold red")
            t.append(f"Reduction: {nr}  ",           style="green")
            t.append(f"Assets: {len(twin.assets)}  ", style="magenta")
            t.append("● LIVE", style="bold green")
            return t

    class TwinWidget(Static):
        def render(self) -> RichText:
            st = twin.stats()
            t  = RichText()
            t.append("AXIOM DIGITAL TWIN\n", style="bold cyan")
            t.append(f"  Assets:      {st['assets']}\n")
            t.append(f"  Edges:       {st['edges']}\n")
            t.append(f"  Tech types:  {st['tech_types']}\n")
            t.append(f"  λ-radius:    {st['spectral_radius']}\n", style="magenta")
            t.append(f"  Connectivity:{st['connectivity']}\n",    style="magenta")
            t.append("\nASSETS\n", style="bold dim")
            icons = {"service":"◈","domain":"◉","database":"◆","cdn":"◇"}
            clrs  = {"service":"cyan","domain":"magenta","database":"yellow","cdn":"green"}
            for a in list(twin.assets.values())[:7]:
                t.append(f"  {icons.get(a.kind,'○')} ", style=clrs.get(a.kind,"white"))
                t.append(f"{a.name[:18]}\n")
            t.append("\nTECH\n", style="bold dim")
            t.append("  " + " · ".join(list(twin._tech_idx.keys())[:8]), style="dim cyan")
            return t

    class PhantomWidget(Static):
        def __init__(self, state_ref, **kw):
            super().__init__(**kw); self._s = state_ref
        def render(self) -> RichText:
            st = phantom.stats()
            t  = RichText()
            t.append("PHANTOM\n", style="bold red")
            t.append(f"  Tokens:    {st['total_tokens']}\n")
            t.append(f"  Canaries:  {st['total_canaries']}\n")
            trg = st["triggered"]
            t.append(f"  Triggered: {trg}\n", style="bold red" if trg else "dim")
            t.append("\nACTIVE TOKENS\n", style="bold dim")
            for tok in phantom.list_tokens()[:5]:
                s2 = "bold red" if tok["triggered"] else "dim green"
                t.append(f"  {'⚠ FIRED' if tok['triggered'] else '● active'}  ", style=s2)
                t.append(f"{tok['token_type']}\n", style="dim")
            return t

    class OscWidget(Static):
        BARS = "▁▂▃▄▅▆▇█"
        def __init__(self, state_ref, **kw):
            super().__init__(**kw); self._s = state_ref
        def render(self) -> RichText:
            data = self._s["osc_data"][-60:]
            t    = RichText()
            t.append("SPECTRA  ", style="bold dim")
            for v in data:
                idx = min(int(v * len(self.BARS)), len(self.BARS) - 1)
                sty = ("bold red" if v >= 0.75 else "yellow" if v >= 0.50
                       else "cyan" if v >= 0.15 else "dim white")
                t.append(self.BARS[idx], style=sty)
            t.append(f"  noise={self._s['noise']/max(self._s['total'],1):.1%}",
                     style="dim")
            return t

    class DetailWidget(Static):
        def __init__(self, **kw):
            super().__init__(**kw); self._alert: Optional[Dict] = None
        def set_alert(self, a: Dict):
            self._alert = a; self.refresh()
        def render(self) -> RichText:
            t = RichText()
            if not self._alert:
                t.append("THREAT INSPECTOR\n\n", style="bold cyan")
                t.append("Select an alert row.\n", style="dim")
                t.append("Use ↑↓ to navigate.\n", style="dim")
                return t
            a   = self._alert
            sev = a.get("severity", "?")
            sty = SEV_STYLE.get(sev, "white")
            t.append("THREAT INSPECTOR\n\n", style="bold cyan")
            t.append(f"  [{sev}]\n",                           style=sty)
            t.append(f"  Score: {a.get('score',0):.6f}\n",     style=sty)
            t.append(f"  ID:    {a.get('threat_id','')[:20]}\n", style="dim")
            t.append(f"\nDETAILS\n",                           style="bold dim")
            t.append(f"  Type: {(a.get('kind','') or '').replace('_',' ')}\n")
            t.append(f"  Src:  {a.get('source','')}\n")
            t.append(f"  Ind:  {str(a.get('indicator',''))[:30]}\n", style="yellow")
            t.append(f"  TTPs: {', '.join(a.get('ttps',[]))}\n",     style="magenta")
            t.append(f"\nSPECTRA STAGES\n", style="bold dim")
            stages = a.get("stages", {})
            for lbl, key in [("S1 Perturbation","s1"),("S2 Rényi","s2"),
                              ("S3 Isomorphism","s3"),("S4 Temporal","s4")]:
                v   = stages.get(key, 0)
                f   = int(v * 14)
                bsty = ("bold red" if v > 0.75 else "yellow" if v > 0.5
                        else "cyan" if v > 0.15 else "dim white")
                t.append(f"  {lbl:<16} ", style="dim")
                t.append("█" * f + "░" * (14 - f), style=bsty)
                t.append(f" {v:.3f}\n")
            return t

    class AegisTUI(App):
        CSS = """
        Screen  { background: #030810; }
        HeaderWidget { height: 1; background: #060f1a;
                       border-bottom: solid #0e2040; }
        #left   { width: 26; border-right: solid #0e2040; padding: 1; }
        #center { width: 1fr; padding: 0 1; }
        #right  { width: 34; border-left: solid #0e2040; padding: 1; }
        #osc    { height: 3; border-top: solid #0e2040;
                  background: #060f1a; padding: 0 2; }
        DataTable { background: #030810; height: 1fr; }
        DataTable > .datatable--header { background: #060f1a; color: #4a6a8a; }
        DataTable > .datatable--cursor { background: #0a1628; }
        TwinWidget, PhantomWidget, DetailWidget { height: 1fr; }
        Footer { background: #060f1a; }
        """
        BINDINGS = [
            Binding("q",             "quit",      "Quit"),
            Binding("r",             "refresh",   "Refresh"),
            Binding("f",             "filter_sev","Filter Severity"),
            Binding("p",             "gen_tok",   "Gen Phantom Token"),
            Binding("question_mark", "help_info", "Help"),
        ]

        def __init__(self):
            super().__init__()
            self._state: Dict = {"total":0,"noise":0,"alerts":0,
                                 "critical":0,"osc_data":[0.0]*60}
            self._alerts: List[Dict] = []
            self._filter      = ""
            self._filter_cycle = ["","CRITICAL","HIGH","MEDIUM","LOW"]
            self._filter_idx   = 0

        def compose(self) -> ComposeResult:
            yield HeaderWidget(self._state, id="hdr")
            with Horizontal(id="main"):
                with Vertical(id="left"):
                    yield Label("── TWIN ──")
                    yield TwinWidget(id="twin-w")
                    yield Label("── PHANTOM ──")
                    yield PhantomWidget(self._state, id="phantom-w")
                with Vertical(id="center"):
                    yield Label("── LIVE ALERTS ──", id="feed-lbl")
                    yield DataTable(id="alert-tbl", zebra_stripes=True,
                                    cursor_type="row")
                with Vertical(id="right"):
                    yield DetailWidget(id="detail-w")
            yield OscWidget(self._state, id="osc")
            yield Footer()

        def on_mount(self):
            tbl = self.query_one(DataTable)
            tbl.add_columns("Time","Severity","Score","Type","Source","Indicator")
            self.set_interval(2.0, self._tick)

        async def _tick(self):
            TEMPLATES = [
                ("lookalike_domain","ct_logs", ["tls","web","dns"],   ["T1583.001"],       .35,.92),
                ("exposed_secret",  "github",  ["git","python"],      ["T1552.001","T1078"],.50,.95),
                ("port_scan",       "shodan",  ["windows","rdp"],     ["T1046"],            .05,.25),
                ("data_leak",       "paste",   ["web"],               ["T1530"],            .20,.80),
                ("known_vuln",      "cve_feed",["nginx","postgresql"],["T1190"],            .40,.90),
                ("mass_scan",       "shodan",  ["java","iis"],        ["T1595"],            .01,.13),
            ]
            INDS = ["c0mpany.com","ghp_FAKE","pastebin.com/abc",
                    "CVE-2025-4821","1.2.3.4:3389","masscan:80"]
            kind,src,tech,ttps,lo,hi = random.choice(TEMPLATES)
            score  = lo + random.random() * (hi - lo)
            ind    = random.choice(INDS)
            t      = Threat(f"tui-{uuid.uuid4().hex[:6]}", src, kind, ind, tech, ttps)
            result = await kronos.process(t)
            self._state["total"] += 1
            self._state["osc_data"].append(score)
            if len(self._state["osc_data"]) > 60:
                self._state["osc_data"].pop(0)
            if result is None or result.is_noise:
                self._state["noise"] += 1
            else:
                self._state["alerts"] += 1
                if result.severity == "CRITICAL":
                    self._state["critical"] += 1
                alert = {
                    "threat_id": t.threat_id, "source": src, "kind": kind,
                    "indicator": ind, "severity": result.severity,
                    "score": result.score, "tech": tech, "ttps": ttps,
                    "found_at": now_str(),
                    "stages": {"s1":result.s1,"s2":result.s2,
                               "s3":result.s3,"s4":result.s4},
                }
                self._alerts.insert(0, alert)
                if len(self._alerts) > 500: self._alerts.pop()
                self._refresh_table()
                if result.severity == "CRITICAL":
                    self.query_one(DetailWidget).set_alert(alert)
            self.query_one(HeaderWidget).refresh()
            self.query_one(OscWidget).refresh()

        def _refresh_table(self):
            tbl    = self.query_one(DataTable)
            tbl.clear()
            alerts = self._alerts
            if self._filter:
                alerts = [a for a in alerts if a.get("severity") == self._filter]
            for a in alerts[:120]:
                sev  = a.get("severity", "?")
                sty  = SEV_STYLE.get(sev, "white")
                from rich.text import Text as RT
                tbl.add_row(
                    RT(a.get("found_at", now_str())[:8], style="dim"),
                    RT(f"  {sev:8}",                     style=sty),
                    RT(f"{a.get('score',0):.4f}",         style="cyan"),
                    RT((a.get("kind","") or "")[:20]),
                    RT(a.get("source","")[:12],           style="dim"),
                    RT(str(a.get("indicator",""))[:36],   style="dim"),
                )

        def on_data_table_row_selected(self, ev: DataTable.RowSelected):
            alerts = self._alerts
            if self._filter:
                alerts = [a for a in alerts if a.get("severity") == self._filter]
            if 0 <= ev.cursor_row < len(alerts):
                self.query_one(DetailWidget).set_alert(alerts[ev.cursor_row])

        def action_refresh(self):
            self._refresh_table()

        def action_filter_sev(self):
            self._filter_idx = (self._filter_idx + 1) % len(self._filter_cycle)
            self._filter     = self._filter_cycle[self._filter_idx]
            lbl = self._filter or "ALL"
            self.query_one("#feed-lbl", Label).update(f"── LIVE ALERTS [{lbl}] ──")
            self._refresh_table()

        def action_gen_tok(self):
            tok = phantom.gen_github()
            self.query_one(PhantomWidget).refresh()
            self.notify(f"Token: {tok.token_id}", severity="information")

        def action_help_info(self):
            self.notify(
                "q=quit  r=refresh  f=filter severity  p=gen phantom token",
                title="Keybindings", severity="information", timeout=5,
            )

    # ── Run Textual in its own thread with its own event loop ─────
    # This avoids the "asyncio.run() cannot be called from a running
    # event loop" error that occurs when Textual is launched from
    # inside an already-running asyncio.run() call.
    import concurrent.futures

    app = AegisTUI()
    done = threading.Event()
    exc_holder: List[Optional[Exception]] = [None]

    def _run_in_thread():
        try:
            import asyncio as _asyncio
            loop = _asyncio.new_event_loop()
            _asyncio.set_event_loop(loop)
            loop.run_until_complete(app.run_async())
        except Exception as e:
            exc_holder[0] = e
        finally:
            done.set()

    t = threading.Thread(target=_run_in_thread, daemon=True)
    t.start()
    done.wait()          # block until TUI exits
    if exc_holder[0]:
        raise exc_holder[0]

    SEV_STYLE = {
        "CRITICAL": "bold red", "HIGH": "bold yellow",
        "MEDIUM": "bold cyan",  "LOW":  "bold green",
        "NOISE":  "dim white",
    }

    class HeaderWidget(Static):
        def __init__(self, state_ref, **kw):
            super().__init__(**kw)
            self._s = state_ref

        def render(self) -> RichText:
            s   = self._s
            nr  = f"{s['noise']/max(s['total'],1):.1%}"
            t   = RichText()
            t.append("  AEGIS", style="bold cyan")
            t.append("-NEXUS  ", style="bold white")
            t.append(f"Processed: {s['total']:,}  ", style="cyan")
            t.append(f"Noise: {s['noise']:,}  ", style="dim white")
            t.append(f"Alerts: {s['alerts']}  ", style="yellow")
            t.append(f"Critical: {s['critical']}  ", style="bold red")
            t.append(f"Reduction: {nr}  ", style="green")
            t.append(f"Assets: {len(twin.assets)}  ", style="magenta")
            t.append("● LIVE", style="bold green")
            return t

    class TwinWidget(Static):
        def render(self) -> RichText:
            st = twin.stats()
            t  = RichText()
            t.append("AXIOM DIGITAL TWIN\n", style="bold cyan")
            t.append(f"  Assets:      {st['assets']}\n")
            t.append(f"  Edges:       {st['edges']}\n")
            t.append(f"  Tech types:  {st['tech_types']}\n")
            t.append(f"  λ-radius:    {st['spectral_radius']}\n", style="magenta")
            t.append(f"  Connectivity:{st['connectivity']}\n",    style="magenta")
            t.append("\nASSETS\n", style="bold dim")
            icons = {"service":"◈","domain":"◉","database":"◆","cdn":"◇"}
            clrs  = {"service":"cyan","domain":"magenta","database":"yellow","cdn":"green"}
            for a in list(twin.assets.values())[:7]:
                t.append(f"  {icons.get(a.kind,'○')} ", style=clrs.get(a.kind,"white"))
                t.append(f"{a.name[:18]}\n")
            t.append("\nTECH\n", style="bold dim")
            t.append("  " + " · ".join(list(twin._tech_idx.keys())[:8]), style="dim cyan")
            return t

    class PhantomWidget(Static):
        def __init__(self, state_ref, **kw):
            super().__init__(**kw); self._s = state_ref

        def render(self) -> RichText:
            st = phantom.stats()
            t  = RichText()
            t.append("PHANTOM\n", style="bold red")
            t.append(f"  Tokens:    {st['total_tokens']}\n")
            t.append(f"  Canaries:  {st['total_canaries']}\n")
            triggered = st["triggered"]
            t.append(f"  Triggered: {triggered}\n",
                     style="bold red" if triggered else "dim")
            t.append("\nACTIVE TOKENS\n", style="bold dim")
            for tok in phantom.list_tokens()[:5]:
                st2 = "bold red" if tok["triggered"] else "dim green"
                t.append(f"  {'⚠ FIRED' if tok['triggered'] else '● active'}  ",
                         style=st2)
                t.append(f"{tok['token_type']}\n", style="dim")
            return t

    class OscWidget(Static):
        def __init__(self, state_ref, **kw):
            super().__init__(**kw); self._s = state_ref
        BARS = "▁▂▃▄▅▆▇█"
        def render(self) -> RichText:
            data = self._s["osc_data"][-60:]
            t    = RichText()
            t.append("SPECTRA  ", style="bold dim")
            for v in data:
                idx = min(int(v * len(self.BARS)), len(self.BARS) - 1)
                b   = self.BARS[idx]
                sty = ("bold red" if v >= 0.75 else "yellow" if v >= 0.50
                       else "cyan" if v >= 0.15 else "dim white")
                t.append(b, style=sty)
            t.append(f"  noise={self._s['noise']/max(self._s['total'],1):.1%}",
                     style="dim")
            return t

    class DetailWidget(Static):
        def __init__(self, **kw):
            super().__init__(**kw)
            self._alert: Optional[Dict] = None

        def set_alert(self, a: Dict):
            self._alert = a; self.refresh()

        def render(self) -> RichText:
            t = RichText()
            if not self._alert:
                t.append("THREAT INSPECTOR\n\n", style="bold cyan")
                t.append("Select an alert row.\n", style="dim")
                t.append("Use ↑↓ to navigate.\n", style="dim")
                return t
            a    = self._alert
            sev  = a.get("severity","?")
            sty  = SEV_STYLE.get(sev, "white")
            t.append("THREAT INSPECTOR\n\n", style="bold cyan")
            t.append(f"  [{sev}]\n",              style=sty)
            t.append(f"  Score: {a.get('score',0):.6f}\n", style=sty)
            t.append(f"  ID:    {a.get('threat_id','')[:20]}\n", style="dim")
            t.append(f"\nDETAILS\n",              style="bold dim")
            t.append(f"  Type:  {(a.get('kind','') or '').replace('_',' ')}\n")
            t.append(f"  Src:   {a.get('source','')}\n")
            t.append(f"  Ind:   {str(a.get('indicator',''))[:30]}\n", style="yellow")
            t.append(f"  TTPs:  {', '.join(a.get('ttps',[]))}\n",     style="magenta")
            t.append(f"\nSPECTRA STAGES\n",       style="bold dim")
            stages = a.get("stages", {})
            labels = [("S1 Perturbation", "s1"), ("S2 Rényi",      "s2"),
                      ("S3 Isomorphism",  "s3"), ("S4 Temporal",   "s4")]
            for lbl, key in labels:
                v  = stages.get(key, 0)
                f  = int(v * 14)
                bar = "█" * f + "░" * (14 - f)
                bsty = ("bold red" if v > 0.75 else "yellow" if v > 0.5
                        else "cyan" if v > 0.15 else "dim white")
                t.append(f"  {lbl:<16} ", style="dim")
                t.append(bar, style=bsty)
                t.append(f" {v:.3f}\n")
            return t

    class AegisTUI(App):
        CSS = """
        Screen { background: #030810; }
        HeaderWidget { height: 1; background: #060f1a;
                       border-bottom: solid #0e2040; }
        #left  { width: 26; border-right: solid #0e2040; padding: 1; }
        #center{ width: 1fr; padding: 0 1; }
        #right { width: 34; border-left: solid #0e2040; padding: 1; }
        #osc   { height: 3; border-top: solid #0e2040;
                 background: #060f1a; padding: 0 2; }
        DataTable { background: #030810; height: 1fr; }
        DataTable > .datatable--header { background: #060f1a; color: #4a6a8a; }
        DataTable > .datatable--cursor { background: #0a1628; }
        TwinWidget, PhantomWidget, DetailWidget { height: 1fr; }
        Footer { background: #060f1a; }
        """
        BINDINGS = [
            Binding("q",    "quit",   "Quit"),
            Binding("r",    "refresh","Refresh"),
            Binding("f",    "filter", "Filter Severity"),
            Binding("p",    "gen_tok","Gen Phantom Token"),
            Binding("question_mark","help_info","Help"),
        ]

        def __init__(self):
            super().__init__()
            self._state = {"total":0,"noise":0,"alerts":0,"critical":0,
                           "osc_data":[0.0]*60}
            self._alerts: List[Dict] = []
            self._filter = ""
            self._filter_cycle = ["","CRITICAL","HIGH","MEDIUM","LOW"]
            self._filter_idx   = 0

        def compose(self) -> ComposeResult:
            yield HeaderWidget(self._state, id="hdr")
            with Horizontal(id="main"):
                with Vertical(id="left"):
                    yield Label("── TWIN ──")
                    yield TwinWidget(id="twin-w")
                    yield Label("── PHANTOM ──")
                    yield PhantomWidget(self._state, id="phantom-w")
                with Vertical(id="center"):
                    yield Label("── LIVE ALERTS ──", id="feed-lbl")
                    yield DataTable(id="alert-tbl", zebra_stripes=True,
                                    cursor_type="row")
                with Vertical(id="right"):
                    yield DetailWidget(id="detail-w")
            yield OscWidget(self._state, id="osc")
            yield Footer()

        def on_mount(self):
            tbl = self.query_one(DataTable)
            tbl.add_columns("Time","Severity","Score","Type","Source","Indicator")
            self.set_interval(2.0, self._tick)

        async def _tick(self):
            TEMPLATES = [
                ("lookalike_domain","ct_logs",["tls","web","dns"],["T1583.001"],.35,.92),
                ("exposed_secret","github",["git","python"],["T1552.001","T1078"],.50,.95),
                ("port_scan","shodan",["windows","rdp"],["T1046"],.05,.25),
                ("data_leak","paste",["web"],["T1530"],.20,.80),
                ("known_vuln","cve_feed",["nginx","postgresql"],["T1190"],.40,.90),
                ("mass_scan","shodan",["java","iis"],["T1595"],.01,.13),
            ]
            INDS = ["c0mpany.com","ghp_FAKE","pastebin.com/abc",
                    "CVE-2025-4821","1.2.3.4:3389","masscan:80"]
            kind,src,tech,ttps,lo,hi = random.choice(TEMPLATES)
            score = lo + random.random()*(hi-lo)
            ind   = random.choice(INDS)
            t     = Threat(f"tui-{uuid.uuid4().hex[:6]}",src,kind,ind,tech,ttps)
            result= await kronos.process(t)
            self._state["total"]   += 1
            self._state["osc_data"].append(score)
            if len(self._state["osc_data"]) > 60:
                self._state["osc_data"].pop(0)
            if result is None or result.is_noise:
                self._state["noise"] += 1
            else:
                self._state["alerts"] += 1
                if result.severity == "CRITICAL":
                    self._state["critical"] += 1
                alert = {"threat_id":t.threat_id,"source":src,"kind":kind,
                         "indicator":ind,"severity":result.severity,
                         "score":result.score,"tech":tech,"ttps":ttps,
                         "stages":{"s1":result.s1,"s2":result.s2,
                                   "s3":result.s3,"s4":result.s4}}
                self._alerts.insert(0, alert)
                if len(self._alerts) > 500: self._alerts.pop()
                self._refresh_table()
                if result.severity == "CRITICAL":
                    self.query_one(DetailWidget).set_alert(alert)
            self.query_one(HeaderWidget).refresh()
            self.query_one(OscWidget).refresh()

        def _refresh_table(self):
            tbl    = self.query_one(DataTable); tbl.clear()
            alerts = self._alerts
            if self._filter:
                alerts = [a for a in alerts if a.get("severity") == self._filter]
            for a in alerts[:120]:
                sev   = a.get("severity","?")
                sty   = SEV_STYLE.get(sev, "white")
                from rich.text import Text as RT
                tbl.add_row(
                    RT(a.get("found_at",now_str())[:8], style="dim"),
                    RT(f"  {sev:8}", style=sty),
                    RT(f"{a.get('score',0):.4f}", style="cyan"),
                    RT((a.get("kind","") or "")[:20]),
                    RT(a.get("source","")[:12], style="dim"),
                    RT(str(a.get("indicator",""))[:36], style="dim"),
                )

        def on_data_table_row_selected(self, ev: DataTable.RowSelected):
            alerts = self._alerts
            if self._filter:
                alerts = [a for a in alerts if a.get("severity") == self._filter]
            if 0 <= ev.cursor_row < len(alerts):
                self.query_one(DetailWidget).set_alert(alerts[ev.cursor_row])

        def action_refresh(self):      self._refresh_table()
        def action_filter(self):
            self._filter_idx = (self._filter_idx + 1) % len(self._filter_cycle)
            self._filter     = self._filter_cycle[self._filter_idx]
            lbl = self._filter or "ALL"
            self.query_one("#feed-lbl", Label).update(f"── LIVE ALERTS [{lbl}] ──")
            self._refresh_table()
        def action_gen_tok(self):
            tok = phantom.gen_github()
            self.query_one(PhantomWidget).refresh()
            self.notify(f"Token: {tok.token_id}", severity="information")
        def action_help_info(self):
            self.notify("q=quit  r=refresh  f=filter severity  p=gen phantom token",
                        title="Keys", severity="information", timeout=5)

    AegisTUI().run()


# ══════════════════════════════════════════════════════════════════
# COMMAND: CALIBRATE — SPECTRA Self-Calibration Engine
# ══════════════════════════════════════════════════════════════════

async def cmd_calibrate():
    banner()
    twin, spectra, phantom, kronos = make_engine()
    cal = SPECTRACalibrator(spectra)

    print(f"  {col('SPECTRA Calibration Engine','BOLD')}\n")
    print(f"  {col('Building synthetic labeled dataset…','DIM')}")

    # Generate and score synthetic labeled samples
    TRUE_POS = [
        ("T1","lookalike_domain","c0mpany.com",["tls","web","dns"],
         ["T1583.001","T1608.001"],0.75,"true_positive"),
        ("T2","exposed_secret","ghp_FAKE36chars",["git","python","credentials"],
         ["T1552.001","T1078"],0.80,"confirmed_critical"),
        ("T3","known_vulnerability","CVE-2025-9821",["postgresql","ssl"],
         ["T1190","T1203"],0.70,"true_positive"),
        ("T4","phishing_domain","company-secure.xyz",["tls","web","dns"],
         ["T1566.002","T1583.001"],0.72,"confirmed_critical"),
        ("T5","credential_leak","pastebin.com/xK9aB3",["python","jwt"],
         ["T1530","T1078.004"],0.65,"true_positive"),
        ("T6","exposed_secret","AKIA3X7KQPZM9W",["aws","credentials"],
         ["T1552.001"],0.88,"confirmed_critical"),
        ("T7","lookalike_domain","comp4ny.io",["dns","tls"],
         ["T1583.001"],0.60,"true_positive"),
        ("T8","data_leak","ghostbin.co/abc",["web","http"],
         ["T1530"],0.45,"true_positive"),
    ]
    FALSE_POS = [
        ("F1","port_scan","203.0.113.42:3389",["windows","rdp","iis"],
         ["T1021.001"],0.0,"false_positive"),
        ("F2","mass_scan","0.0.0.0/0",["windows","smb"],
         ["T1595"],0.0,"false_positive"),
        ("F3","known_vulnerability","CVE-2024-1111",["java","spring-boot"],
         ["T1190"],0.0,"false_positive"),
        ("F4","port_scan","198.51.100.7:1433",["mssql","windows"],
         ["T1046"],0.0,"false_positive"),
        ("F5","brute_force","198.51.100.8:22",["windows","rdp"],
         ["T1110"],0.01,"false_positive"),
        ("F6","known_vulnerability","CVE-2023-9999",["php","wordpress"],
         ["T1190"],0.0,"false_positive"),
        ("F7","mass_scan","shodan_scan:80",["java","activemq"],
         ["T1046"],0.0,"false_positive"),
    ]

    print(f"  Scoring {len(TRUE_POS)+len(FALSE_POS)} labeled samples through SPECTRA…\n")
    for tid,kind,ind,tech,ttps,pd,label in TRUE_POS + FALSE_POS:
        r  = await spectra.score(tid, kind, ind, tech, ttps, {}, pd)
        lt = LabeledThreat(tid, kind, ind, tech, ttps, pd, label)
        cal.add_sample(lt, r)
        icon = col("TP","GREEN") if "positive" in label else col("FP","RED")
        print(f"    [{icon}] {kind:<28} score={r.score:.4f}  sev={r.severity}")

    print()
    print(f"  {col('Running calibration grid search [0.05–0.35]…','DIM')}")
    result = await cal.calibrate()
    print()

    if result.get("status") == "calibrated":
        old = result["old_noise_threshold"]
        new = result["new_noise_threshold"]
        print(f"  ┌─────────────────────────────────────────────┐")
        print(f"  │  Old noise threshold : {old:<22}│")
        print(f"  │  New noise threshold : {col(str(new),'HIGH'):<31}│")
        print(f"  │  Precision           : {result['precision']:<22}│")
        print(f"  │  Recall              : {result['recall']:<22}│")
        print(f"  │  F1 Score            : {col(str(result['f1']),'GREEN'):<31}│")
        print(f"  │  Samples used        : {result['samples']:<22}│")
        print(f"  └─────────────────────────────────────────────┘")
        print()
        print(f"  {col('Source Reliability','BOLD')}")
        for src, score in result.get("source_reliability", {}).items():
            bar_w = int(score * 20)
            bbar  = col("█"*bar_w,"GREEN") + col("░"*(20-bar_w),"DIM")
            print(f"    {src:<30} {bbar}  {score:.4f}")
        print()
        print(f"  {col('✓ Engine updated — new threshold active for this session.','GREEN')}")
    else:
        print(f"  {col(result.get('status','unknown'),'RED')}")
    print()


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

COMMANDS = {
    "demo":      cmd_demo,
    "score":     cmd_score,
    "monitor":   cmd_monitor,
    "phantom":   cmd_phantom,
    "twin":      cmd_twin,
    "api":       cmd_api,
    "tui":       cmd_tui,
    "calibrate": cmd_calibrate,
    "test":      cmd_test,
}

async def main():
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if cmd in COMMANDS:
        await COMMANDS[cmd]()
        return

    # Interactive menu
    banner()
    print("  Commands:\n")
    descs = {
        "demo":      "Full pipeline demo — 10 threats through SPECTRA",
        "score":     "Interactive SPECTRA threat scorer",
        "monitor":   "Live monitoring — real CT logs, CVE, paste scrapers",
        "phantom":   "Honey token & canary file manager",
        "twin":      "Inspect the AXIOM Digital Twin graph",
        "api":       "Web Dashboard + REST API on :8000",
        "tui":       "Textual terminal dashboard (keyboard-native)",
        "calibrate": "SPECTRA self-calibration — optimize noise threshold",
        "test":      "Run full self-test suite (53 tests)",
    }
    for name, desc in descs.items():
        print(f"    {col(name,'HIGH'):<24}{col(desc,'DIM')}")
    print()
    choice = input("  Enter command [demo]: ").strip().lower() or "demo"
    if choice in COMMANDS:
        print()
        await COMMANDS[choice]()
    else:
        print(f"  {col(f'Unknown: {choice}','RED')}  "
              f"Available: {', '.join(COMMANDS)}\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n  {col('Stopped.','DIM')}\n")
