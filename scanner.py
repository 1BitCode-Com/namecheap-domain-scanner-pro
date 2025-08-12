#!/usr/bin/env python3
"""
Advanced Namecheap scanner with:
- Multi-TLD support (e.g., com/net/io) via scanner.tlds in config
- Network preflight & proxies
- Generators (lexicographic/phonetic/dictionary/markov)
- SQLite with resume, scoring, skip rules, RDAP fallback, alerts, sharding, adaptive RPM, warm-up, dry-run

Comments are in English by project convention.
"""

import argparse
import os
import time
import random
import re
import sqlite3
import sys
import logging
import json
from logging.handlers import RotatingFileHandler
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Dict

import requests
import yaml

# Import REVOLUTIONARY NEURAL AI name generator
try:
    from ai_name_generator_neural import AINameGeneratorNeural
    AI_AVAILABLE = True
    print("REVOLUTIONARY NEURAL AI SYSTEM LOADED - 2025 NEUROSCIENCE")
except ImportError as e:
    print(f"Warning: Neural AI name generator not available: {e}")
    AI_AVAILABLE = False

NC_XML_NS = "{http://api.namecheap.com/xml.response}"

class NamecheapAPIError(Exception):
    pass

class RateLimitedError(NamecheapAPIError):
    pass


# ------------------------------- Config dataclasses -------------------------------

@dataclass
class APIConfig:
    user: str
    key: str
    username: str
    client_ip: str
    sandbox: bool


@dataclass
class ScanConfig:
    min_length: int
    max_length: int
    prefix: str
    suffix: str
    include_letters: bool
    include_digits: bool
    include_hyphen: bool
    letters: str
    digits: str
    batch_size: int
    requests_per_minute: int
    show_premium: bool
    db_path: str
    csv_path: str
    stop_after: int
    mode: str
    phonetic: dict
    blacklist_substrings: list
    blacklist_regex: list
    scoring: dict
    skip_rules: dict
    rdap: dict
    alerts: dict
    priority_queue_path: str
    sharding: dict
    rpm_bounds: dict
    dry_run: bool
    warmup: dict
    network: dict
    tlds: list
    logging: dict
    safety: dict


# ------------------------------- Network helpers -------------------------------

def session_with_proxies(proxies: dict) -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    px = {}
    if proxies:
        if proxies.get("http"):
            px["http"] = proxies["http"]
        if proxies.get("https"):
            px["https"] = proxies["https"]
        if proxies.get("no_proxy"):
            os.environ["NO_PROXY"] = proxies["no_proxy"]
    if px:
        s.proxies.update(px)
    return s


def extract_ipv4(text: str) -> Optional[str]:
    m = re.search(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b", text)
    return m.group(0) if m else None


def get_public_ipv4(session: requests.Session, url: str, timeout: int = 10) -> Optional[str]:
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        ip = extract_ipv4(r.text.strip())
        return ip
    except Exception:
        return None


# ------------------------------- Helper clients -------------------------------

class NamecheapClient:
    def __init__(self, api: APIConfig, proxies: dict):
        self.api = api
        self.session = session_with_proxies(proxies)
        self.base = "https://api.sandbox.namecheap.com" if api.sandbox else "https://api.namecheap.com"

    def check(self, domains: List[str]):
        params = {
            "ApiUser": self.api.user,
            "ApiKey": self.api.key,
            "UserName": self.api.username,
            "ClientIp": self.api.client_ip,
            "Command": "namecheap.domains.check",
            "DomainList": ",".join(domains),
        }
        url = f"{self.base}/xml.response"
        r = self.session.get(url, params=params, timeout=30)
        r.raise_for_status()

        available = []
        checked = []
        pricing = {}

        root = ET.fromstring(r.text)
        # Early error detection from XML response
        xml_errors = root.findall(f".//{NC_XML_NS}Errors/{NC_XML_NS}Error")
        if xml_errors:
            messages = []
            for e in xml_errors:
                code = e.attrib.get("Number", "?")
                msg = (e.text or "").strip()
                messages.append(f"{code}:{msg}")
            full_msg = "; ".join(messages)
            low = full_msg.lower()
            if any(k in low for k in ["too many", "limit", "throttle", "exceed"]):
                raise RateLimitedError(full_msg)
            raise NamecheapAPIError(full_msg)
        results = root.findall(f".//{NC_XML_NS}DomainCheckResult")
        if not results:
            log = logging.getLogger("scanner")
            errs = root.findall(f".//{NC_XML_NS}Errors/{NC_XML_NS}Error")
            if errs:
                for e in errs:
                    code = e.attrib.get("Number", "?")
                    msg = (e.text or "").strip()
                    log.error("[API ERROR] code=%s msg=%s", code, msg)
            else:
                snippet = r.text[:300].replace("\n"," ")
                log.warning("[API WARN] No DomainCheckResult. XML snippet: %s", snippet)
        for elem in results:
            domain = elem.attrib.get("Domain", "").lower()
            available_flag = elem.attrib.get("Available", "false").lower() == "true"
            is_premium = elem.attrib.get("IsPremiumName", "false").lower() == "true"

            def to_float(x):
                try:
                    return float(x)
                except Exception:
                    return None
            pricing[domain] = {
                "premium_registration_price": to_float(elem.attrib.get("PremiumRegistrationPrice")),
                "premium_renewal_price": to_float(elem.attrib.get("PremiumRenewalPrice")),
                "premium_restore_price": to_float(elem.attrib.get("PremiumRestorePrice")),
                "premium_transfer_price": to_float(elem.attrib.get("PremiumTransferPrice")),
                "icann_fee": to_float(elem.attrib.get("IcannFee")),
                "eap_fee": to_float(elem.attrib.get("EapFee")),
            }

            if available_flag:
                available.append(domain)
            checked.append((domain, is_premium))

        return available, checked, pricing



class RDAPClient:
    """
    Dynamic RDAP resolver using IANA bootstrap (dns.json).
    - Supports (almost) all RDAP-enabled TLDs without hardcoding.
    - Optional `overrides` in config to force a base URL for certain TLDs.
    - Caches the bootstrap file on disk and refreshes periodically.
    - Returns True/False/None for available/registered/unknown.
    """

    def __init__(self, enabled: bool, rpm: int, proxies: dict, bootstrap_cfg: dict = None, overrides: dict = None, logger=None, logging_cfg: dict = None):
        self.enabled = enabled
        self.session = session_with_proxies(proxies)
        self.interval = 60.0 / max(1, rpm)
        self._last_call = 0.0

        self.bootstrap_cfg = bootstrap_cfg or {}
        self.overrides = {k.lower(): v for k, v in (overrides or {}).items()}
        self.logger = logger
        self.logging_cfg = logging_cfg

        self.bootstrap_map = {}  # tld -> base_url
        if self.enabled:
            self._load_bootstrap()

    def _load_bootstrap(self):
        url = self.bootstrap_cfg.get("url", "https://data.iana.org/rdap/dns.json")
        cache_path = self.bootstrap_cfg.get("cache_path", "rdap_bootstrap_cache.json")
        refresh_hours = int(self.bootstrap_cfg.get("refresh_hours", 24))

        # if cache exists and is fresh, load it
        try:
            if os.path.exists(cache_path):
                mtime = os.path.getmtime(cache_path)
                import time
                if (time.time() - mtime) < refresh_hours * 3600:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self.bootstrap_map = data.get("_map", {})
                    if self.logger: self.logger.info("RDAP bootstrap loaded from cache | tlds=%d", len(self.bootstrap_map))
                    return
        except Exception:
            pass

        # fetch from IANA
        try:
            r = self.session.get(url, timeout=20)
            r.raise_for_status()
            data = r.json()
            # data["services"] is a list of [ [tlds...], [urls...] ]
            mapping = {}
            for service in data.get("services", []):
                tlds = [t.strip().lower() for t in (service[0] or [])]
                urls = [u.strip().rstrip("/") for u in (service[1] or [])]
                if not tlds or not urls:
                    continue
                # pick the first URL as default base for the tld
                for tld in tlds:
                    mapping[tld] = urls[0]
            self.bootstrap_map = mapping
            # write cache
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump({"_map": mapping}, f)
            except Exception:
                pass
            if self.logger: self.logger.info("RDAP bootstrap fetched | tlds=%d", len(self.bootstrap_map))
        except Exception as e:
            if self.logger: self.logger.warning("RDAP bootstrap fetch failed | error=%s", str(e))

    def _rdap_base_for_tld(self, tld: str) -> str:
        tld = (tld or "").lower().lstrip(".")
        # explicit override first
        if tld in self.overrides and self.overrides[tld]:
            return self.overrides[tld].rstrip("/")
        # fallback to bootstrap map
        return (self.bootstrap_map or {}).get(tld)

    def _domain_url(self, base: str, domain: str) -> str:
        # RDAP domain resource path is usually "<base>/domain/<fqdn>"
        base = base.rstrip("/")
        if base.endswith("/domain") or base.endswith("/domain/"):
            return f"{base.rstrip('/')}/{domain}"
        return f"{base}/domain/{domain}"

    def check(self, domain: str) -> Optional[bool]:
        if not self.enabled:
            return None
        # Throttle
        since = time.time() - self._last_call
        if since < self.interval:
            time.sleep(self.interval - since)
        self._last_call = time.time()

        tld = domain.split(".")[-1].lower()
        base = self._rdap_base_for_tld(tld)
        if not base:
            if self.logger: self.logger.debug("RDAP not available for TLD | tld=%s", tld)
            return None

        url = self._domain_url(base, domain)
        try:
            r = self.session.get(url, timeout=20)
            if r.status_code == 404:
                if self.logger: self.logger.debug("RDAP 404 (available) | %s", domain)
                jsonl_emit(self.logging_cfg, "rdap_check", {"domain": domain, "status": 404})
                return True
            if r.status_code == 200:
                if self.logger: self.logger.debug("RDAP 200 (registered) | %s", domain)
                jsonl_emit(self.logging_cfg, "rdap_check", {"domain": domain, "status": 200})
                return False
            if self.logger: self.logger.debug("RDAP unknown status | %s -> %s", domain, r.status_code)
            return None
        except Exception as e:
            if self.logger: self.logger.debug("RDAP error | %s -> %s", domain, str(e))
            return None


# ------------------------------- Storage -------------------------------

class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        self._ensure_columns()

    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                sld TEXT,
                tld TEXT,
                length INTEGER,
                has_digit INTEGER,
                has_hyphen INTEGER,
                score REAL DEFAULT 0,
                is_available INTEGER NOT NULL,
                is_premium INTEGER NOT NULL,
                premium_registration_price REAL,
                premium_renewal_price REAL,
                premium_restore_price REAL,
                premium_transfer_price REAL,
                icann_fee REAL,
                eap_fee REAL,
                rdap_checked INTEGER DEFAULT 0,
                rdap_available INTEGER,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_available ON domains(is_available);
            CREATE INDEX IF NOT EXISTS idx_score ON domains(score);
            CREATE INDEX IF NOT EXISTS idx_tld ON domains(tld);

            CREATE TABLE IF NOT EXISTS progress (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_word TEXT,
                length INTEGER,
                prefix TEXT,
                suffix TEXT,
                min_length INTEGER,
                max_length INTEGER,
                alphabet TEXT,
                mode TEXT,
                patterns TEXT,
                cursor INTEGER DEFAULT 0,
                shard_prefix TEXT
            );

            CREATE TABLE IF NOT EXISTS priority_queue (
                sld TEXT PRIMARY KEY,
                inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS work_leases (
                key TEXT PRIMARY KEY,
                worker_id TEXT,
                lease_until INTEGER,
                meta TEXT
            );

            CREATE TABLE IF NOT EXISTS feedback (
                domain TEXT PRIMARY KEY,
                label TEXT,
                noted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS model_bigrams (
                bigram TEXT PRIMARY KEY,
                weight REAL DEFAULT 0
            );
            """
        )
        self.conn.commit()

    def _ensure_columns(self):
        # add tld column if missing
        cur = self.conn.execute("PRAGMA table_info(domains)")
        cols = [r[1] for r in cur.fetchall()]
        if "tld" not in cols:
            self.conn.execute("ALTER TABLE domains ADD COLUMN tld TEXT")
            self.conn.commit()

    def import_priority(self, path: str):
        if not path or not os.path.exists(path):
            return 0
        added = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                sld = line.strip().lower()
                if not sld or sld.startswith("#"):
                    continue
                try:
                    self.conn.execute("INSERT OR IGNORE INTO priority_queue(sld) VALUES (?)", (sld,))
                    added += 1
                except sqlite3.Error:
                    pass
        self.conn.commit()
        return added

    def pop_priority_batch(self, n: int) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT sld FROM priority_queue ORDER BY inserted_at ASC LIMIT ?", (n,))
        rows = [r[0] for r in cur.fetchall()]
        if rows:
            cur.executemany("DELETE FROM priority_queue WHERE sld = ?", [(r,) for r in rows])
            self.conn.commit()
        return rows

    def claim_lease(self, worker_id: str, prefixes: List[str], lease_seconds: int) -> List[str]:
        if not prefixes:
            return []
        now = int(time.time())
        claimed = []
        for p in prefixes:
            try:
                row = self.conn.execute("SELECT lease_until FROM work_leases WHERE key = ?", (p,)).fetchone()
                if row is None or row[0] < now:
                    until = now + lease_seconds
                    self.conn.execute(
                        "INSERT OR REPLACE INTO work_leases(key, worker_id, lease_until, meta) VALUES (?,?,?,?)",
                        (p, worker_id, until, "{}"),
                    )
                    claimed.append(p)
            except sqlite3.Error:
                pass
        self.conn.commit()
        return claimed

    def save_checked(self, items: List[Tuple[str, bool]], available_set: set, pricing: dict, scorer) -> None:
        cur = self.conn.cursor()
        for domain, is_premium in items:
            parts = domain.split(".")
            tld = parts[-1] if len(parts) > 1 else ""
            sld = ".".join(parts[:-1])
            if sld.endswith("."):  # safety
                sld = sld[:-1]
            length = len(sld)
            has_digit = 1 if any(c.isdigit() for c in sld) else 0
            has_hyphen = 1 if "-" in sld else 0
            score = scorer(sld) if scorer else 0.0
            pr = pricing.get(domain, {})
            try:
                cur.execute(
                    """INSERT OR IGNORE INTO domains(
                        domain, sld, tld, length, has_digit, has_hyphen, score,
                        is_available, is_premium,
                        premium_registration_price, premium_renewal_price,
                        premium_restore_price, premium_transfer_price,
                        icann_fee, eap_fee
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        domain, sld, tld, length, has_digit, has_hyphen, score,
                        1 if domain in available_set else 0, 1 if is_premium else 0,
                        pr.get("premium_registration_price"),
                        pr.get("premium_renewal_price"),
                        pr.get("premium_restore_price"),
                        pr.get("premium_transfer_price"),
                        pr.get("icann_fee"),
                        pr.get("eap_fee"),
                    ),
                )
            except sqlite3.Error:
                pass
        self.conn.commit()

    def mark_rdap(self, domain: str, avail: Optional[bool]):
        try:
            self.conn.execute(
                "UPDATE domains SET rdap_checked=1, rdap_available=? WHERE domain = ?",
                (None if avail is None else (1 if avail else 0), domain),
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def is_checked(self, domain: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (domain,))
        return cur.fetchone() is not None

    def get_progress(self) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[str], Optional[int], Optional[str]]:
        cur = self.conn.execute("SELECT last_word, length, alphabet, mode, patterns, cursor, shard_prefix FROM progress WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            return None, None, None, None, None, None, None
        return row

    def set_progress(self, last_word: str, length: int, alphabet: str, meta: dict, cursor: int = 0, shard_prefix: Optional[str] = None):
        self.conn.execute(
            """
            INSERT INTO progress(id, last_word, length, prefix, suffix, min_length, max_length, alphabet, mode, patterns, cursor, shard_prefix)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              last_word=excluded.last_word,
              length=excluded.length,
              prefix=excluded.prefix,
              suffix=excluded.suffix,
              min_length=excluded.min_length,
              max_length=excluded.max_length,
              alphabet=excluded.alphabet,
              mode=excluded.mode,
              patterns=excluded.patterns,
              cursor=excluded.cursor,
              shard_prefix=excluded.shard_prefix
            """,
            (
                last_word, length, meta["prefix"], meta["suffix"],
                meta["min_length"], meta["max_length"], alphabet,
                meta.get("mode", "lexicographic"),
                ",".join(meta.get("patterns", [])),
                cursor, shard_prefix
            ),
        )
        self.conn.commit()

    def validate_space(self, meta: dict) -> None:
        cur = self.conn.execute("SELECT prefix, suffix, min_length, max_length, alphabet, mode, patterns FROM progress WHERE id=1")
        row = cur.fetchone()
        if row is None:
            return
        (pfx, sfx, mn, mx, alph, mode, patterns) = row
        mismatch = []
        if pfx != meta["prefix"]:
            mismatch.append(f"prefix: db={pfx} cfg={meta['prefix']}")
        if sfx != meta["suffix"]:
            mismatch.append(f"suffix: db={sfx} cfg={meta['suffix']}")
        if mn != meta["min_length"] or mx != meta["max_length"]:
            mismatch.append(f"lengths: db=({mn},{mx}) cfg=({meta['min_length']},{meta['max_length']})")
        if alph != meta["alphabet"]:
            mismatch.append("alphabet differs")
        if (mode or "lexicographic") != meta.get("mode", "lexicographic"):
            mismatch.append(f"mode: db={mode} cfg={meta.get('mode')}")
        # Patterns: only enforce compare in phonetic mode; normalize order to avoid spurious diffs
        def _norm_patterns(x):
            if not x:
                return ""
            if isinstance(x, str):
                arr = [p for p in x.split(",") if p]
            else:
                arr = [p for p in (x or []) if p]
            return ",".join(sorted(set(arr)))
        cfg_mode = (meta.get("mode", "lexicographic") or "lexicographic")
        if cfg_mode == "phonetic":
            db_pats_norm = _norm_patterns(patterns)
            cfg_pats_norm = _norm_patterns(meta.get("patterns", []))
            if db_pats_norm != cfg_pats_norm:
                mismatch.append("patterns differ")

        # In lexicographic mode, allow prefix/suffix to change without blocking resume (we resume core only)
        if cfg_mode == "lexicographic":
            mismatch = [m for m in mismatch if not (m.startswith("prefix:") or m.startswith("suffix:"))]
        if mismatch:
            raise SystemExit(
                "Config-space mismatch with existing DB. Either use a new db_path or delete the old DB:\n  - "
                + "\n  - ".join(mismatch)
            )

    def add_feedback(self, domain: str, label: str):
        try:
            self.conn.execute("INSERT OR REPLACE INTO feedback(domain, label) VALUES (?,?)", (domain, label))
            sld = domain.split(".")[0]
            bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
            for bg in bigrams:
                self.conn.execute(
                    "INSERT INTO model_bigrams(bigram, weight) VALUES (?, 1.0) ON CONFLICT(bigram) DO UPDATE SET weight = weight + 1.0",
                    (bg,),
                )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def bigram_weights(self) -> Dict[str, float]:
        cur = self.conn.execute("SELECT bigram, weight FROM model_bigrams")
        return {r[0]: float(r[1]) for r in cur.fetchall()}


# ------------------------------- Generators & Scorer (same as previous) -------------------------------

class Generator:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        base_letters = list(cfg.letters) if cfg.include_letters else []
        base_digits = list(cfg.digits) if cfg.include_digits else []
        base = base_letters + base_digits + (['-'] if cfg.include_hyphen else [])
        seen = set()
        self.base_alphabet = [c for c in base if not (c in seen or seen.add(c))]

        ph = cfg.phonetic or {}
        self.consonants = list(ph.get("consonants", "bcdfghjklmnpqrstvwxyz"))
        self.vowels = list(ph.get("vowels", "aeiou"))
        self.anyset = list(ph.get("any", "abcdefghijklmnopqrstuvwxyz0123456789"))
        
        # Use syllable-based generation instead of pattern-based
        self.syllables = self.generate_natural_syllables()
        self.patterns = self.generate_auto_patterns(cfg.min_length, cfg.max_length)
        if hasattr(logging, 'getLogger'):
            logger = logging.getLogger("scanner")
            if self.syllables:
                logger.info("Generated natural syllables | count=%d | examples=%s", 
                           len(self.syllables), ",".join(list(self.syllables)[:10]))

        self.dictionary_words = []
        self.markov_corpus = []
        self.markov_order = 2

    def generate_natural_syllables(self) -> set:
        """Generate short, brand-like syllables similar to modern company names"""
        syllables = set()
        
        # Brand-like syllables and word parts (short and catchy)
        brand_syllables = [
            # Two-letter brand parts (like in: Uber, Meta, Nike, etc.)
            "go", "do", "me", "be", "to", "so", "no", "lo",
            "ga", "da", "ma", "ba", "ta", "sa", "na", "la", "ra", "pa",
            "ge", "de", "le", "re", "te", "se", "ne", "pe", "ke",
            "gi", "di", "li", "ri", "ti", "si", "ni", "pi", "ki", "mi",
            "gu", "du", "lu", "ru", "tu", "su", "nu", "pu", "ku", "mu",
            
            # Short endings (like in: Glovo, Zara, Nike, etc.)
            "vo", "ro", "ko", "mo", "po", "bo", "to", "do", "go", "so",
            "va", "ra", "ka", "ma", "pa", "ba", "ta", "da", "ga", "sa",
            "ve", "re", "ke", "me", "pe", "be", "te", "de", "ge", "se",
            "vi", "ri", "ki", "mi", "pi", "bi", "ti", "di", "gi", "si",
            "vu", "ru", "ku", "mu", "pu", "bu", "tu", "du", "gu", "su",
            
            # Three-letter brand parts (like in: Zoom, Bolt, Spot, etc.)
            "oom", "olt", "pot", "dot", "got", "lot", "not", "bot", "rot", "tot",
            "ame", "ome", "ime", "ume", "eme", "ake", "oke", "ike", "uke", "eke",
            "app", "add", "all", "arr", "ass", "att", "ell", "err", "ess", "ett",
            "ill", "irr", "iss", "itt", "oll", "orr", "oss", "ott", "ull", "urr",
            
            # Modern tech-style parts
            "tek", "lex", "nex", "rex", "dex", "pex", "bex", "gex", "sex", "tex",
            "lab", "tab", "cab", "dab", "gab", "hab", "jab", "kab", "nab", "rab",
            "zen", "ben", "den", "gen", "ken", "len", "men", "pen", "ren", "ten"
        ]
        
        # Filter syllables that work with our consonant/vowel sets
        vowel_set = set(self.vowels)
        consonant_set = set(self.consonants)
        
        for syl in brand_syllables:
            # Check if syllable uses only our allowed characters
            if all(c in vowel_set or c in consonant_set for c in syl):
                syllables.add(syl)
        
        return syllables

    def core_length_bounds(self) -> Tuple[int, int]:
        """Compute allowed core length window after subtracting fixed prefix/suffix lengths."""
        prefix_len = len(self.cfg.prefix or "")
        suffix_len = len(self.cfg.suffix or "")
        core_min = max(1, self.cfg.min_length - prefix_len - suffix_len)
        core_max = max(core_min, self.cfg.max_length - prefix_len - suffix_len)
        return core_min, core_max

    def generate_auto_patterns(self, min_length: int, max_length: int) -> List[str]:
        """Generate pronounceable phonetic patterns automatically"""
        patterns = []
        
        for length in range(min_length, max_length + 1):
            # Rule 1: Basic alternating patterns for natural pronunciation
            if length >= 2:
                # CVCV... pattern (most natural)
                cv_pattern = ("cv" * (length // 2)) + ("c" if length % 2 == 1 else "")
                if len(cv_pattern) == length:
                    patterns.append(cv_pattern)
            
            # Rule 2: Start with consonant for better pronunciation
            if length >= 3:
                # CVCVC pattern (very pronounceable)
                if length % 2 == 1:  # Odd lengths
                    pattern = "c" + "vc" * ((length - 1) // 2)
                    patterns.append(pattern)
            
            # Rule 3: Natural word-like patterns
            if length >= 4:
                # CVCCV pattern (like "basic", "magic")
                if length == 5:
                    patterns.extend(["cvccv", "cvcvc"])
                elif length == 6:
                    patterns.extend(["cvcvcv", "cvccvc"])
            
            # Rule 4: Avoid starting with vowels (less natural in many languages)
            # But include some for variety
            if length >= 4 and length <= 6:
                vc_pattern = ("vc" * (length // 2)) + ("v" if length % 2 == 1 else "")
                if len(vc_pattern) == length and self.is_pronounceable_pattern(vc_pattern):
                    patterns.append(vc_pattern)
        
        # Filter patterns for pronounceability and remove duplicates
        pronounceable_patterns = [p for p in set(patterns) if self.is_pronounceable_pattern(p)]
        return pronounceable_patterns

    def is_pronounceable_pattern(self, pattern: str) -> bool:
        """Check if a pattern produces pronounceable words"""
        if len(pattern) == 0:
            return False
            
        # Rule 1: No more than 2 consecutive consonants
        if "ccc" in pattern:
            return False
            
        # Rule 2: No more than 2 consecutive vowels
        if "vvv" in pattern:
            return False
            
        # Rule 3: Avoid starting with double vowels (less natural)
        if pattern.startswith("vv"):
            return False
            
        # Rule 4: Count consecutive runs
        max_consonant_run = 0
        max_vowel_run = 0
        current_consonant_run = 0
        current_vowel_run = 0
        
        for char in pattern:
            if char == 'c':
                current_consonant_run += 1
                current_vowel_run = 0
                max_consonant_run = max(max_consonant_run, current_consonant_run)
            elif char == 'v':
                current_vowel_run += 1
                current_consonant_run = 0
                max_vowel_run = max(max_vowel_run, current_vowel_run)
        
        # Reject if too many consecutive consonants or vowels
        if max_consonant_run > 2 or max_vowel_run > 2:
            return False
            
        return True

    def load_dictionary(self, path: str):
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self.dictionary_words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]

    def load_markov(self, path: str, order: int = 2):
        self.markov_order = max(1, int(order or 2))
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().lower()
            self.markov_corpus = re.findall(r"[a-z0-9\-]+", text)

    def valid_label(self, sld_full: str) -> bool:
        if not (1 <= len(sld_full) <= 63):
            return False
        if sld_full[0] == '-' or sld_full[-1] == '-':
            return False
        return True

    def allowed_by_skip(self, sld: str) -> bool:
        sr = self.cfg.skip_rules or {}
        if sr.get("skip_lengths"):
            if len(sld) in sr["skip_lengths"]:
                return False
        if sr.get("no_double_hyphen", True) and "--" in sld:
            return False
        
        # Enhanced repetition checks
        mrc = int(sr.get("max_repeat_char", 2) or 2)  # Default to 2, not 0
        if mrc > 0:
            run = 1
            for i in range(1, len(sld)):
                run = run + 1 if sld[i] == sld[i-1] else 1
                if run > mrc:
                    return False
        
        # Additional natural language checks
        # Reject words with too many alternating patterns (like "ababa")
        if self.is_too_repetitive(sld):
            return False
            
        # Reject words that don't look like real words
        if not self.looks_natural(sld):
            return False
            
        return True

    def is_too_repetitive(self, sld: str) -> bool:
        """Check if word has too much repetition (like ababa, abcabc)"""
        if len(sld) < 4:
            return False
            
        # Check for ABAB pattern (like abab, cdcd)
        if len(sld) >= 4:
            if sld[0] == sld[2] and sld[1] == sld[3]:
                return True
                
        # Check for ABCABC pattern (like abcabc)
        if len(sld) == 6:
            if sld[:3] == sld[3:]:
                return True
                
        # Check for too much alternation (like ababa, cdcdc)
        if len(sld) == 5:
            if sld[0] == sld[2] == sld[4] and sld[1] == sld[3]:
                return True
                
        return False

    def looks_natural(self, sld: str) -> bool:
        """Check if word looks like it could be a natural word"""
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')
        
        # Must have at least one vowel
        if not any(c in vowels for c in sld):
            return False
            
        # Must have at least one consonant
        if not any(c in consonants for c in sld):
            return False
            
        # Reject words starting with vowel + same vowel (like "aa", "ee")
        if len(sld) >= 2 and sld[0] in vowels and sld[0] == sld[1]:
            return False
            
        # Prefer words that start with common consonants
        if sld[0] not in 'bcdfglmnprst':
            return False
            
        return True

    def is_brand_like(self, word: str) -> bool:
        """Check if word looks like a modern brand name - relaxed for real words"""
        core_min, core_max = self.core_length_bounds()
        if len(word) < core_min or len(word) > core_max:
            return False
            
        # Must have at least one vowel
        vowels = set('aeiou')
        if not any(c in vowels for c in word):
            return False
            
        # Avoid offensive or problematic words
        bad_words = ['shit', 'fuck', 'damn', 'hell', 'kill', 'dead', 'hate', 'evil']
        if word.lower() in bad_words:
            return False
            
        # For real dictionary words, be much more permissive
        # Only reject if it's clearly not brand-suitable
        return True

    def generate_brandable_names(self, needed: int, config: dict) -> List[str]:
        """Generate Namelix-style brandable names"""
        names = []
        keywords = config.get('keywords', [])
        randomness = config.get('randomness', 'medium')
        creativity = config.get('creativity_level', 0.7)
        
        # Brand prefixes and suffixes like modern companies
        prefixes = ['app', 'web', 'net', 'pro', 'max', 'ultra', 'super', 'mega', 'smart', 'quick', 'fast', 'easy', 'simple', 'flex', 'sync', 'flow', 'wave', 'spark', 'boost', 'zoom', 'dash', 'snap', 'swift', 'bright', 'clear', 'fresh', 'pure', 'clean', 'sharp', 'bold', 'strong', 'power', 'force', 'energy', 'vital', 'dynamic', 'active', 'live', 'real', 'true', 'core', 'prime', 'top', 'peak', 'high', 'best', 'gold', 'star', 'crown', 'royal', 'elite', 'premium', 'luxury', 'deluxe']
        
        suffixes = ['ly', 'fy', 'ify', 'ize', 'wise', 'tech', 'lab', 'hub', 'box', 'kit', 'pro', 'max', 'plus', 'edge', 'link', 'sync', 'flow', 'wave', 'spark', 'boost', 'dash', 'snap', 'swift', 'bright', 'clear', 'fresh', 'pure', 'clean', 'sharp', 'bold', 'strong', 'power', 'force', 'energy', 'vital', 'dynamic', 'active', 'live', 'real', 'true', 'core', 'prime', 'peak', 'gold', 'star', 'crown', 'elite', 'premium', 'luxury']
        
        base_words = ['tech', 'digital', 'smart', 'quick', 'fast', 'easy', 'simple', 'flex', 'sync', 'flow', 'wave', 'spark', 'boost', 'zoom', 'dash', 'snap', 'swift', 'bright', 'clear', 'fresh', 'pure', 'clean', 'sharp', 'bold', 'strong', 'power', 'force', 'energy', 'vital', 'dynamic', 'active', 'live', 'real', 'true', 'core', 'prime', 'top', 'peak', 'high', 'best', 'gold', 'star', 'crown', 'royal', 'elite', 'premium', 'luxury', 'deluxe', 'nova', 'apex', 'zenith', 'vertex', 'matrix', 'nexus', 'vortex', 'pixel', 'quantum', 'neural', 'cyber', 'digital', 'virtual', 'augmented', 'enhanced', 'optimized', 'advanced', 'innovative', 'creative', 'modern', 'future', 'next', 'new', 'fresh', 'young', 'trendy', 'cool', 'hot', 'popular', 'viral', 'social', 'mobile', 'cloud', 'online', 'web', 'net', 'app', 'soft', 'ware', 'system', 'platform', 'service', 'solution', 'product', 'brand', 'company', 'business', 'enterprise', 'corporate', 'professional', 'expert', 'master', 'guru', 'ninja', 'wizard', 'genius', 'hero', 'champion', 'winner', 'leader', 'pioneer', 'innovator', 'creator', 'maker', 'builder', 'designer', 'developer', 'engineer', 'architect', 'analyst', 'consultant', 'advisor', 'mentor', 'coach', 'trainer', 'teacher', 'instructor', 'guide', 'helper', 'assistant', 'supporter', 'partner', 'ally', 'friend', 'buddy', 'mate', 'pal', 'companion', 'associate', 'colleague', 'teammate', 'member', 'user', 'client', 'customer', 'consumer', 'buyer', 'purchaser', 'shopper', 'visitor', 'guest', 'audience', 'viewer', 'reader', 'listener', 'watcher', 'observer', 'follower', 'subscriber', 'fan', 'lover', 'enthusiast', 'addict', 'junkie', 'freak', 'geek', 'nerd', 'expert', 'specialist', 'professional', 'master', 'guru', 'ninja', 'wizard', 'genius', 'hero', 'champion', 'winner', 'leader', 'pioneer']
        
        # Add user keywords to base words
        if keywords:
            base_words.extend(keywords)
        
        # Adapt generation based on target length range (core only)
        target_min, target_max = self.core_length_bounds()
        
        # Generate different types of brandable names
        for _ in range(needed * 3):  # Generate more than needed for filtering
            if len(names) >= needed:
                break
                
            rand_val = random.random()
            name = ""
            
            if randomness == 'low':
                # More predictable combinations
                if rand_val < 0.5:
                    # prefix + base, adjust for target length
                    prefix = random.choice(prefixes)
                    base = random.choice(base_words)
                    name = self.adjust_length(prefix + base, target_min, target_max)
                else:
                    # base + suffix, adjust for target length
                    base = random.choice(base_words)
                    suffix = random.choice(suffixes)
                    name = self.adjust_length(base + suffix, target_min, target_max)
            elif randomness == 'high':
                # More creative combinations
                if rand_val < 0.3:
                    # Modified spelling
                    base = random.choice(base_words)
                    name = self.create_alternate_spelling(base)
                    name = self.adjust_length(name, target_min, target_max)
                elif rand_val < 0.6:
                    # Blend two words
                    word1 = random.choice(base_words)
                    word2 = random.choice(base_words)
                    name = self.blend_words(word1, word2)
                    name = self.adjust_length(name, target_min, target_max)
                else:
                    # Complex combinations
                    pre = random.choice(prefixes)
                    base = random.choice(base_words)
                    suf = random.choice(suffixes)
                    name = self.adjust_length(pre + base + suf, target_min, target_max)
            else:  # medium
                # Balanced approach
                if rand_val < 0.4:
                    # prefix + base
                    prefix = random.choice(prefixes)
                    base = random.choice(base_words)
                    name = self.adjust_length(prefix + base, target_min, target_max)
                elif rand_val < 0.8:
                    # base + suffix
                    base = random.choice(base_words)
                    suffix = random.choice(suffixes)
                    name = self.adjust_length(base + suffix, target_min, target_max)
                else:
                    # Blend words
                    word1 = random.choice(base_words)
                    word2 = random.choice(base_words)
                    name = self.blend_words(word1, word2)
                    name = self.adjust_length(name, target_min, target_max)
            
            # Strict length compliance on core (prefix/suffix enforced later)
            if name and target_min <= len(name) <= target_max:
                names.append(name.lower())
            elif name and len(name) != 0:
                # Try one more adjustment if still not in range (core-length)
                adjusted = self.adjust_length(name, target_min, target_max)
                if adjusted and target_min <= len(adjusted) <= target_max:
                    names.append(adjusted.lower())
        
        return list(set(names))  # Remove duplicates

    def create_alternate_spelling(self, word: str) -> str:
        """Create alternate spellings like Lyft, Fiverr"""
        # Simple alternate spelling rules
        word = word.replace('er', 'r')  # better -> bettr
        word = word.replace('ck', 'k')  # quick -> quik
        word = word.replace('ph', 'f')  # phone -> fone
        word = word.replace('gh', '')   # light -> lit
        word = word.replace('ight', 'ite')  # light -> lite
        return word

    def blend_words(self, word1: str, word2: str) -> str:
        """Blend two words like Instagram (instant + telegram)"""
        # Take first part of word1 and last part of word2
        split1 = len(word1) // 2
        split2 = len(word2) // 2
        return word1[:split1] + word2[split2:]

    def generate_compound_names(self, needed: int) -> List[str]:
        """Generate compound names like FedEx, Microsoft"""
        names = []
        
        # Common compound elements
        first_parts = ['fed', 'micro', 'face', 'pay', 'air', 'app', 'soft', 'tech', 'web', 'net', 'data', 'info', 'smart', 'quick', 'fast', 'easy', 'simple', 'flex', 'sync', 'flow', 'wave', 'spark', 'boost', 'zoom', 'dash', 'snap', 'swift', 'bright', 'clear', 'fresh', 'pure', 'clean', 'sharp', 'bold', 'strong', 'power', 'force', 'energy', 'vital', 'dynamic', 'active', 'live', 'real', 'true', 'core', 'prime', 'top', 'peak', 'high', 'best', 'gold', 'star', 'crown', 'royal', 'elite', 'premium', 'luxury']
        
        second_parts = ['ex', 'soft', 'book', 'pal', 'bnb', 'tube', 'gram', 'chat', 'mail', 'drive', 'cloud', 'space', 'time', 'zone', 'hub', 'lab', 'box', 'kit', 'pro', 'max', 'plus', 'edge', 'link', 'sync', 'flow', 'wave', 'spark', 'boost', 'dash', 'snap', 'swift', 'bright', 'clear', 'fresh', 'pure', 'clean', 'sharp', 'bold', 'strong', 'power', 'force', 'energy', 'vital', 'dynamic', 'active', 'live', 'real', 'true', 'core', 'prime', 'peak', 'gold', 'star', 'crown', 'elite', 'premium', 'luxury']
        
        for _ in range(needed * 2):
            if len(names) >= needed:
                break
            first = random.choice(first_parts)
            second = random.choice(second_parts)
            compound = first + second
            # Dynamically respect min_length and max_length from config
            if self.cfg.min_length <= len(compound) <= self.cfg.max_length:
                names.append(compound)
        
        return list(set(names))

    def is_brandable_quality(self, name: str, config: dict) -> bool:
        """Check if name meets brandable quality standards"""
        avoid_words = config.get('avoid_words', [])
        
        # Avoid blacklisted words
        if any(avoid in name.lower() for avoid in avoid_words):
            return False
        
        # Must be pronounceable
        vowels = set('aeiou')
        if not any(c in vowels for c in name):
            return False
        
        # Avoid too many repeated letters
        for i in range(len(name) - 2):
            if name[i] == name[i+1] == name[i+2]:
                return False
        
        return True

    def is_compound_quality(self, name: str) -> bool:
        """Check compound name quality"""
        # Must have at least one vowel
        vowels = set('aeiou')
        if not any(c in vowels for c in name):
            return False
        
        # Should not start or end with same letter
        if len(name) > 1 and name[0] == name[-1]:
            return False
        
        return True

    def adjust_length(self, name: str, target_min: int, target_max: int) -> str:
        """Adjust name length to fit within target range - strict compliance"""
        if not name:
            return ""
            
        # If already in range, return as is
        if target_min <= len(name) <= target_max:
            return name
        
        # If too long, truncate intelligently
        if len(name) > target_max:
            vowels = set('aeiou')
            truncated = name[:target_max]
            
            # Try to end with a natural sound
            if len(truncated) > 1:
                # If ends with consonant cluster, try to fix
                if (truncated[-1] not in vowels and 
                    len(truncated) > 1 and truncated[-2] not in vowels):
                    # Replace last char with vowel for better sound
                    truncated = truncated[:-1] + random.choice(['y', 'a', 'o', 'e', 'i'])
            
            return truncated
        
        # If too short, extend intelligently
        if len(name) < target_min:
            vowels = set('aeiou')
            extensions = []
            
            # Choose extensions based on current ending
            if name[-1] in vowels:
                extensions = ['fy', 'ly', 'py', 'ty', 'dy', 'gy', 'my', 'ny', 'ry', 'sy', 'wy', 'zy']
            else:
                extensions = ['y', 'ly', 'ify', 'fy', 'o', 'a', 'e', 'i', 'u']
            
            extended = name
            attempts = 0
            while len(extended) < target_min and attempts < 10:
                ext = random.choice(extensions)
                if len(extended + ext) <= target_max:
                    extended += ext
                    if len(extended) >= target_min:
                        break
                attempts += 1
            
            # If still too short, pad with vowels
            while len(extended) < target_min and len(extended) < target_max:
                extended += random.choice(['a', 'e', 'i', 'o', 'u'])
            
            return extended if target_min <= len(extended) <= target_max else name
        
        return name

    def apply_blacklist(self, sld: str) -> bool:
        bls = self.cfg.blacklist_substrings or []
        blr = [re.compile(r) for r in (self.cfg.blacklist_regex or [])]
        if any(sub in sld for sub in bls):
            return False
        if any(r.search(sld) for r in blr):
            return False
        return True

    def first_word_lex(self, length: int) -> str:
        if not self.base_alphabet:
            raise ValueError("Alphabet empty; enable letters/digits/hyphen or set custom sets.")
        return self.base_alphabet[0] * length

    def next_word_lex(self, word: str) -> Optional[str]:
        N = len(self.base_alphabet)
        arr = list(word)
        i = len(arr) - 1
        while i >= 0:
            idx = self.base_alphabet.index(arr[i])
            if idx + 1 < N:
                arr[i] = self.base_alphabet[idx + 1]
                return "".join(arr)
            else:
                arr[i] = self.base_alphabet[0]
                i -= 1
        return None

    def pattern_alphabet(self, ch: str) -> List[str]:
        if ch == 'c':
            return self.consonants
        if ch == 'v':
            return self.vowels
        return self.anyset

    def first_word_pat(self, pattern: str) -> str:
        return "".join(self.pattern_alphabet(ch)[0] for ch in pattern)

    def next_word_pat(self, word: str, pattern: str) -> Optional[str]:
        arr = list(word)
        i = len(arr) - 1
        while i >= 0:
            alpha = self.pattern_alphabet(pattern[i])
            idx = alpha.index(arr[i])
            if idx + 1 < len(alpha):
                arr[i] = alpha[idx + 1]
                return "".join(arr)
            else:
                arr[i] = alpha[0]
                i -= 1
        return None

    def dictionary_iter(self, start_idx: int = 0):
        for i in range(start_idx, len(self.dictionary_words)):
            yield self.dictionary_words[i], i

    def build_markov_table(self, order: int) -> Dict[str, List[str]]:
        table: Dict[str, List[str]] = {}
        if not self.markov_corpus:
            return table
        for word in self.markov_corpus:
            if len(word) <= order:
                continue
            for i in range(len(word) - order):
                key = word[i:i+order]
                nxt = word[i+order]
                table.setdefault(key, []).append(nxt)
        return table

    def markov_generate(self, table: Dict[str, List[str]], order: int, length: int, seed: Optional[str] = None) -> str:
        if not table:
            return ""
        if not seed:
            seed = random.choice(list(table.keys()))
        s = seed[:order]
        while len(s) < length:
            key = s[-order:]
            choices = table.get(key) or random.choice(list(table.values()))
            s += random.choice(choices)
        return s

    def generate_batch(self, store, needed: int, state: dict, shard_prefixes: List[str]) -> Tuple[List[str], dict]:
        out: List[str] = []
        mode = self.cfg.mode

        def push_domain_from_sld(core_sld: str):
            # Respect shard prefixes on the variable core only
            if shard_prefixes and core_sld[:1] not in shard_prefixes:
                return
            # Build full SLD with fixed prefix/suffix
            full_sld = f"{self.cfg.prefix}{core_sld}{self.cfg.suffix}"
            # Validate full label against domain rules
            if not self.valid_label(full_sld):
                return
            # Enforce final length on the full SLD (prefix + core + suffix)
            if not (self.cfg.min_length <= len(full_sld) <= self.cfg.max_length):
                return
            # Apply natural/repetition skip rules on variable core only (skip for lexicographic)
            if mode != "lexicographic" and not self.allowed_by_skip(core_sld):
                return
            # Apply blacklist on the full SLD
            if not self.apply_blacklist(full_sld):
                return
            for tld in (self.cfg.tlds or ["com"]):
                domain = f"{full_sld}.{tld}"
                if not store.is_checked(domain):
                    out.append(domain)

        # Only use priority queue for dictionary mode
        if mode == "dictionary":
            pq = store.pop_priority_batch(needed)
            for sld in pq:
                if len(out) >= needed: break
                push_domain_from_sld(sld)

            if len(out) >= needed:
                return out, state

        if mode == "lexicographic":
            core_min, core_max = self.core_length_bounds()
            length = state.get("length", core_min)
            word = state.get("word")
            wrapped = bool(state.get("wrapped", False))
            while len(out) < needed and (length <= core_max or (not wrapped)):
                if not word:
                    word = self.first_word_lex(length)
                while word and len(out) < needed:
                    push_domain_from_sld(word)
                    state["word"] = word
                    word = self.next_word_lex(word)
                if len(out) >= needed:
                    break
                # wrap-around once if we exhausted at this length and there is no larger length window
                if length >= core_max and not wrapped:
                    length = core_min
                    word = ""
                    wrapped = True
                    state["wrapped"] = True
                    continue
                length += 1
                word = None
                state["length"] = length
            state["length"] = length
            return out, state

        if mode == "phonetic":
            # Generate brand-like short names
            core_min, core_max = self.core_length_bounds()
            syllable_idx = state.get("syllable_idx", 0)
            syllable_combinations = list(self.syllables)
            syllable_combinations.sort()  # Consistent ordering
            
            while len(out) < needed and syllable_idx < len(syllable_combinations) * len(syllable_combinations):
                # Generate words by combining syllables
                first_idx = syllable_idx // len(syllable_combinations)
                second_idx = syllable_idx % len(syllable_combinations)
                
                if first_idx >= len(syllable_combinations):
                    break
                    
                first_syl = syllable_combinations[first_idx]
                second_syl = syllable_combinations[second_idx]
                
                # Create brand-like combinations
                combinations = []
                
                # Single syllable (4-5 letters like "zoom", "bolt")
                if core_min <= len(first_syl) <= core_max:
                    combinations.append(first_syl)
                
                # Two syllables (like "glovo", "meta")
                combined = first_syl + second_syl
                if core_min <= len(combined) <= core_max:
                    combinations.append(combined)
                
                # Avoid combinations that are too repetitive or unnatural
                for word in combinations:
                    if len(out) >= needed:
                        break
                    if core_min <= len(word) <= core_max:
                        # Additional check for brand-like quality
                        if self.is_brand_like(word):
                            push_domain_from_sld(word)
                
                syllable_idx += 1
                state["syllable_idx"] = syllable_idx
                
            return out, state

    # dictionary & markov branches omitted here for brevity; identical to previous version
            return out, state

        if mode == "dictionary":
            core_min, core_max = self.core_length_bounds()
            cursor = state.get("cursor", 0)
            for word, idx in self.dictionary_iter(cursor):
                if len(out) >= needed: break
                # Filter for brand-like quality and correct length
                if (core_min <= len(word) <= core_max and 
                    self.is_brand_like(word) and 
                    self.looks_natural(word)):
                    push_domain_from_sld(word)
                state["cursor"] = idx + 1
            return out, state

        if mode == "markov":
            core_min, core_max = self.core_length_bounds()
            if "markov_table" not in state:
                state["markov_table"] = self.build_markov_table(order=2)
            t = state["markov_table"]
            count = 0
            while len(out) < needed and count < needed * 3:
                L = random.randint(core_min, core_max)
                gen = self.markov_generate(t, order=2, length=L)
                count += 1
                if not gen: break
                push_domain_from_sld(gen)
            return out, state

        if mode == "ai_brandable":
            # REVOLUTIONARY NEURAL AI SYSTEM - 2025 NEUROSCIENCE + PROGRESSIVE HOUSE
            if not AI_AVAILABLE:
                print("Error: Neural AI system not available. Falling back to brandable mode.")
                # Fallback to brandable mode
                generated_count = state.get("generated_count", 0)
                brandable_names = self.generate_brandable_names(needed * 2)
                for name in brandable_names:
                    if len(out) >= needed: break
                    if self.cfg.min_length <= len(name) <= self.cfg.max_length:
                        if self.is_brandable_quality(name):
                            push_domain_from_sld(name)
                            generated_count += 1
            else:
                # Use REVOLUTIONARY NEURAL AI generator (prompt-driven)
                print("Activating Neural AI Generation System...")
                generated_count = state.get("generated_count", 0)
                neural_ai = AINameGeneratorNeural()

                # Pull prompt profile (style/keywords) from config if present
                ai_cfg = getattr(self.cfg, 'ai_settings', {}) or {}
                prompt_profile = {}
                if isinstance(ai_cfg, dict):
                    prompt_profile = ai_cfg.get('prompt_profile', {}) or {}
                else:
                    prompt_profile = getattr(ai_cfg, 'prompt_profile', {}) if hasattr(ai_cfg, 'prompt_profile') else {}
                style = (prompt_profile.get('style') if isinstance(prompt_profile, dict) else None) or "modern"
                keywords = (prompt_profile.get('keywords') if isinstance(prompt_profile, dict) else None) or []

                neural_names = neural_ai.generate_intelligent_names(
                    needed * 10,
                    self.cfg.min_length,
                    self.cfg.max_length,
                    style=style,
                    keywords=keywords,
                )

                print(f"Generated {len(neural_names)} revolutionary neural names")

                # De-duplicate across batches using state
                seen = state.get("neural_seen", set())
                for name in neural_names:
                    if len(out) >= needed: break
                    if name in seen:
                        continue
                    if name and self.cfg.min_length <= len(name) <= self.cfg.max_length:
                        # All neural names are high quality by design
                        push_domain_from_sld(name)
                        generated_count += 1
                        seen.add(name)
                state["neural_seen"] = seen

            state["generated_count"] = generated_count
            return out, state
        
        if mode == "brandable":
            # Namelix-style brandable name generation
            generated_count = state.get("generated_count", 0)
            namelix_config = getattr(self.cfg, 'namelix_style', {})
            
            if namelix_config.get('enabled', True):
                brandable_names = self.generate_brandable_names(needed, namelix_config)
                _core_min, _core_max = self.core_length_bounds()
                for name in brandable_names:
                    if len(out) >= needed: break
                    # enforce core length window here
                    if _core_min <= len(name) <= _core_max:
                        if self.is_brandable_quality(name, namelix_config):
                            push_domain_from_sld(name)
                            generated_count += 1
                state["generated_count"] = generated_count
            return out, state

        if mode == "compound":
            # Generate compound words like FedEx, Microsoft
            compound_count = state.get("compound_count", 0)
            compound_names = self.generate_compound_names(needed)
            for name in compound_names:
                if len(out) >= needed: break
                if self.cfg.min_length <= len(name) <= self.cfg.max_length:
                    if self.is_compound_quality(name):
                        push_domain_from_sld(name)
                        compound_count += 1
            state["compound_count"] = compound_count
            return out, state

        return out, state


def build_scorer(cfg, store):
    weights = cfg.scoring or {}
    vowel_set = set("aeiou")
    bigram_weights = store.bigram_weights()

    def pronounceable_bigrams(s: str) -> float:
        total = max(0, len(s) - 1)
        if total == 0: return 0
        score = 0.0
        
        # High quality, natural bigrams (common in real words)
        excellent_bigrams = {
            'ba', 'be', 'da', 'de', 'ga', 'ge', 'ka', 'ke', 'la', 'le', 'ma', 'me',
            'na', 'ne', 'pa', 'pe', 'ra', 're', 'sa', 'se', 'ta', 'te', 'va', 've',
            'ab', 'ad', 'ag', 'al', 'am', 'an', 'ar', 'as', 'at',
            'eb', 'ed', 'el', 'em', 'en', 'er', 'es', 'et',
            'ib', 'id', 'il', 'im', 'in', 'ir', 'is', 'it',
            'ob', 'od', 'ol', 'om', 'on', 'or', 'os', 'ot'
        }
        
        # Difficult or unnatural bigrams to penalize
        difficult_bigrams = {
            'bw', 'bj', 'bq', 'bx', 'bz', 'cj', 'cq', 'cx', 'cz',
            'dj', 'dq', 'dx', 'dz', 'fj', 'fq', 'fx', 'fz',
            'gj', 'gq', 'gx', 'gz', 'hj', 'hq', 'hx', 'hz',
            'jb', 'jc', 'jd', 'jf', 'jg', 'jh', 'jj', 'jk', 'jl', 'jm', 'jn', 'jp', 'jq', 'jr', 'js', 'jt', 'jv', 'jw', 'jx', 'jy', 'jz',
            'kj', 'kq', 'kx', 'kz', 'lj', 'lq', 'lx', 'lz',
            'mj', 'mq', 'mx', 'mz', 'nj', 'nq', 'nx', 'nz',
            'pj', 'pq', 'px', 'pz', 'qb', 'qc', 'qd', 'qf', 'qg', 'qh', 'qj', 'qk', 'ql', 'qm', 'qn', 'qp', 'qq', 'qr', 'qs', 'qt', 'qv', 'qw', 'qx', 'qy', 'qz',
            'rj', 'rq', 'rx', 'rz', 'sj', 'sq', 'sx', 'sz',
            'tj', 'tq', 'tx', 'tz', 'vj', 'vq', 'vx', 'vz',
            'wj', 'wq', 'wx', 'wz', 'xb', 'xc', 'xd', 'xf', 'xg', 'xh', 'xj', 'xk', 'xl', 'xm', 'xn', 'xp', 'xq', 'xr', 'xs', 'xt', 'xv', 'xw', 'xx', 'xy', 'xz',
            'yj', 'yq', 'yx', 'yz', 'zb', 'zc', 'zd', 'zf', 'zg', 'zh', 'zj', 'zk', 'zl', 'zm', 'zn', 'zp', 'zq', 'zr', 'zs', 'zt', 'zv', 'zw', 'zx', 'zy', 'zz',
            'oj', 'uj', 'wo', 'wu'  # Adding problematic combinations from examples
        }
        
        penalty = 0
        for i in range(total):
            bg = s[i:i+2]
            
            # Heavy penalty for difficult bigrams
            if bg in difficult_bigrams:
                penalty += 3.0
                continue
            
            # Bonus for alternating consonant-vowel pattern (but reduced)
            if (s[i] in vowel_set) ^ (s[i+1] in vowel_set):
                score += 0.8  # Reduced from 1.5
            
            # Higher bonus for excellent bigrams only
            if bg in excellent_bigrams:
                score += 1.5  # Reduced from 2.0
            
            # Bonus from learned bigrams (reduced)
            if bg in bigram_weights:
                score += min(1.0, float(bigram_weights[bg]) / 3)
        
        # Apply penalty
        final_score = (score - penalty) / total
        return max(0, final_score)  # Don't allow negative scores

    def scorer(sld: str) -> float:
        L = len(sld)
        has_digit = any(c.isdigit() for c in sld)
        has_hyphen = "-" in sld
        vowels = sum(1 for c in sld if c in vowel_set)
        base = 0.0
        base += (cfg.max_length + 1 - L) * float(weights.get("length_weight", 1.0))
        base += (vowels / max(1, L)) * float(weights.get("vowel_bonus", 1.0))
        if not has_digit:
            base += float(weights.get("no_digit_bonus", 0.0))
        if not has_hyphen:
            base += float(weights.get("no_hyphen_bonus", 0.0))
        base += pronounceable_bigrams(sld) * float(weights.get("pronounceable_bigram_bonus", 0.0))
        return min(base, float(weights.get("max_bonus", 5.0)))

    return scorer


# ------------------------------- Load config -------------------------------

def load_config(path: str) -> Tuple[APIConfig, ScanConfig]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    api = cfg.get("api", {})
    sc = cfg.get("scanner", {})

    api_cfg = APIConfig(
        user=str(api.get("user", "")),
        key=str(api.get("key", "")),
        username=str(api.get("username", "")),
        client_ip=str(api.get("client_ip", "")),
        sandbox=bool(api.get("sandbox", True)),
    )

    scan_cfg = ScanConfig(
        min_length=int(sc.get("min_length", 1)),
        max_length=int(sc.get("max_length", 3)),
        prefix=str(sc.get("prefix", "")),
        suffix=str(sc.get("suffix", "")),
        include_letters=bool(sc.get("include_letters", True)),
        include_digits=bool(sc.get("include_digits", False)),
        include_hyphen=bool(sc.get("include_hyphen", False)),
        letters=str(sc.get("letters", "abcdefghijklmnopqrstuvwxyz")),
        digits=str(sc.get("digits", "0123456789")),
        batch_size=int(sc.get("batch_size", 50)),
        requests_per_minute=int(sc.get("requests_per_minute", 45)),
        show_premium=bool(sc.get("show_premium", False)),
        db_path=str(sc.get("db_path", "scanner.db")),
        csv_path=str(sc.get("csv_path", "available_domains.csv")),
        stop_after=int(sc.get("stop_after", 0)),
        mode=str(sc.get("mode", "lexicographic")).lower(),
        phonetic=dict(sc.get("phonetic", {})),
        blacklist_substrings=list(sc.get("blacklist_substrings", [])),
        blacklist_regex=list(sc.get("blacklist_regex", [])),
        scoring=dict(sc.get("scoring", {})),
        skip_rules=dict(sc.get("skip_rules", {})),
        rdap=dict(sc.get("rdap", {"enabled": False, "requests_per_minute": 10, "check_on_fail_count": 3, "verify_all": False, "verify_scope": "available", "verify_sample_size": 50})),
        alerts=dict(sc.get("alerts", {})),
        priority_queue_path=str(sc.get("priority_queue_path", "")),
        sharding=dict(sc.get("sharding", {})),
        rpm_bounds=dict(sc.get("rpm_bounds", {"min": 10, "max": 55})),
        dry_run=bool(sc.get("dry_run", False)),
        warmup=dict(sc.get("warmup", {"enabled": True, "duration_seconds": 120, "rpm": 12, "batch_size": 10})),
        network=dict(sc.get("network", {
            "preflight": {"enabled": True, "ip_check_url": "https://api.ipify.org", "enforce_match": True, "check_interval_seconds": 60},
            "proxies": {"http": "", "https": "", "no_proxy": ""},
        })),
        tlds=list(sc.get("tlds", ["com"])),
        logging=dict(sc.get("logging", {})),
        safety=dict(sc.get("safety", {"conservative_mode": False, "max_requests_per_minute": 20, "batch_size": 20, "cooldown_every_requests": 10, "cooldown_seconds": 5, "random_sleep_ms_range": [200, 800]})),
    )

    if scan_cfg.batch_size < 1 or scan_cfg.batch_size > 50:
        raise SystemExit("scanner.batch_size must be between 1 and 50 (Namecheap limit).")

    # basic tld validation
    scan_cfg.tlds = [t.strip().lower().lstrip(".") for t in scan_cfg.tlds if t and isinstance(t, str)] or ["com"]

    return api_cfg, scan_cfg


def setup_logging(cfg_logging: dict):
    logger = logging.getLogger("scanner")
    if logger.handlers:
        return logger
    level_name = (cfg_logging or {}).get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    log_file = (cfg_logging or {}).get("file", "logs/scanner.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=int((cfg_logging or {}).get("rotate_max_mb", 5))*1024*1024,
                                  backupCount=int((cfg_logging or {}).get("rotate_backups", 3)))
    handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(sh)
    return logger


def jsonl_emit(cfg_logging: dict, event: str, payload: dict):
    path = (cfg_logging or {}).get("jsonl_file")
    if not path:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "a", encoding="utf-8") as f:
            rec = {"event": event, **payload}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def ensure_csv_header(path: str):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", encoding="utf-8") as f:
            f.write("domain,tld,is_premium,score,premium_registration_price,premium_renewal_price,icann_fee\n")


# ------------------------------- Alerts -------------------------------

def send_alerts(cfg: ScanConfig, items: List[Tuple[str, bool]], pricing: dict, scorer):
    if not (cfg.alerts and cfg.alerts.get("enabled", False)):
        return
    threshold = float(cfg.scoring.get("min_score_for_alert", 0))
    include_premium = bool(cfg.alerts.get("include_premium", False))

    def post(url: str, payload: dict):
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

    for domain, is_premium in items:
        sld = ".".join(domain.split(".")[:-1])
        score = scorer(sld)
        if score < threshold:
            continue
        if is_premium and not include_premium:
            continue
        payload = {
            "domain": domain,
            "score": score,
            "is_premium": bool(is_premium),
            "pricing": pricing.get(domain, {}),
        }
        if cfg.alerts.get("webhook_url"):
            post(cfg.alerts["webhook_url"], payload)
        if cfg.alerts.get("slack_webhook_url"):
            post(cfg.alerts["slack_webhook_url"], {"text": f"Available: {domain} (score={score:.2f})"})
        tg = cfg.alerts.get("telegram", {})
        if tg.get("enabled") and tg.get("bot_token") and tg.get("chat_id"):
            url = f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage"
            data = {"chat_id": tg["chat_id"], "text": f"Available: {domain} (score={score:.2f})"}
            try:
                requests.post(url, data=data, timeout=10)
            except Exception:
                pass


# ------------------------------- Main -------------------------------

def main():
    parser = argparse.ArgumentParser(description="Advanced Namecheap multi-TLD scanner")
    parser.add_argument("--config", required=True, help="Path to YAML config")
    parser.add_argument("--dictionary", help="Optional dictionary wordlist path")
    parser.add_argument("--markov-corpus", help="Optional Markov corpus path")
    parser.add_argument("--markov-order", type=int, default=2, help="Markov order (default=2)")
    parser.add_argument("--feedback", help="Add feedback 'domain:label' (liked/purchased/reject) and exit")
    parser.add_argument("--dry-run", action="store_true", help="Override config: do not call API")
    parser.add_argument("--debug", action="store_true", help="Verbose API/debug logging")
    args = parser.parse_args()

    api_cfg, scan_cfg = load_config(args.config)

    # Initialize logger (must be before any use of `logger`)
    logger = setup_logging(scan_cfg.logging)
    logger.info("Starting scanner | mode=%s | tlds=%s", str(scan_cfg.mode), ",".join(scan_cfg.tlds))

    # Log safety settings
    saf = scan_cfg.safety or {}
    if saf.get('conservative_mode', False):
        logger.info("Safety mode ON | max_rpm=%s batch=%s cooldown_every=%s cooldown_s=%s", str(saf.get('max_requests_per_minute')), str(saf.get('batch_size')), str(saf.get('cooldown_every_requests')), str(saf.get('cooldown_seconds')))
    else:
        logger.info("Safety mode OFF")


    if args.feedback:
        store = Store(scan_cfg.db_path)
        dom, label = args.feedback.split(":", 1)
        store.add_feedback(dom.strip().lower(), label.strip().lower())
        print("Feedback stored.")
        return

    proxies = (scan_cfg.network or {}).get("proxies", {})
    nc_client = NamecheapClient(api_cfg, proxies=proxies)
    rdap_client = RDAPClient(enabled=bool(scan_cfg.rdap.get("enabled", False)),
                             rpm=int(scan_cfg.rdap.get("requests_per_minute", 10)),
                             proxies=proxies,
                             bootstrap_cfg=(scan_cfg.rdap or {}).get('bootstrap', {}),
                             overrides=(scan_cfg.rdap or {}).get('overrides', {}),
                             logger=logger, logging_cfg=scan_cfg.logging)

    pre = (scan_cfg.network or {}).get("preflight", {})
    if pre.get("enabled", True) and not (scan_cfg.dry_run or args.dry_run):
        ip_url = pre.get("ip_check_url", "https://api.ipify.org")
        current_ip = get_public_ipv4(nc_client.session, ip_url)
        if not current_ip:
            logger.error("Preflight failed | unable to detect public IP")
            if pre.get("enforce_match", True):
                raise SystemExit(3)
        else:
            if current_ip != api_cfg.client_ip:
                logger.error("Preflight mismatch | current=%s expected=%s", current_ip, api_cfg.client_ip)
                if pre.get("enforce_match", True):
                    raise SystemExit(3)
            else:
                logger.info("Preflight OK | ip=%s", current_ip)

    store = Store(scan_cfg.db_path)
    gen = Generator(scan_cfg, store)

    # Load dictionary only for dictionary mode, not for brandable mode
    if scan_cfg.mode == "dictionary":
        if args.dictionary:
            gen.load_dictionary(args.dictionary)
        elif scan_cfg.priority_queue_path and os.path.exists(scan_cfg.priority_queue_path):
            gen.load_dictionary(scan_cfg.priority_queue_path)
        else:
            # Load default brand dictionary
            default_dict = "brand_dictionary.txt"
            if os.path.exists(default_dict):
                gen.load_dictionary(default_dict)
    elif args.dictionary:
        gen.load_dictionary(args.dictionary)
        
    if args.markov_corpus:
        gen.load_markov(args.markov_corpus, order=args.markov_order)

    # Only import priority queue for dictionary mode, not brandable mode
    if scan_cfg.mode == "dictionary":
        imported = store.import_priority(scan_cfg.priority_queue_path)
        if imported:
            print(f"Imported {imported} priority names.")
    else:
        print(f"Using {scan_cfg.mode} mode - priority queue disabled.")

    shard_prefixes = []
    if scan_cfg.sharding.get("enabled", False):
        shard_prefixes = list(scan_cfg.sharding.get("allowed_prefixes", []))
        claimed = store.claim_lease(scan_cfg.sharding.get("worker_id", "worker"), shard_prefixes, int(scan_cfg.sharding.get("lease_seconds", 180)))
        print(f"Claimed shard prefixes: {claimed}")

    meta = {
        "prefix": scan_cfg.prefix,
        "suffix": scan_cfg.suffix,
        "min_length": scan_cfg.min_length,
        "max_length": scan_cfg.max_length,
        "alphabet": "".join(gen.base_alphabet),
        "mode": scan_cfg.mode,
        "patterns": gen.patterns,
    }
    store.validate_space(meta)

    last_word, cur_len, saved_alphabet, saved_mode, saved_patterns, cursor, saved_shard = store.get_progress()
    state = {}
    if scan_cfg.mode == "lexicographic":
        core_min, core_max = gen.core_length_bounds()
        if last_word is None:
            cur_len = core_min
            state = {"length": cur_len, "word": "", "wrapped": False}
            store.set_progress("", cur_len, meta["alphabet"], meta, cursor=0, shard_prefix=(shard_prefixes[0] if shard_prefixes else None))
        else:
            resumed_len = cur_len if cur_len is not None else core_min
            if resumed_len < core_min or resumed_len > core_max:
                resumed_len = core_min
            state = {"length": resumed_len, "word": last_word or "", "wrapped": False}
    elif scan_cfg.mode == "phonetic":
        if last_word is None:
            state = {"syllable_idx": 0}
            store.set_progress("", 0, meta["alphabet"], meta, cursor=0, shard_prefix=(shard_prefixes[0] if shard_prefixes else None))
        else:
            state = {"syllable_idx": cursor or 0}
    elif scan_cfg.mode == "dictionary":
        state = {"cursor": cursor or 0}
    else:
        state = {}

    ensure_csv_header(scan_cfg.csv_path)

    if not (scan_cfg.dry_run or args.dry_run):
        if not (api_cfg.user and api_cfg.key and api_cfg.username and api_cfg.client_ip):
            raise SystemExit("Missing API credentials in config.api")

    scorer = build_scorer(scan_cfg, store)

    rpm = scan_cfg.requests_per_minute
    saf = scan_cfg.safety or {}
    safety_active = bool(saf.get('conservative_mode', False))
    safety_max_rpm = int(saf.get('max_requests_per_minute', 20))
    safety_batch = int(saf.get('batch_size', 20))
    cooldown_every = int(saf.get('cooldown_every_requests', 10))
    cooldown_seconds = float(saf.get('cooldown_seconds', 5))
    rand_ms_range = saf.get('random_sleep_ms_range', [200, 800])
    if not isinstance(rand_ms_range, (list, tuple)) or len(rand_ms_range) != 2:
        rand_ms_range = [200, 800]

    min_rpm = int(scan_cfg.rpm_bounds.get("min", 10))
    max_rpm = int(scan_cfg.rpm_bounds.get("max", 55))
    if safety_active and safety_max_rpm < max_rpm:
        max_rpm = safety_max_rpm
        rpm = min(rpm, safety_max_rpm)

    warm_until = 0
    warm_rpm = rpm
    warm_batch = scan_cfg.batch_size
    if scan_cfg.warmup.get("enabled", True):
        warm_until = time.time() + int(scan_cfg.warmup.get("duration_seconds", 120))
        warm_rpm = int(scan_cfg.warmup.get("rpm", rpm))
        warm_batch = int(scan_cfg.warmup.get("batch_size", scan_cfg.batch_size))

    total_checked = 0
    backoff = 1.0

    # Safety counters
    requests_since_cooldown = 0

    # Mid-run IP checker
    last_ip_check = 0.0
    ip_check_interval = int(pre.get("check_interval_seconds", 60)) if pre else 60
    enforce_match = bool(pre.get("enforce_match", True)) if pre else True
    last_seen_ip = None

    try:
        while True:
            if scan_cfg.stop_after and total_checked >= scan_cfg.stop_after:
                logger.info("Stop | reached stop_after=%d", scan_cfg.stop_after)
                jsonl_emit(scan_cfg.logging, 'stop', {'reason': 'stop_after', 'value': scan_cfg.stop_after})
                break

            now = time.time()
            if pre.get("enabled", True) and not (scan_cfg.dry_run or args.dry_run):
                if (now - last_ip_check) >= ip_check_interval:
                    last_ip_check = now
                    current_ip = get_public_ipv4(nc_client.session, pre.get("ip_check_url", "https://api.ipify.org"))
                    if current_ip:
                        if last_seen_ip is None:
                            last_seen_ip = current_ip
                        if current_ip != api_cfg.client_ip or current_ip != last_seen_ip:
                            logger.error("IP changed/different | current=%s expected=%s last_seen=%s", current_ip, api_cfg.client_ip, last_seen_ip)
                            jsonl_emit(scan_cfg.logging, 'stop', {'reason': 'ip_changed', 'current': current_ip, 'expected': api_cfg.client_ip})
                            if enforce_match:
                                break
                        else:
                            print(f"[OK] IP check: {current_ip}")
                    else:
                        print("[WARN] Could not verify public IP this round.")

            effective_rpm = warm_rpm if time.time() < warm_until else rpm
            effective_batch = min(warm_batch, scan_cfg.batch_size) if time.time() < warm_until else scan_cfg.batch_size
            if safety_active:
                effective_batch = min(effective_batch, safety_batch)
            interval = 60.0 / max(1, effective_rpm)

            domains, state = gen.generate_batch(store, effective_batch, state, shard_prefixes)
            req_cfg = (scan_cfg.logging or {}).get('requests', {})
            if req_cfg.get('enabled', True):
                mode = (req_cfg.get('include_domains', 'sample') or 'sample').lower()
                sample = domains[: int(req_cfg.get('sample_size', 20))]
                doms = domains if mode == 'full' else (sample if mode == 'sample' else [])
                logger.info("Batch ready | size=%d | rpm=%d", len(domains), int(effective_rpm))
                jsonl_emit(scan_cfg.logging, 'batch_send', {
                    'size': len(domains), 'rpm': int(effective_rpm), 'domains': doms,
                })
                if doms:
                    logger.debug("Batch domains => %s", ", ".join(doms))
            if not domains:
                logger.info("Stop | generation complete (no more unchecked)")
                jsonl_emit(scan_cfg.logging, 'stop', {'reason': 'depleted'})
                break

            t0 = time.time()
            if args.debug:
                logger.debug("Batch send | size=%d | sample=%s", len(domains), domains[:5])
            if scan_cfg.dry_run or args.dry_run:
                fake_pricing = {d: {} for d in domains}
                fake_checked = [(d, False) for d in domains]
                store.save_checked(fake_checked, set(), fake_pricing, scorer)
                total_checked += len(fake_checked)
                time.sleep(interval)
                continue

            try:
                available, checked, pricing = nc_client.check(domains)
                if safety_active:
                    requests_since_cooldown += 1
                    if requests_since_cooldown >= cooldown_every:
                        logger.info("Cooldown | sleeping %.2fs after %d requests", cooldown_seconds, requests_since_cooldown)
                        time.sleep(cooldown_seconds)
                        requests_since_cooldown = 0
                rpm = min(max_rpm, int(rpm * 1.02 + 1))
                backoff = 1.0

            except requests.HTTPError as e:
                status = getattr(e.response, "status_code", None)
                logger.warning("HTTP error | status=%s | backing off", str(status))
                jsonl_emit(scan_cfg.logging, 'http_error', {'status': status, 'batch_size': len(domains)})
                rpm = max(min_rpm, int(rpm * 0.8))
                for d in domains[: int(scan_cfg.rdap.get('check_on_fail_count', 3)) ]:
                    r = rdap_client.check(d)
                    if r is not None:
                        store.mark_rdap(d, r)
                time.sleep(min(300, interval * (backoff * 4)))
                backoff = min(8.0, backoff * 2)
                continue
            except RateLimitedError as e:
                logger.warning("API rate limited | %s | applying strong backoff", str(e))
                jsonl_emit(scan_cfg.logging, 'api_error', {'type': 'rate_limited', 'message': str(e), 'batch_size': len(domains)})
                rpm = max(min_rpm, int(rpm * 0.6))
                for d in domains[: int(scan_cfg.rdap.get('check_on_fail_count', 3)) ]:
                    r = rdap_client.check(d)
                    if r is not None:
                        store.mark_rdap(d, r)
                time.sleep(min(180, interval * (backoff * 5)))
                backoff = min(8.0, backoff * 2)
                continue
            except NamecheapAPIError as e:
                logger.warning("API error | %s | backing off", str(e))
                jsonl_emit(scan_cfg.logging, 'api_error', {'type': 'xml_error', 'message': str(e), 'batch_size': len(domains)})
                rpm = max(min_rpm, int(rpm * 0.75))
                time.sleep(min(90, interval * (backoff * 3)))
                backoff = min(8.0, backoff * 2)
                continue
            except Exception as e:
                logger.warning("Request failed | error=%s | backing off", str(e))
                jsonl_emit(scan_cfg.logging, 'request_exception', {'error': str(e), 'batch_size': len(domains)})
                rpm = max(min_rpm, int(rpm * 0.85))
                time.sleep(min(60, interval * (backoff * 4)))
                backoff = min(8.0, backoff * 2)
                continue

            store.save_checked(checked, set(available), pricing, scorer)
            res_cfg = (scan_cfg.logging or {}).get('responses', {})
            if res_cfg.get('enabled', True):
                avail_out = available if res_cfg.get('include_available', True) else []
                logger.info("API response | checked=%d | available=%d", len(checked), len(available))
                jsonl_emit(scan_cfg.logging, 'api_response', {
                    'checked': len(checked), 'available_count': len(available), 'available': avail_out,
                })
            if (scan_cfg.logging or {}).get('responses', {}).get('log_checked_domains', False):
                logger.debug("Checked domains => %s", ", ".join([d for (d, _) in checked]))
            total_checked += len(checked)
            send_alerts(scan_cfg, [(d, p) for d, p in checked if d in available], pricing, scorer)

            if available:
                prem_map = {d: p for d, p in checked}
                with open(scan_cfg.csv_path, "a", encoding="utf-8") as f:
                    for d in available:
                        sld = ".".join(d.split(".")[:-1])
                        tld = d.split(".")[-1]
                        scv = scorer(sld)
                        is_prem = 1 if prem_map.get(d, False) else 0
                        if scan_cfg.show_premium or not is_prem:
                            pr = pricing.get(d, {})
                            f.write(
                                f"{d},{tld},{'true' if is_prem else 'false'},{scv},"
                                f"{pr.get('premium_registration_price') or ''},"
                                f"{pr.get('premium_renewal_price') or ''},"
                                f"{pr.get('icann_fee') or ''}\n"
                            )

            if scan_cfg.mode == "lexicographic":
                last_word = state.get("word", "")
                length = state.get("length", scan_cfg.min_length)
                store.set_progress(last_word, length, meta["alphabet"], meta, cursor=state.get("cursor", 0),
                                   shard_prefix=(shard_prefixes[0] if shard_prefixes else None))
            elif scan_cfg.mode == "phonetic":
                store.set_progress("", 0, meta["alphabet"], meta, cursor=state.get("syllable_idx", 0),
                                   shard_prefix=(shard_prefixes[0] if shard_prefixes else None))
            elif scan_cfg.mode == "dictionary":
                store.set_progress("", 0, meta["alphabet"], meta, cursor=state.get("cursor", 0),
                                   shard_prefix=(shard_prefixes[0] if shard_prefixes else None))
            else:
                store.set_progress("", 0, meta["alphabet"], meta, cursor=0,
                                   shard_prefix=(shard_prefixes[0] if shard_prefixes else None))

            elapsed = time.time() - t0
            jitter = random.uniform(0, interval * 0.25)
            sleep_for = max(0.0, (interval * backoff) - elapsed + jitter)
            if safety_active:
                import random as _r
                extra_ms = _r.randint(int(rand_ms_range[0]), int(rand_ms_range[1])) / 1000.0
                sleep_for += extra_ms
            time.sleep(sleep_for)

            logger.info("Progress | checked=%d rpm=%d mode=%s", total_checked, rpm, scan_cfg.mode)
            jsonl_emit(scan_cfg.logging, 'progress', {'checked': total_checked, 'rpm': rpm, 'mode': scan_cfg.mode})

    except KeyboardInterrupt:
        logger.info("Stop | interrupted by user (KeyboardInterrupt)")
    jsonl_emit(scan_cfg.logging, 'stop', {'reason': 'keyboardinterrupt'})

    print("Done. Bye.")


if __name__ == "__main__":
    main()