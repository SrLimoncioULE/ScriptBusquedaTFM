import re
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class MatchResult:
    score: int
    tags: Dict[str, List[str]] = field(default_factory=dict)
    hits: Dict[str, List[str]] = field(default_factory=dict)

class AutomotiveCyberFilter:
    """
    Heurístico de automoción afinado:
      - CAN/VIN estrictos (no confundir 'can' verbo ni 'vin' en 'giving')
      - MOST sólo si es acrónimo real
      - Reclasifica 'dealership/dealer' como retail (bajo peso)
      - Bono por proximidad ciber<->auto
      - Caps por marcas/proveedores
      - Penaliza contextos flojos (sólo marca / sólo manufacturing)
      - Filtra EVSE/protocolos ambiguos ('charge point(s)' genérico)
      - Desambiguación de marcas cortas (ram/mini/seat/ford/fiat/abb)
      - Señales fuertes de telemática/acciones remotas y portales
      - Evita 'autonomous region/city' (no automoción)
    """

    def __init__(self, filters: Dict):
        if not filters:
            raise ValueError("Se requiere un diccionario de filtros.")
        self.filters = filters
        self._compile()

    # --------- Compilación ---------
    def _compile(self):
        c = self.filters["categories"]
        self.rx = {}

        def rx_or(terms: List[str]) -> re.Pattern:
            if not terms:
                return re.compile(r"$^")
            return re.compile(r"(?i)\b(" + r"|".join(terms) + r")\b")

        # Pools multilenguaje
        self.rx["attack_terms"]        = rx_or(c["attack_terms"]["es"] + c["attack_terms"]["en"])
        self.rx["vuln_terms"]          = rx_or(c["vuln_terms"]["es"]   + c["vuln_terms"]["en"])
        self.rx["automotive_terms"]    = rx_or(c["automotive_terms"]["es"] + c["automotive_terms"]["en"])
        self.rx["manufacturing_terms"] = rx_or(c["manufacturing_terms"]["es"] + c["manufacturing_terms"]["en"])
        self.rx["attack_vectors"]      = rx_or(c["attack_vectors"]["es"] + c["attack_vectors"]["en"])
        self.rx["protocols"]           = rx_or(c["protocols"])
        self.rx["standards"]           = rx_or(c["standards"])
        self.rx["outcomes"]            = rx_or(c["outcomes"]["es"] + c["outcomes"]["en"])

        # Marcas / proveedores
        self.brand_map    = self.filters.get("brand_aliases", {})
        self.supplier_map = self.filters.get("supplier_aliases", {})

        for extra in ["SiriusXM", "XM Guardian"]:
            self.supplier_map.setdefault(extra, [])

        self.rx_brands = {
            k: re.compile(r"(?i)\b(" + "|".join(map(re.escape, [k] + list(sorted(set(v))))) + r")\b")
            for k, v in self.brand_map.items()
        }
        self.rx_suppliers = {
            k: re.compile(r"(?i)\b(" + "|".join(map(re.escape, [k] + list(sorted(set(v))))) + r")\b")
            for k, v in self.supplier_map.items()
        }

        # Negativos (si existen en tu JSON)
        neg = self.filters.get("negative_terms", {})
        self.rx["negative"] = rx_or(neg.get("es", []) + neg.get("en", []))

        # Fuertes / utilidades
        self.rx["CVE"] = re.compile(r"(?i)\bCVE-\d{4}-\d+\b")
        self.rx["CWE"] = re.compile(r"(?i)\bCWE-\d+\b")

        # Guardas específicas
        self.CAN_STRICT = re.compile(r"(?i)\bcan(?:\s*bus|\s*fd|\s*xl|\s*network|[-\s]*bus)\b")
        self.MOST_STRICT_ANY = re.compile(
            r"(?:(?<![A-Za-z])MOST(?![a-z])|media\s+oriented\s+systems?\s+transport|most\s*(?:bus|25|150))",
            re.I
        )
        self.VIN_STRICT = re.compile(r"(?i)\bVIN\b|\bvehicle\s+identification\s+number\b")  # === NEW ===
        self.EVSE_AMBIGUOUS = re.compile(r"(?i)\b(charge\s*point|charging\s*points?)\b")

        self.PORTAL_STRICT = re.compile(r"(?i)\b(?:owner|customer|dealer|admin)\s+portal\b")
        self.TELEMATICS_PORTALS = re.compile(
            r"(?i)\b(connected\s*drive|car[-\s]*net|uconnect|onstar|mercedes\s*me|ford\s*pass|kia\s*connect|nissan\s*connect|"
            r"my\s*subaru|mysubaru|hondalink|acuralink|incontrol|we\s*connect|starlink\s*app|xm\s*guardian|sirius\s*xm)\b"
        )
        self.AUTO_ACTIONS = re.compile(
            r"(?i)\b(remote(?:ly)?\s+(?:start|unlock|lock|open|close|track|control)|start\s+(?:engine|car)|unlock\s+(?:door|car)s?|"
            r"immobiliz(?:e|er)|kill\s*switch|precondition(?:ing)?|flash(?:\s+lights)?|horn|honk)\b"
        )

        # Evitar “autonomous … (region/city/…)”
        self.AUTONOMOUS_NONAUTO = re.compile(r"(?i)\bautonomous\s+(?:region|community|city|island|territory|zone|district)\b")

        # Ventanas de proximidad (caracteres)
        self.PROX_SHORT, self.PROX_MID = 80, 160

        # Pesos y caps
        self.W = {
            # Ciber
            "attack_terms": 4, "vuln_terms": 3, "outcomes": 3, "CVE": 1, "CWE": 1, "attack_vectors": 1,
            # Dominio
            "automotive_terms": 4, "manufacturing_terms": 3, "protocols": 2, "standards": 1,
            # Entidades
            "brand_unit": 2, "supplier_unit": 1, "retail_unit": 1,
            # Bonos
            "prox_short": 3, "prox_mid": 1,
            # Penalizaciones
            "neg_per_hit": 2, "neg_cap": 6,
            "only_brand_penalty": 3,
            "only_factory_penalty": 2,
            # señales fuertes
            "auto_actions": 4,
            "portal_strict": 3,
            "telematics_portal": 3,
        }
        self.CAPS = {"brands_max": 4, "suppliers_max": 3}

        self.ambiguous_brand_rules = {
            "ram": re.compile(r"(?i)\bRAM\s*(?:1500|2500|3500|TRX|truck|pickup|trucks)\b"),
            "mini": re.compile(r"(?i)\bMINI\s+(?:Cooper|Countryman|Electric)\b|\bMini\s+Cooper\b"),
            "seat": re.compile(r"(?i)\bSEAT\b|\bCupra\b"),
            "ford": re.compile(r"(?i)\bFord\s+(?:Motor|F-?\d{2,3}|Bronco|Mustang|Ranger|Explorer|Transit)\b"),
            "fiat": re.compile(r"(?i)\bFIAT\s?(?:500|Panda|Tipo|Doblo|Egea|PULSE|Toro)\b"),
            "abb": re.compile(r"(?i)\bABB\b.*\b(charger|evse|ocpp|terra|robot|robotics)\b"),
        }

    # --------- Helpers ---------
    @staticmethod
    def _norm_text(text: str) -> str:
        return re.sub(r"\s+", " ", (text or "").strip())

    @staticmethod
    def _uniq(seq: List[str]) -> List[str]:
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                out.append(x); seen.add(x)
        return out

    def _find_all(self, rx: re.Pattern, t: str) -> List[re.Match]:
        return list(rx.finditer(t))

    def _positions(self, t: str, terms: List[str]) -> List[int]:
        # usa bordes de palabra para tokens cortos
        pos = []
        for w in terms:
            token = w.strip()
            if not token:
                continue
            # bordes sólo si es una sola “palabra” sin espacios
            if re.fullmatch(r"[A-Za-z0-9\-_/]+", token):
                pattern = re.compile(rf"(?i)\b{re.escape(token)}\b")
            else:
                pattern = re.compile(re.escape(token), re.I)
            pos.extend(m.start() for m in pattern.finditer(t))
        return pos

    def _proximity_bonus(self, t: str, A: List[str], B: List[str]) -> int:
        if not A or not B:
            return 0
        pa, pb = self._positions(t, A), self._positions(t, B)
        if not pa or not pb:
            return 0
        best = min(abs(a - b) for a in pa for b in pb)
        if best <= self.PROX_SHORT: return self.W["prox_short"]
        if best <= self.PROX_MID:   return self.W["prox_mid"]
        return 0

    def _refine_protocol_hits(self, t: str, vals: List[str]) -> List[str]:
        """Filtra CAN/MOST/VIN ambiguos y EVSE genérico."""
        out = []
        for v in vals:
            vv = v.lower()
            # CAN: exige forma técnica
            if vv == "can":
                if self.CAN_STRICT.search(t):
                    out.append("CAN bus")
                continue
            # MOST: sólo acrónimo/expansión reales
            if vv == "most":
                if self.MOST_STRICT_ANY.search(t):
                    out.append("MOST")
                continue
            # VIN: forma estricta
            if vv == "vin":
                if self.VIN_STRICT.search(t):
                    out.append("VIN")
                continue
            # EVSE genérico 'charge point(s)' fuera
            if self.EVSE_AMBIGUOUS.search(v):
                continue
            out.append(v)
        return self._uniq(out)

    def _split_retail_from_manufacturing(self, hits: Dict[str, List[str]]) -> None:
        """Mueve 'dealership/dealer' de manufacturing -> retail (peso bajo)."""
        m = hits.get("manufacturing_terms", [])
        if not m: return
        retail_tokens = [x for x in m if x.lower() in {"dealership", "dealer", "dealers"}]
        if retail_tokens:
            hits["manufacturing_terms"] = [x for x in m if x not in retail_tokens] or []
            hits["retail"] = self._uniq(hits.get("retail", []) + retail_tokens)
            if not hits["manufacturing_terms"]:
                hits.pop("manufacturing_terms", None)

    def _disambiguate_brand_hits(self, t: str, hits: Dict[str, List[str]]) -> None:
        """Filtra marcas ambiguas si no hay contexto automotriz claro."""
        if "brands" not in hits:
            return
        kept = []
        for b in hits["brands"]:
            rule = self.ambiguous_brand_rules.get(b.lower())
            if not rule:
                kept.append(b)
                continue
            if rule.search(t) or self.rx["automotive_terms"].search(t) or self.rx["protocols"].search(t):
                kept.append(b)
        if kept:
            hits["brands"] = self._uniq(kept)
        else:
            hits.pop("brands", None)

    # --------- Scoring principal ---------
    def score_text(self, text: str) -> MatchResult:
        t = self._norm_text(text)
        hits: Dict[str, List[str]] = {}
        tags: Dict[str, List[str]] = {}

        def add_hits(key: str, matches: List[re.Match]):
            if matches:
                vals = sorted({m.group(0) for m in matches})
                if vals: hits[key] = vals

        # Evita “autonomous region/city…”
        if self.AUTONOMOUS_NONAUTO.search(t):
            tags.setdefault("negatives", []).append("autonomous_nonauto")

        # Detecta categorías base
        for key in ["attack_terms","vuln_terms","automotive_terms","manufacturing_terms",
                    "attack_vectors","protocols","standards","outcomes","CVE","CWE"]:
            add_hits(key, self._find_all(self.rx[key], t))

        # Refinos protocolos
        if "protocols" in hits:
            refined = self._refine_protocol_hits(t, hits["protocols"])
            if refined: hits["protocols"] = refined
            else: hits.pop("protocols", None)

        self._split_retail_from_manufacturing(hits)

        # Marcas / proveedores
        brands = [name for name, rx in self.rx_brands.items() if rx.search(t)]
        supps  = [name for name, rx in self.rx_suppliers.items() if rx.search(t)]
        if brands: hits["brands"]    = self._uniq(brands)
        if supps:  hits["suppliers"] = self._uniq(supps)

        # Desambiguación de marcas cortas
        self._disambiguate_brand_hits(t, hits)

        # Señales fuertes auto/telemática
        if self.AUTO_ACTIONS.search(t):
            hits["auto_actions"] = [self.AUTO_ACTIONS.search(t).group(0)]
        if self.PORTAL_STRICT.search(t):
            hits["portal_strict"] = [self.PORTAL_STRICT.search(t).group(0)]
        if self.TELEMATICS_PORTALS.search(t):
            hits["telematics_portal"] = [self.TELEMATICS_PORTALS.search(t).group(0)]

        # --------- Puntuación ---------
        W, CAPS = self.W, self.CAPS
        score = 0

        # Señales ciber
        if "attack_terms" in hits:  score += W["attack_terms"]
        if "vuln_terms" in hits:    score += W["vuln_terms"]
        if "outcomes" in hits:      score += W["outcomes"]
        if "CVE" in hits:           score += W["CVE"]
        if "CWE" in hits:           score += W["CWE"]
        if "attack_vectors" in hits: score += W["attack_vectors"]

        # Dominio
        manuf_alone = False
        if "automotive_terms" in hits: score += W["automotive_terms"]
        if "manufacturing_terms" in hits:
            if not any(k in hits for k in ("automotive_terms","brands","protocols")):
                score += max(1, W["manufacturing_terms"] - 2)
                manuf_alone = True
            else:
                score += W["manufacturing_terms"]
        if "protocols" in hits: score += W["protocols"]
        if "standards" in hits: score += W["standards"]

        # Entidades con caps
        if "brands" in hits:    score += min(CAPS["brands_max"],    W["brand_unit"]    * len(hits["brands"]))
        if "suppliers" in hits: score += min(CAPS["suppliers_max"], W["supplier_unit"] * len(hits["suppliers"]))
        if "retail" in hits:    score += W["retail_unit"]

        # Bonos fuertes
        if "auto_actions" in hits:       score += W["auto_actions"]
        if "portal_strict" in hits:      score += W["portal_strict"]
        if "telematics_portal" in hits:  score += W["telematics_portal"]

        # Bono por proximidad ciber<->auto
        cyber_terms = sum([hits.get(k, []) for k in ("attack_terms","vuln_terms","outcomes")], [])
        auto_terms  = sum([hits.get(k, []) for k in ("automotive_terms","protocols","brands","manufacturing_terms","suppliers")], [])
        prox = self._proximity_bonus(t, cyber_terms, auto_terms)
        score += prox
        if prox: tags["proximity"] = [f"{prox}pts"]

        # Negativos (cappeados)
        neg = self._find_all(self.rx["negative"], t)
        if neg or "autonomous_nonauto" in tags.get("negatives", []):
            total_neg = len(neg) + (1 if "autonomous_nonauto" in tags.get("negatives", []) else 0)
            pen = min(W["neg_cap"], W["neg_per_hit"] * total_neg)
            score -= pen
            tags["negatives"] = sorted(set(tags.get("negatives", []) + [m.group(0) for m in neg]))

        # Penalizaciones de contexto flojo
        only_brand = ("brands" in hits) and not any(k in hits for k in ("automotive_terms","protocols","attack_terms","vuln_terms","outcomes","auto_actions","telematics_portal","portal_strict"))
        if only_brand:
            score -= W["only_brand_penalty"]; tags.setdefault("notes", []).append("only_brand")
        if manuf_alone:
            score -= W["only_factory_penalty"]; tags.setdefault("notes", []).append("manufacturing_alone")

        # Etiquetado de dominio
        bucket = []
        if hits.get("manufacturing_terms"): bucket.append("factory")
        if hits.get("brands"):              bucket.append("vehicle")
        if hits.get("suppliers"):           bucket.append("supplier")
        if hits.get("retail"):              bucket.append("retail")
        if not bucket and hits.get("automotive_terms"): bucket.append("vehicle")
        if bucket: tags["domain"] = bucket

        # Etiquetas finas
        for key in ["protocols","attack_vectors","standards","outcomes","auto_actions","telematics_portal","portal_strict"]:
            if key in hits: tags[key] = hits[key]

        return MatchResult(score=score, tags=tags, hits=hits)
