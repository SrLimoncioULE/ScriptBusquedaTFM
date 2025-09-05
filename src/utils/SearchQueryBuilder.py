# utils/SearchQueryBuilder.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re


def _q(s: str) -> str:
    """
    Envuelve con comillas si tiene espacios/guiones/slash.
    Útil para construir grupos OR sin liarla con las frases.
    """
    s = (s or "").strip()
    if not s:
        return ""
    return f"\"{s}\"" if any(c in s for c in (" ", "-", "/")) else s


def _unique(seq: List[str]) -> List[str]:
    """
    Dedupe estable (preserva el orden).
    Lo uso para no repetir tokens en grupos OR ni inflar las queries.
    """
    seen, out = set(), []
    for x in seq or []:
        k = (x or "").strip().lower()
        if k and k not in seen:
            seen.add(k); out.append(x)
    return out


@dataclass
class SearchQueryBuilder:
    """
    Builder de consultas multi-proveedor con fallback Q1→Q2→Q3→(Q4 opcional).
    Soporta:
      - News: GNews, SerpAPI (Google News), GDELT, NewsData.io
      - Papers: Semantic Scholar (bulk), OpenAlex
      - Vulns: NVD, MITRE

    Decisiones clave (y por qué):
      - Cada proveedor tiene *su* sintaxis: AND/OR, +/|, o texto plano.
      - Recorto por proveedor para evitar 414 URI Too Long y límites “oscuros”.
      - Negativos: sólo donde el proveedor lo soporta (evito NOT en S2/OPENALEX/NVD/MITRE).
      - EXPANSIONS agresivas para automoción/OT/ransomware (2020–2025).
    """

    # Preferencias globales
    lang: str = "en"
    allow_broad_q4: bool = True
    precision: str = "tight"  # 'tight' | 'balanced' | 'broad'

    # Límites de longitud aproximados/seguros por proveedor
    GNEWS_MAX: int = 190
    SERPAPI_MAX: int = 2000
    NEWSAPI_MAX: int = 5000
    GDELT_MAX: int = 1000
    NEWSDATA_MAX: int = 512

    # Papers / Vulns (conservadores para no chocar con 414/URI Too Long)
    S2_MAX: int = 700
    OPENALEX_MAX: int = 1200
    NVD_MAX: int = 1200
    MITRE_MAX: int = 700


    # Términos base de seguridad/objetivo
    SECURITY_EN: List[str] = field(default_factory=lambda: [
        "ransomware","cyberattack","breach","leak","exfiltration","extortion",
        "DDoS","hacked","hack","malware","breach","intrusion","data breach"
    ])
    SECURITY_ES: List[str] = field(default_factory=lambda: [
        "ransomware","ciberataque","filtración","fuga","exfiltración","extorsión",
        "DDoS","hackeo","hackeado","malware","brecha","robo de datos"
    ])
    TARGETS_EN:  List[str] = field(default_factory=lambda: [
        "automotive","vehicle","car","OEM","supplier","Tier1","factory","plant",
        "assembly","dealership","ECU","OTA","V2X"
    ])
    TARGETS_ES:  List[str] = field(default_factory=lambda: [
        "automotriz","vehículo","coche","fabricante","proveedor","Tier1","planta",
        "fábrica","concesionario"
    ])

    # Negativos sólo para buscadores de noticias (ruido típico de deportes, farándula…)
    NEG_EN: List[str] = field(default_factory=lambda: [
        "Formula 1","F1","soccer","football","NBA","NFL","NHL","MLB","MotoGP","tennis","golf","cricket","rugby","olympics",
        "shooting","homicide","murder","stabbing","kidnapping","celebrity","gossip","award show"
    ])
    NEG_ES: List[str] = field(default_factory=lambda: [
        "Fórmula 1","F1","fútbol","baloncesto","tenis","golf","MotoGP","olimpiadas",
        "tiroteo","asesinato","homicidio","apuñalamiento","secuestro","celebridad","farándula","premios"
    ])

    # Excludes pensados para papers (evito visión, SLAM, baterías, etc.)
    PAPER_EXCLUDE: List[str] = field(default_factory=lambda: [
        "dataset","benchmark","object detection","SLAM","perception","lane detection",
        "battery","powertrain","traffic flow","ADAS"
    ])

    # expansiones de términos cortos
    EXPANSIONS: Dict[str, str] = field(default_factory=lambda: {
        # --- Buses / diagnóstico / middleware ---
        "can": '"Controller Area Network" OR "CAN bus"',
        "can bus": '"CAN bus" OR "Controller Area Network" OR "CAN-Bus" OR "CAN protocol"',
        "canbus": '"CAN bus" OR "Controller Area Network" OR "CAN-Bus" OR "CAN protocol"',
        "can fd": '"CAN FD" OR "CAN-FD" OR "CAN with Flexible Data-Rate"',
        "lin": 'LIN OR "Local Interconnect Network"',
        "flexray": 'FlexRay',
        "ethernet": 'Ethernet OR "automotive ethernet" OR "100BASE-T1" OR "1000BASE-T1"',
        "uds": 'UDS OR "Unified Diagnostic Services" OR "ISO 14229"',
        "doip": 'DoIP OR "Diagnostics over IP" OR "ISO 13400"',
        "some/ip": 'SOME/IP OR "SOMEIP" OR "Scalable service-Oriented Middleware over IP"',
        "autosar": 'AUTOSAR OR "AUTomotive Open System ARchitecture"',
        "obd": 'OBD OR "OBD-II" OR "On-Board Diagnostics" OR "SAE J1979"',
        "obd ii": '"OBD-II" OR OBD OR "On-Board Diagnostics" OR "SAE J1979"',
        "obdii": '"OBD-II" OR OBD OR "On-Board Diagnostics" OR "SAE J1979"',

        # --- Conectividad / OTA / V2X ---
        "ota": 'OTA OR "over-the-air"',
        "fota": 'FOTA OR "firmware over-the-air"',
        "sota": 'SOTA OR "software over-the-air"',
        "v2x": 'V2X OR "vehicle-to-everything"',
        "v2v": 'V2V OR "vehicle-to-vehicle"',
        "v2i": 'V2I OR "vehicle-to-infrastructure"',
        "cv2x": 'C-V2X OR "cellular vehicle-to-everything"',
        "c v2x": 'C-V2X OR "cellular vehicle-to-everything"',
        "dsrc": 'DSRC OR "dedicated short-range communications"',
        "bluetooth": 'Bluetooth OR BLE OR "Bluetooth Low Energy"',
        "wifi": 'WiFi OR "Wi-Fi" OR WLAN',
        "lte": 'LTE OR 4G OR "Long Term Evolution"',
        "5g": '5G OR "cellular network"',

        # --- Módulos / ECUs ---
        "ecu": 'ECU OR "electronic control unit"',
        "tcu": 'TCU OR "telematics control unit" OR telematics',
        "tbox": '"T-Box" OR TBox OR "telematics box"',
        "t box": '"T-Box" OR TBox OR "telematics box"',
        "bcm": 'BCM OR "body control module"',
        "bms": 'BMS OR "battery management system"',
        "ivi": 'IVI OR "in-vehicle infotainment" OR infotainment',
        "adas": 'ADAS OR "advanced driver assistance system" OR "driver assistance"',
        "hud": 'HUD OR "head-up display"',
        "hvac": 'HVAC OR "climate control"',
        "dcm": 'DCM OR "data communication module"',
        "rke": 'RKE OR "remote keyless entry"',
        "key fob": '"key fob" OR "remote keyless entry"',
        "tpms": 'TPMS OR "tire pressure monitoring system"',
        "gps": 'GPS OR GNSS OR "global positioning system"',
        "gnss": 'GNSS OR GPS OR "global navigation satellite system"',

        # --- OT / Industrial ---
        "ot": 'OT OR "operational technology" OR "factory network" OR "industrial network"',
        "ics": 'ICS OR "industrial control system" OR "industrial control systems"',
        "scada": 'SCADA OR "supervisory control and data acquisition"',
        "plc": 'PLC OR "programmable logic controller"',
        "hmi": 'HMI OR "human-machine interface"',
        "mes": 'MES OR "manufacturing execution system"',
        "erp": 'ERP OR "enterprise resource planning"',
        "dcs": 'DCS OR "distributed control system"',

        # --- Cripto / plataformas seguras (habitual en automoción) ---
        "tpm": '"Trusted Platform Module" OR TPM',
        "hsm": '"Hardware Security Module" OR HSM',
        "tee": '"Trusted Execution Environment" OR TEE',

        # --- Normas (útil para filtrar noticias del sector, 2020+) ---
        "iso 21434": '"ISO/SAE 21434" OR "ISO 21434" OR "Road vehicles — cybersecurity engineering"',
        "wp.29": '"UNECE WP.29" OR R155 OR R156 OR CSMS OR SUMS OR "cybersecurity management system"',
        "wp 29": '"UNECE WP.29" OR R155 OR R156 OR CSMS OR SUMS OR "cybersecurity management system"',

        # --- Actores de ransomware / sinónimos y rebrandings ---
        "alphv": 'ALPHV OR BlackCat',
        "blackcat": 'BlackCat OR ALPHV',
        "lockbit": 'LockBit OR "LockBit 3.0" OR "LockBit Black"',
        "clop": 'Clop OR Cl0p',
        "cl0p": 'Cl0p OR Clop',
        "black basta": '"Black Basta"',
        "8base": '8Base',
        "ragnar locker": '"Ragnar Locker" OR RagnarLocker',
        "vice society": '"Vice Society"',
        "bianlian": 'BianLian OR "Bian Lian"',
        "play": 'Play OR "Play ransomware"',
        "conti": 'Conti OR "Conti Team"',
        "revil": 'REvil OR Sodinokibi OR "Sodinokibi"',
        "maze": 'Maze OR "Maze ransomware"',
        "hive": 'Hive OR "Hive ransomware"',
        "darkside": 'DarkSide OR "Dark Side" OR BlackMatter',
        "blackmatter": 'BlackMatter OR DarkSide',
        "cuba": 'Cuba OR "Cuba ransomware"',
        "snatch": 'Snatch OR "Snatch ransomware"',
        "daixin": 'Daixin OR "Daixin Team"',
        "qilin": 'Qilin OR "Qilin ransomware"',
        "noescape": 'NoEscape OR "NoEscape ransomware"',
        "blackbyte": 'BlackByte OR "BlackByte ransomware"',

        # --- Impacto típico (por si usas el kw como “impacto”) ---
        "production halt": '"production halt" OR "production stop" OR "line shutdown" OR downtime OR "manufacturing disruption"',
        "factory shutdown": '"factory shutdown" OR "plant shutdown" OR "production shutdown"',
        "data leak": '"data leak" OR "data breach" OR "data exfiltration" OR "leak site" OR "leaked data"',
        "extortion": '"extortion" OR "double extortion" OR "triple extortion"',

        # --- OEMs (sinónimos / nombres corporativos) ---
        "vw": '"Volkswagen" OR "Volkswagen Group" OR VAG',
        "vag": '"Volkswagen Group" OR Volkswagen',
        "volkswagen": '"Volkswagen" OR "Volkswagen Group" OR VAG',
        "gm": '"General Motors" OR GM',
        "general motors": '"General Motors" OR GM',
        "ford": '"Ford" OR "Ford Motor Company"',
        "stellantis": 'Stellantis OR "Fiat Chrysler Automobiles" OR FCA OR "Groupe PSA" OR PSA OR "Peugeot SA"',
        "fca": 'FCA OR "Fiat Chrysler Automobiles" OR Stellantis',
        "psa": 'PSA OR "Groupe PSA" OR Stellantis',
        "toyota": 'Toyota OR "Toyota Motor" OR "Toyota Motor Corporation"',
        "honda": 'Honda OR "Honda Motor" OR "Honda Motor Co."',
        "hyundai": 'Hyundai OR "Hyundai Motor Company" OR "Hyundai Motor Group"',
        "kia": 'Kia OR "Kia Corporation" OR "Hyundai-Kia"',
        "hmg": '"Hyundai Motor Group" OR HMG OR "Hyundai-Kia"',
        "renault": 'Renault OR "Groupe Renault" OR "Renault Group"',
        "nissan": 'Nissan OR "Nissan Motor"',
        "bmw": 'BMW OR "BMW Group" OR "Bayerische Motoren Werke"',
        "mercedes": '"Mercedes-Benz" OR Daimler OR "Mercedes-Benz Group"',
        "daimler": 'Daimler OR "Mercedes-Benz" OR "Mercedes-Benz Group"',
        "jlr": '"Jaguar Land Rover" OR JLR',
        "land rover": '"Land Rover" OR "Jaguar Land Rover" OR JLR',
        "jaguar": '"Jaguar" OR "Jaguar Land Rover" OR JLR',
        "volvo": 'Volvo OR "Volvo Cars"',
        "geely": 'Geely OR "Zhejiang Geely Holding" OR "Geely Auto"',
        "saic": 'SAIC OR "SAIC Motor" OR "Shanghai Automotive"',
        "byd": 'BYD OR "BYD Auto"',
        "baic": 'BAIC OR "Beijing Automotive"',
        "faw": 'FAW OR "FAW Group" OR "First Automobile Works"',
        "skoda": 'Škoda OR Skoda OR "Skoda Auto"',
        "seat": 'SEAT OR "SEAT S.A." OR Cupra',
        "porsche": 'Porsche OR "Porsche AG"',
        "tesla": 'Tesla OR "Tesla Motors" OR Gigafactory',
        "lucid": 'Lucid OR "Lucid Motors"',
        "rivian": 'Rivian OR "Rivian Automotive"',
        "tata": '"Tata Motors" OR Tata',

        # --- Proveedores / Tier1 (sinónimos / corporativo) ---
        "bosch": 'Bosch OR "Robert Bosch" OR "Bosch Group"',
        "continental": 'Continental OR "Continental AG"',
        "denso": 'Denso OR "Denso Corporation"',
        "magna": 'Magna OR "Magna International"',
        "zf": 'ZF OR "ZF Group" OR "ZF Friedrichshafen"',
        "valeo": 'Valeo',
        "aptiv": 'Aptiv OR "Delphi Automotive" OR Delphi',
        "forvia": 'Forvia OR Faurecia OR HELLA',
        "faurecia": 'Faurecia OR Forvia',
        "hella": 'HELLA OR Forvia',
        "lear": 'Lear OR "Lear Corporation"',
        "aisin": 'Aisin OR "Aisin Seiki"',
        "marelli": 'Marelli OR "Calsonic Kansei"',
        "gestamp": 'Gestamp OR "Gestamp Automoción"',
        "brembo": 'Brembo',
        "yazaki": 'Yazaki',
        "panasonic": 'Panasonic OR "Panasonic Automotive"',
        "harman": 'Harman OR "Harman International" OR "Harman Automotive"',
        "catl": 'CATL OR "Contemporary Amperex Technology"',
        "infineon": 'Infineon OR "Infineon Technologies"',
        "nxp": 'NXP OR "NXP Semiconductors"',
        "renesas": 'Renesas OR "Renesas Electronics"',
        "onsemi": 'onsemi OR "ON Semiconductor"',
        "hitachi astemo": '"Hitachi Astemo" OR "Hitachi Automotive Systems"',

        # --- Otros acrónimos útiles en noticias del sector ---
        "ev": '"electric vehicle" OR EV',
        "oem": 'OEM OR "original equipment manufacturer" OR automaker OR carmaker',
        "tier1": '"Tier 1" OR Tier1 OR "first-tier supplier" OR T1',
        "tier 1": '"Tier 1" OR Tier1 OR "first-tier supplier" OR T1',
        "t1": 'T1 OR "Tier 1" OR Tier1 OR "first-tier supplier"',
        "tier2": '"Tier 2" OR Tier2 OR "second-tier supplier" OR T2',
        "tier 2": '"Tier 2" OR Tier2 OR "second-tier supplier" OR T2',
        "t2": 'T2 OR "Tier 2" OR Tier2 OR "second-tier supplier"'
    })

    # Buckets (puedes ampliar)
    OOEM_BUCKET = ["Toyota","Volkswagen","Stellantis","GM","Ford","Hyundai","Kia","Renault","Nissan","BMW","Mercedes","Tesla","Volvo","Jaguar","Land Rover","BYD","Geely","SAIC","Skoda","Seat","Porsche"]
    TIER1_BUCKET = ["Bosch","Continental","Denso","Magna","ZF","Valeo","Aptiv","Forvia","Lear","Aisin","Marelli","Gestamp","Brembo","Yazaki","Panasonic","Harman","CATL","Infineon","NXP","Renesas"]
    RW_GROUPS = ["LockBit","ALPHV","BlackCat","Clop","Play","8Base","BlackBasta","Ragnar Locker","BianLian","Qilin","Daixin","BlackByte","Cuba","Snatch","Vice Society","NoEscape"]


    # ---------------- helpers internos (formato por proveedor) ---------------- #

    def _clip(self, q: str, maxlen: int) -> str:
        return q[:maxlen]

    def _or_group(self, terms: List[str]) -> str:
        """OR clásico con comillas en frases. Lo uso en News/OpenAlex."""
        ts = []
        for t in terms:
            t = (t or "").strip()
            if not t: continue
            if t.startswith("(") or t.startswith('"') or t.startswith("-"):
                ts.append(t)
            else:
                ts.append(f"\"{t}\"")
        return "(" + " OR ".join(ts) + ")"

    def _expand_keyword(self, kw: str) -> str:
        k = " ".join((kw or "").strip().lower().replace("-", " ").split())
        return self.EXPANSIONS.get(k, kw)

    def _s2_or_group(self, terms: List[str]) -> str:
        """Semantic Scholar bulk: usa '|' como OR y '+' como AND."""
        toks = []
        for t in terms:
            t = (t or "").strip()
            if not t: continue
            if " " in t or any(c in t for c in "-/"):
                toks.append(f"\"{t}\"")
            else:
                toks.append(t)
        return "(" + " | ".join(toks) + ")"

    def _or_group_gdelt(self, terms: List[str]) -> str:
        """
        En GDELT evito comillas en tokens cortos (error 'phrase too short').
        También respeto grupos/negativos si ya vienen formateados.
        """
        ts = []
        for raw in terms or []:
            t = (raw or "").strip()
            if not t:
                continue

            # Mantén grupos/negativos tal cual
            if t.startswith("(") or t.startswith("-"):
                ts.append(t)
                continue

            # Desenvuelve si venía con comillas
            inner = t[1:-1].strip() if (len(t) >= 2 and t[0] == '"' and t[-1] == '"') else t
            if not inner:
                continue

            is_phrase = (" " in inner) or any(c in inner for c in ("-", "/"))

            if is_phrase:
                # Si la frase contiene tokens de 1–2 chars, mejor no forzar comillas
                toks = re.findall(r"[A-Za-z0-9]+", inner)
                if any(len(tok) < 3 for tok in toks):
                    ts.append(inner)  # sin comillas para evitar el error
                else:
                    ts.append(f'"{inner}"')
            else:
                # Palabra suelta: jamás comillas
                ts.append(inner)

        return "(" + " OR ".join(ts) + ")" if ts else ""

    def _gdelt_kw_group(self, base_kw: str) -> str:
        """
        Expansión segura para GDELT: descarto tokens minúsculos y normalizo frases.
        """
        exp = self._expand_keyword(base_kw)
        terms = [t.strip() for t in exp.split(" OR ")]
        safe = []
        for t in terms:
            if t.startswith("(") and t.endswith(")"): t = t[1:-1].strip()
            inner = t[1:-1].strip() if (t.startswith('"') and t.endswith('"')) else t
            inner = " ".join(inner.split())
            if not inner: continue
            if " " not in inner and len(inner) <= 3:  # descarta tokens microscópicos
                continue
            safe.append(f"\"{inner}\"" if any(c in inner for c in (" ","-","/")) else inner)
        if not safe:
            safe = [exp.replace('"',"").replace(" OR "," ").strip() or base_kw.strip()]
        if len(safe) == 1:
            return safe[0][:self.GDELT_MAX]
        return ("(" + " OR ".join(safe) + ")")[:self.GDELT_MAX]
    
    def _gdelt_lang_token(self) -> str:
        return "sourcelang:spanish" if self.lang == "es" else "sourcelang:english"

    def _gdelt_finalize(self, q: str) -> str:
        # GDELT: espacios = AND
        import re
        q = q.replace(" AND ", " ")
        # quita comillas a palabras sin espacio/guion/slash
        q = re.sub(r'"([A-Za-z0-9]+)"', r'\1', q)
        q = " ".join(q.split())
        return q[:self.GDELT_MAX]

    def _dedupe_list(self, xs: List[str]) -> List[str]:
        # evita duplicados como "breach" dos veces
        return _unique(xs)

    def _apply_negatives_gnews(self, q: str) -> str:
        """
        GNews NO entiende '-', uso AND NOT (...) acotando longitud.
        """
        negs = self.NEG_ES if self.lang == "es" else self.NEG_EN
        # vamos añadiendo hasta que nos acerquemos al tope
        group = []
        q2 = q
        for n in negs:
            cand = f'{q2} AND NOT ({ " OR ".join([_q(n)]) })' if not group else \
                   f'{q} AND NOT ({ " OR ".join(_q(x) for x in group + [n]) })'
            if len(cand) > self.GNEWS_MAX:
                break
            group.append(n); q2 = cand
        return q2

    def _apply_negatives_serpapi(self, q: str) -> str:
        """
        SerpAPI (Google News): estilo Google ('-palabra' / '-"dos palabras"').
        """
        negs = self.NEG_ES if self.lang == "es" else self.NEG_EN
        out = q
        for n in negs:
            add = f' -"{n}"' if " " in n else f" -{n}"
            if len(out) + len(add) > self.SERPAPI_MAX:
                break
            out += add
        return out
    
    def _apply_negatives_newsdata(self, q: str) -> str:
        """NewsData.io permite booleanos: AND NOT ( ... )."""
        negs = self.NEG_ES if self.lang == "es" else self.NEG_EN
        base = q
        group, out = [], q
        for n in negs:
            token = f"\"{n}\"" if any(c in n for c in (" ", "-", "/")) else n
            cand = f"{base} AND NOT ({' OR '.join(group + [token])})"
            if len(cand) > self.NEWSDATA_MAX:
                break
            group.append(token); out = cand
        return out
    
    def _strip_quotes_parens(self, s: str) -> str:
        s = s.strip()
        if s.startswith("(") and s.endswith(")"):
            s = s[1:-1].strip()
        if len(s) >= 2 and s[0] in ('"', "'") and s[-1] == s[0]:
            s = s[1:-1].strip()
        return s

    def _split_plain_terms(self, kw: str) -> List[str]:
        """
        Convierte la expansión del keyword (que puede venir como 'A OR "B C" OR D')
        en una lista de términos/frases planos: ['A','B C','D'] (sin OR, sin comillas).
        """
        exp = self._expand_keyword(kw) if kw else (kw or "")
        if not exp:
            return []
        parts = [p.strip() for p in re.split(r"\s+OR\s+", exp, flags=re.IGNORECASE)]
        terms = [self._strip_quotes_parens(p) for p in parts if self._strip_quotes_parens(p)]
        return _unique(terms)

    # --------------- Fallbacks por proveedor ---------------

    def queries_for(self, provider: str, keyword: str) -> List[str]:
        """
        Devuelve la lista de queries [Q1, Q2, Q3, (Q4 opcional)] ya adaptadas
        al proveedor indicado.
        """
        p = (provider or "").strip().lower()
        lang = self.lang

        SEC = self.SECURITY_ES if lang == "es" else self.SECURITY_EN
        #IMP = self.IMPACT_ES   if lang == "es" else self.IMPACT_EN
        TGT = self.TARGETS_ES  if lang == "es" else self.TARGETS_EN

        kw = (keyword or "").strip()
        kw_exp = self._expand_keyword(kw) if kw else kw

        # ---------- NEWS ----------
        if p in ("gnews", "newsapi"):
            q1 = f"({kw_exp}) AND {self._or_group(SEC)} AND {self._or_group(TGT)}"
            q2 = f"({kw_exp}) AND {self._or_group(SEC)}"
            q3 = f"({kw}) AND {self._or_group(SEC)}"
            return [q1, q2, q3]

        if p in ("serpapigooglenews","serpapi","google_news","google news"):
            q1 = f"({kw_exp}) AND {self._or_group(SEC)} AND {self._or_group(TGT)}"
            q2 = f"({kw_exp}) AND {self._or_group(SEC)} AND {self._or_group(TGT)}"
            q3 = f"({kw_exp}) AND {self._or_group(SEC)}"
            base = [q1, q2, q3]
            base = [self._apply_negatives_serpapi(q) for q in base]
            if self.allow_broad_q4:
                base.append(self._apply_negatives_serpapi(f"{kw_exp}"))
            return base

        if p in ("gdelt",):
            sec = self._or_group_gdelt(self._dedupe_list(SEC))
            tgt = self._or_group_gdelt(self.TARGETS_ES if lang=="es" else [
                "automotive","vehicle","car","OEM","supplier","factory","ECU","OTA","V2X"
            ])

            lang_tok = self._gdelt_lang_token()
            kwg = self._gdelt_kw_group(kw_exp or kw)

            # GDELT: espacios = AND
            q1 = self._gdelt_finalize(f"{kwg} {sec} {tgt} {lang_tok}")
            q2 = self._gdelt_finalize(f"{kwg} {sec} {lang_tok}")
            q3 = self._gdelt_finalize(f"{kwg} {lang_tok}")

            base = _unique([q for q in (q1, q2, q3) if q])
            return base

        if p in ("newsdata","newsdata.io"):
            base = f"({kw_exp}) AND {self._or_group(SEC)} AND {self._or_group(TGT)}"
            q1 = self._apply_negatives_newsdata(base)
            q2 = self._apply_negatives_newsdata(f"({kw_exp}) AND {self._or_group(SEC)}")
            q3 = f"{kw_exp}"
            qs = [q if len(q) <= self.NEWSDATA_MAX else q[:self.NEWSDATA_MAX] for q in (q1, q2, q3)]
            return _unique(qs)

        # ---------- PAPERS ----------
        if p in ("semantic_scholar","s2","semanticscholar"):
            # OJO: '+' = AND y '|' = OR. Evitar NOT.
            sec = self._s2_or_group(SEC)
            tgt = self._s2_or_group(TGT)
            k   = f"({kw_exp})" if kw_exp else ""
            q1 = f"{k} + {sec} + {tgt}"
            q2 = f"{k} + {sec}"
            q3 = f"{k}" if k else f"{self._s2_or_group(SEC)}"
            qs = [self._clip(q, self.S2_MAX) for q in (q1, q2, q3)]
            if self.allow_broad_q4 and kw_exp:
                qs.append(self._clip(f"{kw_exp}", self.S2_MAX))
            return _unique(qs)

        if p in ("openalex",):
            # 'search' acepta texto; AND/OR ayudan pero no es boolean estricto.
            sec = self._or_group(SEC)
            tgt = self._or_group(TGT)
            k   = f"({kw_exp})" if kw_exp else ""
            q1 = f"{k} AND {sec} AND {tgt}"
            q2 = f"{k} AND {sec}"
            q3 = f"{k}" if k else f"{sec}"
            qs = [self._clip(q, self.OPENALEX_MAX) for q in (q1, q2, q3)]
            if self.allow_broad_q4 and kw_exp:
                qs.append(self._clip(f"{kw_exp}", self.OPENALEX_MAX))
            return _unique(qs)