# utils/FilterIncident.py
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class IncidentResult:
    keep: bool
    score: int
    category: str | None
    reasons: List[str] = field(default_factory=list)
    matches: Dict[str, List[str]] = field(default_factory=dict)

class IncidentFilter:
    """
    mode:
      - "strict": solo incidentes con impacto operativo verificado
      - "standard": incluye vulns/PoC con producto/marca afectada
      - "broad": añade robos keyless/relay, movilidad (rail/parking/VTC), y PoC realistas
    scope:
      - "auto-only": automoción pura
      - "mobility": incluye rail, taxi/VTC, carsharing, parking, peajes, ANPR, logística
    """

    def __init__(self, mode: str = "strict", scope: str = "auto-only"):
        self.mode = mode
        self.scope = scope

        # ========= LEXICÓN POSITIVO (ES/EN) =========
        self.positive = {
            # 1) Ataque / brecha confirmada
            "attack_confirmed": [
                # ES
                r"\b(sufri[oó]|padeci[oó]|ha[n]?\s+sufrido|ha[n]?\s+experimentado)\b.*\b(ciber\s*ataque|ciberataque|ciber-ataque|ataque|intrusi[oó]n|brecha|compromiso|hack(eo|eado|eada|eados|eadas))\b",
                r"\b(fue|fueron|ha[n]?\s+sido)\s+(hackeado|atacado|comprometido|vulnerado|violado)\b",
                r"\b(ciber\s*ataque|ciberataque|ciber-ataque|intrusi[oó]n|brecha|compromiso|exfiltraci[oó]n)\s+confirmad[oa]s?\b",
                r"\b(rob(o|ados)|sustra[ií]d[oa]s?|filtr(a|adas|ado|ados))\s+(de\s+)?(datos|credenciales|informaci[oó]n)\b",
                # EN
                r"\b(was|were)\s+(hacked|attacked|compromised|breached)\b",
                r"\b(cyber[-\s]?attack(s)?)\b",
                r"\b(denial[-\s]?of[-\s]?service|ddos)\b",
                r"\b(confirm(ation|ed|s)?)\b.*\b(cyber[-\s]?attack|intrusion|breach|compromise|exfiltration)\b",
                r"\b(hit|suffer(ed)?)\b.*\b(cyber[-\s]?attack|ransomware)\b",
                r"\b(disruption|service\s*outage|system\s*offline|shutdown)\b",
            ],

            # 2) Ransomware / extorsión
            "ransomware": [
                r"\bransom\s*ware\b|\bransomware\b",
                r"\b(lockbit|alphv|black\s*cat|blackcat|clop|black\s*basta|revil|conti|hive|royal|dark\s*side|darkside|babuk|akira|ragnar\s*locker|doppel\s*paymer|maze|ryuk|egregor|play\s+ransomware|play\s+crypt|qilin|blackbyte|no\s*escape|8base|bianlian|daixin|snatch|vice\s*society|turtle|cuba|monti|grief|netwalker|payloadbin)\b",
                r"\bleak\s*site\b|\bshame\s*site\b|\bdata\s+posted\b|\bdata\s+published\b|\bmuestras?\s+publicad[ao]s?\b",
                r"\b(demanda\s+de\s+rescate|extorsi[oó]n|ransom\s+demand(ed|s)?)\b",
            ],

            # 3) Robo / exfiltración / filtración de datos
            "data_theft": [
                r"\b(exfiltraci[oó]n|exfiltrado(s)?|sustracci[oó]n\s+de\s+datos|robo\s+de\s+datos|filtraci[oó]n\s+de\s+datos|exposici[oó]n\s+de\s+datos|data\s+dump|data\s+compromis(e|ed))\b",
                r"\b(data\s+(theft|stolen|steal|exfiltration|leak|dump|breach|exposed|publish(ed)?))\b",
                r"\b(?:breach(?:ed)?|leak(?:ed|s)?)\b.{0,24}\b(data|records?|information|info|customers?|users?|clients?|emails?|credentials?|pii|personal\s+data|vin[s]?)\b",
                r"\bexpos(?:e|ed|es|ure|ing)\b.{0,24}\b(data|records?|information|info|customers?|users?|clients?|emails?|credentials?|pii|personal\s+data|vin[s]?)\b",
                r"\b(accidentally|mistakenly)\s+shared\b.{0,24}\b(data|records?|information|info|customers?|users?|clients?)\b",
                r"\b(base\s+de\s+datos|database)\b.*\b(expuesta|exposed|sin\s+protecci[oó]n|open|p[úu]blica|public)\b",
            ],

            # 4) Disrupción operativa (plantas/servicios/logística)
            "disruption": [
                # ES
                r"\b(par[oó]\s+de\s+producci[oó]n|paralizaci[oó]n|paraliz[ao]|detuvo|detenid[oa]s?|interrumpi[oó]|cierre\s+de\s+planta|apag[oó]n\s+de\s+l[ií]neas)\b",
                r"\b(detiene[n]?|paraliza[n]?|interrumpe[n]?|suspend(e|en)|cesa[n]?)\b.*\b(producci[oó]n|operaciones?|l[ií]neas?|planta[s]?|f[áa]brica|factor[ií]a|montaje)\b",
                r"\b(retrasos?|impacto)\b.*\b(log[ií]stic[ao]s?|env[ií]os|distribuci[oó]n|shipping)\b",
                # EN
                r"\b(plant|factory|facility|assembly\s*line)\s+(shut\s*down|shutdown|halt(ed)?|stopp(ed)?|suspend(ed)?)\b",
                r"\b(outage|service\s*(down|disruption|unavailable)|systems?\s*offline)\b",
                r"\b(shipping|logistics?|fulfillment)\s+(halt(s|ed)?|disrupt(ed)?|delay(ed)?)\b",
                r"\b(outage|outages)\b",
            ],

            # 5) Objetos/tecnologías del dominio auto (+DMS/dealers, EVSE, trackers)
            "targets_auto": [
                r"\b(oem|ecu|tcu|bms|ota|boot\s*loader|secure\s*boot|v2x|can[-\s]*bus|controller\s*area\s*network|socketcan|iso[-\s]*11898|uds|some/ip|doip|obd[- ]?ii?|telematics?|infotainment|head\s*unit|iv[iy]|tacho(graph)?|vin)\b",
                r"\b(key\s*fob|keyless|relay\s*attack|roll\s*jam|rolljam|amplifier|jammer|inhibidor|amplificador\s+de\s+se[nñ]al|clon(a|ado|aci[oó]n)\s+de\s+llave[s]?|sin\s+llave)\b",
                r"\b(connected\s*drive|connecteddrive|car[- ]?net|we\s*connect|we\s*connect\s*id|uconnect|onstar|blue\s*link|kia\s*connect|uvo|ford\s*pass|sync\s*3|sync\s*4|mercedes\s*me|mbux|nissan\s*connect|my(hyundai|chevrolet|gmc|audi|bmw)|subaru\s*starlink|porsche\s*connect|toyota\s*(safety\s*connect|myt)|my\s*skoda)\b",
                r"\b(lidar|adas|radar|phantom\s*images?|phantom\s*object|gps|gnss)\s*(spoof|jamm)(ing|er)?\b",
                r"\b(evse|charger|wallbox|rolec|ocpp|chargepoint|abb\s*terra|tritium|siemens|schneider\s*electric|alfen|kempower|evbox|blink\s*charging|ionity|supercharger)\b",
                r"\b(tracker|gps\s*tracker|telematics?\s*unit|lojack|calamp|teltonika|queclink|ruptela|concox|geotab|mix\s*telematics)\b",
                r"\b(dealer(?:ship)?s?|dms|cdk\s*global|reynolds\s*(?:and|&)\s*reynolds|solera)\b",
                r"\b(anpr|alpr|license\s*plate\s*recognition|lectura\s+de\s+matr[ií]culas)\b",
                r"\b(can\s*injection)\b",
                r"\b(lin\s*bus|flexray|gmlan|k[-\s]*line|immobiliz(?:er|e))\b",
                r"\b(vin(?:s)?\b|vehicle\s+identification\s+number)\b",
                r"\b(key\s*fob|replay\s+attack|roll\s*jam|rolljam)\b",
                r"\b(autopilot|pilot\s*assist|lane[-\s]*keeping|adaptive\s*cruise)\b",
                r"\b(phantom\s*signs?)\b",
            ],

            # 6) Insider / sabotaje
            "insider": [
                r"\b(emplead[oa]|ex[-\s]*emplead[oa]|contratista|insider)\b.*\b(rob(o|a)|sustra[ií]d[oa]s?|filtr[oó]|exfiltr[oó]|alter[oó]|cambi[oó]\s+c[oó]digo|sabotaje)\b",
                r"\b(insider)\s+(threat|sabotage|leak)\b",
                r"\b(employees?|workers?|staff)\b.{0,40}\b(shared|viewed|watched|posted|circulated|leaked)\b.{0,40}\b(images?|videos?|photos?|clips?|footage)\b",
                r"\b(compartier(?:on|an)|difundi(?:eron|an)|filtr(?:aron|aci[oó]n)\b).{0,40}\b(im[aá]genes?|fotos?|videos?)\b",

            ],

            # 7) Señales cuantitativas
            "quantifiers": [
                r"\b(\d{1,3}(\.\d+)?\s*(millones?|millions?)\s+(de\s+)?(datos|registros|usuarios|clientes))\b",
                r"\b(\d{1,3}(\.\d+)?\s*(million|m)\s+records?)\b",
                r"\b(\d{1,3}(\.\d+)?\s*(coches|veh[ií]culos|cars))\b",
                r"\b(par[oó]\s+de\s+24\s*h|24[-\s]*hour\s*stop|one[-\s]*day\s*shutdown)\b",
            ],

            # 1bis) Abuso de portales/API/telemática y acciones remotas
            "portal_abuse": [
                r"\b(admin|dealer|customer)\s+portal\b",
                r"\b(portal)\b.*\b(admin|dealer|customer|api|token|key|endpoint|dashboard)\b",
                r"\b(api)\s*(?:key|token|secret|bearer)\b",
                r"\b(telematics?|connected\s*drive|car[- ]?net|uconnect|onstar|mercedes\s*me|ford\s*pass|kia\s*connect|nissan\s*connect|my\s*(?:audi|bmw|hyundai))\b.*\b(portal|api|endpoint|dashboard|token|key)\b",
                r"\b(mysubaru|my\s*subaru)\b",
                r"\b(hondalink|acuralink)\b",
                r"\b(incontrol)\b",
                r"\b(volvo\s*(on\s*call|cars))\b",
                r"\b(my\s*(chevrolet|gmc|cadillac|buick|skoda|seat|toyota|honda|mazda))\b",
                r"\b(skoda\s*connect|seat\s*connect|cupra\s*connect|peugeot\s*connect|mycitro[eé]n|renault\s*(easy\s*connect|my\s*renault))\b",
                r"\b(hyundai\s*bluelink|blue\s*link)\b",
                r"\b(porsche\s*car\s*connect)\b",
                r"\b(volkswagen\s*we\s*connect|we\s*connect\s*go)\b",
                r"\b(bmw\s*connected\s*drive|connected\s*drive)\b",
                r"\b(mercedes\s*me)\b",
                r"\b(sirius\s*xm|xm\s*guardian)\b",
                r"\b(dealertrack|keyloop|tekion|autosoft)\b",
                r"\b(owner\s+portal|owners?\s+app|my\s*chevrolet|my\s*buick|my\s*gmc|my\s*cadillac)\b",
                r"\b(starlink\s+app)\b",
            ],

            "remote_control": [
                r"\b(remote\s+start|start\s+(?:engine|car)|stop\s+(?:engine|car))\b",
                r"\b(unlock|lock|open|close)\b.*\b(doors?|trunk|boot|tailgate|frunk|windows?)\b",
                r"\b(horn|honk|flash(?:\s+lights)?|hazards?)\b",
                r"\b(track|find\s+my\s+car|geolocat(?:e|ion)|locat(?:e|ion))\b",
                r"\b(remotely\s+control|remote\s+control)\b",
                r"\b(immobiliz(?:e|er)|kill\s*switch)\b",
                r"\b(precondition(?:ing)?|climate\s*(?:control)?|hvac|defrost|heated\s+seats?)\b",
                r"\b(charg(?:e|ing)\s*(?:start|stop|schedule|status))\b",
                r"\bremotely\s+(?:unlock|lock|start|stop|open|close|honk|flash|track|locate)\b",
                r"\b(?:unlock|lock|start|stop)\s+(?:the\s+)?car(s)?\b",
                r"\btrack\s+(?:my|the)\s+car\b",
            ],

            "vuln_found": [
                # (A) técnica / CVE / bug duro
                r"\b(vulnerab(?:ilidad|ility|ilities))\b",
                r"\b(cve-\d{4}-\d{4,7})\b",
                r"\b(rce|remote\s+code\s+execution|auth(?:entication)?\s*bypass|privilege\s+escalation|sql\s+injection|xss|xxe|csrf|directory\s+traversal|path\s+traversal|ssrf)\b",
                r"\b(default|hard[-\s]*coded)\s+(password|credenciales?|credentials?)\b",
                r"\b(unauthenticated|sin\s+autenticaci[oó]n|no\s+auth)\b",
                # (B) redacciones periodísticas
                r"\b(security\s+(?:flaw|bug|issue)|fall[oa]s?\s+de\s+seguridad|vulnerabilit(?:y|ies)|vulnerabilidad(?:es)?)\b",
                r"\b(allow(?:ed|s)?|permite?(?:\s+|[óo]\s+)|permit[ií]a)\b.{0,40}\b(remote|unauthori[sz]ed)\b.{0,20}\b(access|unlock|start|control|commands?)\b",
                r"\b(misconfigur(?:ation|ado)|expuesto\s+p[úu]blicamente|public(?:ly)?\s*exposed)\b",
            ],
        }

        # ========= LEXICÓN NEGATIVO / DILUYENTES =========
        self.negative = {
            "hypothetical": [
                r"\b(podr[ií]a|puede(n)?|posible|te[oó]ric[oa]|prueba\s+de\s+concepto|poc|demostraci[oó]n|demo|investigador(es)?|estudio|paper|study|researchers?|could|may|might|would)\b",
                r"\b(how\s*to|tutorial|walkthrough|step[-\s]*by[-\s]*step|c[oó]mo\s+hacer)\b",
                r"\b(guide\s+(to|for)|user\s+guide|buyer'?s\s+guide)\b",
                r"\b(di[yí]|arduino|raspberry\s*pi|esp32|homebrew)\b",
                r"\b(prank|experimento|simulaci[oó]n|simulado|simulan|simulated)\b",
            ],
            "routine_vuln": [
                r"\b(cve-\d{4}-\d{4,7})\b",
                r"\b(patch(ed|es)?|parche(s)?|actualizaci[oó]n(es)?\s+de\s+seguridad|security\s+update|advisory|bolet[ií]n\s+de\s+seguridad|mitigation)\b",
            ],
            "unconfirmed": [r"\b(rumor(es)?|no\s+confirmad[oa]s?|unconfirm(ed)?|reportedly|sin\s+evidencia)\b"],
            "denial_noimpact": [
                r"\b(desminti[oó]|neg[oó])\b.*\b(ataque|intrusi[oó]n|impacto)\b|\b(sin\s+impacto|no\s+tuvo\s+impacto|no\s+evidence|no\s+impact)\b",
                r"\b(ruled\s+out|descart(ó|a)(?:\s+que)?\s+(?:fuera|ser)\s+un\s+ciberataque)\b"
            ],
            "advisory_only": [
                r"\b(advierte(n)?|alerta(n)?|consejos?|recommendations?)\b.*\b(keyless|relay|ladrones|thieves?)\b",
                r"\b(polic[ií]a|police)\b.*\b(warn(s|ing)?|advierten?)\b",
            ],
            "nonauto_outage": [
                r"\b(crowdstrike|microsoft|cloudflare|meta|whatsapp|instagram|google|aws|azure|openai|reddit)\b.*\b(outage|down|offline)\b",
                r"\b(x|twitter)\b.*\b(outage|down|offline)\b",
                r"\b(global|worldwide)\b.*\b(outage|down|offline)\b",
            ],
            "lifehack_noise": [
                r"\blife\s+hacks?\b",
                r"\b(tiktok|cleaning|kitchen|beauty|parenting|travel|budget|money|camping)\s+hacks?\b",
                r"\bhackathon\b",
                r"\b(genius|simple|easy)\s+hacks?\b"
            ],
            "roundup_structure": [
                r"\b(roundup|recap|digest|highlights|lo\s+que\s+debes\s+saber|what\s+you\s+need\s+to\s+know|cheat\s*sheet|explainer|primer|guía\s+rápida)\b",
            ],
            "unrelated": [
                r"\b(mercado|market|precios|acciones|cotizaci[oó]n|patente|lanzamiento|motorsport|f[óo]rmula\s*1|f1|f[uú]tbol)\b",
                r"\b(encrochat)\b",
                r"\b(vintage|royal[-\s]*era|classic\s+car\s+show|concours\s+d['’]elegance)\b",
            ],
            "market_noise": [
                r"\b(price\s+war|revenue|milestone|most\s+valuable|valuation|sales?\s+(rise|fall|drop|up|down)|tops?\s+list)\b",
                r"\b(ranking|ranked|leaderboard|quarterly\s+results?|earnings|ipo)\b",
                r"\b(stocks?|asx|nasdaq|dow\s+jones|s&p|ftse)\b",
                r"\b(analyst|price\s+target|way\s+to\s+play)\b",
            ],
            "ad_lure": [
                r"\b(advert|advertisement|ads?|malvertis(?:e|ing))\b"
            ],
        }

        # ========= MARCAS / FABRICANTES / PROVEEDORES =========
        self.oems_and_suppliers = [
            # OEMs
            "toyota","lexus","volkswagen","vw","audi","bmw","mercedes","mercedes-benz","daimler","tesla",
            "ford","lincoln","gm","general motors","chevrolet","gmc","cadillac","stellantis","fiat","chrysler","jeep","ram",
            "peugeot","citro[eé]n","citroen","opel","vauxhall","renault","nissan","mitsubishi","honda","acura","hyundai","kia",
            "byd","geely","volvo","polestar","saic","great wall","tata","mahindra","skoda","seat","cupra",
            "porsche","ferrari","lamborghini","jaguar","land rover","mazda","subaru","suzuki",
            "nidec","aisin","aisin seiki","hitachi astemo","lear","adient","schaeffler",
            "tenneco","dana","gkn","mando","hyundai mobis","zf lifetec","zkw","hella",
            "bridgestone","michelin","goodyear","ficosa","sumitomo wiring systems","denso wave",
            # Tiers / HW/SW / telemática / trackers / EVSE / DMS
            "bosch","continental","denso","zf","magna","aptiv","valeo","forvia","faurecia","harman","nxp","infineon",
            "stmicroelectronics","renesas","texas instruments","qualcomm","nvidia","mobileye","panasonic","lg","hella","autoliv",
            "garrett","marelli","yazaki","catl","foxconn","brose","hitachi","kyocera","sumitomo","jabil","onsemi","microchip","alpine",
            "blackberry","qnx","calamp","lojack","teltonika","queclink","ruptela","concox","geotab","mix telematics",
            "rolec","wallbox","chargepoint","ocpp","abb","tritium","siemens","schneider electric","alfen","kempower","evbox","blink charging",
            "cdk global","reynolds and reynolds","solera",
            "parkmobile","paybyphone","easypark","flowbird","parkopedia",
            "dealertrack","keyloop","tekion","autosoft"
        ]

        # ========= COMPILACIÓN DE RE =========
        def comp(lst): return [re.compile(p, re.I) for p in lst]
        self.re_pos = {k: comp(v) for k, v in self.positive.items()}
        self.re_neg = {k: comp(v) for k, v in self.negative.items()}

        def _brand_rx(name: str) -> re.Pattern:
            base = re.escape(name)
            # Algunas cortas comunes que no deben pluralizarse:
            if name in {"gm", "ram"}:
                return re.compile(rf"\b{base}\b", re.I)
            # Acepta plural ('s) / posesivo (’s) sin capturar palabras más largas
            return re.compile(rf"(?<![A-Za-z]){base}(?:'s|’s|s)?(?![A-Za-z])", re.I)

        self.re_companies = [_brand_rx(c) for c in self.oems_and_suppliers]

        self.re_exploitlike = re.compile(
            r"\b(rce|remote\s+code\s+execution|exploit(?:ed|s)?|actively\s+exploited|weaponiz(?:e|ed)|poc|proof\s+of\s+concept|unauthenticated|no\s+auth|authentication\s+bypass|privilege\s+escalation)\b",
            re.I
        )
        self.re_researchers = re.compile(r"\bresearchers?\b", re.I)
        self.re_remote = re.compile(r"\b(remote\s+start|start\s+(?:engine|car)|unlock|lock|horn|honk|flash(?:\s+lights)?|track|locat(?:e|ion)|geolocat(?:e|ion))\b", re.I)
        self.re_portal = re.compile(
            r"\b(admin|dealer|customer)\s+portal\b|\bportal\b|\bapi\b|api\s+(?:key|token)|\btoken\b|\bbearer\b|telematics?\b|"
            r"connected\s*drive|car[- ]?net|uconnect|onstar|mercedes\s*me|ford\s*pass|kia\s*connect|nissan\s*connect|"
            r"mysubaru|incontrol|hondalink|acuralink|volvo\s*(?:on\s*call|cars)|skoda\s*connect|seat\s*connect|cupra\s*connect|"
            r"peugeot\s*connect|mycitro[eé]n|renault\s*(?:easy\s*connect|my\s*renault)|blue\s*link|porsche\s*car\s*connect|"
            r"we\s*connect(?:\s*go)?",
            re.I
        )
        self.re_keyless_like = re.compile(
            r"\b(keyless|relay\s*attack|replay\s*attack|roll\s*jam|can\s*injection)\b", re.I
        )

        # ========= PESOS =========
        self.wpos = {
            "attack_confirmed": 6,
            "ransomware": 6,
            "data_theft": 5,
            "disruption": 5,
            "portal_abuse": 5,
            "remote_control": 5,
            "vuln_found": 5,
            "targets_auto": 4,  # ↑ antes 3
            "insider": 2,
            "quantifiers": 1,
            "company": 2
        }
        self.wneg = {
            "hypothetical": 6 if self.mode == "strict" else 3,
            "routine_vuln": 4,
            "unconfirmed": 6,
            "denial_noimpact": 6,
            "advisory_only": 3,
            "nonauto_outage": 3,
            "lifehack_noise": 3,
            "roundup_structure": 3,
            "unrelated": 4,
            "market_noise": 3,
            "ad_lure": 2,
        }

        # ========= UMBRAL =========
        self.keep_min = 7 if self.mode == "strict" else (6 if self.mode == "standard" else 5)

    # ---- auxiliares ----
    def _hits(self, regs: List[re.Pattern], text: str) -> List[str]:
        out: List[str] = []
        for r in regs:
            out.extend(m.group(0) for m in r.finditer(text))
        seen, uniq = set(), []
        for x in out:
            if x not in seen:
                uniq.append(x); seen.add(x)
        return uniq

    # ---- clasificación principal ----
    def classify(self, title: str, summary: str) -> IncidentResult:
        t = f"{(title or '')} {(summary or '')}".lower()

        reasons, matches = [], {}
        score = 0

        # 1) Contexto automotriz temprano (ampliado)
        auto_context = bool(re.search(
            r"\b(veh[ií]culo|coche|automotive|auto(?:motive)?(?:\s*maker|\s*industry)?|car|cars|oem|fabricante|tier[-\s]*[12]|"
            r"dealer(?:ship)?s?|dms|fleet|telematics?|infotainment|ecu|can[-\s]*bus|controller\s*area\s*network|obd|doip|some/ip|"
            r"v2x|keyless|relay\s*attack|evse|charger|ocpp|onstar|uconnect|mercedes\s*me|connected\s*drive|kia\s*connect|"
            r"nissan\s*connect|ford\s*pass|starlink|blue\s*link|we\s*connect)\b",
            t, re.I
        ))

        # 2) POSITIVOS
        for b, regs in self.re_pos.items():
            hh = self._hits(regs, t)
            if hh:
                matches[b] = hh
                score += self.wpos.get(b, 0)
                reasons.append(f"+{self.wpos.get(b,0)} {b}: {', '.join(hh[:3])}{'…' if len(hh) > 3 else ''}")

        # Marcas/Tiers
        ch = self._hits(self.re_companies, t)
        if ch:
            matches["company"] = ch
            score += self.wpos["company"]
            reasons.append(f"+{self.wpos['company']} company: {', '.join(ch[:6])}{'…' if len(ch) > 6 else ''}")
            auto_context = auto_context or bool(ch)

        # 3) NEGATIVOS
        neg_flags = {}
        for b, regs in self.re_neg.items():
            hh = self._hits(regs, t)
            if hh:
                neg_flags[b] = True
                matches[f"not_{b}"] = hh
                if b not in ("nonauto_outage", "ad_lure"):
                    score -= self.wneg[b]
                    reasons.append(f"-{self.wneg[b]} {b}: {', '.join(hh[:3])}{'…' if len(hh) > 3 else ''}")

        # Penalización nonauto_outage/ad_lure SOLO si NO hay contexto auto
        if neg_flags.get("nonauto_outage") and not auto_context:
            score -= self.wneg["nonauto_outage"]
            reasons.append(f"-{self.wneg['nonauto_outage']} nonauto_outage: {', '.join(matches.get('not_nonauto_outage', [])[:3])}{'…' if len(matches.get('not_nonauto_outage', [])) > 3 else ''}")
        if neg_flags.get("ad_lure") and not auto_context:
            score -= self.wneg.get("ad_lure", 2)
            reasons.append(f"-{self.wneg.get('ad_lure',2)} ad_lure: {', '.join(matches.get('not_ad_lure', [])[:3])}{'…' if len(matches.get('not_ad_lure', [])) > 3 else ''}")

        # Overrides/afinados
        portal_hit   = ("portal_abuse" in matches) or bool(self.re_portal.search(t))
        remote_hit   = ("remote_control" in matches) or bool(self.re_remote.search(t))
        brand_target = ("company" in matches) or ("targets_auto" in matches)
        exploit_like = bool(self.re_exploitlike.search(t))
        auto_evidence = brand_target or portal_hit or remote_hit or exploit_like

        # a) 'hypothetical' – neutralización/agresividad según evidencia
        if "not_hypothetical" in matches:
            # Incidente real presente → neutralizamos completamente la penalización
            if any(k in matches for k in ("attack_confirmed", "ransomware", "data_theft", "disruption")):
                score += self.wneg["hypothetical"]
                reasons.append("± override: hypothetical neutralizado por incidente real")
            # Evidencia práctica auto (portal/remote/vuln/exploit) + marca/targets → -2 neto
            elif (portal_hit or remote_hit or "vuln_found" in matches or exploit_like) and brand_target:
                score += (self.wneg["hypothetical"] - 2)
                reasons.append("± override: researchers/PoC + portal/remote/vuln + brand (hypothetical reducido a -2)")
            # Evidencia auto más débil → -1 neto
            elif auto_evidence:
                score += (self.wneg["hypothetical"] - 1)
                reasons.append("± override: hypothetical atenuado (-1) por evidencia automotriz")

        # b) 'routine_vuln' neutralizado si hay vuln_found + evidencia auto
        if ("not_routine_vuln" in matches and "vuln_found" in matches and auto_evidence):
            score += self.wneg["routine_vuln"]
            reasons.append("± override: routine_vuln neutralizado por vuln_found+auto_context")

        # Sinergias adicionales
        if "portal_abuse" in matches and "company" in matches:
            score += 1; reasons.append("+1 synergy portal+company")
        if "remote_control" in matches and ("company" in matches or "targets_auto" in matches):
            score += 2; reasons.append("+2 synergy remote+brand/target")
        if "vuln_found" in matches and ("company" in matches or "targets_auto" in matches or "portal_abuse" in matches):
            score += 1; reasons.append("+1 synergy vuln+brand/target/portal")
        if "attack_confirmed" in matches and ("company" in matches or "targets_auto" in matches):
            score += 1; reasons.append("+1 synergy attack_confirmed+auto")
        if "data_theft" in matches and ("company" in matches or "targets_auto" in matches):
            score += 1; reasons.append("+1 synergy data_theft+auto")
        if "targets_auto" in matches and "company" in matches:
            score += 1; reasons.append("+1 synergy targets_auto+company")

        # 4) Señales fuertes
        plant_or_ops = bool(re.search(r"\b(planta|f[áa]brica|factor[ií]a|plant|factory|facility|assembly\s*line|producci[oó]n|operaciones?)\b", t, re.I))

        vuln_strong = (
            ("vuln_found" in matches or "data_theft" in matches) and
            (auto_context or "company" in matches or "targets_auto" in matches or "portal_abuse" in matches)
        )

        keyless_like = bool(self.re_keyless_like.search(t))

        strong = (
            any(k in matches for k in ("attack_confirmed","ransomware")) or
            ("disruption" in matches and (auto_context and plant_or_ops)) or
            ((portal_hit or remote_hit) and auto_context) or
            vuln_strong or
            (keyless_like and brand_target)   # <- NUEVO
        )

        # Quita castigo de roundup si hay señal fuerte
        if strong and "not_roundup_structure" in matches:
            score += self.wneg["roundup_structure"]
            reasons.append("± override: roundup_structure neutralizado por señal fuerte")

        # Regla dura: 'unconfirmed' o 'denial' sin strong -> reject
        if (neg_flags.get("unconfirmed") or neg_flags.get("denial_noimpact")) and not strong:
            return IncidentResult(False, score, None, reasons, matches)

        # 5) Umbral efectivo (relajación en ciertos casos)
        keep_min_eff = self.keep_min
        if ("data_theft" in matches) and ("company" in matches):
            keep_min_eff = max(5, keep_min_eff - 2)
        if ("ransomware" in matches) and ("company" in matches):
            keep_min_eff = max(5, keep_min_eff - 2)
        if (("remote_control" in matches or "portal_abuse" in matches) and
            ("company" in matches or "targets_auto" in matches)):
            keep_min_eff = max(5, keep_min_eff - 2)
        # NUEVO: keyless/relay/replay + marca
        if keyless_like and ("company" in matches or "targets_auto" in matches):
            keep_min_eff = max(5, keep_min_eff - 1)

        borderline = (score >= keep_min_eff - 1) and auto_context and brand_target and (keyless_like or portal_hit or remote_hit)
        if not strong and borderline:
            strong = True
            reasons.append("override: borderline (brand + auto action) tratado como señal fuerte")

        # Decisión final
        keep = (score >= keep_min_eff) and strong and auto_context
        if keep and not auto_context:
            keep = False

        # Categoría fina
        cat = "Auto/General"
        if re.search(r"\b(planta|f[áa]brica|factor[ií]a|plant|factory|facility|assembly\s*line)\b", t, re.I):
            cat = "Factory/Plant"
        elif re.search(r"\b(keyless|relay\s*attack|roll\s*jam|rolljam|inhibidor|amplificador\s+de\s+se[nñ]al|clon(a|ado))\b", t, re.I):
            cat = "Keyless/Relay"
        elif re.search(r"\b(obd|ecu|can[-\s]*bus|controller\s*area\s*network|tcu|infotainment|head\s*unit|doip|some/ip)\b", t, re.I):
            cat = "Vehicle/Model"
        elif re.search(r"\b(onstar|uconnect|connected\s*drive|car[- ]?net|blue\s*link|ford\s*pass|mercedes\s*me|nissan\s*connect|starlink|portal|api|token|telematics)\b", t, re.I):
            cat = "Telematics/Portal"
        elif re.search(r"\b(lidar|adas|phantom|gps\s*(spoof|jamm)|gnss\s*(spoof|jamm))\b", t, re.I):
            cat = "Perception Spoofing"
        elif re.search(r"\b(evse|charger|wallbox|ocpp|rolec|chargepoint)\b", t, re.I):
            cat = "Charger/EVSE"
        elif self.scope == "mobility" and re.search(r"\b(rail|train|metro|ferrocarril|tranv[ií]a|parking|park[ií]metro|anpr|lpr|toll|peaje|vtc|ride[- ]?hailing|car\s*sharing)\b", t, re.I):
            cat = "Mobility/Adjacent"
        elif re.search(r"\b(oem|automaker|carmaker|fabricante|marca)\b", t, re.I):
            cat = "Manufacturer/OEM"
        elif re.search(r"\b(proveedor(a)?|supplier|tier\s*-?1|tier\s*-?2|concesionario|dealers?hip|dms)\b", t, re.I):
            cat = "Supplier/Tier"
        elif "insider" in matches:
            cat = "Insider/Sabotage"

        return IncidentResult(keep=keep, score=score, category=cat, reasons=reasons, matches=matches)
