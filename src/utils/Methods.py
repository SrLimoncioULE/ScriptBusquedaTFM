import re
import unicodedata
import hashlib
from typing import Iterable, List, Set, Tuple
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

class Methods:
    # -------------------- Datos/constantes auxiliares --------------------
    # Stopwords extendidas (inglés/español) para tokens "fuertes"
    STOP_EXT = {
        "the","a","an","of","and","for","to","in","on","with","by","vs","was","is","are",
        "la","el","los","las","de","del","y","para","en","con","por","un","una","al","lo"
    }
    # Unificación de compuestos frecuentes
    COMPOUNDS = {
        ("cyber","attack"): "cyberattack",
        ("ransom","ware"): "ransomware",
        ("data","base"): "database",
    }
    # Abreviaturas → forma larga (puedes añadir más)
    ABBR = [
        (re.compile(r"\bnev\.?\b", re.I), "nevada"),
    ]

    # -------------------- Utilidades generales --------------------

    @staticmethod
    def progress_bar(iteration, total, length=30):
        progress = iteration / total if total else 0
        filled = int(progress * length)
        empty = length - filled
        percent = int(progress * 100) if total else 0
        return f"Progreso general: |{'█' * filled}{'-' * empty}| {percent}% ({iteration}/{total})"

    @staticmethod
    def normalize_doi(doi):
        if not isinstance(doi, str):
            return None
        return doi.lower().strip()

    # -------------------- Normalización de títulos/URLs --------------------

    @staticmethod
    def normalize_title(title: str) -> str:
        """
        Normaliza un título para usar como clave:
        - quita elipsis finales
        - elimina sufijos de branding/sitio tras separadores típicos ( - | : — ) si parecen *solo* marca
        - minúsculas, sin acentos/puntuación, espacios colapsados
        """
        if not isinstance(title, str) or not title.strip():
            return ""
        t = title.strip()

        # quitar elipsis del final
        t = re.sub(r"(…|\.{3})\s*$", "", t)

        # intentar quitar branding final: "Titulo — El Diario", "Titulo - Sitio", etc.
        # lo hacemos conservador: si tras el separador hay ≤ 4 palabras y todas son alfabéticas
        sep_pattern = r"\s*([\-–—|:])\s*([^\-–—|:]{1,60})$"
        m = re.search(sep_pattern, t)
        if m:
            tail = m.group(2).strip()
            # si el tail no contiene dígitos y es corto, lo removemos
            if len(tail.split()) <= 4 and not re.search(r"\d", tail):
                t = t[:m.start()].rstrip()

        # normaliza a ASCII sin acentos
        t = unicodedata.normalize("NFKD", t)
        t = "".join(ch for ch in t if not unicodedata.combining(ch)).lower()
        # colapsa espacios y elimina todo lo que no sea a-z0-9 espacio
        t = re.sub(r"\s+", " ", t).strip()
        t = re.sub(r"[^a-z0-9 ]+", "", t)
        return t

    @staticmethod
    def normalize_title_soft(raw: str) -> str:
        """
        Normalización 'suave' para generar tokens fuertes:
        - minúsculas, sin diacríticos
        - corrige abreviaturas básicas (p.ej., 'Nev.' -> 'nevada')
        - mantiene espacios; elimina símbolos
        """
        t = Methods._normalize_text_basic(raw)
        for rx, rep in Methods.ABBR:
            t = rx.sub(rep, t)
        t = re.sub(r"[^a-z0-9 ]+", " ", t)
        t = re.sub(r"\s+", " ", t).strip()
        return t

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normaliza URLs para deduplicar sin colapsar todas las del mismo dominio:
        - minúsculas
        - elimina subdominios móviles/AMP (m., amp.)
        - elimina sufijos AMP (/amp, outputType=amp)
        - elimina parámetros de tracking (utm_*, gclid, fbclid, etc.)
        - conserva path y query útiles
        - sin fragmentos (#...)
        """
        if not isinstance(url, str) or not url.strip():
            return ""
        u = url.strip()

        # Quitar prefijos móviles/AMP comunes
        u = re.sub(r"://m\.", "://", u, flags=re.I)
        u = re.sub(r"://amp\.", "://", u, flags=re.I)

        # Quitar sufijos/flags AMP típicos
        u = re.sub(r"/amp(/|$)", "/", u, flags=re.I)
        u = re.sub(r"[?&]outputType=amp\b", "", u, flags=re.I)

        try:
            parts = urlparse(u)

            # Normalizar path sin barras finales repetidas
            path = re.sub(r"/{2,}", "/", parts.path or "/")
            path = re.sub(r"/+$", "", path) or "/"

            # Filtrar parámetros de tracking
            drop_keys = re.compile(r"^(utm_|fbclid|gclid|mc_|ref$|ref_src$|trk$|spm$|igshid$|si$)", re.I)
            kept_qs = [(k, v) for (k, v) in parse_qsl(parts.query, keep_blank_values=True) if not drop_keys.match(k)]
            query = urlencode(kept_qs, doseq=True)

            norm = parts._replace(path=path, query=query, fragment="")
            return urlunparse(norm).lower()
        except Exception:
            return u.strip().lower()

    @staticmethod
    def url_signature(url: str) -> str:
        """
        Firma estable basada en host+path (sin esquema, sin query, sin fragmento),
        útil para colapsar mismo recurso con parámetros distintos.
        """
        if not isinstance(url, str) or not url.strip():
            return ""
        try:
            u = Methods.normalize_url(url)
            p = urlparse(u)
            host = p.netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            path = re.sub(r"/{2,}", "/", p.path or "/")
            path = re.sub(r"/+$", "", path) or "/"
            return f"{host}{path}"
        except Exception:
            return ""

    # -------------------- Fechas / dominios / claves --------------------

    @staticmethod
    def extract_year(text):
        if not text:
            return "Desconocido"
        m = re.search(r'\b(20[0-3][0-9])\b', text)
        return m.group(1) if m else "Desconocido"

    @staticmethod
    def _domain_of(url_norm: str, source: str = "") -> str:
        if url_norm:
            try:
                d = urlparse(url_norm).netloc.lower()
                return d[4:] if d.startswith("www.") else d
            except Exception:
                pass
        return (source or "").split(" (", 1)[0].strip().lower()

    @staticmethod
    def _title_key(title_norm: str, ymd: str, domain: str) -> str:
        ymd = (ymd or "").strip()
        domain = (domain or "").strip()
        return f"{title_norm}|{ymd}|{domain}"

    @staticmethod
    def _hash12(s: str) -> str:
        return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]

    # -------------------- SimHash / LSH para títulos --------------------

    @staticmethod
    def _normalize_text_basic(s: str) -> str:
        if not isinstance(s, str):
            return ""
        t = unicodedata.normalize("NFKD", s)
        t = "".join(ch for ch in t if not unicodedata.combining(ch))
        t = t.lower()
        t = re.sub(r"\s+", " ", t).strip()
        return t

    @staticmethod
    def char_ngrams(s: str, n: int = 3) -> List[str]:
        s = Methods._normalize_text_basic(s)
        s = re.sub(r"[^a-z0-9 ]+", "", s)
        return [s[i:i+n] for i in range(max(0, len(s)-n+1))] if s else []

    @staticmethod
    def char_shingles(s: str, n: int = 3) -> Set[str]:
        """
        Devuelve conjunto de n-gramas de caracteres (por defecto trigramas)
        sin espacios/símbolos; útil para robustez ante typos y espacios.
        """
        s = Methods._normalize_text_basic(s)
        s = re.sub(r"[^a-z0-9]+", "", s)
        return {s[i:i+n] for i in range(max(0, len(s)-n+1))}

    @staticmethod
    def _stable_hash64(s: str) -> int:
        # hash estable de 64 bits
        return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big")

    @staticmethod
    def simhash64(features: Iterable[str]) -> int:
        V = [0]*64
        for feat in features:
            h = Methods._stable_hash64(feat)
            for i in range(64):
                V[i] += 1 if (h >> i) & 1 else -1
        x = 0
        for i, v in enumerate(V):
            if v >= 0:
                x |= (1 << i)
        return x

    @staticmethod
    def hamming_dist64(a: int, b: int) -> int:
        x = a ^ b
        c = 0
        while x:
            x &= x - 1
            c += 1
        return c

    @staticmethod
    def simhash_title64(title: str) -> int:
        return Methods.simhash64(Methods.char_ngrams(title, n=3))

    @staticmethod
    def simhash_bands(h: int, bands: int = 4, bits: int = 64) -> List[Tuple[int,int]]:
        """Devuelve clave por banda para LSH (por defecto 4 bandas x 16 bits)."""
        bsize = bits // bands
        out = []
        mask = (1 << bsize) - 1
        for i in range(bands):
            part = (h >> (i * bsize)) & mask
            out.append((i, part))
        return out

    # -------------------- Tokens / firmas --------------------

    @staticmethod
    def title_tokens(title: str) -> Set[str]:
        """
        Tokens simples del título 'duro' (legacy). Se mantiene por compatibilidad.
        """
        t = Methods.normalize_title(title)
        STOP = {"the","a","an","of","and","for","to","in","on","with","by","vs"}
        return {w for w in t.split() if len(w) > 2 and w not in STOP}

    @staticmethod
    def tokens_strong(raw: str) -> List[str]:
        """
        Tokens 'fuertes' con normalización suave, stopwords extendidas,
        fusión de compuestos y stemming ligero (s/es/ed/ing).
        """
        t = Methods.normalize_title_soft(raw)
        toks = [w for w in t.split() if len(w) > 2 and w not in Methods.STOP_EXT]

        # fusiona compuestos frecuentes
        out = []
        i = 0
        while i < len(toks):
            if i+1 < len(toks) and (toks[i], toks[i+1]) in Methods.COMPOUNDS:
                out.append(Methods.COMPOUNDS[(toks[i], toks[i+1])])
                i += 2
            else:
                out.append(toks[i])
                i += 1

        # stemming muy ligero
        out = [re.sub(r"(ing|ed|es|s)$", "", w) for w in out]
        return out

    @staticmethod
    def bow_signature(raw: str, k: int = 6) -> str:
        """
        Firma orden-insensible basada en tokens fuertes (top-k ordenados).
        Útil para generar candidatos aunque falle LSH por reparto de bits.
        """
        toks = Methods.tokens_strong(raw)
        return "|".join(sorted(toks)[:k])

    # -------------------- Comparadores de títulos --------------------

    @staticmethod
    def title_prefix_key(title: str, k: int = 5) -> str:
        """
        Clave por prefijo de K tokens “fuertes” en orden. Útil para detectar truncados/equivalencias.
        """
        toks = [w for w in re.findall(r"[a-z0-9]+", Methods.normalize_title(title))]
        return "-".join(toks[:k]) if toks else ""

    @staticmethod
    def jaccard(a: Set[str], b: Set[str]) -> float:
        if not a or not b:
            return 0.0
        inter = len(a & b); union = len(a | b)
        return inter/union if union else 0.0

    @staticmethod
    def ends_with_ellipsis(raw: str) -> bool:
        return isinstance(raw, str) and (raw.rstrip().endswith("...") or raw.rstrip().endswith("…"))

    @staticmethod
    def prefix_title_equiv(t1: str, t2: str) -> bool:
        """
        Detecta truncado “por prefijo”:
        - las dos secuencias coinciden salvo el último token del corto
        - el último token corto es prefijo del siguiente token largo
        - ratio de similitud >= 0.90 en el tramo comparado
        - si hay números en el corto, deben aparecer en el largo
        """
        import difflib
        def _words(s): return re.findall(r"[a-z0-9]+", Methods._normalize_text_basic(s))
        if not t1 or not t2:
            return False
        w1, w2 = _words(t1), _words(t2)
        if not w1 or not w2 or len(w1) == 1 or len(w2) == 1:
            return False
        short, long = (w1, w2) if len(w1) <= len(w2) else (w2, w1)
        if short[:-1] != long[:len(short)-1]:
            return False
        if not long[len(short)-1].startswith(short[-1]):
            return False
        ratio = difflib.SequenceMatcher(None, " ".join(short), " ".join(long[:len(short)+1])).ratio()
        if ratio < 0.90:
            return False
        nums_short = set(re.findall(r"\b\d+\b", " ".join(short)))
        return not nums_short or nums_short.issubset(set(re.findall(r"\b\d+\b", " ".join(long))))
