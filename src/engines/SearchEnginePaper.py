import os
import requests
import time
import random
from datetime import datetime
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter, Retry
from dotenv import load_dotenv, find_dotenv

from src.utils.Methods import Methods
from src.utils.Errors import ProviderRateLimitError, ProviderBlockedError, NetworkError
from src.utils.SearchQueryBuilder import SearchQueryBuilder


# Seguridad/ciber
SEC_WORDS = [
    "cybersecurity",
    "security",
    "vulnerability",
    "vulnerabilities",
    "CVE",
    "exploit",
    "exploitation",
    "attack",
    "attacks",
    "breach",
    "intrusion",
    "malware",
    "ransomware",
    "penetration",
    '"threat model"',
    "backdoor",
]

# Automoción / cadena de suministro / OT
AUTO_WORDS = [
    "automotive",
    "vehicle",
    "car",
    "cars",
    "OEM",
    "ECU",
    "telematics",
    "CAN",
    '"CAN bus"',
    "UDS",
    "V2X",
    "DSRC",
    "C-V2X",
    "OBD-II",
    '"charging station"',
    "EV",
    '"EV charger"',
    "OCPP",
    '"supply chain"',
    "Tier-1",
    "factory",
    "manufacturing",
    "ICS",
    "SCADA",
]

EXCLUDE_WORDS = [
    "dataset",
    "benchmark",
    "object detection",
    "battery",
    "traffic flow",
    "powertrain",
    "SLAM",
    "perception",
    "lane detection",
    "ADAS",
]


class PaperSearchEngine:
    """
    Motor de búsqueda de papers en Semantic Scholar y OpenAlex.
    - Paginación robusta
    - Rate limit por host + backoff + cooldown tras bloqueos blandos (HTML/429)
    - Reintentos HTTP (500/502/503/504)
    - API key S2 desde .env (S2_API_KEY o SEMANTIC_SCHOLAR_API_KEY)
    - Deduplicación por DOI/título
    - Excepciones al caller para guardar estado y retomar
    - Snapshots de estado (get_state_snapshot / load_state_snapshot)
    """

    def __init__(
        self,
        ia_analyzed_ids=None,
        final_results=None,
        semantic_ids=None,
        openalex_ids=None,
        log_manager=None,
    ):
        # Cargar .env si no está ya cargado
        load_dotenv(find_dotenv(), override=False)

        # Palabra clave usada para la búsqueda actual
        self.keyword = ""

        # Conjunto de identificadores de artículos ya analizados con modelos de IA
        self.ia_analyzed_ids = set(ia_analyzed_ids or [])

        # Diccionario con los resultados finales que han pasado todos los filtros (incluyendo IA)
        self.final_results = final_results or {}

        # Diccionario con todos los artículos recuperados de las APIs, indexados por DOI normalizado o título
        self.raw_items = {}

        # Conjuntos con los IDs de papers ya procesados en cada fuente
        self.semantic_ids = set(semantic_ids or [])  # Semantic Scholar
        self.openalex_ids = set(openalex_ids or [])  # OpenAlex

        # Motor de filtrado (años, idioma, IA, etc.)
        self.filter_engine = None

        # Contador de duplicados detectados entre fuentes o resultados ya existentes
        self.duplicate_count = 0

        # Contador de resultados para cada palabra
        self.num_results_bykeyword = 0

        # Controlador de log por pantalla
        self.log_manager = log_manager

        self.apply_filter_ia = False
        self.values_levels_ia = {}

        # ------------------------- Query -------------------------
        self.qb = SearchQueryBuilder()

        # --------- Sesión HTTP con reintentos ----------
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        # --------- Límites y tiempos ----------
        self.openalex_per_page = 200
        self.max_pages_semantic = 5  # None = sin tope
        self.max_pages_openalex = 5  # None = sin tope
        self.base_sleep = 8  # segundos entre páginas (con jitter)
        self.max_sleep = 60
        self.timeout = 30  # timeout por petición

        # Nº máximo de reintentos internos ante 429 con Retry-After.
        # Lo introduzco para imitar la lógica de tu motor de noticias:
        # si el proveedor pide esperar X/Retry-After, esperamos y reintentamos.
        self.max_429_retries = 3

        # Rate limit “duro” por host (mínimo intervalo entre peticiones)
        self.min_interval = {
            "api.semanticscholar.org": 1.2,  # 1 req/s con margen
            "api.openalex.org": 1.0,
        }
        self._last_req = {}
        self._block_counters = {
            "api.semanticscholar.org": 0,
            "api.openalex.org": 0,
        }
        self.cooldown_after_blocks = 2
        self.cooldown_seconds = 10 * 60  # 10 min

        # --------- Cabeceras / API keys ----------
        s2_key = os.getenv("S2_API_KEY") or os.getenv("SEMANTIC_SCHOLAR_API_KEY")
        self.headers_semantic = {
            "User-Agent": "Mozilla/5.0 (compatible; PaperSearchBot/1.0)",
            "Accept": "application/json",
        }
        if s2_key:
            self.headers_semantic["x-api-key"] = s2_key
        else:
            if self.log_manager:
                self.log_manager.log_state(
                    "⚠️ [Semantic Scholar] No se detectó API key (.env)."
                )

        self.headers_openalex = {
            "User-Agent": "PaperBot/1.0 (jblanf05@estudiantes.unileon.es)",
            "Accept": "application/json",
        }

        # --------- Variables para retomar (snapshot) ----------
        self.semantic_token = None
        self.semantic_page = 0
        self.semantic_total_found = 0

        self.openalex_cursor = "*"
        self.openalex_page = 0
        self.openalex_total_found = 0

        # contador de logs (para limpiar bloques de estado si quieres)
        self.log_counter = 0

    # ====================== RATE LIMIT & BLOQUEOS =======================

    def _respect_rate_limit(self, host: str):
        now = time.time()
        last = self._last_req.get(host, 0.0)
        min_gap = self.min_interval.get(host, 1.0)
        wait = min_gap - (now - last)
        if wait > 0:
            time.sleep(wait)
        self._last_req[host] = time.time()

    def _note_block_and_maybe_cooldown(self, host: str):
        self._block_counters[host] += 1
        if self._block_counters[host] >= self.cooldown_after_blocks:
            msg = f"[{host}] Bloqueos consecutivos. Enfriando {self.cooldown_seconds/60:.1f} min…"
            print(msg)
            if self.log_manager:
                self.log_manager.log_state(f"⏳ {msg}")
            time.sleep(self.cooldown_seconds)
            self._block_counters[host] = 0

    def _note_success(self, host: str):
        self._block_counters[host] = 0

    # =================== REQUEST JSON ROBUSTO (con excepciones) ===================

    def _request_json(
        self, url, params, headers, source_host: str, allow_202_retries=3
    ):
        """
        GET robusto que respeta rate limit, maneja 202/429, redirects/HTML (WAF)
        y devuelve dict JSON o lanza:
          - ProviderRateLimitError (429)
          - ProviderBlockedError (WAF/HTML/no JSON o JSON inválido)
          - NetworkError (fallo de red o 202 persistente)
        """
        try:
            # Rate limit mínimo por host
            self._respect_rate_limit(source_host)

            # Bucle de reintentos internos para 429 con Retry-After
            # Antes lanzaba excepción inmediata; ahora dormimos lo que
            # diga el proveedor y reintentamos (máx. self.max_429_retries).
            _429_tries = 0

            resp = self.session.get(
                url, params=params, headers=headers, timeout=self.timeout
            )

            # 202 Accepted: resultado en preparación (Semantic Scholar)
            _202_tries = 0
            while resp.status_code == 202 and _202_tries < allow_202_retries:
                if self.log_manager:
                    self.log_manager.log_state(
                        f"⏳ [{source_host}] 202 Accepted, reintento…"
                    )
                time.sleep(10)
                self._respect_rate_limit(source_host)
                resp = self.session.get(
                    url, params=params, headers=headers, timeout=self.timeout
                )
                _202_tries += 1
            if resp.status_code == 202:
                # tras reintentos seguimos en 202 → trata como problema temporal de proveedor
                raise NetworkError(
                    f"[{source_host}] 202 Accepted persistente (resultado no listo)."
                )

            # 429 Too Many Requests (manejo con Retry-After + backoff)
            while resp.status_code == 429 and _429_tries < self.max_429_retries:
                ra = resp.headers.get("Retry-After")
                # Si el proveedor especifica Retry-After, lo obedecemos. Si no, fallback con jitter.
                try:
                    cool = (
                        int(ra)
                        if ra and ra.isdigit()
                        else self.base_sleep + random.uniform(3, 10)
                    )
                except Exception:
                    cool = self.base_sleep + random.uniform(3, 10)

                _429_tries += 1
                msg = f"[{source_host}] 429 Too Many Requests. Retry-After={ra or '—'}. Esperando {cool:.1f}s (intento {_429_tries}/{self.max_429_retries})…"
                print(msg)
                if self.log_manager:
                    self.log_manager.log_state(f"⏳ {msg}")

                self._note_block_and_maybe_cooldown(source_host)
                time.sleep(min(cool, self.max_sleep))

                self._respect_rate_limit(source_host)
                resp = self.session.get(
                    url, params=params, headers=headers, timeout=self.timeout
                )

            if resp.status_code == 429:
                # 👉 Agotados los reintentos: ahora sí lanzamos la excepción específica
                raise ProviderRateLimitError(
                    f"[{source_host}] 429 persistente tras {self.max_429_retries} intentos."
                )

            # Detecta HTML / redirect a host distinto → posible WAF/bloqueo
            ctype = resp.headers.get("Content-Type", "").lower()
            host = urlparse(resp.url).netloc.lower()
            if ("application/json" not in ctype) or (source_host not in host):
                sample = resp.text[:200].replace("\n", " ")
                msg = (
                    f"[{source_host}] Respuesta no JSON o redirect a '{host}'. "
                    f"Status {resp.status_code}. Muestra: {sample}"
                )
                print(msg)
                if self.log_manager:
                    self.log_manager.log_state(f"⚠️ {msg}")

                # Reintento ligero único tras breve cooldown
                cool = self.base_sleep + random.uniform(0, 3)
                time.sleep(min(cool, self.max_sleep))
                self._respect_rate_limit(source_host)
                resp = self.session.get(
                    url, params=params, headers=headers, timeout=self.timeout
                )
                ctype = resp.headers.get("Content-Type", "").lower()
                host = urlparse(resp.url).netloc.lower()
                if ("application/json" not in ctype) or (source_host not in host):
                    self._note_block_and_maybe_cooldown(source_host)
                    raise ProviderBlockedError(msg)

            # Parseo JSON
            try:
                data = resp.json()
                self._note_success(source_host)
                return data
            except ValueError:
                sample = resp.text[:200].replace("\n", " ")
                msg = f"[{source_host}] Error al parsear JSON. Status {resp.status_code}. Muestra: {sample}"
                print(msg)
                if self.log_manager:
                    self.log_manager.log_state(f"⚠️ {msg}")
                self._note_block_and_maybe_cooldown(source_host)
                raise ProviderBlockedError(msg)

        except requests.RequestException as e:
            # E/S de red, DNS, timeouts, etc.
            raise NetworkError(f"[{source_host}] Error de red: {e}") from e

    # ========================== MODELOS Y MERGE ==========================

    def create_paper_model(
        self, source, doi, title, abstract, year, date, url, authors=None
    ):
        return {
            "DOI": doi,
            "Source": [source],
            "Title": title or "",
            "Summary": abstract or "",
            "Year": year,
            "Date": date,
            "URL": url,
            "Authors": authors or [],
            "SearchTimestamp": datetime.now().isoformat(),
        }

    def add_or_update_result(self, new_data):
        """
        Inserta/actualiza en self.raw_items (clave DOI normalizado o título normalizado).
        Mantiene lista de fuentes y mejora Summary cuando esté vacío/genérico.
        """
        title = new_data.get("Title", "") or ""
        doi = new_data.get("DOI") or ""

        norm_title = Methods.normalize_title(title)
        norm_doi = Methods.normalize_doi(doi)

        if norm_doi and norm_doi in self.raw_items:
            key = norm_doi
        elif norm_title in self.raw_items:
            key = norm_title
            if norm_doi:
                self.raw_items[norm_doi] = self.raw_items.pop(norm_title)
                key = norm_doi
        else:
            key = norm_doi or norm_title

        if key in self.raw_items:
            existing = self.raw_items[key]
            for k, v in new_data.items():
                if k == "Source":
                    for src in v:
                        if src not in existing["Source"]:
                            existing["Source"].append(src)
                elif k == "Summary" and v:
                    prev = (existing.get("Summary") or "").strip().lower()
                    new = v.strip().lower()
                    if (
                        (
                            prev in ("",)
                            or prev.startswith("no abstract")
                            or "not available" in prev
                            or "no disponible" in prev
                        )
                        and new
                        and not new.startswith("no abstract")
                        and "not available" not in new
                        and "no disponible" not in new
                    ):
                        existing["Summary"] = v
                elif not existing.get(k) and v:
                    existing[k] = v
            self.duplicate_count += 1
        else:
            self.raw_items[key] = new_data

    # ================================ PÚBLICO ================================

    def search(self, keyword):
        """
        Búsqueda de papers con fallback de queries por proveedor.
        """
        self.keyword = keyword
        self.num_results_bykeyword = 0
        self.log_counter = 0

        # Reset de cursores por keyword
        self.semantic_token = None
        self.semantic_page = 0
        self.semantic_total_found = 0

        self.openalex_cursor = "*"
        self.openalex_page = 0
        self.openalex_total_found = 0

        # Preparo fallbacks para cada proveedor
        #q_openalex = self.qb.queries_for("openalex", keyword)
        #q_s2       = self.qb.queries_for("semantic_scholar", keyword)

        # --- Normaliza la keyword (frase si tiene espacios) ---
        kw = (keyword or "").strip()
        if " " in kw and not (kw.startswith('"') and kw.endswith('"')):
            kw = f'"{kw}"'  # frase exacta

        # Ejecutar ambas fuentes; si una falla con excepción, permitimos que burbujee
        try:
            #self._search_semantic_scholar(kw)
            self._search_openalex(kw)

        except ProviderRateLimitError as e:
            if self.log_manager:
                self.log_manager.log_state(
                    f"⏭️ [{getattr(e,'provider','?')}] Límite/cuota. Saltando fuente."
                )
        except ProviderBlockedError as e:
            if self.log_manager:
                self.log_manager.log_state(
                    f"⏭️ [{getattr(e,'provider','?')}] Bloqueado. Saltando fuente."
                )
        except NetworkError as e:
            # Si el texto sugiere 429 (por si alguna lib lo envuelve)
            if "429" in str(e).lower():
                if self.log_manager:
                    self.log_manager.log_state(
                        "⏭️ [newsapi.org] 429 detectado. Saltando fuente."
                    )
            # Otros errores de red: ignora esta fuente y sigue
            if self.log_manager:
                self.log_manager.log_state(
                    f"⚠️ Error de red en fuente. Saltando. Detalle: {e}"
                )

        if self.log_manager:
            self.log_manager.remove_last_states(n=self.log_counter)
            self.log_manager.log_state(
                f"🟢 [Papers] Total {self.num_results_bykeyword} resultados con la keyword: {self.keyword}"
            )

        return None

    # ========================== SEMANTIC SCHOLAR ==========================

    def _search_semantic_scholar(self, keyword):  
        host = "api.semanticscholar.org"
        url = "https://api.semanticscholar.org/graph/v1/paper/search/bulk"

        if self.log_manager:
            self.log_manager.log_state("🟠 [Semantic Scholar] Buscando…")
            self.log_counter += 1

        page = self.semantic_page or 0
        total_found = self.semantic_total_found or 0
        token = self.semantic_token

        # ============ Semantic Scholar (BULK) ============
        # Sintaxis S2 bulk: '+' = AND, '|' = OR
        SEC_S2 = "(" + "|".join(SEC_WORDS) + ")"
        AUTO_S2 = "(" + "|".join(AUTO_WORDS) + ")"
        query = f"({keyword}) + {SEC_S2} + {AUTO_S2}"

        base_params = {
            "query": query,
            "year": "2020-",
            "sort": "publicationDate",  # o 'citationCount'
            "fieldsOfStudy": "Computer Science,Engineering",
            "publicationTypes": "JournalArticle,Conference",
            "fields": "title,abstract,year,url,authors,externalIds,publicationDate",
        }

        while True:
            if self.max_pages_semantic is not None and page >= self.max_pages_semantic:
                break

            params = dict(base_params)
            if token:
                params["token"] = token

            data = self._request_json(
                url=url,
                params=params,
                headers=self.headers_semantic,
                source_host=host,
                allow_202_retries=3,
            )

            papers = data.get("data", []) or []
            if not papers:
                break

            page += 1
            if self.log_manager:
                self.log_manager.log_state(
                    f"🟠 [Semantic Scholar] Página {page} → {len(papers)} resultados"
                )
                self.log_counter += 1

            for paper in papers:
                paper_id = paper.get("paperId")
                if paper_id in self.semantic_ids:
                    self.duplicate_count += 1
                    continue

                doi = (paper.get("externalIds") or {}).get("DOI")
                title = paper.get("title")
                abstract = paper.get("abstract", "")
                year = paper.get("year")
                publication_date = paper.get("publicationDate")
                url_item = paper.get("url", "")
                authors = [
                    a.get("name") for a in (paper.get("authors") or []) if a.get("name")
                ]

                model = self.create_paper_model(
                    "Semantic Scholar",
                    doi,
                    title,
                    abstract,
                    year,
                    publication_date,
                    url_item,
                    authors,
                )
                self.add_or_update_result(model)
                self.semantic_ids.add(paper_id)

            total_found += len(papers)
            self.num_results_bykeyword += len(papers)
            if self.log_manager:
                self.log_manager.log_state(
                    f"🟠 [Semantic Scholar] Total acumulado: {total_found} resultados…"
                )
                self.log_counter += 1

            token = data.get("token")
            if not token:
                break

            # snapshot continuo
            self.semantic_token = token
            self.semantic_page = page
            self.semantic_total_found = total_found

            time.sleep(min(self.base_sleep + random.uniform(0, 3), self.max_sleep))

    # ============================= OPENALEX =============================

    def _extract_openalex_summary(self, item):
        """Reconstruye el abstract desde abstract_inverted_index si es necesario."""
        if item.get("abstract"):
            return item["abstract"]

        inverted = item.get("abstract_inverted_index")
        if inverted:
            max_index = max(pos for positions in inverted.values() for pos in positions)
            abstract = [""] * (max_index + 1)
            for word, positions in inverted.items():
                for pos in positions:
                    abstract[pos] = word
            return " ".join(abstract)
        return ""

    def _search_openalex(self, keyword):
        host = "api.openalex.org"
        url = "https://api.openalex.org/works"

        if self.log_manager:
            self.log_manager.log_state("🟠 [OpenAlex] Buscando...")
            self.log_counter += 1

        per_page = self.openalex_per_page
        cursor = self.openalex_cursor or "*"
        page_counter = self.openalex_page or 0
        total_found = self.openalex_total_found or 0

        # ============ Openalex (Query) ============
        # Sintaxis Openalex: AND, OR
        SEC_S2 = "(" + " OR ".join(SEC_WORDS) + ")"
        AUTO_S2 = "(" + " OR ".join(AUTO_WORDS) + ")"
        query = f"({keyword}) AND {SEC_S2} AND {AUTO_S2}"

        # Filtro avanzado en OpenAlex
        openalex_filter_boolean = ",".join(
            [
                "type:journal-article|proceedings-article",
                "language:en",
                "from_publication_date:2020-01-01",
            ]
        )

        print(query)


        while True:
            if (
                self.max_pages_openalex is not None
                and page_counter >= self.max_pages_openalex
            ):
                break

            params = {
                "search": query,
                "per-page": per_page,
                "cursor": cursor,
                #"filter": filter,
                "mailto": "jblanf05@estudiantes.unileon.es",
                # "select": "id,doi,display_name,abstract_inverted_index,publication_year,publication_date,authorships.author.display_name,ids,primary_location.source.display_name,topics.display_name",
            }

            data = self._request_json(
                url=url,
                params=params,
                headers=self.headers_openalex,
                source_host=host,
                allow_202_retries=0,
            )

            papers = data.get("results", []) or []
            if not papers:
                break

            page_counter += 1
            if self.log_manager:
                self.log_manager.log_state(
                    f"🟠 [OpenAlex] Página {page_counter} → {len(papers)} resultados"
                )
                self.log_counter += 1

            for paper in papers:
                paper_id = paper.get("id")
                if paper_id in self.openalex_ids:
                    self.duplicate_count += 1
                    continue

                doi_url = (paper.get("ids") or {}).get("doi")
                doi = doi_url.replace("https://doi.org/", "") if doi_url else None
                title = paper.get("display_name")
                abstract = self._extract_openalex_summary(paper)
                year = paper.get("publication_year")
                publication_date = paper.get("publication_date")
                url_item = paper.get("id", "")
                authors = [
                    a["author"]["display_name"]
                    for a in (paper.get("authorships") or [])
                    if a.get("author")
                ]

                model = self.create_paper_model(
                    "OpenAlex",
                    doi,
                    title,
                    abstract,
                    year,
                    publication_date,
                    url_item,
                    authors,
                )
                self.add_or_update_result(model)
                self.openalex_ids.add(paper_id)

            total_found += len(papers)
            self.num_results_bykeyword += len(papers)
            if self.log_manager:
                self.log_manager.log_state(
                    f"🟠 [OpenAlex] Total acumulado: {total_found} resultados…"
                )
                self.log_counter += 1

            # cursor siguiente
            next_cursor = (data.get("meta") or {}).get("next_cursor")
            if not next_cursor:
                break
            cursor = next_cursor

            # Actualiza snapshot continuo
            self.openalex_cursor = cursor
            self.openalex_page = page_counter
            self.openalex_total_found = total_found

            cool = self.base_sleep + random.uniform(0, 3)
            time.sleep(min(cool, self.max_sleep))

    # ============================ SNAPSHOT/RESUME ============================

    def get_state_snapshot(self) -> dict:
        return {
            "ia_analyzed_ids": list(self.ia_analyzed_ids),
            "final_results": self.final_results,
            "raw_items": self.raw_items,
            "semantic_ids": list(self.semantic_ids),
            "openalex_ids": list(self.openalex_ids),
            "duplicate_count": self.duplicate_count,
            "num_results_bykeyword": self.num_results_bykeyword,
            "apply_filter_ia": self.apply_filter_ia,
            "values_levels_ia": self.values_levels_ia,
            # nuevos:
            "semantic_token": self.semantic_token,
            "semantic_page": self.semantic_page,
            "semantic_total_found": self.semantic_total_found,
            "openalex_cursor": self.openalex_cursor,
            "openalex_page": self.openalex_page,
            "openalex_total_found": self.openalex_total_found,
        }

    def load_state_snapshot(self, snap: dict) -> None:
        self.ia_analyzed_ids = set(snap.get("ia_analyzed_ids", []))
        self.final_results = snap.get("final_results", {}) or {}
        self.raw_items = snap.get("raw_items", {}) or {}
        self.semantic_ids = set(snap.get("semantic_ids", []))
        self.openalex_ids = set(snap.get("openalex_ids", []))
        self.duplicate_count = snap.get("duplicate_count", 0)
        self.num_results_bykeyword = snap.get("num_results_bykeyword", 0)
        self.apply_filter_ia = snap.get("apply_filter_ia", False)
        self.values_levels_ia = snap.get("values_levels_ia", {}) or {}
        # nuevos:
        self.semantic_token = snap.get("semantic_token")
        self.semantic_page = snap.get("semantic_page", 0)
        self.semantic_total_found = snap.get("semantic_total_found", 0)
        self.openalex_cursor = snap.get("openalex_cursor", "*")
        self.openalex_page = snap.get("openalex_page", 0)
        self.openalex_total_found = snap.get("openalex_total_found", 0)
