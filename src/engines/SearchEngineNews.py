import os
import re
import requests
import random
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter, Retry
from dotenv import load_dotenv, find_dotenv
import time
from urllib.parse import urlparse
from collections import defaultdict
import hashlib

from src.utils.Methods import Methods
from src.utils.Errors import ProviderRateLimitError, ProviderBlockedError, NetworkError, ProviderBadQueryError
from src.utils.SearchQueryBuilder import SearchQueryBuilder
from src.utils.DescriptionExtractor import DescriptionExtractor


class NewsSearchEngine:
    """
    Motores: GNews, NewsAPI, SerpAPI(Google News), GDELT, NewsData.io
    - Paginación + rate limiting + backoff
    - Fallbacks delegados en SearchQueryBuilder
    - Límite de páginas por query (por defecto 3)
    """

    def __init__(
        self,
        ia_analyzed_ids=None,
        final_results=None,
        gnews_ids=None,
        newsapi_ids=None,
        serpapi_ids=None,
        gdelt_ids=None,
        newsdata_ids=None,
        log_manager=None,
        lang: str = "en",
        enable_brand_buckets: bool = True,
        max_queries_per_provider: int = 6,
        max_pages_per_query: int = 20,
    ):
        # Cargar .env si no está ya cargado
        load_dotenv(find_dotenv(), override=False)

        # Flags de depuración
        self.debug = os.getenv("DEBUG_LOGS", "0") == "1"
        self.trace_enrich = os.getenv("ENRICH_TRACE", "0") == "1"

        # ------------------------- Estado -------------------------
        self.keyword = ""
        self.ia_analyzed_ids = set(ia_analyzed_ids or [])
        self.final_results = final_results or {}
        self.raw_items = {}
        self.gnews_ids = set(gnews_ids or [])       # GNews
        self.newsapi_ids = set(newsapi_ids or [])   # NewsAPI
        self.serpapi_ids = set(serpapi_ids or [])   # SerpAPI
        self.gdelt_ids = set(gdelt_ids or [])       # GDELT
        self.newsdata_ids = set(newsdata_ids or []) # NewsData
        self.filter_engine = None
        self.duplicate_count = 0
        self.num_results_bykeyword = 0
        self.idx_by_url = {}
        self.idx_by_title = {}

        # ------------------------- Deduplicidad -------------------------
        self.idx_by_title_sha = {}                    # hash fuerte del título normalizado (idénticos exactos)
        self.idx_by_simhash_band = defaultdict(list)  # (band_idx, band_val) -> [master_id,...]
        self.idx_by_url_sig = {}                      # firma de URL sin esquema (host+path normalizados)
        self.idx_by_title_prefix = defaultdict(list)  # primeras K palabras “fuertes” del título
        self.idx_by_bow_sig = defaultdict(list)       # NUEVO: firma bag-of-words (orden-insensible)

        self.simhash_bands = 4
        self.simhash_hamming_threshold = 8            # antes 4
        self.cross_days = 3                           # ventana de fechas ±N días
        self.title_prefix_k = 4                       # antes 6
        self.enable_summary_fallback = True           # usar resumen si los títulos difieren
        self.summary_hamming_threshold = 12           # umbral para SimHash de resumen (64 bits)
        self.summary_jaccard_min = 0.70               # antes 0.75

        # ------------------------- Logging -------------------------
        self.log_manager = log_manager
        self.log_counter = 0

        # ------------------------- Config -------------------------
        self.lang = lang
        self.timeout = 30
        self.base_sleep = 1.1
        self.max_sleep = 60
        self.max_pages_per_query = max(1, int(max_pages_per_query))

        # ------------------------- Query -------------------------
        self.qb = SearchQueryBuilder()

        # ------------------------- Tokens -------------------------
        self.gnews_token = os.getenv("GNEWS_API_TOKEN")
        self.newsapi_token = os.getenv("NEWSAPI_API_KEY") or os.getenv("NEWSAPI_API_TOKEN")  # tolera ambos nombres
        self.serpapi_key = os.getenv("SERPAPI_API_KEY")
        self.newsdata_token = os.getenv("NEWSDATA_API_TOKEN")

        # ------------------------- Sesión con retries -------------------------
        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1.0,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        # ------------------------- Rate limit -------------------------
        self.min_interval = {
            "gnews.io": 1.0,
            "newsapi.org": 1.0,
            "serpapi.com": 0.6,
            "api.gdeltproject.org": 1.0,
            "newsdata.io": 0.6,
        }
        self._last_req = {}
        self._block_counters = {h: 0 for h in self.min_interval.keys()}
        self.cooldown_after_blocks = 2
        self.cooldown_seconds = 10 * 60

        # ------------------------- Fallbacks / flags -------------------------
        self.enable_brand_buckets = enable_brand_buckets
        self.max_queries_per_provider = max(1, int(max_queries_per_provider))
        self.query_fallback_levels = True
        self.allow_broad_q4 = True
        self.auto_relax_if_zero = True
        self.serpapi_use_google_news_engine = True

        # ------------------------- NewsData -------------------------
        self.newsdata_use_archive = True
        self.newsdata_archive_confirmed = None
        self.newsdata_from = "2020-01-01"
        self.newsdata_to = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.newsdata_window_days = 90
        self.newsdata_max_pages_per_window = 80
        self.newsdata_max_windows = None
        self.newsdata_countries = None
        self.newsdata_domains_allow = None
        self.newsdata_tags = None
        self.newsdata_sentiment = None
        self.newsdata_max_q_len = 512

        # 🔴 No caer a Latest (48h) si Archive no está disponible
        self.newsdata_allow_latest_fallback = False

        # ------------------------- GDELT -------------------------
        self.stop_after_empty_windows = 6

    # -------------------------------------------------------------------------
    # Helpers internos (firma URL, prefijo de título, tokens resumen)
    # -------------------------------------------------------------------------
    def _url_signature(self, url: str) -> str:
        """host+path normalizados; evita http/https y query de tracking."""
        try:
            return Methods.url_signature(url)
        except Exception:
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

    def _prefix_key(self, title: str, k: int) -> str:
        """Primeras k palabras tras normalización básica; intenta usar Methods si existe."""
        try:
            return Methods.title_prefix_key(title, k=k)
        except Exception:
            t = Methods._normalize_text_basic(title)
            words = re.findall(r"[a-z0-9]+", t)
            strong = [w for w in words if len(w) > 2]
            return "|".join(strong[:k])

    def _summary_tokens(self, s: str) -> set:
        """Tokens simples para comparar resúmenes."""
        if not s:
            return set()
        t = Methods._normalize_text_basic(s)
        words = re.findall(r"[a-z0-9]+", t)
        return {w for w in words if len(w) > 3}

    # -------------------------------------------------------------------------
    # Logging helper
    # -------------------------------------------------------------------------
    def _log(self, msg: str):
        if self.log_manager:
            self.log_manager.log_state(msg)
        if self.debug:
            print(msg, flush=True)

    # ------------------------- Helpers red -------------------------

    def _respect_rate_limit(self, host: str):
        now = time.time()
        last = self._last_req.get(host, 0.0)
        wait = self.min_interval.get(host, 1.0) - (now - last)
        if wait > 0:
            time.sleep(wait)
        self._last_req[host] = time.time()

    def _note_block_and_maybe_cooldown(self, host: str):
        self._block_counters[host] += 1
        if self._block_counters[host] >= self.cooldown_after_blocks:
            self._log(f"⏳ [{host}] Bloqueos consecutivos. Enfriando {self.cooldown_seconds/60:.1f} min…")
            time.sleep(self.cooldown_seconds)
            self._block_counters[host] = 0

    def _note_success(self, host: str):
        self._block_counters[host] = 0

    def _request_json(self, url: str, params: dict, source_host: str) -> dict:
        # Log de salida (ocultando credenciales)
        if self.debug:
            safe_params = dict(params or {})
            for k in ("api_key", "apikey", "token", "apiKey"):
                if k in safe_params:
                    safe_params[k] = "***"
            print(f"→ GET {url} host={source_host} params={safe_params}", flush=True)

        self._respect_rate_limit(source_host)
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise NetworkError(f"[{source_host}] Error de red: {e}") from e

        if self.debug:
            ctype_dbg = (resp.headers.get("Content-Type") or "").lower()
            print(f"← {source_host} {resp.status_code} ctype={ctype_dbg} bytes={len(resp.content)}", flush=True)

        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            try:
                if ra is not None:
                    self.min_interval[source_host] = max(self.min_interval.get(source_host, 1.0), int(ra))
            except Exception:
                pass
            raise ProviderRateLimitError(
                provider=source_host,
                message="HTTP 429 Too Many Requests",
                context={"retry_after": ra, "url": url, "params": params},
            )

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" not in ctype:
            sample = (resp.text or "")[:200].replace("\n", " ")
            self._log(f"⚠️ [{source_host}] No JSON ({resp.status_code}). Ejemplo: {sample}")
            time.sleep(self.base_sleep + random.uniform(0, 1))
            self._respect_rate_limit(source_host)
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                raise NetworkError(f"[{source_host}] Error de red tras reintento: {e}") from e

            if self.debug:
                ctype_dbg = (resp.headers.get("Content-Type") or "").lower()
                print(f"↩ {source_host} retry {resp.status_code} ctype={ctype_dbg} bytes={len(resp.content)}", flush=True)

            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "application/json" not in ctype:
                body_preview = (resp.text or "")[:200]
                low = body_preview.lower()
                if source_host == "api.gdeltproject.org" and any(
                    s in low for s in (
                        "your query was too short or too long",
                        "the specified phrase is too short",
                        "invalid query",
                    )
                ):
                    raise ProviderBadQueryError(
                        provider=source_host,
                        message="GDELT bad query",
                        context={"preview": body_preview, "url": url, "params": params},
                    )
                self._note_block_and_maybe_cooldown(source_host)
                raise ProviderBlockedError(
                    provider=source_host,
                    message=f"Respuesta no JSON reiterada (status {resp.status_code})",
                    context={"url": url, "params": params, "preview": body_preview},
                )
        try:
            data = resp.json()
            self._note_success(source_host)
            return data
        except ValueError:
            sample = (resp.text or "")[:200].replace("\n", " ")
            self._note_block_and_maybe_cooldown(source_host)
            raise NetworkError(f"[{source_host}] JSON inválido. Ej: {sample}")

    # ------------------------- Orchestrator -------------------------

    def search(self, keyword):
        self.keyword = keyword
        self.num_results_bykeyword = 0
        self.log_counter = 0
        self.duplicate_count = 0

        providers = [
            self._search_gnews,
            self._search_newsapi,
            self._search_serpapi_news,   # rango 2020→hoy (tbs)
            self._search_gdelt,          # histórico amplio
            self._search_newsdata,       # archivo de NewsData (si aplicable)
        ]
        for source_func in providers:
            try:
                source_func(keyword)
            except ProviderRateLimitError as e:
                self._log(f"⏭️ [{getattr(e,'provider','?')}] Límite/cuota. Saltando fuente.")
            except ProviderBlockedError as e:
                self._log(f"⏭️ [{getattr(e,'provider','?')}] Bloqueado. Saltando fuente.")
            except NetworkError as e:
                self._log(f"⚠️ Error de red en fuente. Saltando. Detalle: {e}")

        self.log_manager.remove_last_states(n=self.log_counter)
        self.log_manager.log_state(f"🟢 [NEWS] Total resultados: {self.num_results_bykeyword} | kw: {self.keyword}")

        print(f"\n[NEWS] Total resultados duplicados: {self.duplicate_count} | kw: {self.keyword}")

    # ------------------------- GNews -------------------------

    def _search_gnews(self, keyword):
        host = "gnews.io"
        base_url = "https://gnews.io/api/v4/search"

        if not self.gnews_token:
            self.log_manager.log_state("🟡 [GNews] Sin token.")
            print("🟡 [GNews] Sin token.")
            self.log_counter += 1
            return

        self.log_manager.log_state("🟠 [GNews] Iniciando búsqueda…")
        self.log_counter += 1

        max_per_page = 100
        queries = self.qb.queries_for("GNews", keyword) if self.query_fallback_levels else [self.qb.queries_for("GNews", keyword)[0]]

        for qi, query in enumerate(queries, start=1):
            if qi == 4 and not self.allow_broad_q4:
                break
            start, page_q, got_any, total_found = 0, 0, False, 0
            has_log_msg = False

            print(f"\n[Gnews] Query Q{qi}: {query}")

            while True:
                params = {
                    "q": query,
                    "max": max_per_page,
                    "start": start,
                    "lang": self.lang,
                    "token": self.gnews_token,
                    "in": "title,description,content",
                    "sortby": "relevance",
                    "from": "2020-01-01T00:00:00.000Z",
                }
                data = self._request_json(base_url, params, source_host=host)
                if isinstance(data, dict) and ("errors" in data or "message" in data):
                    msg = str(data.get("message") or data.get("errors") or "").lower()
                    if any(x in msg for x in ("rate", "quota", "limit", "too many")):
                        raise ProviderRateLimitError(host, f"GNews cuota/limite: {data}", {"params": params})
                    break
                news = data.get("articles", []) or []
                if not news:
                    break
                page_q += 1

                if has_log_msg:
                    self.log_manager.remove_last_states(n=2)
                    self.log_counter -= 2
                self.log_manager.log_state(f"🟠 [GNews] Q{qi}/{len(queries)} · Página {page_q} → {len(news)}")
                has_log_msg = True
                self.log_counter += 1

                for new in news:
                    url = (new.get("url") or "").strip()
                    if not url:
                        continue
                    norm_id = Methods.normalize_url(url)
                    if norm_id in self.gnews_ids:
                        self.duplicate_count += 1
                        continue
                    item = self.create_new_model(
                        "GNews",
                        (new.get("title") or "").strip(),
                        (new.get("description") or "").strip(),
                        (new.get("publishedAt") or "").strip(),
                        url,
                        (new.get("source", {}) or {}).get("name", "").strip(),
                    )
                    self.add_or_update_result(item)
                    self.gnews_ids.add(norm_id)
                    got_any = True

                total_found += len(news)
                self.num_results_bykeyword += len(news)
                self.log_manager.log_state(f"🟠 [GNews] Total acumulado: {total_found} resultados…")
                self.log_counter += 1

                if len(news) < max_per_page or page_q >= self.max_pages_per_query:
                    break
                start += max_per_page
                time.sleep(self.base_sleep + random.uniform(0, 0.5))
            if got_any:
                break

        print(f"\n[Gnews] Noticias encontradas: {total_found}")    

    # ------------------------- NewsAPI -------------------------

    def _search_newsapi(self, keyword):
        host = "newsapi.org"
        base_url = "https://newsapi.org/v2/everything"

        if not self.newsapi_token:
            self.log_manager.log_state("🟡 [NewsAPI] Sin token.")
            print("🟡 [NewsAPI] Sin token.")
            self.log_counter += 1
            return

        self.log_manager.log_state("🟠 [NewsAPI] Iniciando búsqueda…")
        self.log_counter += 1

        page_size = 100
        hard_cap = 100
        from_date = (datetime.now() - timedelta(days=28)).strftime("%Y-%m-%d")

        queries = self.qb.queries_for("NewsAPI", keyword) if self.query_fallback_levels else [self.qb.queries_for("NewsAPI", keyword)[0]]

        for qi, query in enumerate(queries, start=1):
            if qi == 4 and not self.allow_broad_q4:
                break
            page, max_pages_reported, got_any, total_found = 1, None, False, 0
            has_log_msg = False

            print(f"\n[NewsAPI] Query Q{qi}: {query}")

            while True:
                params = {
                    "q": query,
                    "language": self.lang,
                    "apiKey": self.newsapi_token,
                    "pageSize": page_size,
                    "page": page,
                    "from": from_date,
                    "searchIn": "title,description,content",
                    "sortBy": "relevancy",
                }
                data = self._request_json(base_url, params, source_host=host)
                status = data.get("status")
                if status != "ok":
                    code = str(data.get("code") or "").lower()
                    message = str(data.get("message") or "").lower()
                    if code in ("ratelimited", "maximumresultsreached") or any(x in message for x in ("rate", "quota", "limit")):
                        raise ProviderRateLimitError(host, f"NewsAPI cuota/limite: {data}", {"page": page, "params": params})
                    break

                news = data.get("articles", []) or []
                if not news:
                    break

                if has_log_msg:
                    self.log_manager.remove_last_states(n=2)
                    self.log_counter -= 2
                self.log_manager.log_state(f"🟠 [NewsAPI] Q{qi}/{len(queries)} · Página {page}/{max_pages_reported} → {len(news)}")
                has_log_msg = True
                self.log_counter += 1

                for new in news:
                    url = (new.get("url") or "").strip()
                    if not url:
                        continue
                    norm_id = Methods.normalize_url(url)
                    if norm_id in self.newsapi_ids:
                        self.duplicate_count += 1
                        continue
                    item = self.create_new_model(
                        "NewsAPI",
                        (new.get("title") or "").strip(),
                        (new.get("description") or "").strip(),
                        (new.get("publishedAt") or "").strip(),
                        url,
                        (new.get("source", {}) or {}).get("name", "").strip(),
                    )
                    self.add_or_update_result(item)
                    self.newsapi_ids.add(norm_id)
                    got_any = True

                self.num_results_bykeyword += len(news)
                total_found += len(news)
                self.log_manager.log_state(f"🟠 [NewsAPI] Total acumulado: {total_found} resultados…")
                self.log_counter += 1

                if (page * page_size) >= hard_cap:
                    break
                if max_pages_reported and page >= max_pages_reported:
                    break
                if page >= self.max_pages_per_query:
                    break

                page += 1
                time.sleep(self.base_sleep + random.uniform(0, 0.5))
            if got_any:
                break


        print(f"\n[NewsAPI] Noticias encontradas: {total_found}")

    # --------------------- SerpAPI (Google News) ---------------------

    def _serpapi_parse_date(self, s: str) -> str:
        if not s:
            return ""
        s = s.strip()
        for fmt in ("%b %d, %Y", "%d %b %Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
            except Exception:
                pass
        import re
        now = datetime.utcnow()
        m = re.match(r"(\d+)\s+(min|mins|minute|minutes)\s+ago", s, flags=re.I)
        if m:
            return (now - timedelta(minutes=int(m.group(1)))).strftime("%Y-%m-%d")
        m = re.match(r"(\d+)\s+(hour|hours|h)\s+ago", s, flags=re.I)
        if m:
            return (now - timedelta(hours=int(m.group(1)))).strftime("%Y-%m-%d")
        m = re.match(r"(\d+)\s+(day|days|d)\s+ago", s, flags=re.I)
        if m:
            return (now - timedelta(days=int(m.group(1)))).strftime("%Y-%m-%d")
        if s.lower().startswith("yesterday"):
            return (now - timedelta(days=1)).strftime("%Y-%m-%d")
        if s.lower().startswith("today"):
            return now.strftime("%Y-%m-%d")
        return ""

    def _search_serpapi_news(self, keyword):
        host = "serpapi.com"
        base_url = "https://serpapi.com/search"

        if not self.serpapi_key:
            self.log_manager.log_state("🟡 [SerpAPI] Sin token.")
            print("🟡 [SerpAPI] Sin token.\n")
            self.log_counter += 1
            return

        self.log_manager.log_state("🟠 [SerpAPI · Google News] Iniciando búsqueda…")
        self.log_counter += 1

        page_size = 100
        hard_cap = 1000
        from_dt = datetime(2020, 1, 1)
        to_dt = datetime.now(timezone.utc)

        queries = [self.qb.queries_for("SerpApiGoogleNews", keyword)[0]]

        if not hasattr(self, "serpapi_ids"):
            self.serpapi_ids = set()

        hl = "es" if self.lang == "es" else "en"
        gl = "es" if self.lang == "es" else "us"

        def _norm_source_name(src):
            if isinstance(src, dict):
                return (src.get("name") or src.get("title") or "").strip()
            return (src or "Google News").strip()

        def _ingest(items):
            count = 0
            if not isinstance(items, list):
                return 0
            for it in items:
                if not isinstance(it, dict):
                    continue
                url = (it.get("link") or "").strip()
                if not url:
                    continue
                norm_id = Methods.normalize_url(url)
                if norm_id in self.serpapi_ids:
                    self.duplicate_count += 1
                    continue

                title = (it.get("title") or "").strip()
                desc = (it.get("snippet") or "").strip()
                src_name = _norm_source_name(it.get("source"))
                raw_date = (it.get("date") or "").strip()
                pub_iso = self._serpapi_parse_date(raw_date) or raw_date

                item = self.create_new_model("SerpAPI.GoogleNews", title, desc, pub_iso, url, src_name)
                self.add_or_update_result(item)
                self.serpapi_ids.add(norm_id)
                count += 1

                stories = it.get("stories") or []
                if isinstance(stories, list):
                    for st in stories:
                        if not isinstance(st, dict):
                            continue
                        s_url = (st.get("link") or "").strip()
                        if not s_url:
                            continue
                        s_norm = Methods.normalize_url(s_url)
                        if s_norm in self.serpapi_ids:
                            self.duplicate_count += 1
                            continue
                        s_title = (st.get("title") or "").strip()
                        s_desc = (st.get("snippet") or "").strip()
                        s_src = _norm_source_name(st.get("source"))
                        s_date = (st.get("date") or "").strip()
                        s_pub = self._serpapi_parse_date(s_date) or s_date
                        s_item = self.create_new_model("SerpAPI.GoogleNews", s_title, s_desc, s_pub, s_url, s_src)
                        self.add_or_update_result(s_item)
                        self.serpapi_ids.add(s_norm)
                        count += 1
            return count

        added_total = 0

        for qi, q in enumerate(queries, start=1):
            page = 1
            start = 0
            total_found = 0
            has_log_msg = False

            cd_min = from_dt.strftime("%m/%d/%Y")
            cd_max = to_dt.strftime("%m/%d/%Y")
            tbs = f"cdr:1,cd_min:{cd_min},cd_max:{cd_max}"

            self.log_manager.log_state(f"🟠 [SerpAPI · News tab] Q{qi}/{len(queries)} · Rango {cd_min}–{cd_max}")
            self.log_counter += 1

            print(f"\n[Gnews] Query Q{qi}: {q}")

            while True:
                params = {
                    "engine": "google",
                    "tbm": "nws",
                    "q": q,
                    "hl": hl,
                    "gl": gl,
                    "google_domain": "google.com",
                    "api_key": self.serpapi_key,
                    "num": page_size,
                    "start": start,
                    "tbs": tbs,
                    "nfpr": "1",
                }

                data = self._request_json(base_url, params, source_host=host)

                if data is None or (isinstance(data, dict) and data.get("error")):
                    msg = (data or {}).get("error", "Error desconocido de SerpAPI")
                    low = str(msg).lower()
                    if any(x in low for x in ("rate", "limit", "quota")):
                        raise ProviderRateLimitError(host, f"SerpAPI cuota/limite: {data}", {"page": page, "params": params})
                    break

                items = data.get("news_results") or []
                if not items:
                    break

                added = _ingest(items)
                added_total += added
                self.num_results_bykeyword += added
                total_found += added

                if has_log_msg:
                    self.log_manager.remove_last_states(n=2)
                    self.log_counter -= 2
                self.log_manager.log_state(f"🟠 [SerpAPI] Página {page} → +{added} · Acum: {total_found} · Total: {added_total}")
                has_log_msg = True
                self.log_counter += 1

                if (page * page_size) >= hard_cap:
                    break
                if page >= self.max_pages_per_query:
                    break
                if len(items) < page_size:
                    break

                start += page_size
                page += 1
                time.sleep(self.base_sleep + random.uniform(0, 0.5))

            if added_total > 0:
                break

            
        print(f"\n[Gnews] Noticias encontradas: {total_found}")

    # --------------------- GDELT ---------------------

    def _fmt_yyyymmddhhmmss(self, dt):
        return dt.strftime("%Y%m%d%H%M%S")

    def _month_windows(self, start_iso: str, end_iso: str):
        start = datetime.strptime(start_iso, "%Y-%m-%d")
        end = datetime.strptime(end_iso, "%Y-%m-%d")
        cur = datetime(start.year, start.month, 1)
        while cur <= end:
            if cur.month == 12:
                nxt = datetime(cur.year + 1, 1, 1) - timedelta(days=1)
            else:
                nxt = datetime(cur.year, cur.month + 1, 1) - timedelta(days=1)
            if nxt > end:
                nxt = end
            yield cur, nxt
            cur = nxt + timedelta(days=1)

    def _search_gdelt(self, keyword):
        host = "api.gdeltproject.org"
        base_url = "https://api.gdeltproject.org/api/v2/doc/doc"

        start_iso = "2020-01-01"
        end_iso = datetime.utcnow().strftime("%Y-%m-%d")

        self.log_manager.log_state(f"🟠 [GDELT] Iniciando búsqueda {start_iso} → {end_iso} (descendente)…")
        self.log_counter += 1

        queries = self.qb.queries_for("GDELT", keyword) if self.query_fallback_levels else [self.qb.queries_for("GDELT", keyword)[0]]
        total_found = 0
        total_added = 0

        windows = list(self._month_windows(start_iso, end_iso))[::-1]

        for qi, q0 in enumerate(queries, start=1):
            bad_query = False
            consecutive_empty = 0
            has_log_msg = False

            print(f"\n[Gnews] Query Q{qi}: {q0}")

            for wi, (w_start, w_end) in enumerate(windows, start=1):
                params = {
                    "query": q0,
                    "mode": "artlist",
                    "format": "json",
                    "maxrecords": 250,
                    "sort": "DateDesc",
                    "startdatetime": self._fmt_yyyymmddhhmmss(w_start.replace(hour=0, minute=0, second=0)),
                    "enddatetime": self._fmt_yyyymmddhhmmss(w_end.replace(hour=23, minute=59, second=59)),
                }

                try:
                    data = self._request_json(base_url, params, source_host=host)
                except ProviderBadQueryError as e:
                    self.log_manager.log_state(f"🟡 [GDELT] Consulta inválida ({e.context.get('preview','')[:80]}). Probando fallback…")
                    print(f"🟡 [GDELT] Consulta inválida ({e.context.get('preview','')[:80]}). Probando fallback…")
                    self.log_counter += 1
                    bad_query = True
                    break
                except ProviderBlockedError:
                    continue
                except Exception:
                    time.sleep(1.0)
                    try:
                        data = self._request_json(base_url, params, source_host=host)
                    except Exception:
                        data = {}

                news = (data.get("articles") or []) if isinstance(data, dict) else []

                if has_log_msg:
                    self.log_manager.remove_last_states(n=2)
                    self.log_counter -= 2
                self.log_manager.log_state(f"🟠 [GDELT] Q{qi}/{len(queries)} · {w_start.date()}–{w_end.date()} → {len(news)} artículos")
                has_log_msg = True
                self.log_counter += 1

                added = 0
                for it in news:
                    url = (it.get("url") or "").strip()
                    if not url or url in self.gdelt_ids:
                        continue
                    title = (it.get("title") or "").strip()
                    pub = (it.get("seendate") or "").strip()
                    pub_iso = ""
                    if len(pub) >= 8:
                        try:
                            pub_iso = datetime.strptime(pub[:8], "%Y%m%d").strftime("%Y-%m-%d")
                        except Exception:
                            pub_iso = ""

                    source = (it.get("sourceCommonName") or it.get("domain") or "").strip()
                    item = self.create_new_model("GDELT", title, "", pub_iso, url, source)
                    lang_code = (it.get("language") or "").strip()
                    if lang_code:
                        item["Language"] = lang_code
                    self.add_or_update_result(item)
                    added += 1

                total_added += added
                total_found += len(news)
                self.num_results_bykeyword += len(news)

                self.log_manager.log_state(f"🟠 [GDELT] Total acumulado: {total_added} resultados…")
                self.log_counter += 1

                if added == 0:
                    consecutive_empty += 1
                    if consecutive_empty >= self.stop_after_empty_windows:
                        self.log_manager.log_state(f"🟠 [GDELT] {consecutive_empty} meses seguidos sin resultados; deteniendo por límite histórico.")
                        print(f"🟠 [GDELT] {consecutive_empty} meses seguidos sin resultados; deteniendo por límite histórico.")
                        self.log_counter += 1
                        break
                else:
                    consecutive_empty = 0

            if bad_query:
                continue
            if total_added > 0:
                break

            
        print(f"\n[Gnews] Noticias encontradas: {total_found}")

    # --------------------- NewsData.io ---------------------

    def _newsdata_iter_date_windows(self, start_date: str, end_date: str, step_days: int):
        cur = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        while cur <= end:
            nxt = min(cur + timedelta(days=step_days - 1), end)
            yield cur.strftime("%Y-%m-%d"), nxt.strftime("%Y-%m-%d")
            cur = nxt + timedelta(days=1)

    def _search_newsdata(self, keyword):
        host = "newsdata.io"
        base_latest = "https://newsdata.io/api/1/news"
        base_archive = "https://newsdata.io/api/1/archive"

        if not self.newsdata_token:
            self.log_manager.log_state("🟡 [NewsData] Sin token.")
            self.log_counter += 1
            return

        self.log_manager.log_state("🟠 [NewsData] Iniciando búsqueda…")
        self.log_counter += 1

        # --- Query building (con fallbacks) ---
        queries = self.qb.queries_for("NewsData", keyword) if self.query_fallback_levels else [self.qb.queries_for("NewsData", keyword)[0]]
        lang_map = {"es": "es", "en": "en"}
        language = lang_map.get(self.lang, "en")

        # parámetros base (EXCLUSIVO: solo 'q')
        def mk_params(q):
            p = {"apikey": self.newsdata_token, "language": language, "q": q}
            if self.newsdata_countries:
                p["country"] = ",".join(self.newsdata_countries[:10])
            if self.newsdata_domains_allow:
                p["domain"] = ",".join(self.newsdata_domains_allow[:5])  # máx. 5
            if self.newsdata_sentiment:
                p["sentiment"] = self.newsdata_sentiment
            if self.newsdata_tags:
                p["tag"] = ",".join(self.newsdata_tags[:5])
            return p

        def ingest_results(results):
            added = 0
            for it in results or []:
                if not isinstance(it, dict):
                    continue
                url = ((it.get("link") or it.get("url")) or "").strip()
                if not url:
                    continue
                norm_id = Methods.normalize_url(url)
                if norm_id in self.newsdata_ids:
                    self.duplicate_count += 1
                    continue

                title = (it.get("title") or "").strip()
                desc = (it.get("description") or "").strip()
                pub = (it.get("pubDate") or "").strip()
                source = (it.get("source_id") or it.get("source") or "").strip()

                item = self.create_new_model("NewsData", title, desc, pub, url, source)

                for k_src, k_dst in [
                    ("ai_tag", "AI_Tags"), ("ai_tags", "AI_Tags"),
                    ("sentiment", "AI_Sentiment"),
                    ("ai_org", "AI_Org"), ("ai_organization", "AI_Org"), ("ai_organizations", "AI_Org"),
                    ("ai_region", "AI_Region"),
                    ("ai_summary", "AI_Summary"), ("summary", "AI_Summary"),
                    ("ai_content", "AI_Content"), ("content", "AI_Content"),
                ]:
                    v = it.get(k_src)
                    if v is not None:
                        item[k_dst] = v if k_dst != "AI_Content" else bool(v)

                self.add_or_update_result(item)
                self.newsdata_ids.add(norm_id)
                added += 1
            return added

        total = 0

        # --- Archive con ventanas, con fallback controlado ---
        use_archive = self.newsdata_use_archive and (self.newsdata_archive_confirmed is not False)
        if use_archive:
            windows = list(self._newsdata_iter_date_windows(self.newsdata_from, self.newsdata_to, self.newsdata_window_days))
            if self.newsdata_max_windows:
                windows = windows[: self.newsdata_max_windows]

            self.log_manager.log_state(f"🟠 [NewsData] Archive desde {self.newsdata_from} hasta {self.newsdata_to} · ventanas de {self.newsdata_window_days} días")
            self.log_counter += 1

            for q_idx, q in enumerate(queries, start=1):
                for wi, (fdate, tdate) in enumerate(windows, start=1):
                    page, pages, win_added = None, 0, 0
                    has_log_msg = False

                    print(f"\n[Gnews] Query Q{q_idx}: {q}")

                    while True:
                        params = mk_params(q)
                        params["from_date"], params["to_date"] = fdate, tdate
                        if page:
                            params["page"] = page

                        data = self._request_json(base_archive, params, source_host=host)
                        status = (data.get("status") or "").lower()

                        if status and status not in ("success",):
                            msg = str(data.get("results") or data)
                            low = msg.lower()
                            if any(s in low for s in ("unsupportedfilter", "upgrade your plan", "unsupportedquerylength", "query length", "paid user", "pricing", "subscribe")):
                                self.newsdata_archive_confirmed = False
                                self.log_manager.log_state("🟡 [NewsData] Archive no disponible en tu plan.")
                                print("🟡 [NewsData] Archive no disponible en tu plan.")
                                self.log_counter += 1
                                use_archive = False
                                break
                            self.log_manager.log_state(f"🟡 [NewsData] status={status}. {str(data)[:140]}")
                            print(f"🟡 [NewsData] status={status}. {str(data)[:140]}")
                            self.log_counter += 1
                            break

                        if self.newsdata_archive_confirmed is None:
                            self.newsdata_archive_confirmed = True

                        res = data.get("results") or []
                        win_added += ingest_results(res)
                        total += len(res)
                        self.num_results_bykeyword += len(res)

                        if has_log_msg:
                            self.log_manager.remove_last_states(n=2)
                            self.log_counter -= 2
                        self.log_manager.log_state(f"🟠 [NewsData] Archive Q{q_idx}/{len(queries)} · Win {wi}/{len(windows)} → {len(res)}")
                        has_log_msg = True
                        self.log_counter += 1

                        page = data.get("nextPage")
                        pages += 1
                        if not page or (self.newsdata_max_pages_per_window and pages >= self.newsdata_max_pages_per_window):
                            break
                        time.sleep(self.base_sleep + random.uniform(0, 0.2))

                    if not use_archive:
                        break
                if total > 0 or not use_archive:
                    break

                
            print(f"\n[Gnews] Noticias encontradas: {total}")

        # --- Latest (48h) solo si lo permites explícitamente ---
        if not use_archive:
            if not self.newsdata_allow_latest_fallback:
                self.log_manager.log_state("🔴 [NewsData] Archive no disponible. Fallback a Latest (48 h) desactivado por configuración.")
                print("🔴 [NewsData] Archive no disponible. Fallback a Latest (48 h) desactivado por configuración.")
                self.log_counter += 1
                return

            for q_idx, q in enumerate(queries, start=1):
                page, pages = None, 0
                while True:
                    params = mk_params(q)
                    if page:
                        params["page"] = page

                    data = self._request_json(base_latest, params, source_host=host)
                    status = (data.get("status") or "").lower()
                    if status and status not in ("success",):
                        self.log_manager.log_state(f"🟡 [NewsData] Latest status={status}. {str(data)[:140]}")
                        print(f"🟡 [NewsData] Latest status={status}. {str(data)[:140]}")
                        self.log_counter += 1
                        break

                    res = data.get("results") or []
                    added = ingest_results(res)
                    total += len(res)
                    self.num_results_bykeyword += len(res)

                    self.log_manager.log_state(f"🟠 [NewsData] Latest Q{q_idx}/{len(queries)} · +{added} artículos")
                    self.log_counter += 1

                    page = data.get("nextPage")
                    pages += 1
                    if not page or pages >= 20 or added == 0:
                        break
                    time.sleep(self.base_sleep + random.uniform(0, 0.2))

                if total > 0:
                    break

                print(f"\n[Gnews] Query Q{q_idx}: {q}")
                print(f"\n[Gnews] Noticias encontradas: {total}")

    # --------------------- Enriquecimiento Descripciones ---------------------

    def _domain(self, url):
        try:
            netloc = urlparse(url).netloc.lower()
            return netloc[4:] if netloc.startswith("www.") else netloc
        except Exception:
            return ""

    def _enrich_missing_summaries(self, max_items=80, per_domain_budget=5, prefer_sources=("GDELT", "SerpAPI.GoogleNews", "NewsData")):
        self.log_manager.log_state(f"🟠 Enriqueciendo resúmenes vacíos (máx {max_items}; {per_domain_budget}/dominio)…")

        # Crea extractor con la sesión del motor (si la clase la soporta)
        try:
            extractor = DescriptionExtractor(self.session)
        except TypeError:
            extractor = DescriptionExtractor()
            if hasattr(extractor, "session"):
                extractor.session = self.session

        done = 0
        budget = {}

        # Prioriza ítems sin summary de fuentes que suelen venir vacías
        def _priority(item):
            srcs = item.get("Source") or []
            src = srcs[0] if srcs else ""
            score = 0
            for i, pref in enumerate(prefer_sources):
                if pref in src:
                    score = len(prefer_sources) - i
                    break
            # más recientes primero
            y = item.get("Year") or 0
            return (-score, -(y or 0))

        items = [it for it in self.raw_items.values() if not (it.get("Summary") or "").strip()]
        items.sort(key=_priority)

        for it in items:
            if done >= max_items:
                break
            url = (it.get("URL") or "").strip()
            if not url:
                continue

            dom = self._domain(url)
            if budget.get(dom, 0) >= per_domain_budget:
                continue

            info = extractor.extract(url)
            desc = info.get("desc") or ""
            if desc:
                it["Summary"] = desc
                it["NeedsEnrichment"] = False
                if info.get("lang") and not it.get("Language"):
                    it["Language"] = info["lang"]

                # Si hay canonical, normaliza y fusiona índices
                canon = info.get("canonical") or ""
                if canon:
                    canon_norm = Methods.normalize_url(canon)
                    if canon_norm and canon_norm != Methods.normalize_url(url):
                        self._maybe_reindex_to_canonical(it.get("ID"), canon)

                done += 1
                budget[dom] = budget.get(dom, 0) + 1

        self._log(f"🟢 Enriquecidos: {done}")

    def enrich_all_pending(self, max_total=200, per_domain_budget=6, min_gap=1.1,
                           backoff_on_block=True, overflow=True, time_budget_s=180):
        """
        Enriquecer descripciones faltantes antes de filtrar/IA.
        - max_total: tope de URLs a enriquecer en esta pasada
        - per_domain_budget: máximo por dominio en esta pasada
        - min_gap: pausa mínima entre hits al mismo dominio (seg)
        - backoff_on_block: si vemos 403/429, multiplicamos pausa
        - overflow: si sobran cupos, se reciclan a dominios con cola
        - time_budget_s: presupuesto de tiempo para esta pasada
        """
        from collections import defaultdict

        # 1) candidatos: sin resumen, con URL, dentro de 2020–2025
        cand = []
        for mid, it in self.raw_items.items():
            if it.get("NeedsEnrichment") and (it.get("URL") or "").strip():
                y = it.get("Year")
                if y and 2020 <= int(y) <= 2025:
                    url = it["URL"].strip()
                    dom = Methods._domain_of(Methods.normalize_url(url), (it.get("Source") or [""])[0])
                    cand.append((mid, url, dom))
        # ordena por fecha desc (si la tienes) para priorizar lo reciente
        cand.sort(key=lambda t: (self.raw_items[t[0]].get("Date") or ""), reverse=True)

        quotas = defaultdict(lambda: per_domain_budget)
        next_ok = defaultdict(float)  # siguiente instante permitido por dominio
        processed = 0
        started = time.time()

        # helper: extractor compartido
        extractor = getattr(self, "_desc_extractor", None)
        if extractor is None:
            try:
                self._desc_extractor = DescriptionExtractor(self.session)
            except TypeError:
                self._desc_extractor = DescriptionExtractor()
                if hasattr(self._desc_extractor, "session"):
                    self._desc_extractor.session = self.session
            extractor = self._desc_extractor

        if self.trace_enrich:
            pending_est = sum(1 for it in self.raw_items.values() if it.get("NeedsEnrichment") and (it.get("URL") or "").strip())
            self._log(f"🔎 Enrichment batch: candidatos={pending_est} max_total={max_total} per_domain={per_domain_budget}")

        # 2) primera pasada: respetando presupuesto por dominio
        leftovers = []
        for mid, url, dom in cand:
            if processed >= max_total or (time.time() - started) > time_budget_s:
                leftovers.append((mid, url, dom))
                continue
            if quotas[dom] <= 0:
                leftovers.append((mid, url, dom))
                continue

            if self.trace_enrich:
                self._log(f"  · {dom} quota={quotas[dom]} wait={max(0.0, next_ok[dom]-time.time()):.2f}s URL={url[:90]}")

            # pacing por dominio
            wait = max(0.0, next_ok[dom] - time.time())
            if wait > 0:
                time.sleep(wait + random.uniform(0, 0.2))

            res = extractor.extract(url)
            desc, lang, canonical = res.get("desc", ""), res.get("lang"), res.get("canonical")

            # backoff si parece bloqueado (heurística mínima)
            blocked = (desc == "") and (lang is None)
            if blocked and backoff_on_block:
                next_ok[dom] = time.time() + (min_gap * 6)
                continue

            if canonical and canonical != url:
                if self.trace_enrich:
                    self._log(f"    ↪ canónica detectada: {canonical}")
                self._maybe_reindex_to_canonical(mid, canonical)

            if desc:
                it = self.raw_items[mid]
                it["Summary"] = desc
                it["Language"] = lang or it.get("Language")
                it["NeedsEnrichment"] = False
                processed += 1
                quotas[dom] -= 1

            next_ok[dom] = time.time() + min_gap + random.uniform(0, 0.4)

        # 3) overflow: reparte cupos sobrantes (opcional)
        if overflow and processed < max_total:
            remaining = max_total - processed
            for mid, url, dom in leftovers:
                if remaining <= 0 or (time.time() - started) > time_budget_s:
                    break

                wait = max(0.0, next_ok[dom] - time.time())
                if wait > 0:
                    time.sleep(wait + random.uniform(0, 0.2))

                res = extractor.extract(url)
                desc, lang, canonical = res.get("desc", ""), res.get("lang"), res.get("canonical")
                if not desc:
                    next_ok[dom] = time.time() + (min_gap * (6 if backoff_on_block else 1))
                    continue

                if canonical and canonical != url:
                    self._maybe_reindex_to_canonical(mid, canonical)

                it = self.raw_items[mid]
                it["Summary"] = desc
                it["Language"] = lang or it.get("Language")
                it["NeedsEnrichment"] = False
                remaining -= 1
                processed += 1
                next_ok[dom] = time.time() + min_gap + random.uniform(0, 0.4)

        self._log(f"🟢 Enrichment: +{processed} items enriquecidos.")
        return processed

    def enrich_until_done(self, batch_size=200, per_domain_budget=6,
                          min_gap=1.1, time_budget_s=1800, sleep_between_batches=(1.5, 3.0),
                          backoff_on_block=True, overflow=True):
        """
        Enriquecimiento exhaustivo: itera por tandas hasta que no queden items
        con NeedsEnrichment=True o hasta agotar el time_budget_s total.
        """
        import time as _t

        started = _t.time()
        total = 0

        # Asegura extractor con sesión compartida
        if not hasattr(self, "_desc_extractor"):
            try:
                self._desc_extractor = DescriptionExtractor(self.session)
            except TypeError:
                self._desc_extractor = DescriptionExtractor()
                if hasattr(self._desc_extractor, "session"):
                    self._desc_extractor.session = self.session

        while True:
            pending = sum(
                1 for it in self.raw_items.values()
                if it.get("NeedsEnrichment") and (it.get("URL") or "").strip()
                   and (it.get("Year") or 0) and 2020 <= int(it["Year"]) <= 2025
            )
            if pending == 0:
                self._log("🟢 Enrichment: backlog vacío.")
                break

            if (_t.time() - started) > time_budget_s:
                self._log("⏱️ Enrichment: agotado time_budget_s.")
                break

            processed = self.enrich_all_pending(
                max_total=batch_size,
                per_domain_budget=per_domain_budget,
                min_gap=min_gap,
                backoff_on_block=backoff_on_block,
                overflow=overflow,
                time_budget_s=min(time_budget_s - (_t.time() - started), time_budget_s)
            )
            total += (processed or 0)

            if not processed:
                self._log("🟡 Enrichment: sin progreso en esta tanda; deteniendo.")
                break

            _t.sleep(random.uniform(*sleep_between_batches))

        return total

    def _maybe_reindex_to_canonical(self, master_id, canonical_url):
        """Si la canónica difiere, mueve índices para que el ID por URL apunte a la canónica."""
        canon_norm = Methods.normalize_url(canonical_url)
        if not canon_norm:
            return
        item = self.raw_items.get(master_id)
        if not item:
            return
        old_url = item.get("URL")
        if old_url and Methods.normalize_url(old_url) == canon_norm:
            return
        # actualiza URL y re-indexa tablas auxiliares si las usas
        item["URL"] = canonical_url
        item["ID"] = item.get("ID") or canon_norm
        if hasattr(self, "idx_by_url"):
            self.idx_by_url[canon_norm] = master_id

    # --------------------- State ---------------------

    def create_new_model(self, api_source, title, abstract, raw_date, url, name_source):
        """
        🔧 ID preferido: título normalizado; si no hay, URL normalizada.
        """
        norm_title = Methods.normalize_title(title or "")
        norm_url = Methods.normalize_url(url=url)
        item_id = norm_title or norm_url  # preferimos título; si no hay, URL

        source = f"{name_source} ({api_source})"
        year, date_format = None, ""
        if raw_date:
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d",
                "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%a, %d %b %Y %H:%M:%S %Z",
                "%a, %d %b %Y %H:%M:%S %z",
            ):
                try:
                    dt = datetime.strptime(raw_date, fmt)
                    date_format = dt.strftime("%d-%m-%Y")
                    year = dt.year
                    break
                except Exception:
                    continue
        return {
            "ID": item_id or "",
            "Source": [source],
            "Title": title or "",
            "Summary": abstract or "",
            "Year": year,
            "Date": date_format,
            "URL": url,
            "Language": None,
            "NeedsEnrichment": not bool(abstract),
            "SearchTimestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _ymd_from_ddmmyyyy(self, s: str):
        if not s:
            return None
        try:
            return datetime.strptime(s, "%d-%m-%Y").date()
        except Exception:
            return None

    def _dates_close(self, d1, d2, days=3):
        # Si falta alguna fecha, no bloqueamos el match (ya lo filtra la similitud)
        if not d1 or not d2:
            return True
        delta = abs((d1 - d2).days)
        return delta <= days

    def add_or_update_result(self, new_data):
        """
        Clave primaria por TÍTULO normalizado + auxiliares por URL, firma de URL (host+path),
        y (título+fecha+dominio) con LSH (SimHash), prefijo de tokens y firma bag-of-words.
        Incluye fallback opcional por similitud de resúmenes.
        """
        # Índice BOW perezoso por si no está declarado en __init__
        if not hasattr(self, "idx_by_bow_sig"):
            from collections import defaultdict
            self.idx_by_bow_sig = defaultdict(list)

        title = (new_data.get("Title") or "").strip()
        url   = (new_data.get("URL") or "").strip()
        date  = (new_data.get("Date") or "").strip()   # esperado "DD-MM-YYYY"
        src   = (new_data.get("Source") or [""])[0]
        summ  = (new_data.get("Summary") or "").strip()

        norm_title = Methods.normalize_title(title)
        norm_url   = Methods.normalize_url(url)
        url_sig    = self._url_signature(url) if url else ""

        # YYYY-MM-DD para la clave (si no lo tienes, deja "")
        ymd = ""
        try:
            if date:
                ymd = datetime.strptime(date, "%d-%m-%Y").strftime("%Y-%m-%d")
        except Exception:
            pass

        domain = Methods._domain_of(norm_url, src)
        t_key  = Methods._title_key(norm_title, ymd, domain) if norm_title else ""

        # --- hashes / firmas del título
        title_sha = hashlib.sha1(norm_title.encode("utf-8")).hexdigest() if norm_title else ""
        title_sim = Methods.simhash_title64(title) if title else 0
        band_keys = Methods.simhash_bands(title_sim, bands=self.simhash_bands) if title_sim else []
        prefix_key = self._prefix_key(title, k=self.title_prefix_k) if title else ""
        bow_sig = Methods.bow_signature(title) if title else ""

        # ---- 1) ¿Existe por URL exacta?
        master_id = None
        if norm_url and norm_url in self.idx_by_url:
            master_id = self.idx_by_url[norm_url]

        # ---- 1b) ¿Existe por firma de URL (host+path)?
        if not master_id and url_sig and url_sig in self.idx_by_url_sig:
            master_id = self.idx_by_url_sig[url_sig]

        # ---- 2) ¿Idéntico por hash fuerte del título normalizado (cross-domain)?
        if not master_id and title_sha and title_sha in self.idx_by_title_sha:
            master_id = self.idx_by_title_sha[title_sha]

        # ---- 3) Candidatos: LSH (bandas), prefijo y bag-of-words (orden-insensible)
        if not master_id and title_sim:
            cand_ids = set()

            # LSH por bandas de SimHash (tolerante a pequeños cambios)
            for bk in band_keys:
                cand_ids.update(self.idx_by_simhash_band.get(bk, []))

            # Prefijo de K tokens "fuertes" (detecta truncados)
            if prefix_key and prefix_key in self.idx_by_title_prefix:
                cand_ids.update(self.idx_by_title_prefix[prefix_key])

            # NUEVO: firma bag-of-words (independiente del orden)
            if bow_sig and bow_sig in self.idx_by_bow_sig:
                cand_ids.update(self.idx_by_bow_sig[bow_sig])

            # Filtra candidatos por fecha ±N días y evalúa similitud
            new_d = self._ymd_from_ddmmyyyy(date)
            best, best_hd, best_score = None, 999, -1.0

            for mid in cand_ids:
                ex = self.raw_items.get(mid)
                if not ex:
                    continue
                ex_d = self._ymd_from_ddmmyyyy(ex.get("Date") or "")
                if not self._dates_close(new_d, ex_d, days=self.cross_days):
                    continue

                ex_title = ex.get("Title") or ""
                ex_sim = ex.get("_simhash64") or Methods.simhash_title64(ex_title)
                hd = Methods.hamming_dist64(title_sim, ex_sim)

                # Métricas de similitud robustas
                # - tokens fuertes (con normalización ligera, compuestos, stopwords extendidos)
                ng_j = Methods.jaccard(set(Methods.tokens_strong(title)), set(Methods.tokens_strong(ex_title)))
                # - trigramas de caracteres (captura 'cyberattack' vs 'cyber attack' y typos)
                sh_j = Methods.jaccard(Methods.char_shingles(title), Methods.char_shingles(ex_title))
                # truncado por prefijo
                trunc_ok = Methods.prefix_title_equiv(title, ex_title)

                # Prefijo exacto (mismo prefijo K)
                ex_prefix = self._prefix_key(ex_title, k=self.title_prefix_k) if ex_title else ""
                prefix_match = (prefix_key and ex_prefix and ex_prefix == prefix_key)

                # Regla de aceptación (más flexible pero segura)
                accept = False
                if hd <= self.simhash_hamming_threshold and (trunc_ok or ng_j >= 0.72 or sh_j >= 0.86):
                    accept = True
                elif ng_j >= 0.78 and sh_j >= 0.84:
                    accept = True
                elif prefix_match and (trunc_ok or ng_j >= 0.70):
                    accept = True

                if accept:
                    # Score combinado: cercanía de simhash + token jaccard + shingles + bonus por prefijo
                    score = (1.0 - hd/64.0) + (0.7*ng_j) + (0.6*sh_j) + (0.05 if prefix_match else 0.0)
                    if (hd < best_hd) or (hd == best_hd and score > best_score):
                        best, best_hd, best_score = mid, hd, score

            if best:
                master_id = best

        # ---- 3bis) Fallback por resumen (si títulos no casan)
        if not master_id and self.enable_summary_fallback and summ:
            # candidatos: todos con resumen presente y misma ventana temporal
            cand_ids = list(self.raw_items.keys())
            new_d = self._ymd_from_ddmmyyyy(date)

            # simhash del resumen nuevo
            try:
                sum_sim = Methods.simhash64(Methods.char_ngrams(summ, n=3))
            except Exception:
                sum_sim = 0

            best_s, best_hd_s, best_sj = None, 999, -1.0
            new_tok = self._summary_tokens(summ)

            for mid in cand_ids:
                ex = self.raw_items.get(mid)
                if not ex:
                    continue
                if not self._dates_close(new_d, self._ymd_from_ddmmyyyy(ex.get("Date") or ""), days=self.cross_days):
                    continue
                ex_sum = (ex.get("Summary") or "").strip()
                if not ex_sum:
                    continue

                try:
                    ex_sum_sim = ex.get("_sum_simhash64") or Methods.simhash64(Methods.char_ngrams(ex_sum, n=3))
                except Exception:
                    ex_sum_sim = 0

                if not sum_sim or not ex_sum_sim:
                    continue

                hd_s = Methods.hamming_dist64(sum_sim, ex_sum_sim)
                sj = Methods.jaccard(new_tok, self._summary_tokens(ex_sum))

                if hd_s <= self.summary_hamming_threshold and sj >= self.summary_jaccard_min:
                    # preferimos menor hamming y mayor jaccard
                    if (hd_s < best_hd_s) or (hd_s == best_hd_s and sj > best_sj):
                        best_s, best_hd_s, best_sj = mid, hd_s, sj

            if best_s:
                master_id = best_s

        # ---- 4) Fallback: título+fecha+dominio
        if not master_id and t_key and t_key in self.idx_by_title:
            master_id = self.idx_by_title[t_key]

        # ---- Alta nueva si no existía
        if not master_id:
            master_id = norm_url if norm_url else f"t:{Methods._hash12(t_key or norm_title or url)}"
            self.raw_items[master_id] = new_data
            self.raw_items[master_id]["ID"] = master_id
            # índices
            if norm_url:
                self.idx_by_url[norm_url] = master_id
            if url_sig:
                self.idx_by_url_sig[url_sig] = master_id
            if t_key:
                self.idx_by_title[t_key] = master_id
            if title_sha:
                self.idx_by_title_sha[title_sha] = master_id
            if title_sim:
                self.raw_items[master_id]["_simhash64"] = title_sim
                for bk in band_keys:
                    self.idx_by_simhash_band[bk].append(master_id)
            if prefix_key:
                self.idx_by_title_prefix[prefix_key].append(master_id)
            if bow_sig:
                self.idx_by_bow_sig[bow_sig].append(master_id)
            # cache simhash de resumen si hay
            if summ:
                try:
                    self.raw_items[master_id]["_sum_simhash64"] = Methods.simhash64(Methods.char_ngrams(summ, n=3))
                except Exception:
                    pass
            return

        # ---- Merge si ya existía
        existing = self.raw_items.get(master_id)
        if not existing:
            self.raw_items[master_id] = new_data
            self.raw_items[master_id]["ID"] = master_id
            if norm_url:
                self.idx_by_url[norm_url] = master_id
            if t_key:
                self.idx_by_title[t_key] = master_id
            if bow_sig:
                self.idx_by_bow_sig[bow_sig].append(master_id)
            return

        for k, v in new_data.items():
            if not v:
                continue
            if k == "Source":
                for s in v:
                    if s not in existing["Source"]:
                        existing["Source"].append(s)
            elif k == "Summary":
                prev = (existing.get("Summary") or "").strip().lower()
                new  = v.strip().lower()
                if not prev or prev in ("no abstract",) or "not available" in prev or "no disponible" in prev:
                    if new and not new.startswith("no abstract") and "not available" not in new and "no disponible" not in new:
                        existing["Summary"] = v
                        # cache simhash de resumen
                        try:
                            existing["_sum_simhash64"] = Methods.simhash64(Methods.char_ngrams(v, n=3))
                        except Exception:
                            pass
            else:
                if not existing.get(k):
                    existing[k] = v

        # asegura índices secundarios
        if norm_url and norm_url not in self.idx_by_url:
            self.idx_by_url[norm_url] = master_id
        if url_sig and url_sig not in self.idx_by_url_sig:
            self.idx_by_url_sig[url_sig] = master_id
        if t_key and t_key not in self.idx_by_title:
            self.idx_by_title[t_key] = master_id
        if title_sha and title_sha not in self.idx_by_title_sha:
            self.idx_by_title_sha[title_sha] = master_id
        if title_sim:
            self.raw_items[master_id]["_simhash64"] = self.raw_items[master_id].get("_simhash64") or title_sim
            for bk in band_keys:
                if master_id not in self.idx_by_simhash_band[bk]:
                    self.idx_by_simhash_band[bk].append(master_id)
        if prefix_key and master_id not in self.idx_by_title_prefix[prefix_key]:
            self.idx_by_title_prefix[prefix_key].append(master_id)
        if bow_sig and master_id not in self.idx_by_bow_sig[bow_sig]:
            self.idx_by_bow_sig[bow_sig].append(master_id)
        if summ and "_sum_simhash64" not in existing:
            try:
                existing["_sum_simhash64"] = Methods.simhash64(Methods.char_ngrams(summ, n=3))
            except Exception:
                pass

        self.duplicate_count += 1


    def get_state_snapshot(self) -> dict:
        return {
            "ia_analyzed_ids": list(self.ia_analyzed_ids),
            "final_results": self.final_results,
            "raw_items": self.raw_items,
            "gnews_ids": list(self.gnews_ids),
            "newsapi_ids": list(self.newsapi_ids),
            "serpapi_ids": list(self.serpapi_ids),
            "gdelt_ids": list(self.gdelt_ids),
            "newsdata_ids": list(self.newsdata_ids),
            "duplicate_count": self.duplicate_count,
            "idx_by_url": self.idx_by_url,
            "idx_by_title": self.idx_by_title,
        }

    def load_state_snapshot(self, snap: dict) -> None:
        self.ia_analyzed_ids = set(snap.get("ia_analyzed_ids", []))
        self.final_results = snap.get("final_results", {}) or {}
        self.raw_items = snap.get("raw_items", {}) or {}
        self.gnews_ids = set(snap.get("gnews_ids", []))
        self.newsapi_ids = set(snap.get("newsapi_ids", []))
        self.serpapi_ids = set(snap.get("serpapi_ids", []))
        self.gdelt_ids = set(snap.get("gdelt_ids", []))
        self.newsdata_ids = set(snap.get("newsdata_ids", []))
        self.duplicate_count = snap.get("duplicate_count", 0)
        self.idx_by_url = snap.get("idx_by_url", {}) or {}
        self.idx_by_title = snap.get("idx_by_title", {}) or {}
