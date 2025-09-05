# utils/test_search_news.py
import sys
import os
import argparse
from datetime import datetime

# Sube dos niveles hasta la raíz del proyecto
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(PROJECT_ROOT)

from engines.SearchEngineNews import NewsSearchEngine

class SimpleLogger:
    def log_state(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")
    def remove_last_states(self, n: int = 0):
        pass

def run_provider(engine: NewsSearchEngine, provider_name: str, kw: str, limit_print: int = 5):
    print(f"\n=== TEST {provider_name} ===")
    before = len(engine.raw_items)
    try:
        getattr(engine, provider_name)(kw)
    except Exception as e:
        print(f"❌ Error en {provider_name}: {e}")
        return
    after = len(engine.raw_items)
    added = after - before
    print(f"✓ {provider_name}: {added} items nuevos (total={after})")
    i = 0
    for _, v in engine.raw_items.items():
        if i >= limit_print: break
        src = ", ".join(v.get("Source", []))
        print(f"- {v.get('Date','?')} | {v.get('Title','')[:90]}… [{src}]")
        i += 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kw", default="CAN bus", help="keyword a probar")
    ap.add_argument("--lang", default="es", choices=["es","en"])
    ap.add_argument("--quick", action="store_true", help="limitar ventanas/páginas para prueba rápida")
    ap.add_argument("--no-q4", action="store_true", help="desactivar Q4 (keyword sola)")
    ap.add_argument("--no-signals", action="store_true", help="no exigir señales en Q4/Latest")
    ap.add_argument("--auto-relax", action="store_true", help="si Q1–Q3=0 y Q4 desactivada, probar Q4 con señales")
    ap.add_argument("--max-pages", type=int, default=3, help="máx páginas por query para GNews/NewsAPI (def 3)")
    args = ap.parse_args()

    logger = SimpleLogger()
    engine = NewsSearchEngine(lang=args.lang, log_manager=logger, max_queries_per_provider=2, max_pages_per_query=args.max_pages)

    if args.quick:
        engine.newsdata_window_days = 30
        engine.newsdata_max_windows = 1
        engine.newsdata_max_pages_per_window = 3
    if args.no_q4:
        engine.allow_broad_q4 = False
    if args.no_signals:
        engine.serpapi_require_signal = False
    engine.auto_relax_if_zero = args.auto_relax

    providers = [
        "_search_gnews",
        "_search_newsapi",
        "_search_serpapi_news",
        "_build_query_for_gdelt",   # solo muestra la query
        "_search_gdelt",
        "_search_newsdata",
    ]

    for p in providers:
        if not hasattr(engine, p):
            print(f"(omitido) {p} no existe en el motor.")
            continue
        if p == "_build_query_for_gdelt":
            print("\n=== TEST _build_query_for_gdelt (solo query) ===")
            print(engine._build_query_for_gdelt(args.kw))
            continue
        run_provider(engine, p, args.kw)

    print("\nResumen:")
    print(f"- Total items: {len(engine.raw_items)}")
    print("- Recuerda exportar o pasar tus filtros después de esta prueba.")

if __name__ == "__main__":
    main()
