import streamlit as st
import pandas as pd
import os
import sys
import json
import hashlib
import re
from dotenv import load_dotenv, find_dotenv

from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

import torch
st.sidebar.markdown(
    f"💻 **Dispositivo IA:** `{'GPU' if torch.cuda.is_available() else 'CPU'}`"
)

# Sube dos niveles hasta la raíz del proyecto
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(PROJECT_ROOT)

# Carpeta results ABSOLUTA (forzamos aquí)
EXPORT_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(EXPORT_DIR, exist_ok=True)   

# Carga el .env desde la raíz
load_dotenv(find_dotenv(filename=os.path.join(PROJECT_ROOT, ".env")), override=False)

from src.app.components import mostrar_buscador
from src.logging.LogManager import LogManager
from src.utils.Errors import ProviderRateLimitError, ProviderBlockedError, NetworkError

from src.engines.SearchEnginePaper import PaperSearchEngine
from src.engines.SearchEngineVulnerability import VulnerabilitySearchEngine
from src.engines.SearchEngineNews import NewsSearchEngine
from src.state.StateManager import StateManager
from src.utils.ExcelResultsExporter import ExcelResultsExporter
from src.filters.FilterEngine import FilterEngine

# Configuración inicial de la página
st.set_page_config(page_title="Buscador Inteligente", layout="wide")
st.sidebar.title("🧠 Buscador Inteligente")
st.sidebar.write("Bienvenido a mi buscador !!!")

# Áreas UI
with st.expander("📝 Resumen de configuración", expanded=True):
    summary_config_area = st.empty()
with st.expander("🔍 Estado de la búsqueda", expanded=True):
    state_area = st.empty()
with st.expander("📄 Logs del clasificador IA", expanded=True):
    ia_classifier_area = st.empty()
with st.expander("📊 Resumen del filtrado", expanded=True):
    resume_filters_area = st.empty()
with st.expander("📚 Resultados obtenidos", expanded=True):
    results_area = st.container()

log_manager = LogManager(state_area, summary_config_area, ia_classifier_area, resume_filters_area, results_area)

DEFAULT_LABELS_IA = [
    # POSITIVAS (real-world)
    "Operational ransomware (production or services disrupted)",
    "Confirmed data breach/exfiltration (customer/employee/PII)",
    "Factory/plant shutdown (production halted)",
    "Supplier/Tier compromise affecting OEMs",
    "Telematics/connected services or portal breach",
    "Dealer/DMS breach (CDK Global, Reynolds & Reynolds, Solera)",
    "Vehicle/backend/ECU compromise (in the wild)",
    "Logistics/shipping disruption tied to cyberattack",
    "Insider/sabotage incident",
    "General automotive cyber incident (real-world)",

    # NEGATIVAS (descartar)
    "Advisory/Patch only (no exploitation)",
    "Research/PoC/demo (no real-world attack)",
    "Hypothetical/simulation/what-if",
    "General IT outage (non-automotive)",
    "IT-only incident (no operational impact reported)",
    "Keyless/relay theft only",
    "Unrelated/marketing/product news",
    "Roundup/digest/list of stories",
]

DEFAULT_BAD_LABELS_IA = [
    "Advisory/Patch only (no exploitation)",
    "Research/PoC/demo (no real-world attack)",
    "Hypothetical/simulation/what-if",
    "General IT outage (non-automotive)",
    "IT-only incident (no operational impact reported)",
    "Keyless/relay theft only",
    "Unrelated/marketing/product news",
    "Roundup/digest/list of stories",
]

# ---- Helpers ----
def _hash_payload(payload: dict) -> str:
    try:
        txt = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except Exception:
        txt = str(payload)
    return hashlib.md5(txt.encode("utf-8")).hexdigest()

def _ts_from_filename(name: str) -> str | None:
    """
    Extrae 'DD-MM-YYYY_HH-MM' de un nombre de estado.
    Acepta patrones: '..._DD-MM-YYYY_HH-MM(.json)?'
    """
    if not name:
        return None
    m = re.search(r"(\d{2}-\d{2}-\d{4})[_-](\d{2}-\d{2})(?:\.json)?$", name)
    return f"{m.group(1)}_{m.group(2)}" if m else None

def mostrar_filtros_ia():
    levels_ia = st.sidebar.slider("¿Cuántos niveles quieres?", 1, 3, 2)
    st.session_state["num_levels_ia"] = levels_ia

    for i in range(levels_ia):
        st.sidebar.subheader(f"Nivel {i + 1}")

        key_available = f"available_labels_level_{i}"
        key_input     = f"new_label_level_{i}"
        key_multi     = f"level_{i}_tags"
        key_bad       = f"level_{i}_bad_tags"
        key_th        = f"threshold_level_{i}"

        if key_available not in st.session_state or not st.session_state[key_available]:
            st.session_state[key_available] = list(DEFAULT_LABELS_IA)

        for lbl in DEFAULT_BAD_LABELS_IA:
            if lbl not in st.session_state[key_available]:
                st.session_state[key_available].append(lbl)

        new_label = st.sidebar.text_input(f"➕ Nueva etiqueta para nivel {i + 1}", key=key_input)
        if st.sidebar.button(f"Añadir etiqueta al nivel {i + 1}", key=f"btn_add_{i}"):
            if new_label.strip() and new_label not in st.session_state[key_available]:
                st.session_state[key_available].append(new_label.strip())

        if key_multi not in st.session_state or not st.session_state[key_multi]:
            st.session_state[key_multi] = list(DEFAULT_LABELS_IA)

        st.sidebar.multiselect(
            f"Selecciona etiquetas para el nivel {i + 1}",
            options=st.session_state[key_available],
            key=key_multi
        )

        if key_bad not in st.session_state or not st.session_state[key_bad]:
            st.session_state[key_bad] = [
                lbl for lbl in DEFAULT_BAD_LABELS_IA if lbl in st.session_state[key_available]
            ]

        st.sidebar.multiselect(
            "Elige etiqueta(s) **🚫 NO RELEVANTES**:",
            options=st.session_state[key_available],
            key=key_bad
        )

        if key_th not in st.session_state:
            st.session_state[key_th] = 0.40
        st.sidebar.slider(
            f"🎯 Umbral de confianza para el nivel {i + 1}",
            min_value=0.0, max_value=1.0, value=st.session_state[key_th], step=0.05, key=key_th
        )

def obtener_keywords(keyword, file_uploaded):
    if file_uploaded:
        try:
            content = file_uploaded.read().decode("utf-8", errors="ignore")
            return [line.strip() for line in content.splitlines() if line.strip()]
        except Exception:
            file_uploaded.seek(0)
            return [line.decode("utf-8", errors="ignore").strip() for line in file_uploaded if line.strip()]
    elif keyword:
        return [keyword.strip()]
    return []

def show_results(searcher, category):
    df = pd.DataFrame.from_dict(searcher.final_results, orient="index")
    log_manager.show_results(category, df)

def _search_by_category(keywords, category, searcher_class, filter_class, apply_filter_ia, values_levels_ia, run_ts: str):
    """
    Ejecuta la búsqueda por categoría, guardando progreso y parando ante excepciones de proveedor.
    **Importante**: antes de llamar a esta función se debe haber ligado un basename de estado
    con StateManager.bind_state_basename(category, basename).
    """
    searcher = searcher_class(log_manager=log_manager)
    searcher.apply_filter_ia = apply_filter_ia
    searcher.values_levels_ia = values_levels_ia
    searcher.filter_engine = filter_class

    # Estado inicial escrito en el fichero ligado (o con run_ts si no hubiera ligadura)
    StateManager.init_state(
        category=category,
        keywords=keywords,
        params={
            "apply_filter_ia": apply_filter_ia,
            "values_levels_ia": values_levels_ia,
        },
        timestamp_str=run_ts,
    )

    processed = 0
    for idx, kw in enumerate(keywords):
        try:
            # Guardamos progreso antes de empezar cada keyword
            StateManager.patch_state(
                category,
                current_keyword=kw,
                progress={
                    "total_keywords": len(keywords),
                    "processed_keywords": processed
                },
                remaining_keywords=keywords[idx:],  # incluye la actual
                results=searcher.final_results,
                analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                filter_stats=searcher.filter_engine.get_stats_dict(),
            )

            log_manager.log_state(f"🔍 Buscando '{kw}' en {category}...")
            searcher.search(kw)
            processed += 1

            # Guardamos tras completar la keyword
            StateManager.patch_state(
                category,
                progress={
                    "total_keywords": len(keywords),
                    "processed_keywords": processed
                },
                remaining_keywords=keywords[idx+1:],  # las que faltan
                results=searcher.final_results,
                analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                filter_stats=searcher.filter_engine.get_stats_dict(),
            )

        except (ProviderRateLimitError, ProviderBlockedError, NetworkError) as e:
            # Guardamos y paramos: el usuario puede retomar luego
            StateManager.mark_error(
                category=category,
                error_type=type(e).__name__,
                message=getattr(e, "message", str(e)),
                remaining_keywords=keywords[idx:],
                current_keyword=kw,
                progress={
                    "total_keywords": len(keywords),
                    "processed_keywords": processed
                },
                results=searcher.final_results,
                analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                filter_stats=searcher.filter_engine.get_stats_dict(),
            )
            st.error(f"⛔ Búsqueda interrumpida por {type(e).__name__}: {getattr(e, 'message', e)}")
            return None

    # Filtrado final sobre todo el conjunto acumulado
    if searcher and searcher.filter_engine:
        searcher.final_results = {}
        searcher.filter_engine.filter_and_classify_items(searcher, item_type=category)

    # Si completó sin errores
    StateManager.mark_completed(
        category,
        remaining_keywords=[],
        current_keyword=None,
        progress={"total_keywords": len(keywords), "processed_keywords": processed},
        results=searcher.final_results,
        analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
        engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
        filter_stats=searcher.filter_engine.get_stats_dict(),
    )

    df = pd.DataFrame.from_dict(searcher.final_results, orient="index")
    log_manager.show_results(category, df)
    return searcher

def _parse_saved_state_from_upload(uploaded_file):
    """Lee JSON de estado desde el file_uploader (no busca nada automáticamente)."""
    if not uploaded_file:
        return None, "Debes subir un archivo JSON de estado."
    try:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        data = json.loads(content)
    except Exception as e:
        return None, f"Formato inválido de archivo de estado: {e}"
    for key in ("category", "remaining_keywords", "engine_state"):
        if key not in data:
            return None, f"Falta la clave '{key}' en el archivo de estado."
    return data, None

# ---(((((( INTERFAZ PRINCIPAL ))))))---
main_action = st.sidebar.selectbox("¿Qué quieres hacer?", ["Nueva Búsqueda", "Retomar Búsqueda"])

if main_action == "Nueva Búsqueda":
    keyword = st.sidebar.text_input("✏️ Introduce la palabra clave:", disabled=st.session_state.get("archivo") is not None)
    file_uploaded = st.sidebar.file_uploader("📁 O sube un archivo .txt de keywords", type=["txt"], key="archivo", disabled=bool(keyword))
    category = st.sidebar.selectbox("Categoría", ["All", "News", "Papers", "Vulnerabilities"])
    if st.sidebar.checkbox("🧠 Filtro IA", key="ia_filter"):
        mostrar_filtros_ia()
else:
    # Retomar/Cargar: cargar un JSON de estado (lo decide la persona usuaria)
    state_file = st.sidebar.file_uploader("📁 Sube el archivo .json de estado guardado", type=["json"], key="resume_file")

# ---(((((( BOTÓN DE EJECUCIÓN ))))))---
if st.sidebar.button("🔍 Ejecutar búsqueda"):
    # Timestamp estable para esta ejecución (Europe/Madrid) con formato DD-MM-YYYY_HH-MM
    if ZoneInfo:
        ts_str = datetime.now(ZoneInfo("Europe/Madrid")).strftime("%d-%m-%Y_%H-%M")
    else:
        ts_str = datetime.now().strftime("%d-%m-%Y_%H-%M")
    st.session_state["current_run_ts"] = ts_str

    if main_action == "Nueva Búsqueda":
        keywords = obtener_keywords(keyword, file_uploaded)
        if not keywords:
            st.warning("Debes introducir al menos una palabra clave o subir un archivo.")
            st.stop()

        # Config IA
        values_by_level_ia = {}
        if st.session_state.get("ia_filter"):
            total_levels = st.session_state.get("num_levels_ia", 1)
            for i in range(total_levels):
                level_id = f"level_{i+1}"
                labels = st.session_state.get(f"level_{i}_tags", [])
                bad_labels = st.session_state.get(f"level_{i}_bad_tags", [])
                threshold = st.session_state.get(f"threshold_level_{i}", 0.4)
                if labels:
                    values_by_level_ia[level_id] = {"labels": labels, "bad_labels": bad_labels, "threshold": threshold}

        # Resumen UI
        resumen_md = f"🔍 **Acción:** Nueva búsqueda\n\n"
        if keyword:
            resumen_md += f"🔑 **Palabra clave:** {keyword}\n\n"
        elif file_uploaded:
            preview = keywords[:10] if len(keywords) > 10 else keywords
            resumen_md += f"📁 **Archivo cargado con {len(keywords)} keywords**\n\n"
            resumen_md += f"🧾 **Vista previa:** {preview}\n\n"
        resumen_md += f"📂 **Categoría:** {category}\n\n"
        if st.session_state.get("ia_filter"):
            resumen_md += "🧠 **Filtro IA activado**\n\n"
            for level_id, cfg in values_by_level_ia.items():
                resumen_md += f"- **{level_id.capitalize()}**\n"
                resumen_md += f"  - Etiquetas: {cfg['labels']}\n"
                resumen_md += f"  - Etiquetas a descartar: {cfg['bad_labels']}\n"
                resumen_md += f"  - Umbral de confianza: {cfg['threshold']}\n"
        else:
            resumen_md += "⚠️ Filtro IA desactivado\n"
        log_manager.show_config_summary(resumen_md)

        categories = {
            "news": NewsSearchEngine,
            "papers": PaperSearchEngine,
            "vulnerabilities": VulnerabilitySearchEngine
        }
        _category = category.lower()

        exporter = ExcelResultsExporter(show_domain_only=False)
        filter_engine = FilterEngine(log_manager=log_manager)

        if _category == "all":
            results_by_category = {}
            for cat_name, engine_class in categories.items():
                # Ligar basename (sin extensión) para cada categoría
                basename = f"state_{cat_name}_{st.session_state['current_run_ts']}"
                StateManager.unbind(cat_name)
                StateManager.bind_state_basename(category=cat_name, basename_without_ext=basename)

                searcher = _search_by_category(
                    keywords=keywords,
                    category=cat_name,
                    searcher_class=engine_class,
                    filter_class=filter_engine,
                    apply_filter_ia=st.session_state.get("ia_filter", False),
                    values_levels_ia=values_by_level_ia,
                    run_ts=st.session_state["current_run_ts"],
                )
                if searcher is None:
                    st.stop()
                results_by_category[cat_name] = searcher.final_results

            log_manager.render_all_tables()

            # Guardado (Excel multi-hoja + JSON combinado) evitando duplicados por hash
            payload_hash = _hash_payload(results_by_category)
            if payload_hash != st.session_state.get("saved_hash_all"):
                try:
                    xlsx_path = exporter.save_multi_to_disk(
                        results_by_category,
                        dir_path=EXPORT_DIR,  # <<<
                        timestamp_str=st.session_state["current_run_ts"]
                    )
                    json_path = exporter.save_multi_json_enriched_to_disk(
                        results_by_category,
                        dir_path=EXPORT_DIR,  # <<<
                        timestamp_str=st.session_state["current_run_ts"],
                        ndjson=True
                    )
                except Exception as e:
                    st.error(f"❌ Error guardando resultados combinados: {e}")
                    st.stop()

                st.session_state["saved_hash_all"] = payload_hash
                st.session_state["saved_path_all_xlsx"] = xlsx_path
                st.session_state["saved_path_all_json"] = json_path

            if st.session_state.get("saved_path_all_xlsx"):
                st.success(f"✅ Excel combinado guardado en: `{st.session_state['saved_path_all_xlsx']}`")
            else:
                st.warning("No hubo resultados para guardar (Excel).")
            if st.session_state.get("saved_path_all_json"):
                st.info(f"🗂️ JSON combinado guardado en: `{st.session_state['saved_path_all_json']}`")

        else:
            engine_class = categories.get(_category)
            if not engine_class:
                st.warning("❌ Categoría no reconocida.")
                st.stop()

            # Ligar basename (sin extensión) para la categoría seleccionada
            basename = f"state_{_category}_{st.session_state['current_run_ts']}"
            StateManager.unbind(_category)
            StateManager.bind_state_basename(category=_category, basename_without_ext=basename)

            searcher = _search_by_category(
                keywords=keywords,
                category=_category,
                searcher_class=engine_class,
                filter_class=filter_engine,
                apply_filter_ia=st.session_state.get("ia_filter", False),
                values_levels_ia=values_by_level_ia,
                run_ts=st.session_state["current_run_ts"],
            )
            log_manager.render_all_tables()
            if searcher is None:
                st.stop()

            payload_hash = _hash_payload(searcher.final_results)
            key_hash = f"saved_hash_{_category}"
            if payload_hash != st.session_state.get(key_hash):
                try:
                    xlsx_path = exporter.save_single_to_disk(
                        searcher.final_results,
                        category=_category,
                        dir_path=EXPORT_DIR,  # <<<
                        timestamp_str=st.session_state["current_run_ts"]
                    )
                    json_path = exporter.save_json_enriched_to_disk(
                        searcher.final_results,
                        category=_category,
                        dir_path=EXPORT_DIR,  # <<<
                        timestamp_str=st.session_state["current_run_ts"],
                        ndjson=True
                    )
                except Exception as e:
                    st.error(f"❌ Error guardando resultados ({_category}): {e}")
                    st.stop()

                st.session_state[key_hash] = payload_hash
                st.session_state[f"saved_path_{_category}_xlsx"] = xlsx_path
                st.session_state[f"saved_path_{_category}_json"] = json_path

            if st.session_state.get(f"saved_path_{_category}_xlsx"):
                st.success(f"✅ Excel guardado en: `{st.session_state[f'saved_path_{_category}_xlsx']}`")
            else:
                st.warning("No hubo resultados para guardar (Excel).")
            if st.session_state.get(f"saved_path_{_category}_json"):
                st.info(f"🗂️ JSON guardado en: `{st.session_state[f'saved_path_{_category}_json']}`")

    elif main_action == "Retomar Búsqueda":
        # 1) Validar archivo subido
        if not state_file:
            st.warning("Debes subir un archivo .json de estado para retomar.")
            st.stop()

        saved_state, err = _parse_saved_state_from_upload(state_file)
        if err:
            st.error(err)
            st.stop()

        # 2) Extraer datos clave del estado
        state_category = (saved_state.get("category") or "").lower()
        remaining_keywords = saved_state.get("remaining_keywords", []) or []
        params = saved_state.get("params", {}) or {}
        engine_snap = saved_state.get("engine_state")
        prev_results = saved_state.get("results", {}) or {}
        prev_analysed = saved_state.get("analiced_ids", []) or []

        if not state_category:
            st.error("El archivo no indica 'category'.")
            st.stop()

        categories = {
            "news": NewsSearchEngine,
            "papers": PaperSearchEngine,
            "vulnerabilities": VulnerabilitySearchEngine
        }
        engine_cls = categories.get(state_category)
        if not engine_cls:
            st.error(f"Categoría no reconocida en el estado: {state_category}")
            st.stop()

        # 3) Ligar basename EXACTO (sin extensión) del archivo subido
        uploaded_name = state_file.name or "estado.json"
        basename_no_ext = os.path.splitext(uploaded_name)[0]
        StateManager.unbind(state_category)
        StateManager.bind_state_basename(
            category=state_category,
            basename_without_ext=basename_no_ext,
            seed_dict=saved_state  # sembrar el fichero local con el contenido subido
        )

        # Fijar run_ts desde el nombre, si lo contiene
        ts_from_name = _ts_from_filename(uploaded_name)
        if ts_from_name:
            st.session_state["current_run_ts"] = ts_from_name

        # 4) Reconstruir el buscador con el snapshot
        searcher = engine_cls(log_manager=log_manager)
        if engine_snap and hasattr(searcher, "load_state_snapshot"):
            try:
                searcher.load_state_snapshot(engine_snap)
            except Exception:
                searcher.final_results = prev_results
                try:
                    searcher.ia_analyzed_ids = set(prev_analysed)
                except Exception:
                    pass
        else:
            searcher.final_results = prev_results
            try:
                searcher.ia_analyzed_ids = set(prev_analysed)
            except Exception:
                pass

        searcher.apply_filter_ia = params.get("apply_filter_ia", False)
        searcher.values_levels_ia = params.get("values_levels_ia", {}) or {}

        filter_engine = FilterEngine(log_manager=log_manager)
        saved_filter_stats = saved_state.get("filter_stats") or (saved_state.get("extras", {}) or {}).get("filter_stats")
        filter_engine.load_stats_from_dict(saved_filter_stats)
        searcher.filter_engine = filter_engine

        # 5) Resumen
        resumen_md = (
            f"🔁 **Retomar búsqueda**\n\n"
            f"📂 **Categoría:** {state_category}\n\n"
            f"⏳ **Pendientes:** {len(remaining_keywords)} keywords\n\n"
            f"🧠 Filtro IA: {'ON' if searcher.apply_filter_ia else 'OFF'}"
        )
        log_manager.show_config_summary(resumen_md)

        if not remaining_keywords:
            st.info("No hay keywords pendientes en el archivo de estado. Nada que retomar.")
            df = pd.DataFrame.from_dict(searcher.final_results, orient="index")
            log_manager.show_results(state_category, df)
            st.stop()

        # 6) Escribir estado actual (ya ligado por basename) y continuar
        StateManager.save_state(
            category=state_category,
            remaining_keywords=remaining_keywords,
            results=searcher.final_results,
            engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
            analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
            params=params,
            filter_stats=searcher.filter_engine.get_stats_dict(),
            status="RUNNING",
            timestamp_str=st.session_state.get("current_run_ts"),
        )

        # 7) Bucle de retomado
        def _resume_loop():
            processed = saved_state.get("progress", {}).get("processed_keywords", 0)
            total = saved_state.get("progress", {}).get("total_keywords", processed + len(remaining_keywords))

            for idx, kw in enumerate(remaining_keywords):
                try:
                    StateManager.patch_state(
                        state_category,
                        timestamp_str=st.session_state.get("current_run_ts"),
                        current_keyword=kw,
                        progress={"total_keywords": total, "processed_keywords": processed},
                        remaining_keywords=remaining_keywords[idx:],
                        results=searcher.final_results,
                        filter_stats=searcher.filter_engine.get_stats_dict(),
                        analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                        engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                    )

                    log_manager.log_state(f"🔍 Retomando '{kw}' en {state_category}...")
                    searcher.search(kw)
                    processed += 1

                    StateManager.patch_state(
                        state_category,
                        timestamp_str=st.session_state.get("current_run_ts"),
                        progress={"total_keywords": total, "processed_keywords": processed},
                        remaining_keywords=remaining_keywords[idx+1:],
                        results=searcher.final_results,
                        filter_stats=searcher.filter_engine.get_stats_dict(),
                        analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                        engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                    )

                except (ProviderRateLimitError, ProviderBlockedError, NetworkError) as e:
                    StateManager.mark_error(
                        category=state_category,
                        timestamp_str=st.session_state.get("current_run_ts"),
                        error_type=type(e).__name__,
                        message=getattr(e, "message", str(e)),
                        remaining_keywords=remaining_keywords[idx:],
                        current_keyword=kw,
                        filter_stats=searcher.filter_engine.get_stats_dict(),
                        progress={"total_keywords": total, "processed_keywords": processed},
                        results=searcher.final_results,
                        analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
                        engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
                    )
                    st.error(f"⛔ Búsqueda interrumpida por {type(e).__name__}: {getattr(e, 'message', e)}")
                    return None
            return True

        ok = _resume_loop()
        if ok is not None:
            searcher.final_results = {}
            searcher.filter_engine.filter_and_classify_items(searcher, item_type=state_category)

        log_manager.render_all_tables()
        if ok is None:
            st.stop()

        # 8) Finalizar + export
        StateManager.mark_completed(
            state_category,
            timestamp_str=st.session_state.get("current_run_ts"),
            remaining_keywords=[],
            current_keyword=None,
            results=searcher.final_results,
            filter_stats=searcher.filter_engine.get_stats_dict(),
            analiced_ids=list(getattr(searcher, "ia_analyzed_ids", [])),
            engine_state=searcher.get_state_snapshot() if hasattr(searcher, "get_state_snapshot") else None,
        )

        exporter = ExcelResultsExporter(show_domain_only=False)
        payload_hash = _hash_payload(searcher.final_results)
        key_hash = f"saved_hash_{state_category}"
        if payload_hash != st.session_state.get(key_hash):
            try:
                xlsx_path = exporter.save_single_to_disk(
                    searcher.final_results,
                    category=state_category,
                    dir_path=EXPORT_DIR,  # <<<
                    timestamp_str=st.session_state.get("current_run_ts")
                )
                json_path = exporter.save_json_enriched_to_disk(
                    searcher.final_results,
                    category=state_category,
                    dir_path=EXPORT_DIR,  # <<<
                    timestamp_str=st.session_state.get("current_run_ts"),
                    ndjson=True
                )
            except Exception as e:
                st.error(f"❌ Error guardando resultados ({state_category}): {e}")
                st.stop()

            st.session_state[key_hash] = payload_hash
            st.session_state[f"saved_path_{state_category}_xlsx"] = xlsx_path
            st.session_state[f"saved_path_{state_category}_json"] = json_path

        if st.session_state.get(f"saved_path_{state_category}_xlsx"):
            st.success(f"✅ Excel guardado en: `{st.session_state[f'saved_path_{state_category}_xlsx']}`")
        else:
            st.warning("No hubo resultados para guardar (Excel).")
        if st.session_state.get(f"saved_path_{state_category}_json"):
            st.info(f"🗂️ JSON guardado en: `{st.session_state[f'saved_path_{state_category}_json']}`")
