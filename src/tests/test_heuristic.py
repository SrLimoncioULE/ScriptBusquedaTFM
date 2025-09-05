from __future__ import annotations
import json
import re
import sys
import os
import unicodedata
import pandas as pd
from pathlib import Path
from typing import Optional, List, Dict, Any

# Añadir el directorio raíz del proyecto al sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.filters.FilterAutomotive import AutomotiveCyberFilter
from src.filters.FilterIncident import IncidentFilter

URL_RX = re.compile(r"https?://", re.I)

# ==============================
# === 1) CASOS HARDCODEADOS ===
# ==============================

CASES: List[Dict[str, Any]] = [
    # ========================== POSITIVOS ==========================
    {"id":  1, "title": "Ransomware paraliza planta de BMW en Alemania: producción detenida dos días",
     "desc": "El ataque interrumpió líneas de montaje y obligó a parar la fábrica temporalmente.", "expect": "POS"},
    {"id":  2, "title": "Proveedor Magna sufre data breach y confirma filtración de documentación",
     "desc": "Los atacantes publicaron parte de los archivos en un leak site para extorsionar.", "expect": "POS"},
    {"id":  3, "title": "Renault cierra temporalmente una fábrica tras ciberataque de ransomware",
     "desc": "Se reportó un production halt y evaluación de impacto en sistemas OT.", "expect": "POS"},
    {"id":  4, "title": "LockBit publica archivos de ZF; proveedor automotriz investiga exfiltración",
     "desc": "Extortion claim con datos de programas y clientes; operaciones afectadas.", "expect": "POS"},
    {"id":  5, "title": "Data breach en concesionarios Toyota expone información de clientes",
     "desc": "Se confirmó robo de datos personales y registros de mantenimiento.", "expect": "POS"},
    {"id":  6, "title": "Nissan confirms cyberattack disrupting operations at Smyrna plant",
     "desc": "Production halt reported in the factory after ransomware hit.", "expect": "POS"},
    {"id":  7, "title": "Clop leaks supplier files impacting automotive manufacturing",
     "desc": "Data exfiltration y disrupción en logística de componentes críticos.", "expect": "POS"},
    {"id":  8, "title": "Kia Motors hit by ransomware in the US, dealers report outage",
     "desc": "Backend systems down; servicios de concesionarios no disponibles.", "expect": "POS"},
    {"id":  9, "title": "Denso confirma exfiltración de datos tras ciberataque",
     "desc": "Proveedor Tier-1 con impacto en sistemas IT y retrasos de envíos.", "expect": "POS"},
    {"id": 10, "title": "Faurecia (Forvia) detiene operaciones en varias plantas por ataque",
     "desc": "Shutdown parcial para contener el incidente y restaurar producción.", "expect": "POS"},
    {"id": 11, "title": "Continental reports data breach after cyberattack; files posted online",
     "desc": "Leak site publicó documentos; investigación y notificación a clientes.", "expect": "POS"},
    {"id": 12, "title": "Hyundai Mobis targeted: extortion attempt follows data theft",
     "desc": "Los atacantes afirman tener diseños y listas de proveedores.", "expect": "POS"},
    {"id": 13, "title": "Volkswagen supplier hit by ransomware; shipping halted",
     "desc": "Disrupción operativa y retrasos en componentes clave.", "expect": "POS"},
    {"id": 14, "title": "Tesla supplier breach confirmed; samples leaked to pressure payment",
     "desc": "Extorsión con publicaciones parciales y amenaza de divulgar más.", "expect": "POS"},
    {"id": 15, "title": "Honda planta en Japón detiene producción por ciberataque",
     "desc": "Factory shutdown y evaluación de sistemas afectados.", "expect": "POS"},
    {"id": 16, "title": "Mercedes-Benz dealership data leak exposes customer records",
     "desc": "Información personal accesible; OEM notificado del incidente.", "expect": "POS"},
    {"id": 17, "title": "Ford Tier-1 supplier suffers ransomware; assembly line impacted",
     "desc": "Paro temporal en planta de ensamblaje por falta de piezas.", "expect": "POS"},
    {"id": 18, "title": "GM Mexico plant hit by cyberattack, assembly halted",
     "desc": "Interrupción de producción y protocolos de contingencia activados.", "expect": "POS"},
    {"id": 19, "title": "Stellantis con disrupción en logística tras intrusión confirmada",
     "desc": "Impacto en envíos; algunos centros reportan paro parcial.", "expect": "POS"},
    {"id": 20, "title": "Supplier Yazaki acknowledges data theft; attackers leak sample files",
     "desc": "Clara exfiltración y amenaza pública; investigación en curso.", "expect": "POS"},

    # ========================== NEGATIVOS ==========================
    {"id": 21, "title": "Investigadores demuestran PoC para hackear CAN bus en laboratorio",
     "desc": "Prueba de concepto sin explotación real en fabricantes ni proveedores.", "expect": "NEG"},
    {"id": 22, "title": "Actualización OTA corrige vulnerabilidad CVE-2023-12345 en infotainment",
     "desc": "Boletín de seguridad; no hay explotación ni impacto operativo.", "expect": "NEG"},
    {"id": 23, "title": "Cómo proteger tu coche de malware: guía práctica para usuarios",
     "desc": "Consejos generales; no hay incidentes confirmados.", "expect": "NEG"},
    {"id": 24, "title": "BMW presenta nuevo modelo eléctrico con mejoras de software",
     "desc": "Lanzamiento de producto sin relación con ciberincidentes.", "expect": "NEG"},
    {"id": 25, "title": "Estudio teórico sobre ataques V2X sin incidentes reportados",
     "desc": "Investigación académica; sin impacto en plantas ni proveedores.", "expect": "NEG"},
    {"id": 26, "title": "Recall por airbag Takata afecta a varios modelos",
     "desc": "Campaña de seguridad mecánica; no ciber.", "expect": "NEG"},
    {"id": 27, "title": "Vulnerabilidad en Gran Turismo permitiría trucos en el simulador",
     "desc": "Videojuego/simulador; no automoción real.", "expect": "NEG"},
    {"id": 28, "title": "Rumores de ataque a planta de Fiat no confirmados",
     "desc": "Sin evidencia de breach, shutdown o leak verificado.", "expect": "NEG"},
    {"id": 29, "title": "Researchers could exploit Bluetooth in cars, but no breaches yet",
     "desc": "Hipotético; sin exfiltración ni disrupción reportada.", "expect": "NEG"},
    {"id": 30, "title": "Auditoría de cumplimiento UN R155 para un OEM — sin incidentes",
     "desc": "Cumplimiento normativo, no incidente.", "expect": "NEG"},
    {"id": 31, "title": "Informe de mercado: acciones de Tesla suben por resultados",
     "desc": "Finanzas/mercado; no seguridad.", "expect": "NEG"},
    {"id": 32, "title": "BMW registra nueva patente de batería para EV",
     "desc": "Propiedad intelectual; no ciberincidente.", "expect": "NEG"},
    {"id": 33, "title": "Ferrari en la Fórmula 1: resultados del GP y estrategia",
     "desc": "Motorsport; fuera del dominio de ciber automotriz real.", "expect": "NEG"},
    {"id": 34, "title": "Mantenimiento mecánico: cómo cambiar pastillas de freno",
     "desc": "Tutorial no ciber.", "expect": "NEG"},
    {"id": 35, "title": "Security advisory corrige fallo en app de infotainment",
     "desc": "Parche disponible; sin explotación activa ni impacto.", "expect": "NEG"},
    {"id": 36, "title": "Hackers aseguran ataque, pero el OEM lo desmiente; sin impacto",
     "desc": "Afirmaciones no verificadas; no hay shutdown ni leak confirmado.", "expect": "NEG"},
    {"id": 37, "title": "Hoax en redes sociales sobre presunto ataque a proveedor",
     "desc": "Engaño sin evidencia; no incidente real.", "expect": "NEG"},
    {"id": 38, "title": "Proveedor gana premio de ciberseguridad por buenas prácticas",
     "desc": "Noticia positiva; no incidente.", "expect": "NEG"},
    {"id": 39, "title": "Actualización de política de privacidad en concesionarios",
     "desc": "Cambios legales; no incidente.", "expect": "NEG"},
    {"id": 40, "title": "Ejercicio de simulacro: fábrica practica respuesta a ciberataques",
     "desc": "Drill/entrenamiento; no ataque real.", "expect": "NEG"},
]


def _metrics(rows: List[Dict[str, Any]], pred_key: str):
    """Calcula métricas (cuando hay 'expect' POS/NEG)."""
    tp = sum(1 for r in rows if r.get("expect") == "POS" and r[pred_key])
    fn = sum(1 for r in rows if r.get("expect") == "POS" and not r[pred_key])
    tn = sum(1 for r in rows if r.get("expect") == "NEG" and not r[pred_key])
    fp = sum(1 for r in rows if r.get("expect") == "NEG" and r[pred_key])
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    acc = (tp + tn) / len([r for r in rows if r.get("expect") in ("POS", "NEG")]) if rows else 0.0
    return tp, fp, tn, fn, prec, rec, acc


def _print_compact(rows: List[Dict[str, Any]]):
    print("\n=== RESULTADOS POR CASO (resumen) ===")
    for r in rows:
        exp = r.get("expect")
        combined = r["combined_accept"]
        ok = (exp == "POS" and combined) or (exp == "NEG" and not combined) or (exp is None)
        mark = "✅" if ok else "❌"
        auto_tag = "A" if r["auto_accept"] else "R"
        inc_tag = "K" if r["inc_keep"] else "X"
        print(f"{mark} #{r['id']:>3} [{exp or 'UNK'}] auto={r['auto_score']:>2}({auto_tag})  inc={r['inc_score']:>2}({inc_tag})  "
              f"COMB={'ACCEPT' if combined else 'REJECT'}  | {r['title']}")


def _evaluate_records(records: List[Dict[str, Any]],
                      cfg_path: str = "config/automotive_cyber_filters_v1.json",
                      heur_cutoff_red: int = 3,
                      save_csv: Optional[str] = None) -> List[Dict[str, Any]]:
    """Evalúa una lista de registros con claves: id, title, desc, (opcional) expect."""
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    auto_clf = AutomotiveCyberFilter(cfg)
    inc_clf = IncidentFilter(mode="strict")

    rows = []
    for c in records:
        title = (c.get("title") or "").strip()
        desc = (c.get("desc") or "").strip()
        if not title and not desc:
            continue

        # 1) Heurístico de automoción
        auto_res = auto_clf.score_text(f"{title} {desc}".strip())
        auto_score = auto_res.score
        auto_accept = auto_score >= heur_cutoff_red

        # 2) Heurístico de incidentes
        inc_res = inc_clf.classify(title, desc)
        inc_keep = inc_res.keep
        inc_score = inc_res.score
        inc_cat = inc_res.category

        # 3) Decisión combinada (AND)
        combined_accept = auto_accept and inc_keep

        rows.append({
            "id": c.get("id"),
            "expect": c.get("expect"),
            "title": title,
            "desc": desc,
            "auto_score": auto_score,
            "auto_accept": auto_accept,
            "inc_score": inc_score,
            "inc_keep": inc_keep,
            "inc_cat": inc_cat,
            "combined_accept": combined_accept,
        })

    # Métricas si hay 'expect'
    if any(r.get("expect") in ("POS", "NEG") for r in rows):
        tp, fp, tn, fn, prec, rec, acc = _metrics(rows, "auto_accept")
        print("\n=== AutomotiveCyberFilter SOLO (umbral >= 3) ===")
        print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}  |  Prec={prec:.2f}  Rec={rec:.2f}  Acc={acc:.2f}")

        tp, fp, tn, fn, prec, rec, acc = _metrics(rows, "inc_keep")
        print("\n=== IncidentFilter SOLO (strict) ===")
        print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}  |  Prec={prec:.2f}  Rec={rec:.2f}  Acc={acc:.2f}")

        tp, fp, tn, fn, prec, rec, acc = _metrics(rows, "combined_accept")
        print("\n=== COMBINADO (Automotive AND Incident) ===")
        print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}  |  Prec={prec:.2f}  Rec={rec:.2f}  Acc={acc:.2f}")
    else:
        # No hay etiquetas -> cuenta aceptados/rechazados
        total = len(rows)
        accepts = sum(1 for r in rows if r["combined_accept"])
        print("\n=== SIN etiquetas (Excel) ===")
        print(f"Total={total} | ACCEPT={accepts} ({accepts/total*100:.1f}%) | REJECT={total-accepts} ({(total-accepts)/total*100:.1f}%)")

    _print_compact(rows)

    if save_csv:
        out = Path(save_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(out, index=False, encoding="utf-8")
        print(f"\n[OK] CSV guardado en: {out.resolve()}")

    return rows


def run_hardcoded_cases():
    """Ejecuta la evaluación con los 40 ejemplos del código."""
    _evaluate_records(CASES, save_csv="results/dual_heuristics_40.csv")


# ===========================================
# === 2) DESDE EXCEL (carga flexible)     ===
# ===========================================

def _norm(s: str) -> str:
    """normaliza: baja, quita acentos y NBSP, colapsa espacios."""
    if s is None:
        return ""
    s = str(s).replace("\u00A0", " ").strip().lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"\s+", " ", s)
    return s

def _auto_detect_columns(df: pd.DataFrame,
                         title_col: Optional[str],
                         desc_col: Optional[str]) -> tuple[str, Optional[str]]:
    """
    Detecta columnas de título y descripción:
    - normaliza encabezados (minúsculas, sin acentos/nbsp)
    - usa alias ES/EN
    - si falla, heurística por contenido (longitud media y evitar URLs)
    """
    # Mapa normalizado -> original
    norm2orig: Dict[str, str] = {}
    for c in df.columns:
        norm2orig[_norm(c)] = c

    def pick_alias(cands: List[str]) -> Optional[str]:
        for cand in cands:
            col = norm2orig.get(_norm(cand))
            if col:
                return col
        return None

    # Si el usuario las pasó, respétalas
    if title_col and title_col in df.columns:
        t_col = title_col
    else:
        t_col = pick_alias([
            "title", "titulo", "título", "titular", "headline", "subject", "name"
        ])

    if desc_col and desc_col in df.columns:
        d_col = desc_col
    else:
        d_col = pick_alias([
            "description", "descripcion", "descripción", "summary", "resumen",
            "content", "contenido", "texto", "body"
        ])

    # Heurística si falta alguno
    def is_url_col(series: pd.Series) -> bool:
        sample = series.dropna().astype(str).head(50)
        if sample.empty: return False
        url_frac = (sample.str.contains(URL_RX, regex=True)).mean()
        return url_frac >= 0.6  # mayormente URLs

    def avg_len(series: pd.Series) -> float:
        sample = series.dropna().astype(str).head(200)
        if sample.empty: return 0.0
        return sample.str.len().mean()

    text_cols = [c for c in df.columns if df[c].dtype == "object"]

    # Evita columna FUENTE/URL para título/desc
    non_url_text_cols = [c for c in text_cols if not is_url_col(df[c])]

    if t_col is None:
        # título: texto, no-URL, longitud media moderada
        candidates = []
        for c in non_url_text_cols:
            L = avg_len(df[c])
            # títulos suelen estar entre ~10 y ~120 chars
            score = -abs(L - 70)  # cuanto más cerca de 70, mejor
            candidates.append((score, c, L))
        if candidates:
            candidates.sort(reverse=True)
            t_col = candidates[0][1]

    if d_col is None:
        # descripción: texto, no-URL, algo más largo que el título
        candidates = []
        for c in non_url_text_cols:
            if c == t_col:
                continue
            L = avg_len(df[c])
            score = L  # cuanto más largo, mejor para descripción
            candidates.append((score, c, L))
        if candidates:
            candidates.sort(reverse=True)
            d_col = candidates[0][1]

    return t_col, d_col


def run_excel_cases(excel_path: str,
                    sheet: Optional[str] = None,
                    title_col: Optional[str] = None,
                    desc_col: Optional[str] = None,
                    limit: Optional[int] = None,
                    dropna: bool = True):
    """
    Lee un Excel y evalúa todas las filas con heurísticos y combinación AND.
    Admite encabezados con acentos/nbps y detecta 'TITULAR'/'DESCRIPCIÓN'.
    """
    path = Path(excel_path)
    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo: {path}")

    engine = None
    if path.suffix.lower() in (".xlsx", ".xlsm", ".xltx", ".xltm"):
        engine = "openpyxl"

    # 1º intento: header=0
    df = pd.read_excel(path, sheet_name=sheet, engine=engine)
    if isinstance(df, dict):
        df = next(iter(df.values()))

    # Si no detecta, probamos header fila 1 (algunas hojas tienen cabecera en la segunda fila)
    def detect_and_report(df_try: pd.DataFrame) -> Optional[tuple[str, str, pd.DataFrame]]:
        t_col, d_col = _auto_detect_columns(df_try, title_col, desc_col)
        if t_col:
            return t_col, d_col, df_try
        return None

    picked = detect_and_report(df)
    if not picked:
        try:
            df2 = pd.read_excel(path, sheet_name=sheet, engine=engine, header=1)
            if isinstance(df2, dict):
                df2 = next(iter(df2.values()))
            picked = detect_and_report(df2)
            if picked:
                df = picked[2]
        except Exception:
            pass

    if not picked:
        # Como último recurso, mostramos columnas disponibles
        print("[DEBUG] Encabezados disponibles:", list(df.columns))
        raise ValueError("No se pudo detectar 'TITULAR' y/o 'DESCRIPCIÓN'. Pásalas con title_col= / desc_col=.")

    title_col, desc_col, _ = picked if isinstance(picked, tuple) else (picked, None, df)

    print(f"[INFO] Columnas detectadas → Título='{title_col}'  Descripción='{desc_col}'")

    # Prepara registros
    records: List[Dict[str, Any]] = []
    use_cols = [title_col] + ([desc_col] if desc_col and desc_col in df.columns else [])
    it = df[use_cols].itertuples(index=True, name=None)

    count = 0
    for row in it:
        if desc_col and len(use_cols) == 2:
            idx, title, desc = row
        else:
            idx, title = row
            desc = ""
        t = (str(title) if pd.notna(title) else "").replace("\u00A0", " ").strip()
        d = (str(desc) if pd.notna(desc) else "").replace("\u00A0", " ").strip()
        if dropna and not (t or d):
            continue
        records.append({"id": int(idx) if isinstance(idx, (int, float)) else idx,
                        "title": t, "desc": d})
        count += 1
        if limit and count >= limit:
            break

    print(f"\n[INFO] Excel cargado: {len(records)} filas a evaluar "
          f"(sheet='{sheet or 'AUTO'}'). Ejemplos:")
    for sample in records[:3]:
        print(f"  - {sample['id']}: TIT='{sample['title'][:80]}' | DESC='{sample['desc'][:80]}'")

    # Evalúa y guarda CSV
    _evaluate_records(records, save_csv="results/dual_heuristics_excel.csv")


# ====================
# === PUNTO DE ENTRADA
# ====================
if __name__ == "__main__":
    # >>> MODO 1: ejemplos hardcodeados
    run_hardcoded_cases()

    # >>> MODO 2: leer desde Excel (descomenta y ajusta ruta/hoja/columnas si hace falta)
    run_excel_cases(
        excel_path=r"C:\Users\jose_\Downloads\20200608_datos_casos_reales_filtros.xlsx",
        sheet=None,          # o el nombre exacto de la hoja
        title_col=None,      # puedes forzar "TITULAR"
        desc_col=None,       # o forzar "DESCRIPCIÓN"
        limit=None,
        dropna=True
    )
