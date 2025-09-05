# src/filters/FilterEngine.py
import re
import streamlit as st
import json, os

from src.utils.Methods import Methods
from src.filters.MultiModelTaggerLocal import MultiModelTaggerLocal
from src.filters.FilterAutomotive import AutomotiveCyberFilter
from src.filters.FilterIncident import IncidentFilter


class FilterEngine:
    """
    Aplica:
      1) Filtro heurístico automoción (ruido vs dominio)
      2) Filtro heurístico de incidentes (acción real vs hipotético)
      3) Filtro IA (ensemble zero-shot, niveles encadenados)

    Además:
      - Dedup por título (norm_key) en noticias
      - Guarda descartes en JSON para análisis:
          * output/automocion_descartados.json
          * output/incidentes_descartados.json
          * output/ia_descartados.json
    """

    def __init__(self, log_manager=None, incident_mode: str = "strict", incident_scope: str = "auto-only"):
        self.analyzer = MultiModelTaggerLocal(_log_manager=log_manager)
        self.log_manager = log_manager

        # Debug por consola opcional
        self.debug = os.getenv("DEBUG_LOGS", "0") == "1"

        # === Heurístico automoción ===
        self._init_automotive_filter()

        # === Filtro de incidentes ===
        self._incident_filter = IncidentFilter(
            mode=os.getenv("INCIDENT_MODE", incident_mode),
            scope=os.getenv("INCIDENT_SCOPE", incident_scope)
        )

        # -------- Contadores --------
        self.total_items = 0
        self.missing_summary = 0
        self.filtered_by_ai = 0
        self.filtered_by_year = 0
        self.saved_items = 0
        self.already_processed_ia = 0
        self.filtered_by_heuristic_auto = 0
        self.filtered_by_heuristic_inci = 0

        # -------- Buffers + rutas de descartes --------
        self._discarded_incidents = []
        self._incident_rejects_path = os.getenv("INCIDENT_REJECTS_PATH", "output/incidentes_descartados.json")

        self._discarded_ai = []
        self._ai_rejects_path = os.getenv("IA_REJECTS_PATH", "output/ia_descartados.json")

        self._discarded_auto = []
        self._auto_rejects_path = os.getenv("AUTO_REJECTS_PATH", "output/automocion_descartados.json")

    # ----------------- Logging helper -----------------
    def _log(self, msg: str):
        if self.log_manager:
            self.log_manager.log_state(msg)
        if self.debug:
            print(msg, flush=True)

    # ----------------- Persistencia de descartes -----------------
    def _save_json_list(self, items: list, path: str, flush_after: bool = True, tag: str = "items"):
        """Fusiona con el JSON existente (si lo hay) y lo persiste."""
        if not items:
            return
        try:
            dirpath = os.path.dirname(path)
            if dirpath:
                os.makedirs(dirpath, exist_ok=True)

            existing = []
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                        if not isinstance(existing, list):
                            existing = []
                except Exception:
                    existing = []

            existing.extend(items)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, ensure_ascii=False, indent=2)

            self._log(f"💾 Guardados {len(items)} {tag} en {path}")

            if flush_after:
                items.clear()
        except Exception as e:
            self._log(f"🔴 Error guardando {tag}: {e}")

    def _save_discarded_incidents(self, flush: bool = True):
        self._save_json_list(self._discarded_incidents, self._incident_rejects_path, flush_after=flush, tag="descartes de incidentes")

    def _save_discarded_ai(self, flush: bool = True):
        self._save_json_list(self._discarded_ai, self._ai_rejects_path, flush_after=flush, tag="descartes de IA")

    def _save_discarded_auto(self, flush: bool = True):
        self._save_json_list(self._discarded_auto, self._auto_rejects_path, flush_after=flush, tag="descartes de automoción")

    # ----------------- Filtro automoción -----------------
    def _init_automotive_filter(self):
        """Carga el diccionario de filtros y crea el clasificador heurístico."""
        cfg_path = os.getenv("AC_FILTERS_PATH", "config/automotive_cyber_filters_v1.json")
        try:
            with open(cfg_path, encoding="utf-8") as f:
                self._auto_cfg = json.load(f)
            self._log("🟢 Filtros automoción cargados.")
            self._auto_clf = AutomotiveCyberFilter(self._auto_cfg)
        except Exception as e:
            self._auto_cfg = None
            self._auto_clf = None
            self._log(f"🔴 No se pudieron cargar los filtros automoción: {e}")

        # Umbrales del semáforo
        self._cutoff_red = 4   # <4 → descartar (ruido)
        self._cutoff_green = 9 # ≥9 → aceptar directo (muy claro)

    def _heuristic_score(self, title: str, summary: str, extra: str = ""):
        """Devuelve (score, tags, hits); si no hay filtro cargado, devuelve ceros."""
        if not self._auto_clf:
            return 0, {}, {}
        text = " ".join([t for t in [title or "", summary or "", extra or ""] if t])
        res = self._auto_clf.score_text(text)
        return res.score, res.tags, res.hits

    def _keyword_strict_match(self, keyword, title, description):
        """Devuelve True si todas las palabras clave están en el título o descripción."""
        keyword_terms = re.findall(r"\w+", keyword.lower())
        combined_text = (title or "") + " " + (description or "")
        return all(term in combined_text.lower() for term in keyword_terms)

    # ----------------- Resumen / UI -----------------
    def get_summary_pretty(self) -> dict:
        return {
            "Total analizados": self.total_items,
            "Sin resumen": self.missing_summary,
            "Filtrados por año": self.filtered_by_year,
            "Filtrados por heuristica automotriz": getattr(self, "filtered_by_heuristic_auto", 0),
            "Filtrados por heuristica incidentes": getattr(self, "filtered_by_heuristic_inci", 0),
            "Repetidos IA": self.already_processed_ia,
            "No relacionados (IA)": self.filtered_by_ai,
            "Guardados": self.saved_items,
        }

    def mostrar_resultados(self):
        if self.log_manager:
            self.log_manager.show_filter_resume(self.get_summary_pretty())

    # ----------------- Core -----------------
    def filter_and_classify_items(self, engine, item_type):
        """
        Aplica todos los filtros y usa el clasificador IA.
        """
        self._log("🟠 🧪 Aplicando filtros y clasificando con IA...")
        self.total_items += len(engine.raw_items)
        self._log(f"🧪 Filtrado: total_raw={len(engine.raw_items)}")

        # Asegura estructuras del motor
        if not hasattr(engine, "ia_analyzed_ids"):
            engine.ia_analyzed_ids = set()
        if not hasattr(engine, "final_results"):
            engine.final_results = {}

        for key, item in engine.raw_items.items():
            title = item.get("Title", "") or ""
            summary = item.get("Summary", "") or ""

            # >>> Inicializa campos de decisión para la tarjeta
            item["Decision"] = None
            item["DecisionGate"] = None
            item["DecisionReasons"] = []
            item["RulesVersion"] = os.getenv("RULES_VERSION", "rules@v1")

            # Año
            try:
                year = int(item.get("Year"))
            except (ValueError, TypeError):
                year = None

            # Identificador normalizado
            if item_type == "papers":
                raw_id = item.get("DOI", "") or ""
                norm_key = Methods.normalize_doi(raw_id) or Methods.normalize_title(title)
                source_ref = raw_id or None
            elif item_type == "vulnerabilities":
                vid = (item.get("ID") or "").strip().upper()
                norm_key = vid
                source_ref = vid or None
            elif item_type == "news":
                # ✅ dedup por TÍTULO (según tu decisión)
                norm_key = Methods.normalize_title(title)
                source_ref = item.get("URL") or item.get("url") or None
            else:
                st.warning(f"⚠️ Tipo desconocido: {item_type}")
                continue

            # Filtro de años
            if not year or not (2020 <= year <= 2025):
                self.filtered_by_year += 1
                if self.debug:
                    self._log(f"⏭️ fuera de rango ({year}) · {title[:80]}")
                continue

            """
            # Recuperar resumen si sigue vacío
            if not summary.strip():
                summary = (
                    item.get("content")
                    or item.get("body")
                    or item.get("Description")
                    or item.get("Abstract")
                    or ""
                ).strip()
            if not summary.strip():
                self.missing_summary += 1
                if self.debug:
                    self._log(f"⏭️ sin resumen · {title[:80]}")
                continue
            """

            # === 1) Heurístico automoción ===
            extra_text = (
                item.get("Content")
                or item.get("Body")
                or item.get("description")
                or item.get("abstract")
                or ""
            )
            heur_score, heur_tags, heur_hits = self._heuristic_score(title, summary, extra_text)
            item["Heur_Score"] = heur_score
            item["Heur_Tags"] = heur_tags
            item["Heur_Hits"] = heur_hits

            if heur_score < self._cutoff_red:
                self.filtered_by_heuristic_auto += 1

                # Guardar descarte de automoción (no invocamos aún filtro de incidentes)
                self._discarded_auto.append({
                    "NormKey": norm_key,
                    "ItemType": item_type,
                    "SourceRef": source_ref,
                    "Title": title,
                    "Summary": summary,
                    "Year": year,
                    "Heur_Score": heur_score,
                    "Heur_Tags": heur_tags,
                    "Heur_Hits": heur_hits,
                    "IncidentScore": None,
                    "IncidentReasons": [],
                    "IncidentCategory": None,
                })


                # >>> Marca decisión DROP por automoción
                item["Decision"] = "drop"
                item["DecisionGate"] = "automotive_filter"
                # razones “humanas”
                auto_reasons = []
                if heur_hits.get("brands"):
                    auto_reasons.append(f"Marca detectada: {', '.join(heur_hits['brands'])}")
                if heur_hits.get("attack_terms"):
                    auto_reasons.append(f"Menciona: {', '.join(heur_hits['attack_terms'])}")
                auto_reasons.append(f"Automoción insuficiente (score={heur_score}<{self._cutoff_red})")
                item["DecisionReasons"] = auto_reasons[:5]

                if self.debug:
                    self._log(f"⛔ auto-heuristic score={heur_score} · {title[:80]}")
                continue

            # === 2) INCIDENTES REALES (Action Gate) ===
            action_gate = self._incident_filter.classify(title, summary)
            item["IncidentScore"] = action_gate.score
            item["IncidentReasons"] = action_gate.reasons
            item["IncidentCategory"] = action_gate.category

            if not action_gate.keep:
                # Guardar descarte de incidentes
                self._discarded_incidents.append({
                    "NormKey": norm_key,
                    "ItemType": item_type,
                    "SourceRef": source_ref,
                    "Title": title,
                    "Summary": summary,
                    "Year": year,
                    "Heur_Score": item.get("Heur_Score"),
                    "Heur_Tags": item.get("Heur_Tags"),
                    "Heur_Hits": item.get("Heur_Hits"),
                    "IncidentScore": action_gate.score,
                    "IncidentReasons": action_gate.reasons,
                    "IncidentCategory": action_gate.category,
                })

                # >>> Marca decisión DROP por incident_filter
                item["Decision"] = "drop"
                item["DecisionGate"] = "incident_filter"
                # razones legibles (limpia prefijos +N / -N si existieran)
                inc_reasons = [re.sub(r"^\+?-?\d+\s*", "", r) for r in (action_gate.reasons or [])]
                if not inc_reasons:
                    inc_reasons = ["No evidencia suficiente de incidente real"]
                item["DecisionReasons"] = inc_reasons[:5]

                self.filtered_by_heuristic_inci += 1

                if self.debug:
                    self._log(f"⛔ incident-gate {action_gate.category} score={action_gate.score} · {title[:80]}")
                continue

            # Duplicados IA
            if norm_key in engine.ia_analyzed_ids:
                self.already_processed_ia += 1
                if self.debug:
                    self._log(f"🌀 IA ya analizado · {title[:80]}")
                continue

            # === 3) Clasificación con IA (ensemble) ===
            discarded_by_ia = False
            if getattr(engine, "apply_filter_ia", False):
                niveles = getattr(engine, "values_levels_ia", {})

                if not niveles or not isinstance(niveles, dict):
                    st.warning("⚠️ No se han definido niveles válidos para el filtrado IA.")
                    return

                for level_id, config in niveles.items():
                    etiquetas_nivel = config.get("labels", [])
                    etiquetas_malas = config.get("bad_labels", [])
                    umbral = config.get("threshold", 0.4)

                    # parámetros avanzados
                    min_votes = config.get("min_votes", 2)
                    min_margin = config.get("min_margin", 0.15)
                    entropy_cap = config.get("entropy_cap", 1.50)
                    per_model_min = config.get("per_model_min", 0.00)
                    abstain_label = config.get("abstain_label", "NO_LABEL")

                    if not etiquetas_nivel:
                        continue

                    # (label, score, per_model, dbg)
                    label, score, per_model, dbg = self.analyzer.classify_with_ensemble(
                        title,
                        summary,
                        custom_labels=etiquetas_nivel,
                        threshold=umbral,
                        min_votes=min_votes,
                        min_margin=min_margin,
                        entropy_cap=entropy_cap,
                        per_model_min=per_model_min,
                        abstain_label=abstain_label,
                    )

                    item[f"Label_{level_id}"] = label
                    item[f"Score_{level_id}"] = round(score, 3)
                    item[f"Accepted_{level_id}"] = dbg.get("accepted", False)
                    item[f"Votes_{level_id}"] = dbg.get("votes", 0)
                    item[f"Margin_{level_id}"] = round(dbg.get("margin", 0.0), 3)
                    item[f"Entropy_{level_id}"] = round(dbg.get("entropy", 0.0), 3)

                    if self.debug:
                        self._log(f"  [{level_id}] label={label} score={score:.3f} votes={dbg.get('votes')} "
                                  f"margin={dbg.get('margin', 0.0):.3f} accepted={dbg.get('accepted')}")

                    # Condiciones de descarte por IA
                    rejected = (
                        (not dbg.get("accepted", False)) or
                        (label in etiquetas_malas) or
                        (label == abstain_label)
                    )

                    if rejected:
                        self.filtered_by_ai += 1
                        discarded_by_ia = True

                        # ✅ Guardar descarte de IA
                        self._discarded_ai.append({
                            "NormKey": norm_key,
                            "ItemType": item_type,
                            "SourceRef": source_ref,
                            "Title": title,
                            "Summary": summary,
                            "Year": year,
                            "Heur_Score": item.get("Heur_Score"),
                            "Heur_Tags": item.get("Heur_Tags"),
                            "Heur_Hits": item.get("Heur_Hits"),
                            "IncidentScore": item.get("IncidentScore"),
                            "IncidentReasons": item.get("IncidentReasons"),
                            "IncidentCategory": item.get("IncidentCategory"),
                            "IA_Level": level_id,
                            "IA_Label": label,
                            "IA_Score": round(score, 3),
                            "IA_Threshold": umbral,
                            "IA_Votes": dbg.get("votes", 0),
                            "IA_Margin": round(dbg.get("margin", 0.0), 3),
                            "IA_Entropy": round(dbg.get("entropy", 0.0), 3),
                            "IA_Accepted": dbg.get("accepted", False),
                            "IA_AbstainLabel": abstain_label,
                            "IA_BadLabels": list(etiquetas_malas),
                            # Opcional: top-3 por modelo para auditoría ligera
                            "IA_PerModelTop3": {
                                m: rows[:3] for m, rows in (per_model or {}).items()
                            }
                        })

                        # >>> Marca decisión DROP por IA
                        item["Decision"] = "drop"
                        item["DecisionGate"] = "ai_zeroshot"
                        reason = []
                        reason.append(f"Nivel {level_id}: label={label} score={round(score,3)} thr={umbral}")
                        if label == abstain_label:
                            reason.append("Abstención IA")
                        if label in etiquetas_malas:
                            reason.append("Etiqueta negativa")
                        if not dbg.get("accepted", False):
                            reason.append("No cumple aceptación del ensemble")
                        item["DecisionReasons"] = reason[:5]

                        if self.debug:
                            self._log(f"  ↪ descartado por IA en nivel {level_id} (label={label})")
                        break  # no hace falta evaluar más niveles

                if discarded_by_ia:
                    continue

                engine.ia_analyzed_ids.add(norm_key)


            # === Guardar en resultados finales ===
            # >>> Marca decisión KEEP (pasó auto + incidentes y, si aplica, IA)
            if item.get("Decision") is None:
                item["Decision"] = "keep"
                item["DecisionGate"] = "final"
                keep_reasons = []
                if heur_hits.get("brands"):
                    keep_reasons.append(f"Marca detectada: {', '.join(heur_hits['brands'])}")
                if heur_hits.get("attack_terms"):
                    keep_reasons.append(f"Menciona: {', '.join(heur_hits['attack_terms'])}")
                # añade hasta 3 razones del action gate ya calculadas
                inc_reasons_short = [re.sub(r"^\+?-?\d+\s*", "", r) for r in (item.get("IncidentReasons") or [])][:3]
                keep_reasons.extend(inc_reasons_short)
                item["DecisionReasons"] = (keep_reasons or ["Cumple filtros automoción e incidente"])[:5]

            # === Guardar en resultados finales ===
            engine.final_results[norm_key] = item
            self.saved_items += 1
            if self.debug:
                self._log(f"✅ SAVE → {title[:80]}")

        # Persistir todos los descartes al finalizar el bucle
        self._save_discarded_auto(flush=True)
        self._save_discarded_incidents(flush=True)
        self._save_discarded_ai(flush=True)

        # Mostrar resumen
        self.mostrar_resultados()

    # ----------------- Stats (persistencia de contadores) -----------------
    def get_stats_dict(self) -> dict:
        return {
            "total_items": self.total_items,
            "missing_summary": self.missing_summary,
            "filtered_by_year": self.filtered_by_year,
            "filtered_by_heuristic_auto": getattr(self, "filtered_by_heuristic_auto", 0),
            "filtered_by_heuristic_inci": getattr(self, "filtered_by_heuristic_inci", 0),
            "already_processed_ia": self.already_processed_ia,
            "filtered_by_ai": self.filtered_by_ai,
            "saved_items": self.saved_items,
        }

    def load_stats_from_dict(self, d: dict | None):
        if not d:
            return
        self.total_items = int(d.get("total_items", 0))
        self.missing_summary = int(d.get("missing_summary", 0))
        self.filtered_by_year = int(d.get("filtered_by_year", 0))
        self.filtered_by_heuristic_auto = int(d.get("filtered_by_heuristic_auto", 0))
        self.filtered_by_heuristic_inci = int(d.get("filtered_by_heuristic_inci", 0))
        self.already_processed_ia = int(d.get("already_processed_ia", 0))
        self.filtered_by_ai = int(d.get("filtered_by_ai", 0))
        self.saved_items = int(d.get("saved_items", 0))
