import streamlit as st
from transformers import pipeline
from collections import defaultdict, Counter
import torch
import math
import pandas as pd


labels = [
    # ——— POSITIVAS (real-world) ———
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

    # ——— NEGATIVAS (para descartar) ———
    "Advisory/Patch only (no exploitation)",
    "Research/PoC/demo (no real-world attack)",
    "Hypothetical/simulation/what-if",
    "General IT outage (non-automotive)",
    "IT-only incident (no operational impact reported)",
    "Keyless/relay theft only",
    "Unrelated/marketing/product news",
    "Roundup/digest/list of stories"
]

bad_labels = [
    "Advisory/Patch only (no exploitation)",
    "Research/PoC/demo (no real-world attack)",
    "Hypothetical/simulation/what-if",
    "General IT outage (non-automotive)",
    "IT-only incident (no operational impact reported)",
    "Keyless/relay theft only",
    "Unrelated/marketing/product news",
    "Roundup/digest/list of stories"
]


MODELS = {
    "deberta_large": "cross-encoder/nli-deberta-v3-large",
    "deberta_multi": "MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli",
    "bart": "facebook/bart-large-mnli",
}

MODEL_WEIGHTS = {
    "deberta_large": 0.45,
    "deberta_multi": 0.25,
    "bart": 0.25,
}

class MultiModelTaggerLocal:
    def __init__(self, _log_manager=None, hypothesis_template: str = "This article is about {}."):
        self.log_manager = _log_manager
        self.pipelines = {}
        self.hypothesis_template = hypothesis_template

        is_cuda = torch.cuda.is_available()
        if self.log_manager:
            self.log_manager.log_state("🟠 🔄 Cargando modelos en GPU..." if is_cuda else "🔄 Cargando modelos en CPU...")

        for key, model_name in MODELS.items():
            try:
                pipe = pipeline(
                    "zero-shot-classification",
                    model=model_name,
                    tokenizer=model_name,
                    use_fast=False,
                    device=0 if torch.cuda.is_available() else -1
                )
                self.pipelines[key] = pipe
                if self.log_manager:
                    self.log_manager.log_state(f"🟢 ✅ Modelo '{key}' cargado.")
            except Exception as e:
                if self.log_manager:
                    self.log_manager.log_state(f"🔴 ❌ Error cargando {key}: {e}")

        num_models = len(MODELS.items()) + 1
        if self.log_manager:
            self.log_manager.remove_last_states(n=num_models)
            self.log_manager.log_state("🟢 ✅ Modelos cargados correctamente.")

    @staticmethod
    def _entropy(probs: dict[str, float]) -> float:
        s = 0.0
        for p in probs.values():
            if p > 0:
                s -= p * math.log(p)
        return s

    @staticmethod
    def _softmax_from_multilabel(scores: dict[str, float], temperature: float = 1.3) -> dict[str, float]:
        """
        Convierte las 'probabilidades' multi-label en una distribución categórica
        aproximada: aplica logit a cada p y luego softmax(z/T).
        """
        eps = 1e-6
        z = {lbl: math.log((p + eps) / (1.0 - p + eps)) for lbl, p in scores.items()}
        zT = {k: v / max(1e-6, temperature) for k, v in z.items()}
        max_z = max(zT.values()) if zT else 0.0
        exps = {k: math.exp(v - max_z) for k, v in zT.items()}
        Z = sum(exps.values()) or 1.0
        return {k: v / Z for k, v in exps.items()}

    def classify_with_ensemble(
        self,
        title: str,
        description: str,
        custom_labels: list[str],
        *,
        # --- fusión/aceptación ---
        threshold: float = 0.55,        # score final mínimo (mezcla multi-label ponderada)
        min_votes: int = 1,             # nº mínimo de modelos que votan top-1
        min_margin: float = 0.05,       # margen mínimo (en la dist. categórica agregada)
        entropy_cap: float | None = None,  # si None → 0.75 * ln(N etiquetas)
        per_model_min: float = 0.20,    # al menos un modelo debe pasar esto para la ganadora
        abstain_label: str = "NO_LABEL",
        # --- reglas en cascada ---
        hi_conf: float = 0.85,          # aceptación directa si final_score ≥ hi_conf
        mid_conf: float = 0.65,         # aceptación si votes ≥ min_votes y final_score ≥ mid_conf
        low_conf: float = 0.50,         # participación mínima en la tercera regla
        # --- calibración ---
        temperature: float = 1.3,       # para softmax categórico por modelo
        hypothesis_template: str | None = None,  # para poder sobreescribir ad-hoc
        # --- rescate por etiquetas "duras" + señales en título/descripción ---
        use_hard_label_rules: bool = True,
    ):
        """
        Devuelve: (label_final | abstain_label, score_final_norm, resultados_por_modelo, debug_dict)
        """
        if not custom_labels:
            if self.log_manager:
                self.log_manager.log_state("🟡 ⚠️ No se proporcionaron etiquetas personalizadas.")
            return abstain_label, 0.0, {}, {"reason": "no_labels"}

        text = f"{title}. {description}".strip()
        candidate_labels = list(dict.fromkeys(custom_labels))

        # 1) Pasada multi-label por cada modelo -> scores independientes por etiqueta
        agg_scores = defaultdict(float)       # para el score final (multi-label, ponderado)
        per_label_votes = Counter()           # votos de top-1 por modelo
        model_results = {}                    # logging
        per_model_scores = {}                 # {model: {label: score}}

        total_weight = sum(MODEL_WEIGHTS.get(k, 0.0) for k in self.pipelines if k in MODEL_WEIGHTS)

        for key, pipe in self.pipelines.items():
            try:
                res = pipe(
                    text,
                    candidate_labels=candidate_labels,
                    multi_label=True,
                    hypothesis_template=hypothesis_template or self.hypothesis_template
                )
                labels_res = res["labels"]
                scores_res = res["scores"]
                weight = MODEL_WEIGHTS.get(key, 0.0)

                # Guarda crudo
                model_results[key] = [{"label": lbl, "score": float(scr)} for lbl, scr in zip(labels_res, scores_res)]
                per_model_scores[key] = {lbl: float(scr) for lbl, scr in zip(labels_res, scores_res)}

                # Voto del top-1 de este modelo
                if labels_res:
                    per_label_votes[labels_res[0]] += 1

                # Acumula en fusión ponderada (para score final)
                for lbl, scr in zip(labels_res, scores_res):
                    agg_scores[lbl] += weight * float(scr)

            except Exception as e:
                if self.log_manager:
                    self.log_manager.log_state(f"🔴 ❌ Error en modelo {key}: {e}")
                continue

        if not agg_scores:
            if self.log_manager:
                self.log_manager.log_state("⚠️ No se pudieron calcular puntuaciones (sin modelos válidos).")
            return abstain_label, 0.0, {}, {"reason": "no_model_scores"}

        # 2) Normaliza fusión multi-label a [0,1]
        norm_scores = {lbl: (score / total_weight if total_weight > 0 else 0.0) for lbl, score in agg_scores.items()}
        ordered = sorted(norm_scores.items(), key=lambda x: x[1], reverse=True)
        final_label, final_score = ordered[0]
        second_score = ordered[1][1] if len(ordered) > 1 else 0.0

        # 3) Construye distribución categórica agregada (para margen/entropía)
        soft_agg = defaultdict(float)
        for key, scores_dict in per_model_scores.items():
            weight = MODEL_WEIGHTS.get(key, 0.0)
            soft = self._softmax_from_multilabel(scores_dict, temperature=temperature)
            for lbl, p in soft.items():
                soft_agg[lbl] += weight * p
        # normaliza
        Z = sum(soft_agg.values()) or 1.0
        soft_agg = {k: v / Z for k, v in soft_agg.items()}

        soft_sorted = sorted(soft_agg.items(), key=lambda x: x[1], reverse=True)
        cat_top1, cat_p1 = soft_sorted[0]
        cat_p2 = soft_sorted[1][1] if len(soft_sorted) > 1 else 0.0
        margin = cat_p1 - cat_p2  # margen “categórico” (más significativo que con multi-label)

        votes = per_label_votes.get(final_label, 0)
        N = max(1, len(candidate_labels))
        ent_cap = entropy_cap if entropy_cap is not None else 0.75 * math.log(N)
        entropy = self._entropy(soft_agg)

        # ¿Algún modelo supera per_model_min para la ganadora?
        winner_model_max = 0.0
        for key, scores_dict in per_model_scores.items():
            winner_model_max = max(winner_model_max, scores_dict.get(final_label, 0.0))

        # 4) Reglas de decisión (en cascada)
        accepted = False
        reasons: list[str] = []

        # Alta confianza por score absoluto
        if final_score >= hi_conf and winner_model_max >= per_model_min:
            accepted = True
            reasons.append("hi_conf")

        # Consenso moderado: votos + score razonable + margen mínimo
        if not accepted and (votes >= min_votes and final_score >= mid_conf and margin >= 0.05 and winner_model_max >= per_model_min):
            accepted = True
            reasons.append("mid_conf")

        # Consenso suave: umbrales más laxos + entropía dinámica
        if not accepted and (final_score >= threshold and margin >= min_margin and entropy <= ent_cap and winner_model_max >= per_model_min and final_score >= low_conf):
            accepted = True
            reasons.append("soft_consensus")

        # Regla de rescate para etiquetas "duras" con señales en título/descripción
        if not accepted and use_hard_label_rules:
            HARD_LABELS = {
                "Operational ransomware (production or services disrupted)",
                "Confirmed data breach/exfiltration (customer/employee/PII)",
                "Vehicle/backend/ECU compromise (in the wild)",
                "Telematics/connected services or portal breach",
                "Dealer/DMS breach (CDK Global, Reynolds & Reynolds, Solera)",
            }
            TITLE_SIGNALS = (
                "ransomware", "data leak", "data breach", "exfiltration",
                "unlock", "relay attack", "remote start", "remote control",
                "hacked", "breach", "stolen data", "cdk", "reynolds & reynolds", "solera", "dms"
            )
            blob = f"{title} {description}".lower()
            has_signals = any(sig in blob for sig in TITLE_SIGNALS)

            if (final_label in HARD_LABELS) and has_signals and final_score >= 0.70 and winner_model_max >= per_model_min:
                accepted = True
                reasons.append("hard_label_rescue")

        # 5) Logging y salida
        if self.log_manager:
            lines = []
            lines.append("**📝 Texto evaluado:**\n")
            lines.append(f"🔖 Título: {title}\n")
            lines.append(f"🧾 Descripción: {description}\n\n")
            lines.append("**🎯 Predicciones por modelo (top-3):**\n")
            for m, rows in model_results.items():
                top3 = rows[:3]
                txt = ", ".join([f"{r['label']} ({round(r['score']*100, 2)}%)" for r in top3])
                lines.append(f"- `{m}` → {txt}")
            lines.append("\n**🔮 Ensamble (normalizado):**")
            for lbl, sc in ordered[:5]:
                lines.append(f"- {lbl}: {round(sc, 3)}")
            lines.append("\n**📊 Métricas de decisión (categóricas):**")
            lines.append(f"- margin: `{round(margin, 3)}`  entropy: `{round(entropy, 3)}`  ent_cap: `{round(ent_cap, 3)}`")
            lines.append(f"- votes: `{votes}`  winner_model_max: `{round(winner_model_max, 3)}`")
            lines.append(f"- final_score: `{round(final_score, 3)}`  second: `{round(second_score, 3)}`")
            if accepted:
                lines.append(f"\n✅ **ACEPTADO** → 🏷️ **Etiqueta final:** `{final_label}`  _(razones: {', '.join(reasons)})_\n")
            else:
                lines.append(f"\n🚫 **DESCARTADO** → 🏷️ **{abstain_label}**  _(razones: score/margen/entropía/votos insuficientes)_\n")
            self.log_manager.log_ia("\n".join(lines))

        if not accepted:
            return abstain_label, final_score, model_results, {
                "accepted": False,
                "margin": margin,
                "votes": votes,
                "entropy": entropy,
                "winner_model_max": winner_model_max,
                "ent_cap": ent_cap,
                "reason": "thresholds"
            }

        return final_label, final_score, model_results, {
            "accepted": True,
            "margin": margin,
            "votes": votes,
            "entropy": entropy,
            "winner_model_max": winner_model_max,
            "ent_cap": ent_cap,
            "reason": ",".join(reasons)
        }