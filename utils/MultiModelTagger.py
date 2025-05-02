import requests
import time

HUGGINGFACE_TOKEN = "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"

MODELS = {
    "bart": "facebook/bart-large-mnli",
    "deberta": "MoritzLaurer/mDeBERTa-v3-base-mnli-xnli",
    "roberta": "joeddav/xlm-roberta-large-xnli"
}

HEADERS = {"Authorization": f"Bearer {HUGGINGFACE_TOKEN}"}

LABEL_CANDIDATES = [
    "vulnerability in connected or autonomous vehicle",
    "vulnerability in automotive embedded system (ECU, CAN, ADAS, etc.)",
    "vulnerability in automotive backend or infrastructure (telematics, MQTT, V2X)",
    "vulnerability in automotive supplier or factory",
    "not related to automotive"
]

MAX_RETRIES = 10  # Reintentos por modelo
RETRY_DELAY = 5  # Segundos entre reintentos


class MultiModelTagger:

    def __init__(self):
        pass

    @staticmethod
    def classify_text(text: str, model_name: str):
        api_url = f"https://api-inference.huggingface.co/models/{model_name}"
        payload = {
            "inputs": text,
            "parameters": {
                "candidate_labels": LABEL_CANDIDATES,
                "multi_label": False
            }
        }

        try:
            response = requests.post(api_url, headers=HEADERS, json=payload, timeout=30)
            if not response.content:
                return "error", 0.0
            
            result = response.json()
            if "labels" in result:
                return result["labels"][0], result["scores"][0]
            else:
                return "error", 0.0
            
        except Exception as e:
            return "error", 0.0


    @staticmethod
    def classify_with_ensemble(cve_id: str, description: str):
        combined_text = f"{cve_id}. {description}"
        model_results = {}
        positive_votes = 0

        for model_key, model_name in MODELS.items():
            attempts = 0
            label, score = "error", 0.0

            while label == "error" and attempts < MAX_RETRIES:
                label, score = MultiModelTagger.classify_text(combined_text, model_name)
                if label == "error":
                    attempts += 1
                    print(f"[{model_key}] Fallo (intento {attempts}/{MAX_RETRIES}). Reintentando en {RETRY_DELAY}s...")
                    time.sleep(RETRY_DELAY)

            if label == "error":
                print(f"[{model_key}] Falló definitivamente tras {MAX_RETRIES} intentos.")
                return "SAVE_AND_EXIT"

            model_results[model_key] = {"label": label, "score": score}
            if label != "not related to automotive" and score > 0.35:
                positive_votes += 1

        # Mayoría simple
        final_result = "RELATED" if positive_votes >= (len(MODELS) / 2) else "NOT_RELATED"
        
        print("\n--- Resultados por modelo ---")
        for model_key, info in model_results.items():
            print(f"{model_key}: {info['label']} ({round(info['score']*100, 2)}%)")
        
        print(f"\n✅ Clasificación Final: {final_result}")
        return final_result