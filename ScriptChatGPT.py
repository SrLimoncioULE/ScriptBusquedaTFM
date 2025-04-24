import requests

HUGGINGFACE_TOKEN = "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"


def clasificar_con_huggingface(texto):
    API_URL = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
    headers = {"Authorization": f"Bearer {HUGGINGFACE_TOKEN}"}

    payload = {
        "inputs": texto,
        "parameters": {
            "candidate_labels": [
                "relacionado con ciberseguridad automotriz",
                "no relacionado"
            ],
            "multi_label": False
        }
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        result = response.json()

        # Escogemos la etiqueta más probable
        if "labels" in result:
            top_label = result["labels"][0]
            top_score = result["scores"][0]
            print(f"[HF] Clasificado como: {top_label} ({round(top_score*100, 2)}%)")
            return top_label, top_score
        else:
            print("[HF] Error en la respuesta:", result)
            return "desconocido", 0.0

    except Exception as e:
        print(f"[HF] Error al consultar HuggingFace: {e}")
        return "error", 0.0