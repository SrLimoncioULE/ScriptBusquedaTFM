import requests
import time

HUGGINGFACE_TOKEN = "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"

MODELOS = {
    "bart": "facebook/bart-large-mnli",
    "deberta": "MoritzLaurer/mDeBERTa-v3-base-mnli-xnli",
    "roberta": "joeddav/xlm-roberta-large-xnli"
}

HEADERS = {"Authorization": f"Bearer {HUGGINGFACE_TOKEN}"}

LABELS = [
    "vulnerability in connected or autonomous vehicle",
    "vulnerability in automotive embedded system (ECU, CAN, ADAS, etc.)",
    "vulnerability in automotive backend or infrastructure (telematics, MQTT, V2X)",
    "vulnerability in automotive supplier or factory",
    "not related to automotive"
]

MAX_RETRIES = 5  # Reintentos por modelo
RETRY_DELAY = 5  # Segundos entre reintentos

def clasificar_texto(texto, modelo):
    api_url = f"https://api-inference.huggingface.co/models/{modelo}"
    payload = {
        "inputs": texto,
        "parameters": {
            "candidate_labels": LABELS,
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


def clasificacion_conjunta(texto):
    resultados = {}
    votos_positivos = 0

    for nombre, modelo in MODELOS.items():
        intentos = 0
        etiqueta, puntuacion = "error", 0.0

        while etiqueta == "error" and intentos < MAX_RETRIES:
            etiqueta, puntuacion = clasificar_texto(texto, modelo)
            if etiqueta == "error":
                intentos += 1
                print(f"[{nombre}] Fallo (intento {intentos}/{MAX_RETRIES}). Reintentando en {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)

        if etiqueta == "error":
            print(f"[{nombre}] Falló definitivamente tras {MAX_RETRIES} intentos.")
            return "CLASIFICACIÓN ABORTADA POR FALLO DE MODELOS"

        resultados[nombre] = {"etiqueta": etiqueta, "puntuacion": puntuacion}
        if etiqueta != "not related to automotive":
            if puntuacion > 0.4:
                votos_positivos += 1

    # Mayoría simple
    resultado_final = "RELACIONADO" if votos_positivos >= (len(MODELOS) / 2) else "NO RELACIONADO"
    
    print("\n--- Resultados por modelo ---")
    for nombre, info in resultados.items():
        print(f"{nombre}: {info['etiqueta']} ({round(info['puntuacion']*100, 2)}%)")
    
    print(f"\n✅ Clasificación Final: {resultado_final}")
    return resultado_final