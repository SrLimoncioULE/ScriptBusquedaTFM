import json
import os
from datetime import date

from utils.StateManager import StateManager
from utils.VulnerabilitySearchEngine import VulnerabilitySearchEngine
# from utils.NoticeSearcherEngine import NoticeSearcherEngine
# from utils.DocumentSearcherEngine import DocumentSearcherEngine


RECOVERY_PATH_NEWS = "recovery/recovery_notices.json"
RECOVERY_PATH_PAPERS = "recovery/recovery_papers.json"
RECOVERY_PATH_CVE = "recovery/recovery_vulnerabilities.json"


def buscar_en_todo():
    keyword = input("Introduce la palabra clave: ")
    print(f"🔎 Buscando '{keyword}' en noticias, documentos y vulnerabilidades...")
    # TODO: implementar lógica de búsqueda en las tres categorías


def load_keywords_from_file(self, filename):
    if not os.path.exists(filename):
        print("❌ Archivo no encontrado.")
        return

    with open(filename, "r", encoding="utf-8") as f:
        keywords = [line.strip() for line in f if line.strip()]
    
    return keywords


def load_and_search_in_category(keywords, category, searcher=None):

    if not searcher:
        if category == "notices":
            print("⚠️ Módulo de noticias aún no implementado.")
            return
        
        elif category == "documents":
            print("⚠️ Módulo de documentos aún no implementado.")
            return
        
        elif category == "vulnerabilities":
            searcher = VulnerabilitySearchEngine()

        else:
            print("❌ Categoría no reconocida.")
            return
    
    keyword_counter = 0
    remaining_keywords = keywords.copy()

    while remaining_keywords:
        current_keyword = remaining_keywords.pop(0)
        print(f"\n🔎 Buscando '{current_keyword}' en {category}...")
        result = searcher.search(current_keyword)  # Adaptar a categoría si fuera otra

        if result == "SAVE_AND_EXIT":
            remaining_keywords.insert(0, current_keyword)
            StateManager.save_state(
                category=category,
                remaining_keywords=remaining_keywords,
                analiced_ids=searcher.analiced_cve_ids,
                results=searcher.vulnerabilities
            )
            print("⏸️ Búsqueda pausada. Estado guardado.")
            return

        keyword_counter += 1

        if keyword_counter % 5 == 0:
            print(f"💾 Guardando progreso tras {keyword_counter} keywords...")
            StateManager.save_state(
                category=category,
                remaining_keywords=remaining_keywords,
                analiced_ids=searcher.analiced_cve_ids,
                results=searcher.vulnerabilities
            )

    # Guardado final (por si no era múltiplo de 5)
    StateManager.save_state(
        category=category,
        remaining_keywords=[],
        analiced_ids=searcher.analiced_cve_ids,
        results=searcher.vulnerabilities
    )
    print("✅ Búsqueda completada. Estado final guardado.")



def resume_from_recovery(category):
    state = StateManager.load_state(category)
    if not state:
        print("❌ No hay estado para retomar.")
        return

    print(f"🔁 Retomando búsqueda en categoría: '{category}'...")

    remaining_keywords = state.get("remaining_keywords", [])
    analiced_ids = set(state.get("analiced_ids", []))
    results = state.get("results", {})

    if category == "vulnerabilities":
        searcher = VulnerabilitySearchEngine(analiced_cve_ids=analiced_ids, vulnerabilities=results)
        load_and_search_in_category(remaining_keywords, category, searcher)
    else:
        print("⚠️ Solo implementado retomar vulnerabilidades por ahora.")


def generar_documentacion_apa():
    print("📄 Generando documentación en formato APA...")
    # TODO: implementar lógica de generación APA

def cargar_progreso(ruta):
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f).get("index", 0)
    return 0

def guardar_progreso(ruta, index):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump({"index": index}, f)

def show_menu():
    print("\n" + "="*40)
    print("🧠  APLICACIÓN DE BÚSQUEDA INTELIGENTE")
    print("="*40)
    print("📌 Opciones disponibles:\n")
    print(" 1️⃣  🔍 Buscar por palabra clave en las 3 categorías")
    print(" 2️⃣  📥 Cargar keywords desde archivo y buscar en 📰 Noticias")
    print(" 3️⃣  📥 Cargar keywords desde archivo y buscar en 📄 Documentos")
    print(" 4️⃣  📥 Cargar keywords desde archivo y buscar en 🛡️ Vulnerabilidades")
    print(" 5️⃣  🔁 Retomar búsqueda en 📰 Noticias donde se quedó")
    print(" 6️⃣  🔁 Retomar búsqueda en 📄 Documentos donde se quedó")
    print(" 7️⃣  🔁 Retomar búsqueda en 🛡️ Vulnerabilidades donde se quedó")
    print(" 8️⃣  📚 Generar documentación en formato APA")
    print(" 0️⃣  🚪 Salir de la aplicación")
    print("="*40)

def main():
    while True:
        show_menu()
        option = input("Elige una opción: ").strip()

        if option == "1":
            # buscar_en_todo()
            print("De momento solo busca vulnerabilidades")

        elif option == "2":
            file = input("Nombre del archivo de keywords: ")
            keywords = load_keywords_from_file(file)
            if keywords:
                load_and_search_in_category(keywords, "notices")

        elif option == "3":
            file = input("Nombre del archivo de keywords: ")
            keywords = load_keywords_from_file(file)
            if keywords:
                load_and_search_in_category(keywords, "documents")

        elif option == "4":
            file = input("Nombre del archivo de keywords: ")
            keywords = load_keywords_from_file(file)
            if keywords:
                load_and_search_in_category(keywords, None, "vulnerabilities")

        elif option == "5":
            resume_from_recovery("notices")

        elif option == "6":
            resume_from_recovery("documents")

        elif option == "7":
            resume_from_recovery("vulnerabilities")

        elif option == "8":
            generar_documentacion_apa()

        elif option == "0":
            print("👋 Saliendo...")
            break

        else:
            print("❗ Opción no válida. Intenta de nuevo.")


if __name__ == "__main__":
    main()
