import json
import os
from datetime import date

from utils.RecoverySearch import RecoverySearch
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

def load_and_search_in_category(filename, category):
    if not os.path.exists(filename):
        print("❌ Archivo no encontrado.")
        return

    with open(filename, "r", encoding="utf-8") as f:
        keywords = [line.strip() for line in f if line.strip()]

    if category == "notices":
        # searcher = NoticiasSearcher()
        for keyword in keywords:
            print(f"🔎 Searching news for: {keyword}")
            # results = searcher.search_news(keyword)
            # Utils.save_results(results, "results/news", f"news_{keyword}")
        return
    
    elif category == "documents":
        # searcher = DocumentosSearcher()
        for keyword in keywords:
            print(f"📄 Searching documents for: {keyword}")
            # results = searcher.search_documents(keyword)
            # Utils.save_results(results, "results/documents", f"docs_{keyword}")
        return
    
    elif category == "vulnerabilities":
        searcher = VulnerabilitySearchEngine()
        for keyword in keywords:
            print("antes de añadir")
            print(searcher.vulnerabilities)
            results = searcher.search_vulnerabilities(keyword)
            if results == "SAVE_AND_EXIT":
                print("logica save and exit")
                break
            print("despues de añadir")
            print(searcher.vulnerabilities)
        # Guardar resultados
        #Utils.save_analyzed_cves(searcher.analyzed_cve_ids)
        #Utils.save_results(searcher.vulnerabilities, "results/vulnerabilities", "vulnerabilities")
        #Utils.print_summary(searcher.vulnerabilities, "🔐 Vulnerabilities Found")
        return
    else:
        print("❌ Categoría no reconocida.")
        return

def resume_from_recovery(self, category):
    
    if category == "notices":
        return
    
    elif category == "documents":
        return
    
    elif category == "vulnerabilities":
        recovery = RecoverySearch()
        recovery.load(RECOVERY_PATH_CVE)
        print(recovery)
        #load_and_search_in_category(recovery.remaining_keywords, category)
        return
    else:
        print("❌ Categoría no reconocida.")
        return

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
            load_and_search_in_category(file, "notices")
        elif option == "3":
            file = input("Nombre del archivo de keywords: ")
            load_and_search_in_category(file, "documents")
        elif option == "4":
            file = input("Nombre del archivo de keywords: ")
            load_and_search_in_category(file, "vulnerabilities")
        elif option == "5":
            retomar_busqueda("noticias")
        elif option == "6":
            retomar_busqueda("documentos")
        elif option == "7":
            retomar_busqueda("vulnerabilidades")
        elif option == "8":
            generar_documentacion_apa()
        elif option == "0":
            print("👋 Saliendo...")
            break
        else:
            print("❗ Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()
