import json
import os
import pandas as pd
import re

class Methods:

    """
        Metodo que carga las palabras que se utilizaran en la busqueda.
    """
    @staticmethod
    def load_keywords_from_txt(path_file):
        try:
            with open(path_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            keywords = [line.strip() for line in lines if line.strip()]
            print(f"🔤 {len(keywords)} keywords load from '{path_file}'")
            return keywords
        except Exception as e:
            print(f"❌ Error when reading {path_file}: {e}")
            return []


    @staticmethod
    def save_results_by_year(dictionary, folder, name):
        os.makedirs(folder, exist_ok=True)
        counter_new_items = 0

        for year, items in dictionary.items():
            filename = f"{folder}/{name}_{year}.json"
            existing_data = []
            existing_titles = set()
            new_items = []

            # Cargar datos existentes si el archivo ya existe.
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as f:
                    try:
                        existing_data = json.load(f)
                        existing_titles = {item["Title"] for item in existing_data}
                    except json.JSONDecodeError:
                        print(f"[Advertencia] El archivo {filename} está corrupto o vacío. Se sobrescribirá.")

            print(f"[Guardar] Añadiendo {len(items)} vulnerabilidades a {name}_{year}")

            # Añadir nuevos ítems y guardar
            for item in items:
                new_item_title = item["Title"]
                if new_item_title not in existing_titles:
                    new_items.append(item)
                    counter_new_items += 1
            
            print(f"[Guardar] Guardando {len(counter_new_items)} vulnerabilidades nuevas en {name}_{year}")

            # Guardar los datos actualizados
            updated_data = existing_data + new_items
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(updated_data, f, ensure_ascii=False, indent=2)


    @staticmethod
    def load_added_cve_ids(path="analizados.json"):
        if not os.path.exists(path):
            return set()
        with open(path, "r", encoding="utf-8") as f:
            return set(json.load(f))
        

    @staticmethod
    def guardar_cves_analizados(cves_set, path="analizados.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(cves_set), f, indent=2)


    @staticmethod
    def print_resume(dataset, name):
        print(f"\n📊 Conteo final de {name}:")

        print("\n" + "=" * 40)
        print(f"{name}")
        print("=" * 40)

        for year in sorted(dataset.keys()):
            print(f" - {year}: {len(dataset[year])} resultados")

        print(f"\n✅ Conteo de {name} completado con éxito.")


    # Metodo que extrae el año de un texto.
    @staticmethod
    def extract_year(text):
        if not text:
            return "Desconocido"

        match = re.search(r'\b(20[0-3][0-9])\b', text)
        return match.group(1) if match else "Desconocido"
