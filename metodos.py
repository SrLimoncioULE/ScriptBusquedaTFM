import json
import os
import pandas as pd

class Metodos:

    @staticmethod
    def cargar_keywords_desde_txt(ruta_archivo):
        try:
            with open(ruta_archivo, "r", encoding="utf-8") as f:
                lineas = f.readlines()
            keywords = [linea.strip() for linea in lineas if linea.strip()]
            print(f"🔤 {len(keywords)} palabras clave cargadas desde '{ruta_archivo}'")
            return keywords
        except Exception as e:
            print(f"❌ Error al leer {ruta_archivo}: {e}")
            return []


    @staticmethod
    def save_resultados_by_year(diccionario, carpeta, nombre):
        os.makedirs(carpeta, exist_ok=True)

        for year, items in diccionario.items():

            print(f"[Guardar] {len(items)} resultados en {nombre}_{year}")

            with open(f"{carpeta}/{nombre}_{year}.txt", "w", encoding="utf-8") as f:
                for i, item in enumerate(items, 1):
                    f.write(f"{i}. {item['Título']}\n")
                    f.write(f"Fecha: {item['Fecha']}\n")
                    f.write(f"Fuente: {item['Fuente']}\n")
                    f.write(f"URL: {item['URL']}\n")
                    f.write(f"{item['Descripción']}\n\n")


    @staticmethod
    def cargar_cves_analizados(path="analizados.json"):
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