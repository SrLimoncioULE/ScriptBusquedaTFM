import requests
import time
from datetime import datetime
import re
from collections import defaultdict
from bs4 import BeautifulSoup

from metodos import Metodos
from HuggingFaceMultiModel import clasificacion_conjunta

# Configuración inicial

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_API_KEY = '3bc56854-b66b-4996-9047-9c2d3c21f215'

keywords = Metodos.cargar_keywords_desde_txt("keywords.txt")
cve_analizados = Metodos.cargar_cves_analizados()

# Diccionarios agrupados por año
vulns_dict = {}

def extract_year(text):
    if not text:
        return "Desconocido"

    match = re.search(r'\b(20[0-3][0-9])\b', text)
    return match.group(1) if match else "Desconocido"


def buscar_cves_nvd(query):
    print(f"[NVD] Buscando: {query}")

    results_per_page = 2000  # máximo permitido por la API
    start_index = 0
    total_resultados = 0

    headers = {
        'apiKey': NVD_API_KEY
    }

    keywords_strict = ' AND '.join(kw.strip() for kw in query.split())

    while True:
        params = {
            'keywordSearch': keywords_strict,
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
        }

        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers)
            resp = response.json()
            resultados = resp.get('vulnerabilities', [])

            if not resultados:
                break

            print(f"[NVD] Página {start_index // results_per_page + 1} → {len(resultados)} resultados")
            total_resultados += len(resultados)

            for item in resultados:
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'CVE')
                published_raw = cve.get('published', '')
                fecha = datetime.fromisoformat(published_raw)
                year = str(fecha.year)

                descripcion = cve.get('descriptions', [{}])[0].get('value', '')

                # Evita analizar si ya fue procesado
                if cve_id in cve_analizados:
                    continue

                # Clasificación con IA antes de guardar
                es_relacionado = clasificacion_conjunta(cve_id + ". " + descripcion)
                cve_analizados.add(cve_id)

                if es_relacionado == "NO RELACIONADO":
                    continue

                if cve_id in vulns_dict:
                    if "NVD" not in vulns_dict[cve_id]['Fuente']:
                        vulns_dict[cve_id]['Fuente'] += ", NVD"

                else:
                    vulns_dict[cve_id] = {
                        'Fecha': year,
                        'Fuente': 'NVD',
                        'Título': cve_id,
                        'URL': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'Descripción': descripcion
                    }

            if len(resultados) < results_per_page:
                break  # última página

            start_index += results_per_page
            time.sleep(1)

        except Exception as e:
            print(f"[NVD] Error en página {start_index // results_per_page + 1}: {e}")
            break

    print(f"[NVD] Total acumulado: {total_resultados} resultados\n")


def buscar_cves_mitre(query):
    print(f"[MITRE] Buscando: {query}")
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query.replace(' ', '+')}"
    total_resultados = 0

    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        rows = soup.select('table tr')[1:]  # Ignorar encabezado

        for row in rows:
            cols = row.find_all('td')

            if len(cols) == 2:
                cve_id = cols[0].text.strip()
                descripcion = cols[1].text.strip().lower() # Descripcion en minusculas
                query_words = query.lower().split() # Palabras de la busqueda en minusculas
                year = extract_year(cve_id)

                # Comprobamos que la descripcion contenga las palabras de la busqueda, sino descartamos resultado.
                if all(word in descripcion for word in query_words):

                    # Evita analizar si ya fue procesado
                    if cve_id in cve_analizados:
                        continue

                    # Clasificación con IA antes de guardar
                    es_relacionado = clasificacion_conjunta(cve_id + ". " + descripcion)
                    cve_analizados.add(cve_id)

                    if es_relacionado == "NO RELACIONADO":
                        continue

                    if cve_id in vulns_dict:
                        if "MITRE" not in vulns_dict[cve_id]['Fuente']:
                            vulns_dict[cve_id]['Fuente'] += ", MITRE"

                    else:
                        vulns_dict[cve_id] = {
                            'Fecha': year,
                            'Fuente': 'MITRE',
                            'Título': cve_id,
                            'URL': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                            'Descripción': descripcion
                        }

                    total_resultados += 1

        print(f"[MITRE] {total_resultados} resultados encontrados\n")

    except Exception as e:
        print(f"[MITRE] Error: {e}")


print("🚀 Iniciando búsqueda de vulnerabilidades ...\n")

for kw in keywords:
    buscar_cves_nvd(kw)
    buscar_cves_mitre(kw)

# Agrupar por año final
vulns_by_year = defaultdict(list)
for v in vulns_dict.values():
    vulns_by_year[v["Fecha"]].append(v)

# Guardar y mostrar resumen
Metodos.guardar_cves_analizados(cve_analizados)
Metodos.save_resultados_by_year(vulns_by_year, "resultados/vulnerabilidades", "vulnerabilidades")
Metodos.print_resume(vulns_by_year, "🔐 Vulnerabilidades")