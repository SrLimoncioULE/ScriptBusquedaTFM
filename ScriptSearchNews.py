import requests
import time
from datetime import datetime
import re
from collections import defaultdict
from bs4 import BeautifulSoup

from utils.metodos import Metodos


# Configuración inicial
NEWSAPI_URL = 'https://newsapi.org/v2/everything'
NEWSAPI_KEY = '911291fd807740a1aca40f7ef1436215'


keywords = Metodos.cargar_keywords_desde_txt("keywords.txt")


# Diccionario agrupado por año
news_dict = {}
news_by_year = defaultdict(list)
urls_guardadas = set() # Evitar noticias duplicadas


def extract_year(text):
    if not text:
        return "Desconocido"

    match = re.search(r'\b(20[0-3][0-9])\b', text)
    return match.group(1) if match else "Desconocido"


def buscar_noticias_newsapi(query):
    print(f"[NewsAPI] Buscando: {query}")

    page = 1
    total_resultados = 0
    max_pages = 5  # el plan gratuito de NewsAPI permite hasta 100 resultados

    while page <= max_pages:
        print('"' + query + '"')
        params = {
            'qInTitle': '(seat AND (hacked OR breach OR attack))',
            'language': 'en',
            'apiKey': NEWSAPI_KEY,
            'pageSize': 20,
            'page': page
        }

        try:
            resp = requests.get(NEWSAPI_URL, params=params).json()
            resultados = resp.get('articles', [])
            
            if not resultados:
                break

            print(f"[NewsAPI] Página {page} → {len(resultados)} resultados")
            total_resultados += len(resultados)

            for item in resultados:
                url = item.get('url')
                if url in urls_guardadas:
                    continue  # noticia ya procesada

                fecha_raw = item.get('publishedAt', '')
                fecha = datetime.strptime(fecha_raw, "%Y-%m-%dT%H:%M:%SZ")
                solo_fecha = str(fecha.day) + '/' + str(fecha.month) + '/' + str(fecha.year)
                year = extract_year(fecha_raw)

                noticia = {
                    'Título': item['title'],
                    'URL': url,
                    'Fecha': solo_fecha,
                    'Fuente': 'NewsAPI',
                    'Descripción': item.get('description', '')
                }
                news_by_year[year].append(noticia)
                urls_guardadas.add(url)

            page += 1
            time.sleep(1)

        except Exception as e:
            print(f"[NewsAPI] Error en página {page}: {e}")
            break

    print(f"[NewsAPI] Total acumulado: {total_resultados} resultados\n")



print("🚀 Iniciando búsqueda de noticias ...\n")

for kw in keywords:
    buscar_noticias_newsapi(kw)

# Agrupar por año final
vulns_by_year = defaultdict(list)
for v in news_dict.values():
    vulns_by_year[v["Año"]].append(v)

# Guardar y mostrar resumen
Metodos.save_resultados_by_year(news_by_year, "resultados/noticias", "noticias")
Metodos.print_resume(news_by_year, "📰 Noticias")