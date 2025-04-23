import requests
import pandas as pd
import time
from datetime import datetime
import os
import re
from collections import defaultdict
from bs4 import BeautifulSoup

# Configuración inicial

SERPAPI_KEY = '8c773b84f3a28c9de599e573cc0adcb6ed5ee998cbbe6c4621296095ae07e409'

NEWSAPI_KEY = '911291fd807740a1aca40f7ef1436215'

CORE_API_URL = 'https://core.ac.uk:443/api-v2/search/'

CORE_API_KEY = 'PDNbq2zO4pTZcXnAFsK6RIjxw5akmBSd'

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

NVD_API_KEY ='3bc56854-b66b-4996-9047-9c2d3c21f215'

SEMANTIC_SCHOLAR_URL = 'https://api.semanticscholar.org/graph/v1/paper/search'



# Palabras clave excluidas: "car cybersecurity", "automotive cybersecurity", "autonomous vehicle security"

keywords = [

    "vehicle hacking", "cyber attack on cars", "connected car vulnerabilities", "ECU hacking", "CAN bus vulnerabilities", "V2X security"
    "EV charging station hacking", "OBD-II hacking", "TPMS vulnerability",
    "Toyota hacked", "Toyota hacking", "Toyota cyber attack", "Toyota vulnerability", "Toyota exploit", "Toyota breach", "Toyota malware",
    "Honda hacked", "Honda hacking", "Honda cyber attack", "Honda vulnerability", "Honda exploit", "Honda breach", "Honda malware", 
    "Ford hacked", "Ford hacking", "Ford cyber attack", "Ford vulnerability", "Ford exploit", "Ford breach", "Ford malware", 
    "Chevrolet hacked", "Chevrolet hacking", "Chevrolet cyber attack", "Chevrolet vulnerability", "Chevrolet exploit", "Chevrolet breach", "Chevrolet malware", 
    "Nissan hacked", "Nissan hacking", "Nissan cyber attack", "Nissan vulnerability", "Nissan exploit", "Nissan breach", "Nissan malware", 
    "Volkswagen hacked", "Volkswagen hacking", "Volkswagen cyber attack", "Volkswagen vulnerability", "Volkswagen exploit", "Volkswagen breach", "Volkswagen malware", 
    "BMW hacked", "BMW hacking", "BMW cyber attack", "BMW vulnerability", "BMW exploit", "BMW breach", "BMW malware", 
    "Mercedes-Benz hacked", "Mercedes-Benz hacking", "Mercedes-Benz cyber attack", "Mercedes-Benz vulnerability", "Mercedes-Benz exploit", "Mercedes-Benz breach", "Mercedes-Benz malware", 
    "Audi hacked", "Audi hacking", "Audi cyber attack", "Audi vulnerability", "Audi exploit", "Audi breach", "Audi malware", 
    "Hyundai hacked", "Hyundai hacking", "Hyundai cyber attack", "Hyundai vulnerability", "Hyundai exploit", "Hyundai breach", "Hyundai malware", 
    "Kia hacked", "Kia hacking", "Kia cyber attack", "Kia vulnerability", "Kia exploit", "Kia breach", "Kia malware", 
    "Tesla hacked", "Tesla hacking", "Tesla cyber attack", "Tesla vulnerability", "Tesla exploit", "Tesla breach", "Tesla malware", 
    "Volvo hacked", "Volvo hacking", "Volvo cyber attack", "Volvo vulnerability", "Volvo exploit", "Volvo breach", "Volvo malware", 
    "Peugeot hacked", "Peugeot hacking", "Peugeot cyber attack", "Peugeot vulnerability", "Peugeot exploit", "Peugeot breach", "Peugeot malware", 
    "Renault hacked", "Renault hacking", "Renault cyber attack", "Renault vulnerability", "Renault exploit", "Renault breach", "Renault malware", 
    "Fiat hacked", "Fiat hacking", "Fiat cyber attack", "Fiat vulnerability", "Fiat exploit", "Fiat breach", "Fiat malware", 
    "Chrysler hacked", "Chrysler hacking", "Chrysler cyber attack", "Chrysler vulnerability", "Chrysler exploit", "Chrysler breach", "Chrysler malware", 
    "Dodge hacked", "Dodge hacking", "Dodge cyber attack", "Dodge vulnerability", "Dodge exploit", "Dodge breach", "Dodge malware", 
    "Jeep hacked", "Jeep hacking", "Jeep cyber attack", "Jeep vulnerability", "Jeep exploit", "Jeep breach", "Jeep malware", 
    "RAM hacked", "RAM hacking", "RAM cyber attack", "RAM vulnerability", "RAM exploit", "RAM breach", "RAM malware", 
    "GMC hacked", "GMC hacking", "GMC cyber attack", "GMC vulnerability", "GMC exploit", "GMC breach", "GMC malware", 
    "Buick hacked", "Buick hacking", "Buick cyber attack", "Buick vulnerability", "Buick exploit", "Buick breach", "Buick malware", 
    "Mazda hacked", "Mazda hacking", "Mazda cyber attack", "Mazda vulnerability", "Mazda exploit", "Mazda breach", "Mazda malware", 
    "Subaru hacked", "Subaru hacking", "Subaru cyber attack", "Subaru vulnerability", "Subaru exploit", "Subaru breach", "Subaru malware", 
    "Mitsubishi hacked", "Mitsubishi hacking", "Mitsubishi cyber attack", "Mitsubishi vulnerability", "Mitsubishi exploit", "Mitsubishi breach", "Mitsubishi malware", 
    "Land Rover hacked", "Land Rover hacking", "Land Rover cyber attack", "Land Rover vulnerability", "Land Rover exploit", "Land Rover breach", "Land Rover malware", 
    "Jaguar hacked", "Jaguar hacking", "Jaguar cyber attack", "Jaguar vulnerability", "Jaguar exploit", "Jaguar breach", "Jaguar malware", 
    "Porsche hacked", "Porsche hacking", "Porsche cyber attack", "Porsche vulnerability", "Porsche exploit", "Porsche breach", "Porsche malware", 
    "Lexus hacked", "Lexus hacking", "Lexus cyber attack", "Lexus vulnerability", "Lexus exploit", "Lexus breach", "Lexus malware", 
    "Infiniti hacked", "Infiniti hacking", "Infiniti cyber attack", "Infiniti vulnerability", "Infiniti exploit", "Infiniti breach", "Infiniti malware", 
    "Acura hacked", "Acura hacking", "Acura cyber attack", "Acura vulnerability", "Acura exploit", "Acura breach", "Acura malware", 
    "Skoda hacked", "Skoda hacking", "Skoda cyber attack", "Skoda vulnerability", "Skoda exploit", "Skoda breach", "Skoda malware", 
    "SEAT hacked", "SEAT hacking", "SEAT cyber attack", "SEAT vulnerability", "SEAT exploit", "SEAT breach", "SEAT malware", 
    "Citroen hacked", "Citroen hacking", "Citroen cyber attack", "Citroen vulnerability", "Citroen exploit", "Citroen breach", "Citroen malware", 
    "Alfa Romeo hacked", "Alfa Romeo hacking", "Alfa Romeo cyber attack", "Alfa Romeo vulnerability", "Alfa Romeo exploit", "Alfa Romeo breach", "Alfa Romeo malware", 
    "Opel hacked", "Opel hacking", "Opel cyber attack", "Opel vulnerability", "Opel exploit", "Opel breach", "Opel malware", 
    "Mini hacked", "Mini hacking", "Mini cyber attack", "Mini vulnerability", "Mini exploit", "Mini breach", "Mini malware", 
    "Suzuki hacked", "Suzuki hacking", "Suzuki cyber attack", "Suzuki vulnerability", "Suzuki exploit", "Suzuki breach", "Suzuki malware", 
    "Daihatsu hacked", "Daihatsu hacking", "Daihatsu cyber attack", "Daihatsu vulnerability", "Daihatsu exploit", "Daihatsu breach", "Daihatsu malware", 
    "Tata hacked", "Tata hacking", "Tata cyber attack", "Tata vulnerability", "Tata exploit", "Tata breach", "Tata malware", 
    "Mahindra hacked", "Mahindra hacking", "Mahindra cyber attack", "Mahindra vulnerability", "Mahindra exploit", "Mahindra breach", "Mahindra malware", 
    "Geely hacked", "Geely hacking", "Geely cyber attack", "Geely vulnerability", "Geely exploit", "Geely breach", "Geely malware", 
    "BYD hacked", "BYD hacking", "BYD cyber attack", "BYD vulnerability", "BYD exploit", "BYD breach", "BYD malware", 
    "Chery hacked", "Chery hacking", "Chery cyber attack", "Chery vulnerability", "Chery exploit", "Chery breach", "Chery malware", 
    "NIO hacked", "NIO hacking", "NIO cyber attack", "NIO vulnerability", "NIO exploit", "NIO breach", "NIO malware", 
    "Lucid hacked", "Lucid hacking", "Lucid cyber attack", "Lucid vulnerability", "Lucid exploit", "Lucid breach", "Lucid malware", 
    "Rivian hacked", "Rivian hacking", "Rivian cyber attack", "Rivian vulnerability", "Rivian exploit", "Rivian breach", "Rivian malware", 
    "Polestar hacked", "Polestar hacking", "Polestar cyber attack", "Polestar vulnerability", "Polestar exploit", "Polestar breach", "Polestar malware", 
    "VinFast hacked", "VinFast hacking", "VinFast cyber attack", "VinFast vulnerability", "VinFast exploit", "VinFast breach", "VinFast malware", 
    "Bugatti hacked", "Bugatti hacking", "Bugatti cyber attack", "Bugatti vulnerability", "Bugatti exploit", "Bugatti breach", "Bugatti malware", 
    "Ferrari hacked", "Ferrari hacking", "Ferrari cyber attack", "Ferrari vulnerability", "Ferrari exploit", "Ferrari breach", "Ferrari malware", 
    "Lamborghini hacked", "Lamborghini hacking", "Lamborghini cyber attack", "Lamborghini vulnerability", "Lamborghini exploit", "Lamborghini breach", "Lamborghini malware", 
    "McLaren hacked", "McLaren hacking", "McLaren cyber attack", "McLaren vulnerability", "McLaren exploit", "McLaren breach", "McLaren malware", 
    "Pagani hacked", "Pagani hacking", "Pagani cyber attack", "Pagani vulnerability", "Pagani exploit", "Pagani breach", "Pagani malware", 
    "Koenigsegg hacked", "Koenigsegg hacking", "Koenigsegg cyber attack", "Koenigsegg vulnerability", "Koenigsegg exploit", "Koenigsegg breach", "Koenigsegg malware", 
    "Scania hacked", "Scania hacking", "Scania cyber attack", "Scania vulnerability", "Scania exploit", "Scania breach", "Scania malware", 
    "MAN hacked", "MAN hacking", "MAN cyber attack", "MAN vulnerability", "MAN exploit", "MAN breach", "MAN malware", 
    "Dacia hacked", "Dacia hacking", "Dacia cyber attack", "Dacia vulnerability", "Dacia exploit", "Dacia breach", "Dacia malware", 
    "Lada hacked", "Lada hacking", "Lada cyber attack", "Lada vulnerability", "Lada exploit", "Lada breach", "Lada malware"
]


# Diccionarios agrupados por año

news_by_year = defaultdict(list)

papers_by_year = defaultdict(list)

vulns_by_year = defaultdict(list)

vulns_mitre_by_year = defaultdict(list)





def extract_year(text):

    if not text:

        return "Desconocido"

    match = re.search(r'\b(20[0-3][0-9])\b', text)

    return match.group(1) if match else "Desconocido"



def buscar_noticias_serpapi(query):

    print(f"[SerpAPI] Buscando: {query}")

    url = 'https://serpapi.com/search.json'

    start = 0

    total_resultados = 0



    while True:

        params = {

            'q': query,

            'tbm': 'nws',

            'api_key': SERPAPI_KEY,

            'num': 10,

            'start': start

        }

        try:

            resp = requests.get(url, params=params).json()

            resultados = resp.get('news_results', [])

            if not resultados:

                break



            print(f"[SerpAPI] Página {start // 10 + 1} → {len(resultados)} resultados encontrados")

            total_resultados += len(resultados)



            for item in resultados:

                year = extract_year(item.get('date', ''))

                news_by_year[year].append({

                    'Fuente': 'SerpAPI',

                    'Título': item['title'],

                    'URL': item['link'],

                    'Descripción': item.get('snippet', '')

                })



            start += 10

            time.sleep(1)  # pausa para no saturar la API



        except Exception as e:

            print(f"[SerpAPI] Error en página {start // 10 + 1}: {e}")

            break



    print(f"[SerpAPI] Total acumulado: {total_resultados} resultados\n")





def buscar_noticias_newsapi(query):

    print(f"[NewsAPI] Buscando: {query}")

    url = 'https://newsapi.org/v2/everything'

    page = 1

    total_resultados = 0

    max_pages = 5  # el plan gratuito de NewsAPI permite hasta 100 resultados



    while page <= max_pages:

        params = {

            'q': query,

            'language': 'en',

            'apiKey': NEWSAPI_KEY,

            'pageSize': 20,

            'page': page

        }

        try:

            resp = requests.get(url, params=params).json()

            resultados = resp.get('articles', [])

            if not resultados:

                break



            print(f"[NewsAPI] Página {page} → {len(resultados)} resultados")

            total_resultados += len(resultados)



            for item in resultados:

                year = extract_year(item.get('publishedAt', ''))

                news_by_year[year].append({

                    'Fuente': 'NewsAPI',

                    'Título': item['title'],

                    'URL': item['url'],

                    'Descripción': item.get('description', '')

                })



            page += 1

            time.sleep(1)



        except Exception as e:

            print(f"[NewsAPI] Error en página {page}: {e}")

            break



    print(f"[NewsAPI] Total acumulado: {total_resultados} resultados\n")



def buscar_papers_semantic(query):

    print(f"[Semantic Scholar] Buscando: {query}")

    limit = 20  # número de resultados por página

    offset = 0

    total_resultados = 0

    max_total = 100  # puedes ajustar este valor según el uso permitido sin clave



    while offset < max_total:

        params = {

            'query': query,

            'limit': limit,

            'offset': offset,

            'fields': 'title,url,authors,year'

        }

        try:

            resp = requests.get(SEMANTIC_SCHOLAR_URL, params=params).json()

            resultados = resp.get('data', [])

            if not resultados:

                break



            print(f"[Semantic Scholar] Offset {offset} → {len(resultados)} resultados")

            total_resultados += len(resultados)



            for item in resultados:

                year = str(item.get('year', 'Desconocido'))

                authors = ', '.join([a['name'] for a in item['authors']])

                papers_by_year[year].append({

                    'Fuente': 'Semantic Scholar',

                    'Título': item['title'],

                    'URL': item['url'],

                    'Descripción': f"Autores: {authors}"

                })



            offset += limit

            time.sleep(1)



        except Exception as e:

            print(f"[Semantic Scholar] Error en offset {offset}: {e}")

            break



    print(f"[Semantic Scholar] Total acumulado: {total_resultados} resultados\n")





def buscar_cves_nvd(query):

    print(f"[NVD] Buscando: {query}")

    results_per_page = 2000  # máximo permitido por la API
    start_index = 0
    total_resultados = 0

    headers = {
        'apiKey': NVD_API_KEY
    }


    while True:

        params = {
            'keywordSearch': query,
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
        }

        try:
            response = requests.get(NVD_API_URL, params=params)
            resp = response.json()

            resultados = resp.get('vulnerabilities', [])

            if not resultados:
                break

            print(f"[NVD] Página {start_index // results_per_page + 1} → {len(resultados)} resultados")

            total_resultados += len(resultados)

            for item in resultados:

                cve = item.get('cve', {})
                published = cve.get('published', '')
                year = extract_year(published)
                vulns_by_year[year].append({
                    'Fuente': 'NVD',
                    'Título': cve.get('id', 'CVE'),
                    'URL': f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                    'Descripción': cve.get('descriptions', [{}])[0].get('value', '')
                })



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

                description = cols[1].text.strip()

                year = extract_year(cve_id)

                vulns_mitre_by_year[year].append({

                    'Fuente': 'MITRE',

                    'Título': cve_id,

                    'URL': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",

                    'Descripción': description

                })

                total_resultados += 1

        print(f"[MITRE] {total_resultados} resultados encontrados\n")

    except Exception as e:

        print(f"[MITRE] Error: {e}")



def guardar_resultados_por_anio(diccionario, carpeta, nombre):
    os.makedirs(carpeta, exist_ok=True)

    for year, items in diccionario.items():
        print(f"[Guardar] {len(items)} resultados en {nombre}_{year}")
        df = pd.DataFrame(items)
        df.to_csv(f"{carpeta}/{nombre}_{year}.csv", index=False)

        with open(f"{carpeta}/{nombre}_{year}.txt", "w", encoding="utf-8") as f:
            for i, item in enumerate(items, 1):
                f.write(f"{i}. {item['Título']}\n")
                f.write(f"Fuente: {item['Fuente']}\n")
                f.write(f"URL: {item['URL']}\n")
                f.write(f"{item['Descripción']}\n\n")



# Ejecutar búsquedas

print("🚀 Iniciando búsqueda en todas las APIs...\n")

for kw in keywords:
    #buscar_noticias_serpapi(kw)
    #buscar_noticias_newsapi(kw)
    buscar_papers_semantic(kw)

    buscar_cves_nvd(kw)

    buscar_cves_mitre(kw)



# Guardar archivos

print("\n💾 Guardando archivos agrupados por año...\n")

guardar_resultados_por_anio(news_by_year, "resultados/noticias", "noticias")

guardar_resultados_por_anio(papers_by_year, "resultados/papers", "papers")

guardar_resultados_por_anio(vulns_by_year, "resultados/vulnerabilidades", "vulnerabilidades")

guardar_resultados_por_anio(vulns_mitre_by_year, "resultados/mitre", "mitre")



# Resumen final

print("\n📊 Resumen final:")

for dataset, name in [(news_by_year, "Noticias"), (papers_by_year, "Papers"), (vulns_by_year, "Vulnerabilidades"), (vulns_mitre_by_year, "Mitre")]:

    print(f"\n{name}:")

    for year in sorted(dataset.keys()):

        print(f" - {year}: {len(dataset[year])} resultados")



print("\n✅ Proceso completado con éxito.")



#(papers_by_year, "📄 Papers")