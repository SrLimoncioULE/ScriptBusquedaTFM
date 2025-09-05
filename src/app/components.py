import streamlit as st

# --- FUNCIONES COMUNES ---

def mostrar_buscador():
    st.title("Buscador Inteligente")
    keyword = st.text_input("Introduce la palabra clave:")
    file_uploaded = st.file_uploader("O sube un archivo .txt de keywords", type=["txt"])

    category = st.selectbox("Categoria", ["Todas", "Noticias", "Papers", "Vulnerabilidades"])

    
    # Simulamos una base de datos con algunos elementos
    elementos = ["Abyssal Carrier", "Abyssal Destroyer", "Abyssal Battleship", "Abyssal Submarine"]

    # Expander con el buscador desplegable
    with st.expander("Busqueda", expanded=True):
        seleccion = st.selectbox("Selecciona un enemigo", elementos)
        buscar = st.button("Buscar")

    # Mostrar resultado si se pulsó el botón
    if buscar:
        st.session_state.resultado = seleccion  # Guardamos el resultado en session_state

    # Mostrar resultado solo si hay algo guardado
    if "resultado" in st.session_state:
        st.markdown("---")
        st.subheader(f"🧾 Resultado de búsqueda: **{st.session_state.resultado}**")
        # Aquí puedes cargar una imagen o datos del enemigo si quieres



    search_button = st.button("Ejecutar búsqueda")

    st.write(search_button)

    room = st.selectbox("Filter by Room", ["All", "Angel", "Drone", "Tyrannos"])
    tags = st.multiselect(
        "Filter by Tags",
        ["T1", "T2", "T3", "Neut", "Web", "Scram", "Disruption", "RR", "Healer"],
        default=["T1", "T2", "Web", "Scram"]
    )

    st.title("Ejemplo de Checkbox")

    # Checkbox
    mostrar = st.checkbox("Mostrar más opciones")

    # Contenido condicional
    if mostrar:
        st.write("✅ ¡Has activado el contenido adicional!")
        st.text_input("Introduce algo aquí")
        st.slider("Selecciona un valor", 0, 100)


    return keyword
