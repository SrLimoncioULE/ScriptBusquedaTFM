# 1) Crear y activar entorno virtual
python -m venv env310
# Windows:
#   env310\Scripts\activate
# macOS/Linux:
source env310/bin/activate

# 2) Actualizar pip
python -m pip install --upgrade pip

# 3) Instalar dependencias
pip install -r requirements.txt

# 4) (opcional) Instalar PyTorch según tu caso (CPU/GPU)
#    Ejemplos:
#    pip install torch        # CPU simple
#    # o CUDA específica: visita https://pytorch.org/get-started/locally/

# 5) Crear .env en la raíz del proyecto
echo "S2_API_KEY=SD1...tu_clave..." > .env
# (en Windows puedes crear el archivo a mano)

# 6) Ejecutar la app
streamlit run app/main_app.py