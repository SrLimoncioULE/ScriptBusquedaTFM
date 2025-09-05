import streamlit as st
import pandas as pd
from st_aggrid import AgGrid, GridOptionsBuilder


class LogManager:
    def __init__(self, state_area=None, summary_config_area=None, ia_classifier_area=None, 
                 resume_filters_area=None, results_area=None):
        
        # Status area
        self.state_logs = []
        self.state_area = state_area or st.empty()


        # Summary Config area
        self.config_summary = ""
        self.summary_config_area = summary_config_area or st.empty()

        # IA Classifier area
        self.ia_classifier_logs = []
        self.ia_classifier_area = ia_classifier_area or st.empty()
        self.max_ia_classifier_logs = 10

        # Resume Filters area
        self.resumes_filters = []
        self.resume_filters_area = resume_filters_area or st.empty()

        # Results area
        self.result_tables = {}
        self.results_area = results_area or st.empty()


    # 1. Añadir estados tipo: 'Iniciando búsqueda...'
    def log_state(self, message: str):
        self.state_logs.append(message)
        self._refresh_state_display()


    # 1.1 Eliminar el ultimo estado
    def remove_last_states(self, n=1):
        if n > 0:
            self.state_logs = self.state_logs[:-n]
            self._refresh_state_display()


    def _refresh_state_display(self):
        """Muestra todos los mensajes actuales en el placeholder dentro del expander"""
        if self.state_area:
            content = "  \n".join(f"{msg}" for msg in self.state_logs)
            self.state_area.markdown(content)

    
    # 2. Mostrar resumen de configuración
    def show_config_summary(self, markdown_str: str):
        self.config_summary = markdown_str
        if self.summary_config_area:
            self.summary_config_area.empty()
            with self.summary_config_area:
                st.markdown("#### ⚙️ Resumen de configuración actual")
                st.markdown(self.config_summary)

    
    # 3. Añadir logs del clasificador IA (últimos 10)
    def log_ia(self, message: str = ""):
        # Guardamos el mensaje en la lista de logs
        self.ia_classifier_logs.append(message)
        self.ia_classifier_logs = self.ia_classifier_logs[-self.max_ia_classifier_logs:]

        if self.ia_classifier_area:
            content = "  \n".join(f"{msg}" for msg in self.ia_classifier_logs)
            self.ia_classifier_area.markdown(content)


    # 4. Mostrar resumen del filtrado
    def show_filter_resume(self, summary_dict: dict):
        if self.resume_filters_area:
            self.resume_filters_area.empty()
            with self.resume_filters_area:
                st.markdown("### 📊 Resumen del filtrado")
                st.write(summary_dict)


    # 5. Mostrar resultado final (DataFrame)
    def show_results(self, category, df: pd.DataFrame):
        self.result_tables[category] = df


    def render_all_tables(self):
        if self.results_area:
            for category, df in self.result_tables.items():
                if df is not None and not df.empty:
                    with self.results_area.expander(f"📊 Resultados en {category.capitalize()}:", expanded=True):
                        gb = GridOptionsBuilder.from_dataframe(df)
                        gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=10)
                        gb.configure_side_bar()
                        grid_options = gb.build()

                        unique_key = f"aggrid_results_{category}"
                        AgGrid(df, gridOptions=grid_options, height=500, theme="alpine-dark", fit_columns_on_grid_load=False, key=unique_key)

