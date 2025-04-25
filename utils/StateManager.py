import json
import os

class StateManager:

    BASE_PATH = "data"

    @classmethod
    def _get_file_path(cls, category):
        """
        Devuelve la ruta del archivo de estado para una categoría específica.
        """

        filename = f"state_{category.lower()}.json"
        return os.path.join(cls.BASE_PATH, filename)


    @classmethod
    def save_state(cls, category, remaining_keywords, analiced_ids, results):
        """
        Guarda el estado actual para una categoría (vulnerabilities, news, papers).
        """

        os.makedirs(cls.BASE_PATH, exist_ok=True)

        state = {
            "remaining_keywords": list(remaining_keywords),
            "analiced_ids": list(analiced_ids),
            "results": results
        }

        file_path = cls._get_file_path(category)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=4)

        print(f"💾 Estado guardado para categoría '{category}'.")


    @classmethod
    def load_state(cls, category):
        """
        Carga el estado guardado de una categoría, si existe.
        """
        file_path = cls._get_file_path(category)
        if not os.path.exists(file_path):
            print(f"⚠️ No hay estado guardado para categoría '{category}'.")
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            state = json.load(f)

        print(f"🔄 Estado cargado para categoría '{category}'.")
        return state


    @classmethod
    def clear_state(cls, category):
        """
        Elimina el archivo de estado de una categoría.
        """

        file_path = cls._get_file_path(category)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"🗑️ Estado eliminado para categoría '{category}'.")
