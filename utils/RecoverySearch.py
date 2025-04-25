import os
import json

class RecoverySearch:
    def __init__(self, recovery_file):
        self.recovery_file = recovery_file
        self.remaining_keywords = []
        self.added_cve_ids = set()
        self.partial_results = {}

    def save(self, current_keyword, full_keyword_list, added_cve_ids, results_dict):
        os.makedirs(os.path.dirname(self.recovery_file), exist_ok=True)

        remaining_keywords = full_keyword_list[full_keyword_list.index(current_keyword):]

        recovery = {
            "remaining_keywords": remaining_keywords,
            "added_cve_ids": list(added_cve_ids),
            "partial_results": list(results_dict.values())
        }

        with open(self.recovery_file, "w", encoding="utf-8") as f:
            json.dump(recovery, f, ensure_ascii=False, indent=2)

        print(f"💾 Estado de recuperación guardado en: {self.recovery_file}")

    def load(self):
        if not os.path.exists(self.recovery_file):
            print("❌ No hay archivo de recuperación disponible.")
            return False

        with open(self.recovery_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.remaining_keywords = data["remaining_keywords"]
        self.added_cve_ids = set(data["added_cve_ids"])
        self.partial_results = {item["Title"]: item for item in data["partial_results"]}

        print(f"🔁 Cargado archivo de recuperación: {len(self.remaining_keywords)} keywords pendientes")
        return True

    def cleanup(self):
        if os.path.exists(self.recovery_file):
            os.remove(self.recovery_file)
            print(f"🧹 Archivo de recuperación eliminado: {self.recovery_file}")

    def get_keywords(self):
        return self.remaining_keywords

    def get_results(self):
        return self.partial_results

    def get_added_cves(self):
        return self.added_cve_ids
