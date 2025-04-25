def _save_recovery_state(self):
        os.makedirs("recovery", exist_ok=True)
        recovery = {
            "keyword": self.keyword,
            "added_cve_ids": list(self.added_cve_ids),
            "partial_results": list(self.vulnerabilities.values())
        }
        with open(self.recovery_path, "w", encoding="utf-8") as f:
            json.dump(recovery, f, ensure_ascii=False, indent=2)
        print(f"💾 Estado guardado en '{self.recovery_path}'")


    def resume_from_recovery(self):
        if not os.path.exists(self.recovery_path):
            print("❌ No hay estado de recuperación.")
            return []

        with open(self.recovery_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.keyword = data["keyword"]
        self.added_cve_ids = set(data["added_cve_ids"])
        self.vulnerabilities = {item["Title"]: item for item in data["partial_results"]}

        print(f"🔁 Reanudando búsqueda desde: '{self.keyword}'")
        result = self.search_vulnerabilities(self.keyword, from_resume=True)

        os.remove(self.recovery_path)
        print(f"🧹 Archivo de recuperación eliminado.")
        return result