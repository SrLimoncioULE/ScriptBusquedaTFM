import json
import os
import tempfile
import re
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# Carpeta base donde se guardan los estados
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
STATE_DIR = Path(PROJECT_ROOT) / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

class StateManager:
    """
    Gestor de estado:
    - Permite "ligar" un basename (sin extensión) por categoría.
    - Todas las escrituras (init/save/patch/mark_*) van SIEMPRE a '<STATE_DIR>/<category>/<basename>.json'.
    - En "retomar", se liga el basename exacto del archivo subido (sin su .json) y se sobreescribe ahí.
    """
    SCHEMA_VERSION = 3

    _BOUND_BASENAME_BY_CATEGORY: Dict[str, str] = {}  # category -> basename (sin extensión)

    # ------------ fechas ------------
    @classmethod
    def _now_iso(cls) -> str:
        return datetime.utcnow().isoformat() + "Z"

    @classmethod
    def _now_ts(cls) -> str:
        if ZoneInfo:
            return datetime.now(ZoneInfo("Europe/Madrid")).strftime("%d-%m-%Y_%H-%M")
        return datetime.now().strftime("%d-%m-%Y_%H-%M")

    # ------------ utilidades de path ------------
    @classmethod
    def _safe_basename(cls, name_wo_ext: str) -> str:
        """Sanitiza el basename (sin extensión) para ser nombre de archivo."""
        base = (name_wo_ext or "").strip()
        base = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-")
        return base or f"state_{cls._now_ts()}"

    @classmethod
    def bind_state_basename(cls, category: str, basename_without_ext: str, seed_dict: Optional[dict] = None) -> Path:
        """
        Liga un basename (sin extensión) a la categoría y, opcionalmente, escribe un estado inicial (seed_dict).
        """
        cat = (category or "").lower()
        safe = cls._safe_basename(basename_without_ext)
        cls._BOUND_BASENAME_BY_CATEGORY[cat] = safe
        path = cls._resolve_state_path(category=cat)
        if seed_dict is not None:
            cls._atomic_write(str(path), seed_dict)
        return path

    @classmethod
    def current_bound_path(cls, category: str) -> Optional[Path]:
        cat = (category or "").lower()
        base = cls._BOUND_BASENAME_BY_CATEGORY.get(cat)
        if not base:
            return None
        p = STATE_DIR / cat / f"{base}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def unbind(cls, category: Optional[str] = None) -> None:
        if category is None:
            cls._BOUND_BASENAME_BY_CATEGORY.clear()
        else:
            cls._BOUND_BASENAME_BY_CATEGORY.pop((category or "").lower(), None)

    @classmethod
    def _resolve_state_path(cls, category: str, timestamp_str: Optional[str] = None) -> Path:
        """
        Resuelve el path de estado:
        - Si hay basename ligado -> '<STATE_DIR>/<category>/<basename>.json'
        - Si no hay ligadura -> usa 'state_<category>_<timestamp_str or now>.json'
        """
        cat = (category or "").lower()
        bound = cls.current_bound_path(cat)
        if bound:
            return bound
        ts = (timestamp_str or cls._now_ts())
        default_basename = f"state_{cat}_{ts}"
        return cls.bind_state_basename(cat, default_basename)

    # ------------ escritura atómica ------------
    @classmethod
    def _atomic_write(cls, file_path: str, data_dict: dict):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(file_path), prefix=".tmp_state_", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data_dict, f, indent=4, ensure_ascii=False)
            os.replace(tmp_path, file_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    # ------------ API pública ------------
    @classmethod
    def init_state(cls, category: str, keywords: list[str] | None, params: dict | None = None, timestamp_str: str | None = None):
        """
        Crea un estado inicial en el fichero resuelto (ligado o por defecto con timestamp).
        """
        state = {
            "version": cls.SCHEMA_VERSION,
            "category": category,
            "status": "RUNNING",
            "params": params or {},
            "remaining_keywords": list(keywords) if keywords else [],
            "current_keyword": None,
            "cursors": {},
            "analiced_ids": [],
            "results": {},
            "engine_state": None,
            "filter_stats": {},
            "progress": {
                "total_keywords": len(keywords) if keywords else 0,
                "processed_keywords": 0,
            },
            "last_error": None,
            "last_saved_at": cls._now_iso(),
        }
        path = cls._resolve_state_path(category, timestamp_str=timestamp_str)
        cls._atomic_write(str(path), state)
        return state

    @classmethod
    def save_state(cls,
                   category: str,
                   remaining_keywords: list | None = None,
                   results: dict | None = None,
                   engine_state: dict | None = None,
                   analiced_ids: list | None = None,
                   timestamp_str: str | None = None,
                   filter_stats: dict | None = None,
                   **extra):
        path = cls._resolve_state_path(category, timestamp_str=timestamp_str)
        status = extra.get("status", "RUNNING")
        params = extra.get("params", {})
        current_keyword = extra.get("current_keyword")
        cursors = extra.get("cursors", {})
        last_error = extra.get("last_error")

        if "progress" in extra:
            progress = extra["progress"]
        else:
            total_kw = len(remaining_keywords) if remaining_keywords else 0
            processed = extra.get("processed_keywords", 0)
            progress = {"total_keywords": total_kw, "processed_keywords": processed}

        state = {
            "version": cls.SCHEMA_VERSION,
            "category": category,
            "status": status,
            "params": params,
            "remaining_keywords": list(remaining_keywords) if remaining_keywords is not None else [],
            "current_keyword": current_keyword,
            "cursors": cursors,
            "analiced_ids": list(analiced_ids) if analiced_ids is not None else [],
            "results": results if results is not None else {},
            "engine_state": engine_state,
            "progress": progress,
            "filter_stats": filter_stats or {},
            "last_error": last_error,
            "last_saved_at": cls._now_iso(),
        }

        known = {"status","params","current_keyword","cursors","progress","last_error","processed_keywords"}
        extras = {k: v for k, v in extra.items() if k not in known}
        if extras:
            state["extras"] = extras

        cls._atomic_write(str(path), state)
        return state

    @classmethod
    def patch_state(cls, category: str, timestamp_str: str | None = None, filter_stats: dict | None = None, **patch):
        path = cls._resolve_state_path(category, timestamp_str=timestamp_str)
        try:
            with open(path, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
        if filter_stats is not None:
            state["filter_stats"] = filter_stats
        state.update(patch)
        state["last_saved_at"] = cls._now_iso()
        cls._atomic_write(str(path), state)
        return state

    @classmethod
    def load_state(cls, category: str) -> dict | None:
        """
        Carga desde el fichero ligado. Si no hay ligadura, NO busca nada (comportamiento estricto).
        """
        path = cls.current_bound_path(category)
        if not path or not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)

        # Normalizaciones mínimas
        state.setdefault("version", 1)
        state.setdefault("status", "RUNNING")
        state.setdefault("params", {})
        state.setdefault("current_keyword", None)
        state.setdefault("cursors", {})
        state.setdefault("analiced_ids", [])
        state.setdefault("results", {})
        state.setdefault("filter_stats", {})
        state.setdefault("engine_state", None)
        if "progress" not in state:
            total = len(state.get("remaining_keywords", []))
            state["progress"] = {"total_keywords": total, "processed_keywords": 0}
        state.setdefault("last_error", None)
        state.setdefault("last_saved_at", cls._now_iso())
        return state

    @classmethod
    def clear_state(cls, category: str):
        path = cls.current_bound_path(category)
        if path and path.exists():
            os.remove(path)

    # ------------ helpers semánticos ------------
    @classmethod
    def mark_error(cls, category: str, timestamp_str: str | None = None, filter_stats: dict | None = None, **extra):
        return cls.patch_state(category, timestamp_str=timestamp_str, status="ERROR", filter_stats=filter_stats, **extra)

    @classmethod
    def mark_completed(cls, category: str, timestamp_str: str | None = None, filter_stats: dict | None = None, **extra):
        return cls.patch_state(category, timestamp_str=timestamp_str, status="COMPLETED", last_error=None, filter_stats=filter_stats, **extra)
