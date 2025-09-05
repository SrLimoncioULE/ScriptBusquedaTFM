import os

class DescriptionExtractor:
    def __init__(self, session=None):
        self.session = session

    def _is_text_html(self, r):
        ctype = (r.headers.get("Content-Type") or "").lower()
        return "text/html" in ctype

    def _good_desc(self, s: str) -> str:
        if not s:
            return ""
        txt = " ".join(s.split())
        low = txt.lower()
        bad = ("cookie", "suscríbete", "subscribe", "sign in", "javascript must be enabled")
        if any(b in low for b in bad):
            return ""
        return txt[:400] if len(txt) >= 40 else ""

    def extract(self, url: str, timeout: int = 10):
        from bs4 import BeautifulSoup
        debug = os.getenv("DEBUG_LOGS", "0") == "1"
        try:
            if debug:
                print(f"🌐 Fetch {url}", flush=True)
            r = self.session.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code >= 400 or not self._is_text_html(r):
                if debug:
                    print(f"  ✖ status={r.status_code} ctype={r.headers.get('Content-Type')}", flush=True)
                return {"desc": "", "lang": None, "canonical": None}
            soup = BeautifulSoup(r.text, "html.parser")

            # language
            html_tag = soup.find("html")
            lang = (html_tag.get("lang") or html_tag.get("xml:lang")) if html_tag else None
            if lang:
                lang = lang.strip().lower().split("-")[0]

            # canonical
            lc = soup.find("link", rel=lambda v: v and "canonical" in v.lower())
            canonical = (lc.get("href") or "").strip() if lc else None

            for selector, attr, tagname in [
                ('meta[property="og:description"]', "content", "og:description"),
                ('meta[name="description"]', "content", "meta:description"),
                ('meta[name="twitter:description"]', "content", "twitter:description"),
            ]:
                tag = soup.select_one(selector)
                if tag and tag.get(attr):
                    d = self._good_desc(tag.get(attr))
                    if d:
                        if debug:
                            print(f"  ✓ desc via {tagname} len={len(d)}", flush=True)
                        return {"desc": d, "lang": lang, "canonical": canonical}

            p = soup.find("p")
            if p:
                d = self._good_desc(p.get_text(" "))
                if d:
                    if debug:
                        print(f"  ✓ desc via <p> len={len(d)}", flush=True)
                    return {"desc": d, "lang": lang, "canonical": canonical}
        except Exception as e:
            if debug:
                print(f"  ⚠️ extractor error: {e}", flush=True)
        if debug:
            print("  ↪ no description found", flush=True)
        return {"desc": "", "lang": None, "canonical": None}
