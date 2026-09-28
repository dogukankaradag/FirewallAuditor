"""
Palo Alto PAN-OS XML API istemcisi.
Tek bir API çağrısıyla tüm vsys'lerin security rule'larını çeker,
analyzer.py'nin beklediği formata dönüştürür.
"""

import urllib3
import requests
import xml.etree.ElementTree as ET
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class PaloAltoClient:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url = f"https://{host}:{port}/api"
        self.username = username
        self.password = password
        self.api_key = None

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self):
        """API key alır."""
        resp = requests.get(
            self.base_url,
            params={
                "type": "keygen",
                "user": self.username,
                "password": self.password,
            },
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        status = root.get("status", "")
        if status != "success":
            msg = root.findtext(".//msg", default="bilinmeyen hata")
            raise RuntimeError(f"Palo Alto login başarısız: {msg}")
        self.api_key = root.findtext(".//key")
        if not self.api_key:
            raise RuntimeError("Palo Alto API key alınamadı")
        log.info("Palo Alto login başarılı")

    # ── Yardımcı ─────────────────────────────────────────────────────────

    def _api_get(self, params: dict, timeout: int = 120) -> ET.Element:
        params["key"] = self.api_key
        resp = requests.get(
            self.base_url,
            params=params,
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        status = root.get("status", "")
        if status != "success":
            msg = root.findtext(".//msg", default="bilinmeyen hata")
            raise RuntimeError(f"Palo Alto API hatası: {msg}")
        return root

    @staticmethod
    def _get_members(element: ET.Element | None, tag: str) -> list[str]:
        """
        <tag><member>val1</member><member>val2</member></tag>
        yapısını ["val1", "val2"] listesine çevirir.
        Element ya da tag bulunamazsa ["any"] döner.
        """
        if element is None:
            return ["any"]
        container = element.find(tag)
        if container is None:
            return ["any"]
        members = [m.text or "" for m in container.findall("member") if m.text]
        return members if members else ["any"]

    @staticmethod
    def _extract_security_profiles(entry: ET.Element) -> dict:
        """
        <profile-setting> bloğundan güvenlik profillerini çıkarır.

        İki format desteklenir:
          1. Grup profili: <profile-setting><group><member>group-name</member></group></profile-setting>
          2. Tekil profiller: <profile-setting><profiles><virus>...</virus><url-filtering>...</url-filtering>...</profiles></profile-setting>

        Döner:
          {
            "av": str,          # Antivirus profil adı (boş = yok)
            "webfilter": str,   # URL Filtering profil adı
            "filefilter": str,  # File Blocking profil adı
            "ips": str,         # IPS (vulnerability/spyware) profil adı
            "group": str,       # Profil grubu adı (varsa)
          }
        """
        result = {"av": "", "webfilter": "", "filefilter": "", "ips": "", "group": ""}

        ps = entry.find("profile-setting")
        if ps is None:
            return result

        # Grup profili
        group_el = ps.find("group")
        if group_el is not None:
            members = group_el.findall("member")
            if members and members[0].text:
                result["group"] = members[0].text.strip()
            return result

        # Tekil profiller
        profiles_el = ps.find("profiles")
        if profiles_el is None:
            return result

        # Antivirus: <virus><member>prof-name</member></virus>
        virus_el = profiles_el.find("virus")
        if virus_el is not None:
            m = virus_el.find("member")
            if m is not None and m.text:
                result["av"] = m.text.strip()

        # URL Filtering / Web Filter: <url-filtering>
        url_el = profiles_el.find("url-filtering")
        if url_el is not None:
            m = url_el.find("member")
            if m is not None and m.text:
                result["webfilter"] = m.text.strip()

        # File Blocking: <file-blocking>
        fb_el = profiles_el.find("file-blocking")
        if fb_el is not None:
            m = fb_el.find("member")
            if m is not None and m.text:
                result["filefilter"] = m.text.strip()

        # IPS — vulnerability profile: <vulnerability>
        vuln_el = profiles_el.find("vulnerability")
        if vuln_el is not None:
            m = vuln_el.find("member")
            if m is not None and m.text:
                result["ips"] = m.text.strip()

        # IPS — spyware (anti-spyware): <spyware>
        if not result["ips"]:
            spy_el = profiles_el.find("spyware")
            if spy_el is not None:
                m = spy_el.find("member")
                if m is not None and m.text:
                    result["ips"] = m.text.strip()

        return result

    # ── Rule parse ───────────────────────────────────────────────────────

    def _parse_security_rules(self, vsys_entry: ET.Element) -> list[dict]:
        """Bir vsys entry elementinden security rule listesi üretir."""
        rules = []
        rulebase = vsys_entry.find("rulebase/security/rules")
        if rulebase is None:
            return rules

        for entry in rulebase.findall("entry"):
            name = entry.get("name", "")

            # disabled: <disabled>yes</disabled>
            disabled_el = entry.find("disabled")
            disabled = (disabled_el is not None and
                        (disabled_el.text or "").strip().lower() == "yes")

            # log
            log_start_el = entry.find("log-start")
            log_end_el   = entry.find("log-end")
            log_start = (log_start_el is not None and
                         (log_start_el.text or "").strip().lower() == "yes")
            log_end   = (log_end_el is not None and
                         (log_end_el.text or "").strip().lower() == "yes")

            # action: <action>allow</action>
            action_el = entry.find("action")
            action = (action_el.text or "deny").strip().lower() if action_el is not None else "deny"

            # description
            desc_el = entry.find("description")
            description = (desc_el.text or "").strip() if desc_el is not None else ""

            # security profiles
            security_profiles = self._extract_security_profiles(entry)

            rules.append({
                "name":               name,
                "source":             self._get_members(entry, "source"),
                "destination":        self._get_members(entry, "destination"),
                "application":        self._get_members(entry, "application"),
                "service":            self._get_members(entry, "service"),
                "from_zones":         self._get_members(entry, "from"),
                "to_zones":           self._get_members(entry, "to"),
                "action":             action,
                "log_start":          log_start,
                "log_end":            log_end,
                "disabled":           disabled,
                "description":        description,
                "security_profiles":  security_profiles,
            })
        return rules

    # ── Ana çekme metodu ─────────────────────────────────────────────────

    def fetch_all(self) -> dict:
        """
        Tek API çağrısıyla tüm vsys'leri ve security rule'larını çeker.
        analyzer.py'nin beklediği formatta döndürür:
        {"vsys_list": [{"name": ..., "customer": ..., "rules": [...]}]}
        """
        self.login()

        # Tek seferde tüm vsys + rulebase
        root = self._api_get(
            {
                "type":   "config",
                "action": "get",
                "xpath":  "/config/devices/entry/vsys/entry",
            },
            timeout=120,
        )

        vsys_list = []
        # Yanıt: <response><result><entry name="vsys1">...</entry>...</result></response>
        result_el = root.find("result")
        if result_el is None:
            log.warning("Palo Alto yanıtında <result> bulunamadı")
            return {"vsys_list": vsys_list}

        entries = result_el.findall("entry")
        log.info(f"Palo Alto: {len(entries)} vsys bulundu")

        for entry in entries:
            vsys_name = entry.get("name", "vsys?")
            display_name_el = entry.find("display-name")
            display_name = display_name_el.text.strip() if display_name_el is not None and display_name_el.text else ""
            customer_label = f"{display_name} ({vsys_name})" if display_name else vsys_name
            rules = self._parse_security_rules(entry)
            log.info(f"  vsys '{vsys_name}' ({display_name}): {len(rules)} kural")
            vsys_list.append({
                "name":     vsys_name,
                "customer": customer_label,
                "rules":    rules,
            })

        return {"vsys_list": vsys_list}
