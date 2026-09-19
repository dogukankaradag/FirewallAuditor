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

            rules.append({
                "name":        name,
                "source":      self._get_members(entry, "source"),
                "destination": self._get_members(entry, "destination"),
                "application": self._get_members(entry, "application"),
                "service":     self._get_members(entry, "service"),
                "from_zones":  self._get_members(entry, "from"),
                "to_zones":    self._get_members(entry, "to"),
                "action":      action,
                "log_start":   log_start,
                "log_end":     log_end,
                "disabled":    disabled,
                "description": description,
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
            rules = self._parse_security_rules(entry)
            log.info(f"  vsys '{vsys_name}': {len(rules)} kural")
            vsys_list.append({
                "name":     vsys_name,
                "customer": vsys_name,
                "rules":    rules,
            })

        return {"vsys_list": vsys_list}
