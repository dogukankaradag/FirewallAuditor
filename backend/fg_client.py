"""
FortiGate REST API istemcisi.
Doğrudan FortiGate cihazlarından güvenlik politikalarını çeker.
FortiOS 6.4+ REST API (/api/v2) kullanılır.
"""

import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class FortiGateClient:
    """
    FortiGate REST API istemcisi.
    Token tabanlı kimlik doğrulama (api_key) veya kullanıcı adı/şifre desteklenir.
    """

    def __init__(self, host: str, port: int = 443,
                 username: str = "", password: str = "", api_key: str = ""):
        self.base_url = f"https://{host}:{port}/api/v2"
        self.username = username
        self.password = password
        self.api_key  = api_key
        self.session  = requests.Session()
        self.session.verify = False
        self._logged_in = False

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self):
        if self.api_key:
            # Token kimlik doğrulama — header ile
            self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
            self._logged_in = True
            log.info("FortiGate token ile bağlandı: %s", self.base_url)
            return

        # Kullanıcı adı/şifre ile session cookie
        resp = self.session.post(
            f"{self.base_url}/authentication",
            json={"username": self.username, "secretkey": self.password, "ack_pre_disclaimer": True},
            timeout=30,
        )
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"FortiGate login başarısız: HTTP {resp.status_code}")
        data = resp.json()
        if data.get("http_status") not in (200, None):
            raise RuntimeError(f"FortiGate login hatası: {data.get('error', data)}")
        self._logged_in = True
        log.info("FortiGate kullanıcı/şifre ile bağlandı: %s", self.base_url)

    def _get(self, path: str, params: dict | None = None, timeout: int = 60) -> list | dict:
        """GET /api/v2/{path} → result listesi."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        resp = self.session.get(url, params=params or {}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # FortiGate başarılı yanıtı: {"http_status": 200, "results": [...]}
        if isinstance(data, dict):
            return data.get("results", data)
        return data

    # ── Politika katmanı ──────────────────────────────────────────────────

    def get_vdoms(self) -> list[str]:
        """Mevcut VDOM listesini döner."""
        try:
            data = self._get("cmdb/system/vdom")
            if isinstance(data, list):
                return [d.get("name", "") for d in data if isinstance(d, dict) and d.get("name")]
        except Exception:
            pass
        return ["root"]

    @staticmethod
    def _extract_members(field) -> list[str]:
        """
        FortiGate API addr alanlarını isim listesine çevirir.
        Gelecek format: [{"name": "all", "q_origin_key": "all"}] veya ["all"] veya "all"
        """
        if not field:
            return ["all"]
        if isinstance(field, str):
            return [field]
        if isinstance(field, list):
            result = []
            for item in field:
                if isinstance(item, dict):
                    result.append(item.get("name", item.get("q_origin_key", "")))
                elif isinstance(item, str):
                    result.append(item)
            return result or ["all"]
        return ["all"]

    def get_policies(self, vdom: str = "root") -> list[dict]:
        """
        GET /api/v2/cmdb/firewall/policy?vdom={vdom}
        Normalize edilmiş politika listesi döner.
        """
        try:
            raw = self._get("cmdb/firewall/policy", params={"vdom": vdom})
        except Exception as exc:
            log.warning("FortiGate politika çekilemedi vdom=%s: %s", vdom, exc)
            return []

        policies = []
        for pol in (raw if isinstance(raw, list) else []):
            if not isinstance(pol, dict):
                continue

            action_raw = pol.get("action", "deny")
            if isinstance(action_raw, int):
                action = "accept" if action_raw == 1 else "deny"
            else:
                action = "accept" if str(action_raw).lower() in ("accept", "allow") else "deny"

            status_raw = pol.get("status", "enable")
            status = "enable" if str(status_raw).lower() in ("enable", "1", "enabled") else "disable"

            log_raw = pol.get("logtraffic", "disable")
            if isinstance(log_raw, int):
                logtraffic = {0: "disable", 1: "enable", 2: "all", 3: "utm"}.get(log_raw, "disable")
            else:
                logtraffic = str(log_raw).lower()

            # Güvenlik profilleri
            security_profiles = {
                "av":         str(pol.get("av-profile",          "") or ""),
                "webfilter":  str(pol.get("webfilter-profile",   "") or ""),
                "filefilter": str(pol.get("file-filter-profile", "") or ""),
                "ips":        str(pol.get("ips-sensor",          "") or ""),
                "group":      str(pol.get("profile-group",       "") or ""),
            }

            policies.append({
                "policyid":          pol.get("policyid", pol.get("id", "?")),
                "name":              pol.get("name") or f"policy-{pol.get('policyid', '?')}",
                "srcaddr":           self._extract_members(pol.get("srcaddr")),
                "dstaddr":           self._extract_members(pol.get("dstaddr")),
                "service":           self._extract_members(pol.get("service")),
                "srcintf":           self._extract_members(pol.get("srcintf")),
                "dstintf":           self._extract_members(pol.get("dstintf")),
                "action":            action,
                "logtraffic":        logtraffic,
                "status":            status,
                "comments":          pol.get("comments", ""),
                "security_profiles": security_profiles,
                "_vdom":             vdom,
            })
        return policies

    def fetch_all(self, customer_map: dict | None = None) -> dict:
        """
        Tüm VDOM'lardan politikaları çeker.
        customer_map: {vdom_name: customer_label} — boşsa vdom adı kullanılır.
        Döner: {"vdoms": [{"name": str, "customer": str, "policies": [...]}]}
        """
        self.login()
        vdoms = self.get_vdoms()
        log.info("FortiGate tarama: %d VDOM", len(vdoms))

        result = []
        for vdom in vdoms:
            policies = self.get_policies(vdom)
            customer = (customer_map or {}).get(vdom, vdom)
            log.info("VDOM '%s' → %d kural", vdom, len(policies))
            result.append({
                "name":     vdom,
                "customer": customer,
                "policies": policies,
            })

        return {"vdoms": result}

    # ── Healthcheck ───────────────────────────────────────────────────────

    def get_system_info(self) -> dict:
        """GET /api/v2/monitor/system/status"""
        try:
            data = self._get("monitor/system/status")
            if isinstance(data, dict):
                return {
                    "hostname":   str(data.get("hostname",    "") or ""),
                    "model":      str(data.get("model_name",  data.get("hardware-version", "")) or ""),
                    "serial":     str(data.get("serial",      "") or ""),
                    "version":    str(data.get("version",     "") or ""),
                    "build":      str(data.get("build",       "") or ""),
                    "vdom_count": str(data.get("vdom_count",  "") or ""),
                    "uptime":     str(data.get("up_time",     data.get("uptime", "")) or ""),
                    "ha_mode":    str(data.get("ha_mode",     "") or ""),
                }
        except Exception as exc:
            log.warning("FortiGate sistem bilgisi alınamadı: %s", exc)
        return {}

    def get_licenses(self) -> list:
        """GET /api/v2/monitor/license/status"""
        try:
            data = self._get("monitor/license/status")
            if isinstance(data, dict):
                licenses = []
                for key, val in data.items():
                    if isinstance(val, dict) and "status" in val:
                        exp = val.get("expires", val.get("expire_date", ""))
                        licenses.append({
                            "feature":     key,
                            "description": str(val.get("type", val.get("desc", "")) or ""),
                            "expires":     str(exp or ""),
                            "expired":     str(val.get("status", "")).lower() in ("expired", "invalid"),
                        })
                return licenses
        except Exception as exc:
            log.warning("FortiGate lisans bilgisi alınamadı: %s", exc)
        return []

    def healthcheck(self) -> dict:
        self.login()
        return {
            "platform": "fortigate",
            "info":     self.get_system_info(),
            "licenses": self.get_licenses(),
        }
