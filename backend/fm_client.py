"""
FortiManager JSON-RPC API istemcisi.
Tüm ADOM'ları ve her ADOM'un policy paketlerini çeker,
analyzer.py'nin beklediği formata dönüştürür.
"""

import urllib3
import requests
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class FortiManagerClient:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url = f"https://{host}:{port}/jsonrpc"
        self.username = username
        self.password = password
        self.session_id = None

    # ── Düşük seviye RPC ────────────────────────────────────────────────

    def _rpc(self, method: str, params: list, session: str = None) -> dict:
        payload = {
            "id": 1,
            "method": method,
            "params": params,
            "session": session or self.session_id,
            "verbose": 1,
        }
        resp = requests.post(
            self.base_url,
            json=payload,
            verify=False,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result", [{}])
        if isinstance(result, list):
            result = result[0]
        status = result.get("status", {})
        code = status.get("code", 0)
        if code != 0:
            raise RuntimeError(
                f"FortiManager RPC hatası ({method} {params}): "
                f"code={code} msg={status.get('message', '')}"
            )
        return result.get("data", {}) or {}

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self):
        result = self._rpc(
            "exec",
            [{"url": "/sys/login/user",
              "data": {"user": self.username, "passwd": self.password}}],
            session=None,
        )
        # Session token farklı versiyonlarda result ya da root response'ta olabilir
        # Önce result içinde ara, bulamazsan direkt response'u çek
        resp = requests.post(
            self.base_url,
            json={
                "id": 1,
                "method": "exec",
                "params": [{"url": "/sys/login/user",
                             "data": {"user": self.username, "passwd": self.password}}],
            },
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        self.session_id = body.get("session")
        if not self.session_id:
            raise RuntimeError("FortiManager login başarısız: session token alınamadı")
        log.info("FortiManager login başarılı")

    def logout(self):
        try:
            self._rpc("exec", [{"url": "/sys/logout"}])
        except Exception:
            pass
        self.session_id = None

    # ── ADOM ─────────────────────────────────────────────────────────────

    def get_adoms(self) -> list[str]:
        """Tüm ADOM isimlerini döndürür (yalnızca FortiAnalyzer yönetim ADOM'u hariç)."""
        data = self._rpc("get", [{"url": "/dvmdb/adom", "option": ["count", "object member"]}])
        adoms = []
        for item in (data if isinstance(data, list) else []):
            name = item.get("name", "")
            # Sadece FortiAnalyzer yönetim ADOM'unu atla; "root" dahil diğer tüm ADOM'ları çek
            if name and name.lower() not in ("fortiananalyzer", "fortianalyzer"):
                adoms.append(name)
        return adoms

    # ── Policy paketleri ─────────────────────────────────────────────────

    def get_policy_packages(self, adom: str) -> list[str]:
        """
        Bir ADOM'daki tüm policy paket isimlerini döndürür.
        Klasör (folder) içindeki paketler de dahil edilir.
        """
        data = self._rpc("get", [{"url": f"/pm/pkg/adom/{adom}"}])
        return self._collect_packages(data if isinstance(data, list) else [])

    def _collect_packages(self, items: list) -> list[str]:
        """Düz liste + klasör içi paketleri özyinelemeli toplar."""
        pkgs = []
        for item in items:
            item_type = item.get("type", "pkg")
            name = item.get("name", "")
            if not name:
                continue
            if item_type == "folder":
                # Klasör içindeki subobject'leri de tara
                sub = item.get("subobj", []) or []
                pkgs.extend(self._collect_packages(sub))
            else:
                # "pkg" veya type alanı olmayan her şey kural paketidir
                pkgs.append(name)
        return pkgs

    def get_policies(self, adom: str, package: str) -> list[dict]:
        """Bir policy paketindeki kuralları çeker ve normalize eder."""
        data = self._rpc(
            "get",
            [{"url": f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy",
              "option": ["get reserved"]}],
        )
        raw = data if isinstance(data, list) else []
        return [self._transform_policy(p) for p in raw]

    @staticmethod
    def _transform_policy(pol: dict) -> dict:
        """
        FM API'sinden gelen `[{"name": "all"}]` formatındaki adresleri
        analyzer.py'nin beklediği `["all"]` string listesine çevirir.

        FortiManager bazı alanları integer olarak döndürür:
          action:     1=accept, 0=deny, 6=deny (drop)
          logtraffic: 0=disable, 1=enable, 2=all, 3=utm
          status:     0=disable, 1=enable
        """
        def extract_names(field) -> list[str]:
            if isinstance(field, list):
                result = []
                for item in field:
                    if isinstance(item, dict):
                        result.append(item.get("name", str(item)))
                    else:
                        result.append(str(item))
                return result or ["any"]
            if isinstance(field, str):
                return [field]
            return ["any"]

        # action: integer → string
        action_raw = pol.get("action", "deny")
        if isinstance(action_raw, int):
            action_str = "accept" if action_raw == 1 else "deny"
        else:
            action_str = str(action_raw).lower()

        # logtraffic: integer → string
        log_raw = pol.get("logtraffic", "disable")
        if isinstance(log_raw, int):
            log_map = {0: "disable", 1: "enable", 2: "all", 3: "utm"}
            log_str = log_map.get(log_raw, "disable")
        else:
            log_str = str(log_raw).lower()

        # status: integer → string
        status_raw = pol.get("status", "enable")
        if isinstance(status_raw, int):
            status_str = "enable" if status_raw == 1 else "disable"
        else:
            status_str = str(status_raw).lower()

        return {
            "policyid":   pol.get("policyid", ""),
            "name":       pol.get("name", f"policy-{pol.get('policyid', '?')}"),
            "srcaddr":    extract_names(pol.get("srcaddr", ["all"])),
            "dstaddr":    extract_names(pol.get("dstaddr", ["all"])),
            "service":    extract_names(pol.get("service", ["ALL"])),
            "action":     action_str,
            "logtraffic": log_str,
            "status":     status_str,
            "comments":   pol.get("comments", ""),
        }

    # ── Ana çekme metodu ─────────────────────────────────────────────────

    def fetch_all(self) -> dict:
        """
        Tüm ADOM'ların policy'lerini çekip
        analyzer.py'nin beklediği formatta döndürür:
        {"adoms": [{"name": ..., "customer": ..., "policies": [...]}]}
        """
        self.login()
        try:
            adoms = self.get_adoms()
            log.info(f"FortiManager: {len(adoms)} ADOM bulundu: {adoms}")
            result_adoms = []

            for adom_name in adoms:
                policies = []
                try:
                    packages = self.get_policy_packages(adom_name)
                    log.info(f"  ADOM '{adom_name}': {len(packages)} paket")
                    for pkg in packages:
                        try:
                            pols = self.get_policies(adom_name, pkg)
                            policies.extend(pols)
                            log.info(f"    Paket '{pkg}': {len(pols)} kural")
                        except Exception as e:
                            log.warning(f"    Paket '{pkg}' hata: {e}")
                except Exception as e:
                    log.warning(f"  ADOM '{adom_name}' policy paketi hatası: {e}")

                result_adoms.append({
                    "name":     adom_name,
                    "customer": adom_name,
                    "policies": policies,
                })

            return {"adoms": result_adoms}
        finally:
            self.logout()
