"""
FortiManager JSON-RPC API istemcisi.

Response yapısı:
  POST /jsonrpc → {"result": [{"status": {"code": 0}, "data": [...]}]}
  ADOM listesi : result[0].data[].name
  Policy pkg   : result[0].data[].name
  Policies     : result[0].data[].policyid / .srcaddr / .dstaddr / ...
"""

import logging
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class FortiManagerClient:
    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self.base_url   = f"https://{host}:{port}/jsonrpc"
        self.username   = username
        self.password   = password
        self.session_id: str | None = None

    # ──────────────────────────────────────────────────────────────────────
    #  Düşük seviye katman
    # ──────────────────────────────────────────────────────────────────────

    def _post(self, payload: dict) -> dict:
        """Ham HTTP POST — response dict döndürür."""
        resp = requests.post(
            self.base_url,
            json=payload,
            verify=False,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def _rpc(self, method: str, params: list) -> Any:
        """
        JSON-RPC çağrısı yapar.

        Dönen değer result[0].data içeriğidir:
          - Liste  → list
          - Dict   → dict
          - None   → None   (veri yoksa)

        Hata kodu != 0 ise RuntimeError fırlatır.
        """
        payload = {
            "id":      1,
            "method":  method,
            "params":  params,
            "session": self.session_id,
            "verbose": 1,
        }
        body    = self._post(payload)
        results = body.get("result", [])
        result  = results[0] if isinstance(results, list) and results else {}

        status  = result.get("status", {})
        code    = status.get("code", 0)
        if code != 0:
            raise RuntimeError(
                f"FortiManager RPC hatası — method={method} "
                f"url={params[0].get('url') if params else '?'} "
                f"code={code} msg={status.get('message', '')}"
            )

        # KRITIK: data None / [] / {} hepsini olduğu gibi döndür
        # "or {}" kullanma — boş listeyi {}'ye dönüştürür!
        return result.get("data")

    def _as_list(self, data: Any) -> list:
        """_rpc'den gelen veriyi güvenle listeye çevirir."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []

    # ──────────────────────────────────────────────────────────────────────
    #  Auth
    # ──────────────────────────────────────────────────────────────────────

    def login(self) -> None:
        """
        FortiManager'a bağlanır; session token'ı kök response'tan alır.
        result[0].data değil, response.session alanı kullanılır.
        """
        body = self._post({
            "id":     1,
            "method": "exec",
            "params": [{"url": "/sys/login/user",
                        "data": {"user": self.username, "passwd": self.password}}],
        })

        # Oturum token'ı kök response'ta
        self.session_id = body.get("session")
        if not self.session_id:
            raise RuntimeError("FortiManager login başarısız: session token alınamadı")

        log.info("FortiManager login başarılı (session=%s…)", self.session_id[:8])

    def logout(self) -> None:
        try:
            self._rpc("exec", [{"url": "/sys/logout"}])
        except Exception:
            pass
        self.session_id = None
        log.info("FortiManager logout")

    # ──────────────────────────────────────────────────────────────────────
    #  ADOM katmanı
    # ──────────────────────────────────────────────────────────────────────

    def get_adoms(self) -> list[str]:
        """
        GET /dvmdb/adom → result[0].data[].name

        FortiAnalyzer yönetim ADOM'u hariç tüm ADOM isimleri döner.
        "root" dahil.
        """
        data  = self._rpc("get", [{"url": "/dvmdb/adom"}])
        items = self._as_list(data)

        skip  = {"fortiananalyzer", "fortianalyzer"}
        adoms = [
            item["name"]
            for item in items
            if isinstance(item, dict)
            and item.get("name", "").strip()
            and item["name"].lower() not in skip
        ]

        log.info("get_adoms → %d ADOM: %s", len(adoms), adoms)
        return adoms

    # ──────────────────────────────────────────────────────────────────────
    #  Policy paketi katmanı
    # ──────────────────────────────────────────────────────────────────────

    def get_policy_packages(self, adom: str) -> list[str]:
        """
        GET /pm/pkg/adom/{adom} → result[0].data[].name

        Klasör (type=folder) içindeki paketler özyinelemeli eklenir.
        """
        data  = self._rpc("get", [{"url": f"/pm/pkg/adom/{adom}"}])
        items = self._as_list(data)
        pkgs  = self._collect_packages(items)

        log.info("get_policy_packages(%s) → %d paket: %s", adom, len(pkgs), pkgs)
        return pkgs

    def _collect_packages(self, items: list) -> list[str]:
        """Düz ve klasör içi paketleri özyinelemeli toplar."""
        pkgs = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name      = item.get("name", "").strip()
            item_type = item.get("type", "pkg")
            if not name:
                continue
            if item_type == "folder":
                sub = self._as_list(item.get("subobj"))
                pkgs.extend(self._collect_packages(sub))
            else:
                pkgs.append(name)
        return pkgs

    # ──────────────────────────────────────────────────────────────────────
    #  Policy (kural) katmanı
    # ──────────────────────────────────────────────────────────────────────

    def get_policies(self, adom: str, package: str) -> list[dict]:
        """
        GET /pm/config/adom/{adom}/pkg/{package}/firewall/policy
        → result[0].data[]

        Ham kuralları normalize edilmiş dict listesine dönüştürür.
        """
        data = self._rpc(
            "get",
            [{"url": f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy",
              "option": ["get reserved"]}],
        )
        raw = self._as_list(data)
        policies = [self._normalize_policy(p) for p in raw if isinstance(p, dict)]

        log.info("get_policies(%s, %s) → %d kural", adom, package, len(policies))
        return policies

    @staticmethod
    def _normalize_policy(pol: dict) -> dict:
        """
        FortiManager API çıktısını analyzer.py'nin beklediği formata çevirir.

        FM API integer döndürebilir:
          action:     1=accept  0/6=deny
          logtraffic: 0=disable 1=enable 2=all 3=utm
          status:     0=disable 1=enable
        Adres/servis alanları [{"name": "all"}] formatında gelir → ["all"]
        """

        def extract_names(field: Any, fallback: str = "any") -> list[str]:
            if isinstance(field, list):
                names = []
                for item in field:
                    names.append(item["name"] if isinstance(item, dict) else str(item))
                return names or [fallback]
            if isinstance(field, str):
                return [field]
            return [fallback]

        # action
        action_raw = pol.get("action", "deny")
        if isinstance(action_raw, int):
            action = "accept" if action_raw == 1 else "deny"
        else:
            action = str(action_raw).lower()

        # logtraffic
        log_raw = pol.get("logtraffic", "disable")
        if isinstance(log_raw, int):
            log_map = {0: "disable", 1: "enable", 2: "all", 3: "utm"}
            logtraffic = log_map.get(log_raw, "disable")
        else:
            logtraffic = str(log_raw).lower()

        # status
        status_raw = pol.get("status", "enable")
        if isinstance(status_raw, int):
            status = "enable" if status_raw == 1 else "disable"
        else:
            status = str(status_raw).lower()

        return {
            "policyid":   pol.get("policyid", ""),
            "name":       pol.get("name") or f"policy-{pol.get('policyid', '?')}",
            "srcaddr":    extract_names(pol.get("srcaddr"), fallback="all"),
            "dstaddr":    extract_names(pol.get("dstaddr"), fallback="all"),
            "service":    extract_names(pol.get("service"), fallback="ALL"),
            "action":     action,
            "logtraffic": logtraffic,
            "status":     status,
            "comments":   pol.get("comments", ""),
        }

    # ──────────────────────────────────────────────────────────────────────
    #  Ana çekme metodu
    # ──────────────────────────────────────────────────────────────────────

    def fetch_all(self) -> dict:
        """
        Tüm ADOM'ların tüm policy paketlerindeki kuralları çeker.

        Dönen format (analyzer.py ile uyumlu):
          {"adoms": [{"name": str, "customer": str, "policies": [...]}, ...]}
        """
        self.login()
        try:
            adoms        = self.get_adoms()
            result_adoms = []

            for adom_name in adoms:
                policies: list[dict] = []
                try:
                    packages = self.get_policy_packages(adom_name)
                    for pkg in packages:
                        try:
                            pols = self.get_policies(adom_name, pkg)
                            policies.extend(pols)
                        except Exception as exc:
                            log.warning("Paket '%s/%s' atlandı: %s", adom_name, pkg, exc)
                except Exception as exc:
                    log.warning("ADOM '%s' paket listesi alınamadı: %s", adom_name, exc)

                result_adoms.append({
                    "name":     adom_name,
                    "customer": adom_name,
                    "policies": policies,
                })
                log.info("ADOM '%s' → %d kural toplandı", adom_name, len(policies))

            return {"adoms": result_adoms}
        finally:
            self.logout()
