"""
FortiManager JSON-RPC API istemcisi.

Response yapısı:
  POST /jsonrpc → {"result": [{"status": {"code": 0}, "data": [...]}]}
  ADOM listesi : result[0].data[].name
  Policy pkg   : result[0].data[].name
  Policies     : result[0].data[].policyid / .srcaddr / .dstaddr / ...
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

# Paralel ADOM tarama için maksimum iş parçacığı sayısı
_MAX_WORKERS = 10
# Her HTTP isteği için zaman aşımı (saniye)
_REQUEST_TIMEOUT = 30


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
            timeout=_REQUEST_TIMEOUT,
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
        KRITIK: `or {}` KULLANMA — boş listeyi dict'e dönüştürür.
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

        status = result.get("status", {})
        code   = status.get("code", 0)
        if code != 0:
            raise RuntimeError(
                f"FortiManager RPC hatası — method={method} "
                f"url={params[0].get('url') if params else '?'} "
                f"code={code} msg={status.get('message', '')}"
            )

        return result.get("data")   # None / list / dict — olduğu gibi döner

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
        FortiManager'a bağlanır.
        Session token kök response'taki 'session' alanından alınır.
        """
        body = self._post({
            "id":     1,
            "method": "exec",
            "params": [{"url": "/sys/login/user",
                        "data": {"user": self.username, "passwd": self.password}}],
        })
        self.session_id = body.get("session")
        if not self.session_id:
            raise RuntimeError("FortiManager login başarısız: session token alınamadı")
        log.info("FortiManager login başarılı")

    def logout(self) -> None:
        try:
            self._rpc("exec", [{"url": "/sys/logout"}])
        except Exception:
            pass
        self.session_id = None

    # ──────────────────────────────────────────────────────────────────────
    #  ADOM katmanı
    # ──────────────────────────────────────────────────────────────────────

    def get_adoms(self) -> list[str]:
        """
        GET /dvmdb/adom → result[0].data[].name

        FortiAnalyzer yönetim ADOM'u hariç tüm ADOM isimleri döner.
        'root' dahil.
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

        log.info("get_adoms → %d ADOM bulundu", len(adoms))
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
        log.debug("get_policy_packages(%s) → %d paket", adom, len(pkgs))
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
        """
        data = self._rpc(
            "get",
            [{"url": f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy",
              "option": ["get reserved"]}],
        )
        raw = self._as_list(data)
        return [self._normalize_policy(p) for p in raw if isinstance(p, dict)]

    @staticmethod
    def _normalize_policy(pol: dict) -> dict:
        """
        FM API çıktısını analyzer.py'nin beklediği formata dönüştürür.

        FM API integer döndürebilir:
          action:     1=accept  0/6=deny
          logtraffic: 0=disable 1=enable 2=all 3=utm
          status:     0=disable 1=enable
        Adres/servis alanları [{"name": "all"}] formatında gelir → ["all"]

        Security profile alanları doğrudan string olarak gelir:
          av-profile, webfilter-profile, ips-sensor, file-filter-profile
        """
        def extract_names(field: Any, fallback: str = "any") -> list[str]:
            if isinstance(field, list):
                names = [item["name"] if isinstance(item, dict) else str(item) for item in field]
                return names or [fallback]
            if isinstance(field, str):
                return [field]
            return [fallback]

        action_raw = pol.get("action", "deny")
        action = "accept" if (isinstance(action_raw, int) and action_raw == 1) \
            else ("accept" if str(action_raw).lower() == "accept" else "deny")

        log_raw = pol.get("logtraffic", "disable")
        if isinstance(log_raw, int):
            logtraffic = {0: "disable", 1: "enable", 2: "all", 3: "utm"}.get(log_raw, "disable")
        else:
            logtraffic = str(log_raw).lower()

        status_raw = pol.get("status", "enable")
        if isinstance(status_raw, int):
            status = "enable" if status_raw == 1 else "disable"
        else:
            status = str(status_raw).lower()

        # Security profiles — FM'de doğrudan string alan adları
        security_profiles = {
            "av":         str(pol.get("av-profile", "") or ""),
            "webfilter":  str(pol.get("webfilter-profile", "") or ""),
            "filefilter": str(pol.get("file-filter-profile", "") or ""),
            "ips":        str(pol.get("ips-sensor", "") or ""),
            "group":      "",   # FM'de profil grubu kavramı yok
        }

        return {
            "policyid":          pol.get("policyid", ""),
            "name":              pol.get("name") or f"policy-{pol.get('policyid', '?')}",
            "srcaddr":           extract_names(pol.get("srcaddr"), fallback="all"),
            "dstaddr":           extract_names(pol.get("dstaddr"), fallback="all"),
            "service":           extract_names(pol.get("service"),  fallback="ALL"),
            "action":            action,
            "logtraffic":        logtraffic,
            "status":            status,
            "comments":          pol.get("comments", ""),
            "security_profiles": security_profiles,
        }

    # ──────────────────────────────────────────────────────────────────────
    #  ADOM bazlı paralel tarama
    # ──────────────────────────────────────────────────────────────────────

    def _fetch_adom_policies(self, adom_name: str) -> tuple[str, list[dict]]:
        """
        Tek bir ADOM'un tüm policy paketlerini çeker.
        ThreadPoolExecutor worker'ı olarak çalışır.
        Döner: (adom_name, policies_list)
        """
        policies: list[dict] = []
        try:
            packages = self.get_policy_packages(adom_name)
            for pkg in packages:
                try:
                    pols = self.get_policies(adom_name, pkg)
                    policies.extend(pols)
                    log.debug("  %s / %s → %d kural", adom_name, pkg, len(pols))
                except Exception as exc:
                    log.warning("  Paket atlandı %s/%s: %s", adom_name, pkg, exc)
        except Exception as exc:
            log.warning("  ADOM atlandı %s: %s", adom_name, exc)
        return adom_name, policies

    # ──────────────────────────────────────────────────────────────────────
    #  Ana çekme metodu
    # ──────────────────────────────────────────────────────────────────────

    def fetch_all(self) -> dict:
        """
        Tüm ADOM'ların policy'lerini PARALEL olarak çeker.

        _MAX_WORKERS iş parçacığı aynı anda çalışır; 100+ ADOM için
        sıralı çekmeye kıyasla ~10x hızlanma sağlar.

        Dönen format (analyzer.py ile uyumlu):
          {"adoms": [{"name": str, "customer": str, "policies": [...]}, ...]}
        """
        self.login()
        try:
            adoms = self.get_adoms()
            log.info("Paralel tarama başlıyor: %d ADOM, %d worker", len(adoms), _MAX_WORKERS)

            # adom_name → policies sözlüğü (sırayı korumak için)
            results: dict[str, list[dict]] = {}

            with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
                futures = {
                    pool.submit(self._fetch_adom_policies, adom_name): adom_name
                    for adom_name in adoms
                }
                for future in as_completed(futures):
                    adom_name, policies = future.result()
                    results[adom_name] = policies
                    log.info("ADOM '%s' tamamlandı → %d kural", adom_name, len(policies))

            # Orijinal ADOM sırasını koru
            return {
                "adoms": [
                    {"name": name, "customer": name, "policies": results.get(name, [])}
                    for name in adoms
                ]
            }
        finally:
            self.logout()
