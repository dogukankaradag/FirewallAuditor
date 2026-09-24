"""
Firewall Zafiyet Analiz Motoru
FortiManager (ADOM) ve Palo Alto (VSYS) kurallarını tarar.
"""

from datetime import datetime
from typing import List, Dict, Any
import uuid

from .models import Finding, ScanResult, Platform, Severity

# Riskli port -> servis adı eşlemesi
RISKY_PORTS = {
    "22": "SSH",
    "23": "Telnet",
    "21": "FTP",
    "3389": "RDP",
    "3306": "MySQL",
    "1433": "MSSQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
}

# FortiManager'da "herkese açık" anlamına gelen adresler
FM_ANY_ADDRS = {"all", "any", "ALL", "ANY"}

# Palo Alto'da "herkese açık" anlamına gelen adresler
PA_ANY_ADDRS = {"any", "ANY"}

# FortiManager log kapalı değerleri
FM_LOG_DISABLED = {"disable", "0", "none"}

# Geniş subnet prefix'leri (risky)
BROAD_PREFIXES = {"/8", "/9", "/10", "/11", "/12", "/13", "/14", "/15", "/16"}


def _finding(platform, device_name, customer, rule_id, rule_name,
             severity, check_name, description, recommendation, rule_details) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        platform=platform,
        device_name=device_name,
        customer=customer,
        rule_id=str(rule_id),
        rule_name=rule_name,
        severity=severity,
        check_name=check_name,
        description=description,
        recommendation=recommendation,
        rule_details=rule_details,
        detected_at=datetime.now(),
    )


# ─────────────────────────────────────────────
#  FortiManager Kontrolleri
# ─────────────────────────────────────────────

def _fm_is_any(addr_list: List[str]) -> bool:
    return any(a in FM_ANY_ADDRS for a in addr_list)


def _fm_has_risky_service(services: List[str]) -> List[str]:
    """Riskli servis adlarını döndürür (SSH, RDP, Telnet vb.)"""
    risky = []
    upper = [s.upper() for s in services]
    checks = {
        "SSH": ["SSH"],
        "RDP": ["RDP", "MS-RDP", "REMOTE-DESKTOP"],
        "Telnet": ["TELNET"],
        "FTP": ["FTP"],
        "HTTP": ["HTTP", "HTTP_ALL"],
        "HTTPS": ["HTTPS", "HTTPS_ALL"],
        "MySQL": ["MYSQL"],
        "MSSQL": ["MSSQL", "MS-SQL"],
    }
    for svc_name, patterns in checks.items():
        if any(p in upper for p in patterns):
            risky.append(svc_name)
    return risky


def analyze_fortimanager_adom(adom: Dict[str, Any]) -> ScanResult:
    device_name = adom["name"]
    customer = adom["customer"]
    policies = adom.get("policies", [])
    findings: List[Finding] = []

    for pol in policies:
        pid = pol.get("policyid", "?")
        pname = pol.get("name", f"policy-{pid}")
        src = pol.get("srcaddr", [])
        dst = pol.get("dstaddr", [])
        services = pol.get("service", [])
        action = pol.get("action", "deny").lower()
        log = pol.get("logtraffic", "enable").lower()
        status = pol.get("status", "enable").lower()
        comments = pol.get("comments", "")

        details = {
            "Kaynak Adres": ", ".join(src),
            "Hedef Adres": ", ".join(dst),
            "Servis": ", ".join(services),
            "Aksiyon": action.upper(),
            "Log": log,
            "Durum": status,
            "Açıklama": comments or "(yok)",
        }

        # 1. Any-Any-Any: CRITICAL
        if (action == "accept"
                and _fm_is_any(src)
                and _fm_is_any(dst)
                and ("ALL" in [s.upper() for s in services] or _fm_is_any(services))):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "Any-Any-Any Kuralı",
                "Kaynak, hedef ve servis alanlarının tamamı 'any/all' olarak tanımlanmış. "
                "Bu kural tüm trafiğe izin veriyor.",
                "Kuralı mümkün olan en kısıtlı kaynak/hedef/servis kombinasyonuyla yeniden yazın. "
                "Gereksinim yoksa silin.",
                details,
            ))

        # 1b. Kaynak=Any (ama any-any-any değil): HIGH
        src_any = _fm_is_any(src)
        dst_any = _fm_is_any(dst)
        svc_any = ("ALL" in [s.upper() for s in services] or _fm_is_any(services))
        if action == "accept" and src_any and not (dst_any and svc_any):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.HIGH,
                "Kaynak Kısıtsız Erişim",
                "Kaynak adres 'any/all' olarak tanımlanmış; hedef veya servis kısıtlaması mevcut olsa da "
                "herhangi bir IP'den bu kurala erişilebilir.",
                "Kaynak adres alanını yalnızca yetkili IP bloğu veya adres nesnesiyle sınırlandırın.",
                details,
            ))

        # 1c. Hedef=Any, Kaynak=Spesifik: HIGH
        if action == "accept" and dst_any and not src_any:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.HIGH,
                "Hedef Kısıtsız Erişim",
                "Hedef adres 'any/all' olarak tanımlanmış. Trafik herhangi bir hedefe yönlendirilebilir; "
                "veri sızıntısı ve yanal hareket riski oluşturur.",
                "Hedef adres alanını yalnızca gerekli sunucu/subnet ile sınırlandırın.",
                details,
            ))

        # 1d. Servis=ALL/Any, Kaynak ve Hedef Spesifik: MEDIUM
        if action == "accept" and svc_any and not src_any and not dst_any:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.MEDIUM,
                "Tüm Servisler/Portlar Açık",
                "Servis alanı 'ALL/any' olarak tanımlanmış. Kaynak ve hedef kısıtlı olsa da "
                "tüm portlar üzerinden bağlantıya izin veriliyor.",
                "Servis alanını yalnızca gerekli protokol ve portlarla sınırlandırın.",
                details,
            ))

        # 2. SSH internete açık: CRITICAL
        if action == "accept" and _fm_is_any(src) and "SSH" in [s.upper() for s in services]:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "SSH Tüm Dünyaya Açık",
                "SSH (Port 22) erişimine izin verilmiş kaynak adres kısıtlaması olmaksızın. "
                "Brute-force ve yetkisiz erişim riski yüksek.",
                "SSH erişimini yalnızca yönetim IP bloğuna kısıtlayın veya VPN üzerinden erişim zorunlu kılın.",
                details,
            ))

        # 3. RDP internete açık: CRITICAL
        rdp_svcs = ["RDP", "MS-RDP", "REMOTE-DESKTOP", "MICROSOFT-RDP"]
        if action == "accept" and _fm_is_any(src) and any(s.upper() in rdp_svcs for s in services):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "RDP Tüm Dünyaya Açık",
                "RDP (Port 3389) erişimine kaynak kısıtlaması olmaksızın izin verilmiş. "
                "Ransomware ve kimlik bilgisi saldırılarına açık.",
                "RDP erişimini yalnızca VPN üzerinden sağlayın. "
                "Doğrudan internetten RDP erişimine kapatın.",
                details,
            ))

        # 4. Telnet: HIGH
        if action == "accept" and "TELNET" in [s.upper() for s in services]:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.HIGH,
                "Telnet Kullanımı",
                "Telnet protokolü şifresiz metin iletişimi kullanır. "
                "Kimlik bilgileri ve komutlar ağda açık görünür.",
                "Telnet'i devre dışı bırakın, SSH veya başka şifreli protokol kullanın.",
                details,
            ))

        # 5. FTP internete açık: HIGH
        if action == "accept" and _fm_is_any(src) and "FTP" in [s.upper() for s in services]:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.HIGH,
                "FTP Tüm Dünyaya Açık",
                "FTP (Port 21) erişimine kaynak kısıtlaması olmaksızın izin verilmiş. "
                "Şifresiz protokol; kimlik bilgileri açıkta.",
                "SFTP veya FTPS kullanın. FTP'ye internetten erişimi kapatın.",
                details,
            ))

        # 6. HTTP/HTTPS internete açık: HIGH
        http_svcs = {"HTTP", "HTTPS", "HTTP_ALL", "HTTPS_ALL"}
        if action == "accept" and _fm_is_any(src) and http_svcs.intersection([s.upper() for s in services]):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.HIGH,
                "HTTP/HTTPS Kaynaksız Açık",
                "HTTP veya HTTPS erişimine herhangi bir kaynaktan izin verilmiş. "
                "Web sunucusu saldırılarına karşı savunmasız.",
                "WAF (Web Application Firewall) arkasına alın. "
                "Gereksiz portları kapatın ve kaynak IP kısıtlaması uygulayın.",
                details,
            ))

        # 7. Log kapalı (accept kurallarında): MEDIUM
        if action == "accept" and log in FM_LOG_DISABLED:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.MEDIUM,
                "Log Kapalı",
                "İzin kuralında trafik loglama devre dışı bırakılmış. "
                "Güvenlik olayları kayıt altına alınamıyor.",
                "logtraffic değerini en az 'utm' veya 'all' yapın. "
                "SIEM entegrasyonu için log zorunludur.",
                details,
            ))

        # 8. Devre dışı kural: MEDIUM
        if status == "disable":
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.MEDIUM,
                "Devre Dışı Kural",
                "Kural devre dışı bırakılmış ancak silinmemiş. "
                "Kural seti karmaşıklığını artırır ve yanlışlıkla etkinleştirilebilir.",
                "Artık kullanılmayan kuralları silin. "
                "Gerektiğinde yorum satırı veya versiyon kontrol sistemi kullanın.",
                details,
            ))

        # 9. Geniş kaynak subnet: HIGH
        for addr in src:
            if any(addr.endswith(p) for p in BROAD_PREFIXES):
                findings.append(_finding(
                    Platform.FORTIMANAGER, device_name, customer, pid, pname,
                    Severity.HIGH,
                    "Geniş Kaynak Subnet",
                    f"Kaynak adres olarak geniş subnet kullanılmış: {addr}. "
                    "Bu, beklenenden çok daha fazla kaynağa erişim izni verebilir.",
                    "Kaynak IP bloğunu yalnızca gerçekten ihtiyaç duyulan aralıkla sınırlandırın.",
                    details,
                ))
                break

        # 10. Açıklama yok (accept kurallarında): LOW
        if action == "accept" and not comments.strip():
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.LOW,
                "Kural Açıklaması Eksik",
                "İzin kuralında açıklama (comments) alanı boş. "
                "Kuralın amacı ve sorumlusu bilinmiyor.",
                "Her kurala kısa bir açıklama, oluşturulma tarihi ve sorumlu ekip bilgisi ekleyin.",
                details,
            ))

    return ScanResult(
        device_id=f"fm_{device_name}",
        device_name=device_name,
        device_label=adom.get("_device_label", ""),
        device_host=adom.get("_device_host", ""),
        platform=Platform.FORTIMANAGER,
        customer=customer,
        total_rules=len(policies),
        findings=findings,
        scanned_at=datetime.now(),
    )


# ─────────────────────────────────────────────
#  Palo Alto Kontrolleri
# ─────────────────────────────────────────────

def _pa_is_any(member_list: List[str]) -> bool:
    return any(m in PA_ANY_ADDRS for m in member_list)


def analyze_paloalto_vsys(vsys: Dict[str, Any]) -> ScanResult:
    device_name = vsys["name"]
    customer = vsys["customer"]
    rules = vsys.get("rules", [])
    findings: List[Finding] = []

    for rule in rules:
        rname = rule.get("name", "unnamed")
        sources = rule.get("source", ["any"])
        destinations = rule.get("destination", ["any"])
        applications = rule.get("application", ["any"])
        services = rule.get("service", ["application-default"])
        action = rule.get("action", "deny").lower()
        log_end = rule.get("log_end", True)
        log_start = rule.get("log_start", False)
        disabled = rule.get("disabled", False)
        description = rule.get("description", "")
        from_zones = rule.get("from_zones", ["any"])
        to_zones = rule.get("to_zones", ["any"])

        details = {
            "Kaynak Zone": ", ".join(from_zones),
            "Hedef Zone": ", ".join(to_zones),
            "Kaynak": ", ".join(sources),
            "Hedef": ", ".join(destinations),
            "Uygulama": ", ".join(applications),
            "Servis": ", ".join(services),
            "Aksiyon": action.upper(),
            "Log End": "Açık" if log_end else "Kapalı",
            "Durum": "Devre Dışı" if disabled else "Aktif",
            "Açıklama": description or "(yok)",
        }

        # 0. ACİL: Untrust zone kaynaklı + servis=any
        untrust_zones = {"untrust", "outside", "wan", "internet", "external", "l3-untrust", "zone_untrust"}
        zone_is_untrust = any(z.lower() in untrust_zones for z in from_zones)
        pa_svc_any_acil = any(s.lower() == "any" for s in services)
        if action == "allow" and zone_is_untrust and pa_svc_any_acil:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.ACIL,
                "source zone: Any Kuralı",
                "Dış zone (Untrust) kaynaklı tüm servislere izin veriliyor. "
                "İnternet kaynaklı her türlü protokol ve port hedef sistemlere erişebilir; "
                "saldırı yüzeyini kritik düzeyde genişletmektedir.",
                "Untrust zone için servis alanını yalnızca zorunlu portlarla (örn. HTTP/443, SMTP/25) "
                "sınırlandırın. Genel "any" servis kuralı yerine spesifik uygulama veya port grupları tanımlayın.",
                details,
            ))

        # 1. Any-Any-Any: CRITICAL
        if (action == "allow"
                and _pa_is_any(sources)
                and _pa_is_any(destinations)
                and _pa_is_any(applications)):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Any-Any-Any Kuralı",
                "Kaynak, hedef ve uygulama alanlarının tamamı 'any'. "
                "Tüm trafiğe izin veren açık kapı kuralı.",
                "Kuralı spesifik kaynak/hedef/uygulama kombinasyonuyla yeniden tanımlayın.",
                details,
            ))

        # 1b. Kaynak=Any, Hedef=Any ama App=Spesifik (CRITICAL'dan kaçan): HIGH
        pa_src_any = _pa_is_any(sources)
        pa_dst_any = _pa_is_any(destinations)
        pa_app_any = _pa_is_any(applications)
        pa_svc_any = any(s.lower() == "any" for s in services)

        if action == "allow" and pa_src_any and pa_dst_any and not pa_app_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.HIGH,
                "Kaynak ve Hedef Kısıtsız",
                "Kaynak ve hedef 'any' olarak tanımlanmış; yalnızca uygulama kısıtlaması mevcut. "
                "Herhangi bir kaynak herhangi bir hedefe ulaşabilir.",
                "Kaynak ve hedef alanlarını belirli zone, IP grubu veya adres nesnesiyle sınırlandırın.",
                details,
            ))

        # 1c. Kaynak=Any, Hedef=Spesifik (not caught by check #8 below): duplication avoided
        # (Check #8 already handles this case - keep as-is)

        # 1d. Hedef=Any, Kaynak=Spesifik: HIGH
        if action == "allow" and pa_dst_any and not pa_src_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.HIGH,
                "Hedef Kısıtsız Erişim",
                "Hedef adres 'any' olarak tanımlanmış. Kaynak kısıtlı olsa da trafik "
                "herhangi bir hedefe yönlendirilebilir; veri sızıntısı riski oluşturur.",
                "Hedef alanını yalnızca gerekli sunucu, zone veya adres grubuyla sınırlandırın.",
                details,
            ))

        # 1e. Servis=Any (tüm portlar), Kaynak ve Hedef Spesifik: MEDIUM
        if action == "allow" and pa_svc_any and not pa_src_any and not pa_dst_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.MEDIUM,
                "Tüm Portlar Açık",
                "Servis alanı 'any' olarak tanımlanmış; kaynak ve hedef kısıtlı olsa da "
                "tüm TCP/UDP portlarına izin veriliyor.",
                "Servis alanını yalnızca gerekli port ve protokollerle sınırlandırın. "
                "'application-default' kullanmayı değerlendirin.",
                details,
            ))

        # 2. SSH any: CRITICAL
        ssh_services = {"service-ssh", "ssh", "tcp-22"}
        if action == "allow" and _pa_is_any(sources) and any(s.lower() in ssh_services for s in services):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "SSH Tüm Dünyaya Açık",
                "SSH servisi herhangi bir kaynaktan erişilebilir şekilde tanımlanmış.",
                "SSH erişimini yönetim zone'u ve belirli IP adres gruplarıyla sınırlandırın.",
                details,
            ))

        # 3. RDP any: CRITICAL
        rdp_services = {"service-rdp", "rdp", "tcp-3389", "ms-rdp"}
        if action == "allow" and _pa_is_any(sources) and any(s.lower() in rdp_services for s in services):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "RDP Tüm Dünyaya Açık",
                "RDP servisi herhangi bir kaynaktan erişilebilir şekilde tanımlanmış.",
                "RDP'yi yalnızca VPN üzerinden erişilebilir yapın veya tamamen kapatın.",
                details,
            ))

        # 4. Herhangi bir uygulama: HIGH
        if action == "allow" and _pa_is_any(applications) and not _pa_is_any(sources):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.HIGH,
                "Uygulama Kısıtlaması Yok",
                "Kural belirli bir uygulama kısıtlaması içermiyor (application: any). "
                "Tüm uygulamaların bu kural üzerinden geçmesine izin veriliyor.",
                "App-ID kullanarak yalnızca gerekli uygulamaları açıkça tanımlayın.",
                details,
            ))

        # 5. Telnet uygulaması: HIGH
        telnet_apps = {"telnet"}
        if action == "allow" and any(a.lower() in telnet_apps for a in applications):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.HIGH,
                "Telnet Uygulamasına İzin",
                "Telnet uygulamasına açıkça izin verilmiş. Şifresiz metin iletişimi güvenlik açığı oluşturur.",
                "Telnet'i devre dışı bırakın, SSH kullanın.",
                details,
            ))

        # 6. Log kapalı: MEDIUM
        if action == "allow" and not log_end and not log_start:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.MEDIUM,
                "Log Kapalı",
                "Allow kuralında log-end ve log-start her ikisi de kapalı. "
                "Trafik kayıt altına alınmıyor.",
                "En az log-end: yes ayarlayın. Kritik kurallar için log-start da aktif edin.",
                details,
            ))

        # 7. Devre dışı kural: MEDIUM
        if disabled:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.MEDIUM,
                "Devre Dışı Kural",
                "Kural disabled: yes olarak işaretlenmiş. "
                "Politika setinde gereksiz karmaşıklık yaratıyor.",
                "Kullanılmayan kuralları silin veya yorum ekleyerek gerekçesini belgeleyin.",
                details,
            ))

        # 8. any kaynak + allow: HIGH
        if action == "allow" and _pa_is_any(sources) and not _pa_is_any(destinations):
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.HIGH,
                "Kaynak Kısıtlaması Yok",
                "Allow kuralında kaynak 'any' olarak tanımlanmış. "
                "Herhangi bir IP adresi bu kural üzerinden erişim sağlayabilir.",
                "Kaynak olarak belirli IP grupları, adres nesneleri veya bölgeler tanımlayın.",
                details,
            ))

        # 9. Açıklama eksik: LOW
        if action == "allow" and not description.strip():
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.LOW,
                "Kural Açıklaması Eksik",
                "Kural açıklama alanı boş. Kuralın amacı, sahibi ve oluşturulma tarihi bilinmiyor.",
                "Her kurala kısa bir açıklama, tarih ve sorumlu ekip bilgisi ekleyin.",
                details,
            ))

    return ScanResult(
        device_id=f"pa_{device_name}",
        device_name=device_name,
        device_label=vsys.get("_device_label", ""),
        device_host=vsys.get("_device_host", ""),
        platform=Platform.PALOALTO,
        customer=customer,
        total_rules=len(rules),
        findings=findings,
        scanned_at=datetime.now(),
    )


# ─────────────────────────────────────────────
#  Ana Tarayıcı
# ─────────────────────────────────────────────

class FirewallAnalyzer:
    def scan_all(self, fm_data: Dict, pa_data: Dict,
                 device_label: str = "", device_host: str = "") -> List[ScanResult]:
        """
        fm_data / pa_data: mock ya da gerçek API'dan gelen veri.
        device_label / device_host: hangi fiziksel cihazdan geldiği bilgisi.
        """
        results = []
        for adom in fm_data.get("adoms", []):
            adom["_device_label"] = device_label
            adom["_device_host"]  = device_host
            results.append(analyze_fortimanager_adom(adom))
        for vsys in pa_data.get("vsys_list", []):
            vsys["_device_label"] = device_label
            vsys["_device_host"]  = device_host
            results.append(analyze_paloalto_vsys(vsys))
        return results

    def scan_device(self, device: Dict, fm_data: Dict = None, pa_data: Dict = None) -> List[ScanResult]:
        """
        Tek bir fiziksel cihazı tara.
        device: connectors.FIREWALL_DEVICES içindeki bir kayıt.
        """
        label = device.get("label", "")
        host  = device.get("host", "")
        dtype = device.get("type", "")

        if dtype == "fortimanager" and fm_data:
            return self.scan_all(fm_data, {}, device_label=label, device_host=host)
        elif dtype == "paloalto" and pa_data:
            return self.scan_all({}, pa_data, device_label=label, device_host=host)
        return []
