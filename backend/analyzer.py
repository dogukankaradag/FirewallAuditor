"""
Firewall Zafiyet Analiz Motoru
FortiManager (ADOM) ve Palo Alto (VSYS) kurallarını tarar.

Ciddiyet seviyeleri: ACİL > KRİTİK > ÇÖZÜLDÜ (Orta/Düşük/Yüksek kaldırıldı)
"""

from datetime import datetime
from typing import List, Dict, Any
import uuid

from .models import Finding, ScanResult, Platform, Severity

# ─────────────────────────────────────────────────────────────────────────────
#  Yüksek Riskli Port Sözlüğü  {port: (servis_adı, açıklama)}
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_PORTS: Dict[str, tuple] = {
    "20":    ("FTP-Data",        "şifresiz dosya transferi veri kanalı"),
    "21":    ("FTP",             "şifresiz dosya transferi"),
    "22":    ("SSH",             "brute-force hedefi"),
    "23":    ("Telnet",          "şifresiz metin protokolü"),
    "25":    ("SMTP",            "e-posta spam/relay riski"),
    "53":    ("DNS",             "DNS amplifikasyon/zone transfer"),
    "69":    ("TFTP",            "şifresiz/anonim dosya transferi"),
    "80":    ("HTTP",            "şifresiz web trafiği"),
    "110":   ("POP3",            "şifresiz e-posta"),
    "111":   ("RPC",             "uzak prosedür çağrısı"),
    "135":   ("MSRPC",           "Windows RPC"),
    "137":   ("NetBIOS-NS",      "NetBIOS isim servisi"),
    "138":   ("NetBIOS-DGM",     "NetBIOS datagram"),
    "139":   ("NetBIOS-SSN",     "NetBIOS oturum"),
    "143":   ("IMAP",            "şifresiz e-posta"),
    "161":   ("SNMP",            "topluluk string - kimlik riski"),
    "162":   ("SNMP-Trap",       "SNMP tuzak"),
    "389":   ("LDAP",            "şifresiz dizin erişimi"),
    "445":   ("SMB",             "WannaCry/EternalBlue - dosya paylaşımı"),
    "512":   ("Rexec",           "uzak komut çalıştırma"),
    "513":   ("Rlogin",          "şifresiz uzak oturum"),
    "514":   ("RSH",             "şifresiz uzak shell"),
    "515":   ("LPD",             "ağ yazdırma servisi"),
    "873":   ("Rsync",           "şifresiz dosya senkronizasyonu"),
    "1080":  ("SOCKS",           "proxy sunucu"),
    "1433":  ("MSSQL",           "Microsoft SQL Server"),
    "1434":  ("MSSQL-UDP",       "MSSQL keşif portu"),
    "1521":  ("Oracle",          "Oracle veritabanı"),
    "1723":  ("PPTP",            "şifresiz VPN tüneli"),
    "2049":  ("NFS",             "şifresiz ağ dosya sistemi"),
    "2181":  ("ZooKeeper",       "dağıtık koordinasyon servisi"),
    "2375":  ("Docker",          "Docker daemon şifresiz API"),
    "2376":  ("Docker-TLS",      "Docker daemon TLS"),
    "3306":  ("MySQL",           "MySQL veritabanı"),
    "3389":  ("RDP",             "uzak masaüstü - ransomware hedefi"),
    "4444":  ("Backdoor",        "yaygın zararlı yazılım portu"),
    "5000":  ("UPnP",            "UPnP/geliştirme sunucusu"),
    "5432":  ("PostgreSQL",      "PostgreSQL veritabanı"),
    "5900":  ("VNC",             "şifresiz grafik uzak erişim"),
    "5984":  ("CouchDB",         "şifresiz NoSQL veritabanı"),
    "6379":  ("Redis",           "kimlik doğrulamasız bellek cache"),
    "7001":  ("WebLogic",        "Oracle WebLogic uygulama sunucusu"),
    "8080":  ("HTTP-Proxy",      "alternatif HTTP/yönetim arayüzü"),
    "8443":  ("HTTPS-Alt",       "alternatif HTTPS yönetim"),
    "8888":  ("HTTP-Alt",        "alternatif HTTP"),
    "9000":  ("PHP-FPM",         "PHP hızlı CGI/uygulama sunucusu"),
    "9200":  ("Elasticsearch",   "şifresiz arama motoru REST API"),
    "9300":  ("ES-Cluster",      "Elasticsearch cluster TCP"),
    "11211": ("Memcached",       "şifresiz bellek cache sunucusu"),
    "27017": ("MongoDB",         "kimlik doğrulamasız NoSQL veritabanı"),
    "27018": ("MongoDB-Shard",   "MongoDB parçalanmış küme"),
    "50000": ("DB2",             "IBM DB2 veritabanı"),
}

# Servis adı → port (büyük harf, alias dahil)
_SVC_ALIASES: Dict[str, str] = {
    "SSH":              "22",
    "TELNET":           "23",
    "FTP":              "21",
    "FTP-DATA":         "20",
    "FTPDATA":          "20",
    "HTTP":             "80",
    "HTTPS":            "443",
    "SMTP":             "25",
    "DNS":              "53",
    "TFTP":             "69",
    "POP3":             "110",
    "IMAP":             "143",
    "SNMP":             "161",
    "SNMP-TRAP":        "162",
    "LDAP":             "389",
    "SMB":              "445",
    "NETBIOS":          "139",
    "NETBIOS-SSN":      "139",
    "NETBIOS-NS":       "137",
    "NETBIOS-DGM":      "138",
    "RPC":              "111",
    "MSRPC":            "135",
    "NFS":              "2049",
    "RSYNC":            "873",
    "RDP":              "3389",
    "MS-RDP":           "3389",
    "REMOTE-DESKTOP":   "3389",
    "MICROSOFT-RDP":    "3389",
    "SERVICE-RDP":      "3389",
    "VNC":              "5900",
    "MYSQL":            "3306",
    "MSSQL":            "1433",
    "MS-SQL":           "1433",
    "ORACLE":           "1521",
    "POSTGRESQL":       "5432",
    "POSTGRES":         "5432",
    "MONGODB":          "27017",
    "MONGO":            "27017",
    "REDIS":            "6379",
    "ELASTICSEARCH":    "9200",
    "DOCKER":           "2375",
    "MEMCACHED":        "11211",
    "MEMCACHE":         "11211",
    "ZOOKEEPER":        "2181",
    "SOCKS":            "1080",
    "SOCKS5":           "1080",
    "PPTP":             "1723",
}

# Tüm ISO 3166-1 alpha-2 ülke kodları
_ISO2_CODES = {
    "AF","AX","AL","DZ","AS","AD","AO","AI","AQ","AG","AR","AM","AW","AU","AT",
    "AZ","BS","BH","BD","BB","BY","BE","BZ","BJ","BM","BT","BO","BQ","BA","BW",
    "BV","BR","IO","BN","BG","BF","BI","CV","KH","CM","CA","KY","CF","TD","CL",
    "CN","CX","CC","CO","KM","CG","CD","CK","CR","CI","HR","CU","CW","CY","CZ",
    "DK","DJ","DM","DO","EC","EG","SV","GQ","ER","EE","SZ","ET","FK","FO","FJ",
    "FI","FR","GF","PF","TF","GA","GM","GE","DE","GH","GI","GR","GL","GD","GP",
    "GU","GT","GG","GN","GW","GY","HT","HM","VA","HN","HK","HU","IS","IN","ID",
    "IR","IQ","IE","IM","IL","IT","JM","JP","JE","JO","KZ","KE","KI","KP","KR",
    "KW","KG","LA","LV","LB","LS","LR","LY","LI","LT","LU","MO","MG","MW","MY",
    "MV","ML","MT","MH","MQ","MR","MU","YT","MX","FM","MD","MC","MN","ME","MS",
    "MA","MZ","MM","NA","NR","NP","NL","NC","NZ","NI","NE","NG","NU","NF","MK",
    "MP","NO","OM","PK","PW","PS","PA","PG","PY","PE","PH","PN","PL","PT","PR",
    "QA","RE","RO","RU","RW","BL","SH","KN","LC","MF","PM","VC","WS","SM","ST",
    "SA","SN","RS","SC","SL","SG","SX","SK","SI","SB","SO","ZA","GS","SS","ES",
    "LK","SD","SR","SJ","SE","CH","SY","TW","TJ","TZ","TH","TL","TG","TK","TO",
    "TT","TN","TR","TM","TC","TV","UG","UA","AE","GB","US","UM","UY","UZ","VU",
    "VE","VN","VG","VI","WF","EH","YE","ZM","ZW",
}

# FortiManager'da "herkese açık" anlamına gelen adresler
FM_ANY_ADDRS = {"all", "any", "ALL", "ANY"}

# Palo Alto'da "herkese açık" anlamına gelen adresler
PA_ANY_ADDRS = {"any", "ANY"}

# FortiManager log kapalı değerleri
FM_LOG_DISABLED = {"disable", "0", "none"}

# Geniş subnet prefix'leri (risky)
BROAD_PREFIXES = {"/8", "/9", "/10", "/11", "/12", "/13", "/14", "/15", "/16"}

# Palo Alto untrust zone adları (harfe duyarsız)
PA_UNTRUST_ZONES = {
    "untrust", "outside", "wan", "internet", "external",
    "l3-untrust", "zone_untrust", "dmz-untrust",
}

# Palo Alto trust/iç ağ zone adları
PA_TRUST_ZONES = {
    "trust", "inside", "internal", "lan", "intranet",
    "l3-trust", "zone_trust", "users", "servers",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Yardımcı Fonksiyonlar
# ─────────────────────────────────────────────────────────────────────────────

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


def _detect_high_risk_ports(services: List[str], applications: List[str] = None) -> List[str]:
    """
    Servis/uygulama listelerinde yüksek riskli port kullanımı tespit eder.
    Döner: ["22/SSH", "3389/RDP", ...] — boş liste ise risk yok.
    """
    found: List[str] = []
    seen_ports: set = set()

    check_list = list(services or []) + list(applications or [])

    for item in check_list:
        if not item:
            continue
        item_upper = item.upper().strip()

        # Direkt port numarası veya tcp-PORT / udp-PORT kalıpları
        for port, (svc_name, _) in HIGH_RISK_PORTS.items():
            if port in seen_ports:
                continue
            if (item_upper == port
                    or item_upper == f"TCP-{port}"
                    or item_upper == f"UDP-{port}"
                    or item_upper == f"PORT-{port}"
                    or item_upper == f"SERVICE-{port}"
                    or item_upper.endswith(f"/{port}")
                    or item_upper.startswith(f"{port}/")):
                found.append(f"{port}/{svc_name}")
                seen_ports.add(port)

        # Alias eşlemesi
        alias_port = _SVC_ALIASES.get(item_upper)
        if alias_port and alias_port not in seen_ports and alias_port in HIGH_RISK_PORTS:
            found.append(f"{alias_port}/{HIGH_RISK_PORTS[alias_port][0]}")
            seen_ports.add(alias_port)

    return found


def _is_geo_addr(name: str) -> bool:
    """Bir adres nesnesinin coğrafi (ülke bazlı) olup olmadığını kontrol eder."""
    if not name:
        return False
    n = name.upper().strip()
    if n in _ISO2_CODES:
        return True
    if n.startswith("GEO_") or n.startswith("GEO-"):
        return True
    if "COUNTRY" in n:
        return True
    # ISO kodu + ayırıcı prefix (örn. "CN_addresses", "RU-all")
    for code in _ISO2_CODES:
        if n.startswith(code + "_") or n.startswith(code + "-"):
            return True
    return False


def _find_geo_addrs(addrs: List[str]) -> List[str]:
    """Bir adres listesinden coğrafi olanları döndürür."""
    return [a for a in addrs if _is_geo_addr(a)]


# ─────────────────────────────────────────────────────────────────────────────
#  FortiManager Kontrolleri
# ─────────────────────────────────────────────────────────────────────────────

def _fm_is_any(addr_list: List[str]) -> bool:
    return any(a in FM_ANY_ADDRS for a in addr_list)


def analyze_fortimanager_adom(adom: Dict[str, Any]) -> ScanResult:
    device_name = adom["name"]
    customer    = adom["customer"]
    policies    = adom.get("policies", [])
    findings: List[Finding] = []

    for pol in policies:
        pid      = pol.get("policyid", "?")
        pname    = pol.get("name", f"policy-{pid}")
        src      = pol.get("srcaddr", [])
        dst      = pol.get("dstaddr", [])
        services = pol.get("service", [])
        action   = pol.get("action", "deny").lower()
        log      = pol.get("logtraffic", "enable").lower()
        status   = pol.get("status", "enable").lower()
        comments = pol.get("comments", "")

        # Oluşturan / değiştiren bilgisi (fm_client tarafından paslanırsa göster)
        created_by  = pol.get("created_by", "") or pol.get("_create_by", "") or ""
        modified_by = pol.get("modified_by", "") or pol.get("_modified_by", "") or ""

        details: Dict[str, Any] = {
            "Kaynak Adres": ", ".join(src),
            "Hedef Adres":  ", ".join(dst),
            "Servis":       ", ".join(services),
            "Aksiyon":      action.upper(),
            "Log":          log,
            "Durum":        status,
            "Açıklama":     comments or "(yok)",
        }
        if created_by:
            details["Oluşturan"] = created_by
        if modified_by:
            details["Son Değiştiren"] = modified_by

        src_any = _fm_is_any(src)
        dst_any = _fm_is_any(dst)
        svc_any = ("ALL" in [s.upper() for s in services] or _fm_is_any(services))

        # ── ACİL 1: Any-Any-Any ────────────────────────────────────────────
        if (action == "accept"
                and src_any and dst_any and svc_any):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.ACIL,
                "Any-Any-Any Kuralı",
                "Kaynak, hedef ve servis alanlarının tamamı 'any/all' olarak tanımlanmış. "
                "Bu kural tüm trafiğe izin veriyor.",
                "Kuralı mümkün olan en kısıtlı kaynak/hedef/servis kombinasyonuyla yeniden yazın. "
                "Gereksinim yoksa silin.",
                details,
            ))

        # ── KRİTİK 1b: Kaynak=Any (any-any-any değilse) ───────────────────
        if action == "accept" and src_any and not (dst_any and svc_any):
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "Kaynak Kısıtsız Erişim",
                "Kaynak adres 'any/all' olarak tanımlanmış; herhangi bir IP'den bu kurala erişilebilir.",
                "Kaynak adres alanını yalnızca yetkili IP bloğu veya adres nesnesiyle sınırlandırın.",
                details,
            ))

        # ── KRİTİK 1c: Hedef=Any, Kaynak=Spesifik ────────────────────────
        if action == "accept" and dst_any and not src_any:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "Hedef Kısıtsız Erişim",
                "Hedef adres 'any/all' olarak tanımlanmış. Trafik herhangi bir hedefe yönlendirilebilir; "
                "veri sızıntısı ve yanal hareket riski oluşturur.",
                "Hedef adres alanını yalnızca gerekli sunucu/subnet ile sınırlandırın.",
                details,
            ))

        # ── KRİTİK 1d: Servis=ALL, Kaynak ve Hedef Spesifik ──────────────
        if action == "accept" and svc_any and not src_any and not dst_any:
            findings.append(_finding(
                Platform.FORTIMANAGER, device_name, customer, pid, pname,
                Severity.CRITICAL,
                "Servis Kısıtsız Erişim",
                "Servis alanı 'ALL/any' olarak tanımlanmış. Kaynak ve hedef kısıtlı olsa da "
                "tüm portlar üzerinden bağlantıya izin veriliyor.",
                "Servis alanını yalnızca gerekli protokol ve portlarla sınırlandırın.",
                details,
            ))

        # ── KRİTİK 2: Kritik Port Kullanımları ────────────────────────────
        high_risk = _detect_high_risk_ports(services)
        if action == "accept" and high_risk:
            port_list = ", ".join(high_risk)
            geo_addrs = _find_geo_addrs(src)

            # ACİL: Coğrafi kaynak + kritik port
            if geo_addrs:
                findings.append(_finding(
                    Platform.FORTIMANAGER, device_name, customer, pid, pname,
                    Severity.ACIL,
                    "Geolocation Bazlı Kritik Kullanım",
                    f"Coğrafi kaynak ({', '.join(geo_addrs)}) ile kritik port kullanımı tespit edildi: "
                    f"{port_list}. Ülke bazlı kaynak + riskli port birleşimi çok yüksek risk oluşturur.",
                    "Coğrafi kaynaklardan kritik portlara erişimi tamamen kısıtlayın. "
                    "Gerekiyorsa VPN tüneli zorunlu kılın.",
                    details,
                ))
            else:
                # KRİTİK: Normal kaynak + kritik port
                findings.append(_finding(
                    Platform.FORTIMANAGER, device_name, customer, pid, pname,
                    Severity.CRITICAL,
                    "Kritik Port Kullanımları",
                    f"Aşağıdaki yüksek riskli portlar bu kural kapsamında açık: {port_list}.",
                    "Gereksiz portları kapatın. SSH/RDP için kaynak kısıtlaması ve VPN zorunlu kılın. "
                    "Veritabanı portlarına doğrudan internet erişimine izin vermeyin.",
                    details,
                ))

        # ── KRİTİK 3: Geniş Kaynak Subnet ────────────────────────────────
        for addr in src:
            if any(addr.endswith(p) for p in BROAD_PREFIXES):
                findings.append(_finding(
                    Platform.FORTIMANAGER, device_name, customer, pid, pname,
                    Severity.CRITICAL,
                    "Geniş Kaynak Subnet",
                    f"Kaynak adres olarak geniş subnet kullanılmış: {addr}. "
                    "Beklenenden çok daha fazla kaynağa erişim izni verebilir.",
                    "Kaynak IP bloğunu yalnızca gerçekten ihtiyaç duyulan aralıkla sınırlandırın.",
                    details,
                ))
                break

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


# ─────────────────────────────────────────────────────────────────────────────
#  Palo Alto Kontrolleri
# ─────────────────────────────────────────────────────────────────────────────

def _pa_is_any(member_list: List[str]) -> bool:
    return any(m in PA_ANY_ADDRS for m in member_list)


def analyze_paloalto_vsys(vsys: Dict[str, Any]) -> ScanResult:
    device_name = vsys["name"]
    customer    = vsys["customer"]
    rules       = vsys.get("rules", [])
    findings: List[Finding] = []

    for rule in rules:
        rname        = rule.get("name", "unnamed")
        sources      = rule.get("source", ["any"])
        destinations = rule.get("destination", ["any"])
        applications = rule.get("application", ["any"])
        services     = rule.get("service", ["application-default"])
        action       = rule.get("action", "deny").lower()
        log_end      = rule.get("log_end", True)
        log_start    = rule.get("log_start", False)
        disabled     = rule.get("disabled", False)
        description  = rule.get("description", "")
        from_zones   = rule.get("from_zones", ["any"])
        to_zones     = rule.get("to_zones", ["any"])
        sec_profiles = rule.get("security_profiles", {})

        # Oluşturan / değiştiren (PA API sağlarsa)
        created_by  = rule.get("created_by", "") or ""
        modified_by = rule.get("modified_by", "") or ""

        details: Dict[str, Any] = {
            "Kaynak Zone":  ", ".join(from_zones),
            "Hedef Zone":   ", ".join(to_zones),
            "Kaynak":       ", ".join(sources),
            "Hedef":        ", ".join(destinations),
            "Uygulama":     ", ".join(applications),
            "Servis":       ", ".join(services),
            "Aksiyon":      action.upper(),
            "Log End":      "Açık" if log_end else "Kapalı",
            "Durum":        "Devre Dışı" if disabled else "Aktif",
            "Açıklama":     description or "(yok)",
        }
        if created_by:
            details["Oluşturan"] = created_by
        if modified_by:
            details["Son Değiştiren"] = modified_by

        # Zone hesaplamaları
        zone_is_untrust   = any(z.lower() in PA_UNTRUST_ZONES for z in from_zones)
        zone_dst_is_trust = any(z.lower() in PA_TRUST_ZONES   for z in to_zones)
        zone_src_any      = any(z.lower() == "any"             for z in from_zones)

        pa_src_any = _pa_is_any(sources)
        pa_dst_any = _pa_is_any(destinations)
        pa_app_any = _pa_is_any(applications)
        pa_svc_any = any(s.lower() == "any" for s in services)

        # Webfilter kontrolü
        wf  = str(sec_profiles.get("webfilter", "") or "").strip()
        grp = str(sec_profiles.get("group",     "") or "").strip()
        has_webfilter = bool(wf or grp)

        # ── ACİL A5: (Untrust/Any zone) + Kaynak=Any + Servis=Any ─────────
        if action == "allow" and (zone_is_untrust or zone_src_any) and pa_src_any and pa_svc_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.ACIL,
                "Untrust/Any Zone + Kaynak=Any + Servis=Any",
                "Dış zone (Untrust) veya zone=any kaynaktan herhangi bir IP'ye tüm servislere izin "
                "veriliyor. İnternet kaynaklı her türlü saldırı bu kural üzerinden geçebilir.",
                "Zone, kaynak IP ve servis alanlarını kısıtlayın. "
                "Untrust zone için hiçbir zaman kaynak=any ve servis=any birlikteliğine izin vermeyin.",
                details,
            ))

        # ── ACİL A0: Untrust Zone + Tüm Servisler (kaynak spesifik) ──────
        if action == "allow" and zone_is_untrust and pa_svc_any and not pa_src_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.ACIL,
                "Untrust Zone: Tüm Servisler Açık",
                "Dış zone (Untrust) kaynaklı tüm servislere izin veriliyor. "
                "İnternet kaynaklı her türlü protokol ve port hedef sistemlere erişebilir.",
                "Untrust zone için servis alanını yalnızca zorunlu portlarla (örn. HTTPS/443) "
                "sınırlandırın.",
                details,
            ))

        # ── KRİTİK: Any-Any-Any ──────────────────────────────────────────
        if action == "allow" and pa_src_any and pa_dst_any and pa_app_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Any-Any-Any Kuralı",
                "Kaynak, hedef ve uygulama alanlarının tamamı 'any'. "
                "Tüm trafiğe izin veren açık kapı kuralı.",
                "Kuralı spesifik kaynak/hedef/uygulama kombinasyonuyla yeniden tanımlayın.",
                details,
            ))

        # ── KRİTİK: Kaynak+Hedef Kısıtsız (App=Spesifik) ─────────────────
        if action == "allow" and pa_src_any and pa_dst_any and not pa_app_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Kaynak ve Hedef Kısıtsız",
                "Kaynak ve hedef 'any' olarak tanımlanmış; yalnızca uygulama kısıtlaması mevcut. "
                "Herhangi bir kaynak herhangi bir hedefe ulaşabilir.",
                "Kaynak ve hedef alanlarını belirli zone, IP grubu veya adres nesnesiyle sınırlandırın.",
                details,
            ))

        # ── KRİTİK: Hedef Kısıtsız ───────────────────────────────────────
        if action == "allow" and pa_dst_any and not pa_src_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Hedef Kısıtsız Erişim",
                "Hedef adres 'any' olarak tanımlanmış. Trafik herhangi bir hedefe yönlendirilebilir; "
                "veri sızıntısı riski oluşturur.",
                "Hedef alanını yalnızca gerekli sunucu, zone veya adres grubuyla sınırlandırın.",
                details,
            ))

        # ── KRİTİK: Kaynak Kısıtsız (Hedef Spesifik) ─────────────────────
        if action == "allow" and pa_src_any and not pa_dst_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Kaynak Kısıtlaması Yok",
                "Allow kuralında kaynak 'any' olarak tanımlanmış. "
                "Herhangi bir IP adresi bu kural üzerinden erişim sağlayabilir.",
                "Kaynak olarak belirli IP grupları, adres nesneleri veya bölgeler tanımlayın.",
                details,
            ))

        # ── KRİTİK: Untrust→Trust + Web Filter ───────────────────────────
        if action == "allow" and zone_is_untrust and zone_dst_is_trust and has_webfilter:
            wf_label = wf if wf else f"(grup: {grp})"
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Untrust→Trust: Web Filter Uygulanmış",
                f"İnternet (Untrust) → İç Ağ (Trust) yönlü bu kurala '{wf_label}' Web Filter profili "
                "atanmış. Bu yöndeki trafiğe Web Filter uygulanması meşru erişimleri engelleyebilir.",
                "Untrust→Trust yönlü kurallarda Web Filter profilini kaldırın ya da kural amacını "
                "gözden geçirin. İçerik filtrelemesi genellikle Trust→Untrust yönlü uygulanmalıdır.",
                details,
            ))

        # ── KRİTİK: Servis=Any, Kaynak+Hedef Spesifik ────────────────────
        if action == "allow" and pa_svc_any and not pa_src_any and not pa_dst_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Servis Kısıtsız Erişim",
                "Servis alanı 'any' olarak tanımlanmış; kaynak ve hedef kısıtlı olsa da "
                "tüm TCP/UDP portlarına izin veriliyor.",
                "Servis alanını yalnızca gerekli port ve protokollerle sınırlandırın. "
                "'application-default' kullanmayı değerlendirin.",
                details,
            ))

        # ── KRİTİK: Uygulama Kısıtlaması Yok ────────────────────────────
        if action == "allow" and pa_app_any and not pa_src_any:
            findings.append(_finding(
                Platform.PALOALTO, device_name, customer, rname, rname,
                Severity.CRITICAL,
                "Uygulama Kısıtlaması Yok",
                "Kural belirli bir uygulama kısıtlaması içermiyor (application: any). "
                "Tüm uygulamaların bu kural üzerinden geçmesine izin veriliyor.",
                "App-ID kullanarak yalnızca gerekli uygulamaları açıkça tanımlayın.",
                details,
            ))

        # ── KRİTİK: Kritik Port Kullanımları ─────────────────────────────
        high_risk = _detect_high_risk_ports(services, applications)
        if action == "allow" and high_risk:
            port_list = ", ".join(high_risk)
            geo_addrs = _find_geo_addrs(sources)

            # ACİL: Coğrafi kaynak + kritik port
            if geo_addrs:
                findings.append(_finding(
                    Platform.PALOALTO, device_name, customer, rname, rname,
                    Severity.ACIL,
                    "Geolocation Bazlı Kritik Kullanım",
                    f"Coğrafi kaynak ({', '.join(geo_addrs)}) ile kritik port kullanımı tespit edildi: "
                    f"{port_list}. Ülke bazlı kaynak + riskli port birleşimi çok yüksek risk oluşturur.",
                    "Coğrafi kaynaklardan kritik portlara erişimi tamamen kısıtlayın. "
                    "Gerekiyorsa VPN tüneli zorunlu kılın.",
                    details,
                ))
            else:
                findings.append(_finding(
                    Platform.PALOALTO, device_name, customer, rname, rname,
                    Severity.CRITICAL,
                    "Kritik Port Kullanımları",
                    f"Aşağıdaki yüksek riskli portlar bu kural kapsamında açık: {port_list}.",
                    "Gereksiz portları kapatın. SSH/RDP için kaynak kısıtlaması ve VPN zorunlu kılın. "
                    "Veritabanı portlarına doğrudan internet erişimine izin vermeyin.",
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


# ─────────────────────────────────────────────────────────────────────────────
#  Ana Tarayıcı
# ─────────────────────────────────────────────────────────────────────────────

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
