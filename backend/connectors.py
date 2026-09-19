"""
Firewall cihaz kayıt defteri.
Gerçek entegrasyonda bu listeye kendi cihazlarını ekle.
Her cihaz için: id, label (görünen isim), type, host (IP), port, credentials.
"""

FIREWALL_DEVICES = [
    # ── FortiManager Cihazları ──────────────────────────────────────────
    {
        "id":       "fm-01",
        "label":    "FortiManager-Istanbul",
        "type":     "fortimanager",
        "host":     "172.30.33.31",
        "port":     443,
        "username": "admin",
        "password": "changeme",
        # Gerçek entegrasyonda bu cihaza bağlanıp ADOM listesini çekersin.
        # Şimdilik mock_data.FORTIMANAGER_MOCK kullanılıyor.
        "mock": True,
    },
    {
        "id":       "fm-02",
        "label":    "FortiManager-Ankara",
        "type":     "fortimanager",
        "host":     "172.30.44.15",
        "port":     443,
        "username": "admin",
        "password": "changeme",
        "mock": True,
    },

    # ── Palo Alto Cihazları ─────────────────────────────────────────────
    {
        "id":       "pa-01",
        "label":    "PaloAlto-Istanbul",
        "type":     "paloalto",
        "host":     "172.30.33.50",
        "port":     443,
        "username": "admin",
        "password": "changeme",
        "mock": True,
    },
    {
        "id":       "pa-02",
        "label":    "PaloAlto-Ankara",
        "type":     "paloalto",
        "host":     "172.30.44.60",
        "port":     443,
        "username": "admin",
        "password": "changeme",
        "mock": True,
    },
]


def get_device(device_id: str) -> dict | None:
    return next((d for d in FIREWALL_DEVICES if d["id"] == device_id), None)


def list_devices() -> list[dict]:
    """Şifreler olmadan cihaz listesi döndürür (API response için)."""
    return [
        {
            "id":    d["id"],
            "label": d["label"],
            "type":  d["type"],
            "host":  d["host"],
            "port":  d["port"],
        }
        for d in FIREWALL_DEVICES
    ]
