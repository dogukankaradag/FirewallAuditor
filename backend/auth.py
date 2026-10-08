"""
JWT tabanlı kimlik doğrulama.
Roller: admin (tam yetki) | editor (tara/düzenle, ayarlar yok, kullanıcı yönetimi yok) | readonly (sadece görüntüleme ve Excel export)
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from . import db_models

log = logging.getLogger(__name__)


def _load_secret_key() -> str:
    """JWT imzalama anahtarı.

    Öncelik: SECRET_KEY ortam değişkeni → proje kökündeki .secret_key dosyası.
    Dosya yoksa ilk açılışta rastgele bir anahtar üretilip oraya yazılır (git'e girmez).
    Koda gömülü sabit bir anahtar YOKTUR; aksi halde anahtarı bilen herkes admin token'ı üretebilir.
    """
    env_key = os.getenv("SECRET_KEY", "").strip()
    if env_key == "fw-audit-dev-secret-change-in-prod-2024!":
        log.error("SECRET_KEY eski, herkesçe bilinen varsayılan değere ayarlı; yok sayılıyor.")
        env_key = ""
    if env_key:
        if len(env_key) < 32:
            log.warning("SECRET_KEY 32 karakterden kısa; daha uzun rastgele bir değer önerilir.")
        return env_key
    path = Path(os.getenv("SECRET_KEY_FILE", Path(__file__).resolve().parent.parent / ".secret_key"))
    try:
        if path.exists():
            key = path.read_text(encoding="utf-8").strip()
            if len(key) >= 32:
                return key
        key = secrets.token_urlsafe(48)
        path.write_text(key, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        log.warning("Yeni JWT imzalama anahtarı oluşturuldu: %s", path)
        return key
    except OSError as e:
        # Dosyaya yazılamazsa geçici anahtar: uygulama çalışır ama her yeniden başlatmada oturumlar düşer
        log.error("SECRET_KEY dosyası yazılamadı (%s); geçici anahtar kullanılıyor. "
                  "SECRET_KEY ortam değişkenini tanımlayın.", e)
        return secrets.token_urlsafe(48)


SECRET_KEY = _load_secret_key()
ALGORITHM  = "HS256"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ── Parola ────────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# ── Token ─────────────────────────────────────────────────────────────

def create_access_token(username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependency'ler ────────────────────────────────────────────────────

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> db_models.User:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Geçersiz veya süresi dolmuş oturum. Lütfen tekrar giriş yapın.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if not username:
            raise exc
    except JWTError:
        raise exc

    user = db.query(db_models.User).filter(
        db_models.User.username == username,
        db_models.User.is_active == True,
    ).first()
    if not user:
        raise exc
    return user


def require_admin(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için admin yetkisi gereklidir.",
        )
    return current_user


def require_editor_or_admin(current_user: db_models.User = Depends(get_current_user)) -> db_models.User:
    """Admin veya Firewall Editor rolüne izin verir."""
    if current_user.role not in ("admin", "editor"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için admin veya editor yetkisi gereklidir.",
        )
    return current_user


# ── Kullanıcı yardımcıları ────────────────────────────────────────────

def authenticate_user(db: Session, username: str, password: str) -> Optional[db_models.User]:
    user = db.query(db_models.User).filter(
        db_models.User.username == username,
        db_models.User.is_active == True,
    ).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def create_user(
    db: Session,
    username: str,
    password: str,
    role: str = "readonly",
    full_name: str = "",
) -> db_models.User:
    user = db_models.User(
        username=username,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# Eski sürümlerin kodda yazılı varsayılan parolaları — hâlâ kullanılıyorsa açılışta uyarılır
_LEGACY_DEFAULTS = {"admin": "Admin1234!", "readonly": "Readonly1234!"}


def ensure_default_users(db: Session) -> None:
    """İlk çalıştırmada yalnızca admin kullanıcısını oluşturur.

    Parola ADMIN_PASSWORD ortam değişkeninden alınır; yoksa rastgele üretilir ve
    yalnızca bu ilk açılışta konsola yazdırılır. Koda gömülü varsayılan parola yoktur.
    Diğer kullanıcılar arayüzdeki Kullanıcılar ekranından eklenir.
    """
    if db.query(db_models.User).count() > 0:
        _warn_legacy_passwords(db)
        return

    from_env = bool(os.getenv("ADMIN_PASSWORD"))
    password = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    create_user(db, "admin", password, "admin", "Sistem Yöneticisi")

    print("\n" + "=" * 60)
    print("  🔐 İlk admin kullanıcısı oluşturuldu")
    if from_env:
        print("     admin / (ADMIN_PASSWORD ortam değişkenindeki parola)")
    else:
        print(f"     admin / {password}")
        print("  ⚠️  Bu parola bir daha gösterilmeyecek; giriş yapıp değiştirin.")
    print("=" * 60 + "\n")


def _warn_legacy_passwords(db: Session) -> None:
    for username, legacy in _LEGACY_DEFAULTS.items():
        user = db.query(db_models.User).filter(
            db_models.User.username == username,
            db_models.User.is_active == True,
        ).first()
        if user and verify_password(legacy, user.hashed_password):
            msg = (f"GÜVENLİK UYARISI: '{username}' kullanıcısı hâlâ eski varsayılan parolayı kullanıyor. "
                   f"Kullanıcılar ekranından hemen değiştirin.")
            log.warning(msg)
            print("\n⚠️  " + msg + "\n")
