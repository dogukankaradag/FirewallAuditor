"""
JWT tabanlı kimlik doğrulama.
Roller: admin (tam yetki) | readonly (sadece görüntüleme ve Excel export)
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from . import db_models

# Üretimde ortam değişkeniyle override et
SECRET_KEY = os.getenv("SECRET_KEY", "fw-audit-dev-secret-change-in-prod-2024!")
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


def ensure_default_users(db: Session) -> None:
    """İlk çalıştırmada varsayılan kullanıcıları oluşturur."""
    if db.query(db_models.User).count() > 0:
        return

    defaults = [
        ("admin",    "Admin1234!",    "admin",    "Sistem Yöneticisi"),
        ("readonly", "Readonly1234!", "readonly", "Salt Okunur Kullanıcı"),
    ]
    for username, password, role, full_name in defaults:
        create_user(db, username, password, role, full_name)

    print("\n" + "="*55)
    print("  🔐 Varsayılan kullanıcılar oluşturuldu:")
    print("     admin    / Admin1234!    (tam yetki)")
    print("     readonly / Readonly1234! (salt okunur)")
    print("  ⚠️  Üretimde parolaları değiştirin!")
    print("="*55 + "\n")
