"""
Veritabanını sıfırlar. Sunucuyu durdurmadan önce çalıştırın.
Kullanım: python reset_db.py
"""
import os
import sys

db_file = os.path.join(os.path.dirname(__file__), "firewall_audit.db")
journal = db_file + "-journal"
wal = db_file + "-wal"
shm = db_file + "-shm"

for path in [db_file, journal, wal, shm]:
    if os.path.exists(path):
        os.remove(path)
        print(f"Silindi: {path}")

print("\n✅ Veritabanı sıfırlandı. Şimdi 'python run.py' ile uygulamayı yeniden başlatın.")
print("   Uygulama açılışta otomatik tarama yaparak yeni verilerle veritabanını oluşturacak.")
