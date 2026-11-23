# -*- coding: utf-8 -*-
# ============================================================================
#  SukurBoot 2.0 on the System  (sukurboot_2.0.py)
#  Сторож системных файлов с зашифрованным хранилищем эталонов на D:
#
#  Зависимости:  pip install pywin32 cryptography
#
#  Команды (первый запуск — от имени администратора):
#    python sukurboot_2.0.py init-system — создать эталоны ОТ ИМЕНИ SYSTEM
#                                          (одноразовая задача планировщика)
#    python sukurboot_2.0.py init        — то же, но в текущем контексте
#                                          (только для отладки; ключ тогда
#                                          будет в DPAPI администратора!)
#    python sukurboot_2.0.py install     — автозапуск мониторинга от SYSTEM
#    python sukurboot_2.0.py status      — что накопилось в ожидании реанимации
#    python sukurboot_2.0.py verify      — разовая сверка с эталоном
#    python sukurboot_2.0.py refresh     — принять текущее состояние как эталон
#    python sukurboot_2.0.py unlock      — ручная реанимация (нужен SYSTEM)
#  Без аргументов — режим мониторинга (запускается планировщиком при загрузке).
#
#  Как это работает:
#    1. init: сканирует защищённые каталоги, каждый файл шифруется AES-GCM
#       ключом, выведенным из случайно сгенерированного пароля (PBKDF2).
#    2. Пароль шифруется через DPAPI в контексте SYSTEM и лежит в хранилище.
#       Расшифровать его может только процесс от SYSTEM.
#    3. Монитор сверяет хэши с эталоном: подменённый файл уходит в карантин
#       и мгновенно заменяется эталоном. Исчезнувший файл восстанавливается.
#       Массовая порча (>= DAMAGE_THRESHOLD файлов за цикл) — вероятный
#       шифровальщик: только карантин, восстановление ждёт команды unlock.
# ============================================================================

import os
import sys
import json
import time
import shutil
import hashlib
import secrets
import subprocess
import ctypes
from pathlib import Path
from datetime import datetime

# ============================ НАСТРОЙКИ ====================================

WATCH_DIRS = [
    r"C:\Windows\System32\Boot",
    r"C:\Windows\System32\drivers",
    r"C:\Windows\System32\config",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

VAULT            = Path(r"D:\SukurBootVault")
MAX_FILE         = 64 * 1024 * 1024   # файлы крупнее не хэшируем
CHECK_INTERVAL   = 15                 # сек между циклами проверки
DAMAGE_THRESHOLD = 10                 # порог массовой порчи за цикл
KDF_ITERATIONS   = 300_000            # PBKDF2
TASK_NAME        = "SukurBoot2_0_Monitor"

META       = VAULT / "vault.meta"     # соль (32) + верификатор ключа (16)
INDEX      = VAULT / "index.json"     # lower(путь) -> {hash, enc}
BASELINE   = VAULT / "baseline.json"  # lower(путь) -> hash
KEY_FILE   = VAULT / "key.bin"        # пароль, зашифрованный DPAPI (SYSTEM)
LOG        = VAULT / "monitor.log"
QUARANTINE = VAULT / "quarantine"
PENDING    = VAULT / "pending.json"
ENC_DIR    = VAULT / "clean"

try:
    import win32crypt
    HAS_DPAPI = True
except ImportError:
    HAS_DPAPI = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04


# ----------------------------- утилиты ------------------------------------

def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def hide_folder():
    try:
        ctypes.windll.kernel32.SetFileAttributesW(
            str(VAULT), ATTR_HIDDEN | ATTR_SYSTEM)
    except Exception:
        pass


def derive_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, KDF_ITERATIONS)


def sha256_file(path: Path):
    """Хэш файла; None — не читается; TOO_BIG — крупнее лимита."""
    try:
        if path.stat().st_size > MAX_FILE:
            return "TOO_BIG"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def scan():
    """Состояние наблюдаемых файлов: НАСТОЯЩИЙ путь -> хэш.
    Регистр пути сохраняется — доступ к файлам идёт только по нему.
    Нижний регистр используется лишь как ключ словарей."""
    state = {}
    for root in WATCH_DIRS:
        if not Path(root).exists():
            continue
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                p = Path(dirpath) / name
                digest = sha256_file(p)
                if digest:
                    state[str(p)] = digest
    return state


def rel_of(real_path: str) -> str:
    # C:\Windows\... -> C_Windows\... (структура сохраняется в хранилище)
    return real_path[0] + "_" + real_path[3:]


def enc_write(key: bytes, src: Path, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_bytes(12)
    enc = AESGCM(key).encrypt(nonce, src.read_bytes(), None)
    dest.write_bytes(nonce + enc)


def enc_read(key: bytes, src: Path, dest: Path):
    blob = src.read_bytes()
    plain = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(plain)


def build_index_and_baseline(key: bytes):
    """Сканирует, шифрует эталоны, пишет index.json и baseline.json."""
    state = scan()
    print("Найдено файлов: %d" % len(state))
    index = {}
    done = 0
    for real_path, digest in state.items():
        p = Path(real_path)
        if digest == "TOO_BIG":
            index[real_path.lower()] = {"hash": digest}
        else:
            try:
                enc_write(key, p, ENC_DIR / rel_of(real_path))
                index[real_path.lower()] = {"hash": digest, "enc": rel_of(real_path)}
            except (PermissionError, OSError) as exc:
                log("Нет доступа, эталон не создан: %s (%r)" % (real_path, exc))
                index[real_path.lower()] = {"hash": digest}
        done += 1
        if done % 500 == 0:
            print("  обработано %d / %d" % (done, len(state)))
    INDEX.write_text(json.dumps(index, ensure_ascii=False, indent=1),
                     encoding="utf-8")
    BASELINE.write_text(
        json.dumps({k.lower(): v for k, v in state.items()},
                   ensure_ascii=False, indent=1),
        encoding="utf-8")


# ------------------------- ключ: DPAPI (SYSTEM) ---------------------------

def protect_key(password: bytes) -> bytes:
    if not HAS_DPAPI:
        raise RuntimeError("pywin32 не установлен: pip install pywin32")
    blob, _ = win32crypt.CryptProtectData(password, "SukurBoot2.0",
                                          None, None, None, 0)
    return blob


def unprotect_key(blob: bytes) -> bytes:
    if not HAS_DPAPI:
        raise RuntimeError("pywin32 не установлен: pip install pywin32")
    _desc, password = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
    return password


def load_session_key():
    """Ключ AES из DPAPI-хранилища. None — недоступен из этого контекста."""
    if not (KEY_FILE.exists() and META.exists()):
        return None
    try:
        password = unprotect_key(KEY_FILE.read_bytes())
        salt = META.read_bytes()[:32]
        return derive_key(password, salt)
    except Exception as exc:
        log("Ключ недоступен из этого контекста: %r" % (exc,))
        return None


def is_system_context() -> bool:
    try:
        return os.environ.get("USERNAME", "").upper() == "SYSTEM" or \
               "SYSTEM" in os.environ.get("USERPROFILE", r"").upper()
    except Exception:
        return False


# ------------------------------ команды -----------------------------------

def cmd_init():
    VAULT.mkdir(parents=True, exist_ok=True)
    QUARANTINE.mkdir(exist_ok=True)
    PENDING.write_text("[]", encoding="utf-8")

    if not is_system_context():
        print("[!] Внимание: ты запускаешь init НЕ от SYSTEM.")
        print("    Тогда ключ будет защищён в контексте администратора, а монитор")
        print("    от SYSTEM его не прочтёт. Правильно: python sukurboot_2.0.py init-system")

    password = secrets.token_urlsafe(24)   # пароль не знает никто, даже ты
    salt = secrets.token_bytes(32)
    key = derive_key(password.encode(), salt)
    verifier = hashlib.sha256(key).digest()[:16]

    print("Сканирование и шифрование эталонов — это может занять несколько минут...")
    build_index_and_baseline(key)
    META.write_bytes(salt + verifier)
    KEY_FILE.write_bytes(protect_key(password.encode()))
    hide_folder()

    log("База создана. Ключ в DPAPI-контейнере %s."
        % ("SYSTEM" if is_system_context() else "текущего пользователя"))
    print("\n[+] Хранилище: %s (папка скрыта)" % VAULT)
    print("[i] Пароль не показывается и не хранится в открытом виде.")
    print("[i] Проверка целостности: python sukurboot_2.0.py verify")


def cmd_init_system():
    """Создаёт одноразовую задачу, выполняющую init от SYSTEM."""
    script = Path(__file__).resolve()
    tr = '\\"%s\\" \\"%s\\" init' % (sys.executable, script)
    task = "SukurBoot2_0_Init"
    sch = ('schtasks /Create /TN %s /TR "%s" /SC ONCE /ST 00:00 '
           '/RU SYSTEM /RL HIGHEST /F' % (task, tr))
    r = subprocess.run(sch, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print("[!] Планировщик ответил: %s %s" % (r.stdout.strip(), r.stderr.strip()))
        return
    subprocess.run("schtasks /Run /TN %s" % task, shell=True)
    print("[+] Init запущен от SYSTEM. Процесс идёт в фоне.")
    print("    Прогресс и результат: %s" % LOG)
    subprocess.run("schtasks /Delete /TN %s /F" % task, shell=True)
    print("[i] Через несколько минут проверь: python sukurboot_2.0.py verify")


def cmd_install():
    script = Path(__file__).resolve()
    tr = '\\"%s\\" \\"%s\\" monitor' % (sys.executable, script)
    sch = ('schtasks /Create /TN %s /TR "%s" /SC ONSTART /RU SYSTEM '
           '/RL HIGHEST /F' % (TASK_NAME, tr))
    r = subprocess.run(sch, shell=True, capture_output=True, text=True)
    if r.returncode == 0:
        print("[+] Автозапуск от SYSTEM установлен (задача: %s)" % TASK_NAME)
    else:
        print("[!] Планировщик ответил: %s %s" % (r.stdout.strip(), r.stderr.strip()))
        print("    Выполни команду от имени администратора.")


def cmd_verify():
    if not BASELINE.exists():
        print("[!] Базы нет. Сначала: python sukurboot_2.0.py init-system")
        return
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    current = scan()
    changed, missing, new = [], [], []
    for real_path, digest in current.items():
        old = baseline.get(real_path.lower())
        if old is None:
            new.append(real_path)
        elif old != digest and digest != "TOO_BIG":
            changed.append(real_path)
    for low in baseline:
        if low not in {p.lower() for p in current}:
            missing.append(low)
    print("Проверено файлов: %d" % len(current))
    print("Изменённых: %d | Исчезнувших: %d | Новых: %d"
          % (len(changed), len(missing), len(new)))
    for lst, label in ((changed, "ИЗМЕНЁН"), (missing, "ИСЧЕЗ"), (new, "НОВЫЙ")):
        for p in lst[:15]:
            print("  [%s] %s" % (label, p))
    if not changed and not missing:
        print("[+] Система соответствует эталону.")
    else:
        print("[!] Есть отклонения. После легитимных обновлений Windows это"
              " нормально — обнови эталон: python sukurboot_2.0.py refresh")


def cmd_refresh():
    """Принять текущее состояние как новый эталон (после обновлений Windows)."""
    if not (KEY_FILE.exists() and META.exists() and INDEX.exists()):
        print("[!] Сначала init-system.")
        return
    key = load_session_key()
    if key is None:
        return
    print("Шифрование новых эталонов...")
    build_index_and_baseline(key)
    META_salt = META.read_bytes()[:32]     # соль прежняя
    verifier = hashlib.sha256(key).digest()[:16]
    META.write_bytes(META_salt + verifier)
    hide_folder()
    log("Эталон обновлён (%d файлов)." % len(json.loads(INDEX.read_text(encoding="utf-8"))))


def cmd_status():
    pending = json.loads(PENDING.read_text(encoding="utf-8")) if PENDING.exists() else []
    print("В ожидании ручной реанимации: %d" % len(pending))
    for item in pending[:20]:
        print(" - %s (%s)" % (item.get("path", "?"), item.get("time", "?")))


def quarantine_copy(real_path: str) -> bool:
    p = Path(real_path)
    dest = QUARANTINE / datetime.now().strftime("%Y%m%d_%H%M%S") / rel_of(real_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(p, dest)
        return True
    except OSError:
        return False


def restore_from_index(real_or_low_path: str):
    """Заменить файл эталоном из хранилища.
    Возвращает чистый хэш файла или None, если восстановить не удалось."""
    key = load_session_key()
    if key is None:
        return None
    try:
        index = json.loads(INDEX.read_text(encoding="utf-8"))
        info = index.get(real_or_low_path.lower(), {})
        enc = ENC_DIR / info["enc"] if "enc" in info else None
        if enc and enc.exists():
            enc_read(key, enc, Path(real_or_low_path))
            log("ВОССТАНОВЛЕН: %s" % real_or_low_path)
            return info["hash"]
    except Exception as exc:
        log("Не удалось восстановить %s: %r" % (real_or_low_path, exc))
    return None


def append_pending(item):
    pending = json.loads(PENDING.read_text(encoding="utf-8")) if PENDING.exists() else []
    pending.append(item)
    PENDING.write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")


def cmd_unlock():
    """Ручная реанимация накопившегося (когда автовосстановление не помогло)."""
    if not (PENDING.exists() and INDEX.exists()):
        print("[!] Нечего реанимировать.")
        return
    key = load_session_key()
    if key is None:
        print("[!] Ключ недоступен: запускай от SYSTEM (задача %s)." % TASK_NAME)
        return
    pending = json.loads(PENDING.read_text(encoding="utf-8"))
    if not pending:
        print("[i] Накопившихся изменений нет.")
        return
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    restored = 0
    for item in pending:
        real_path = item["path"]
        info = index.get(real_path.lower(), {})
        enc = ENC_DIR / info["enc"] if "enc" in info else None
        if enc and enc.exists():
            try:
                enc_read(key, enc, Path(real_path))
                restored += 1
            except Exception:
                log("НЕ ВОССТАНОВЛЕНО: %s" % real_path)
        else:
            log("НЕТ ЭТАЛОНА: %s" % real_path)
    PENDING.write_text("[]", encoding="utf-8")
    print("[+] Реанимация: восстановлено %d из %d." % (restored, len(pending)))


def cmd_monitor():
    if not BASELINE.exists():
        print("[!] Базы нет. Сначала: python sukurboot_2.0.py init-system")
        return
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    print("[i] SukurBoot 2.0: мониторинг запущен. Файлов под наблюдением: %d."
          % len(baseline))
    while True:
        current = scan()
        pending_paths = {i.get("path", "").lower()
                         for i in json.loads(PENDING.read_text(encoding="utf-8"))} \
            if PENDING.exists() else set()
        damaged = 0
        for real_path, digest in current.items():
            old = baseline.get(real_path.lower())
            if old is None:
                log("НОВЫЙ ФАЙЛ: %s" % real_path)
            elif old != digest and digest != "TOO_BIG":
                damaged += 1
                low = real_path.lower()
                if low in pending_paths:
                    continue   # уже ждёт реанимации, не дублируем
                if damaged >= DAMAGE_THRESHOLD:
                    log("МАССОВАЯ ПОРЧА (%d файлов)! Вероятен шифровальщик:"
                        " восстановление остановлено, ждём unlock." % damaged)
                    append_pending({"path": real_path,
                                    "time": datetime.now().isoformat(timespec="seconds")})
                    pending_paths.add(low)
                    continue
                log("ВНИМАНИЕ, возможная подмена: %s" % real_path)
                quarantine_copy(real_path)
                clean = restore_from_index(real_path)
                if clean is not None:
                    baseline[low] = clean   # эталон сразу актуален
                else:
                    append_pending({"path": real_path,
                                    "time": datetime.now().isoformat(timespec="seconds")})
                    pending_paths.add(low)
        real_of = {p.lower(): p for p in current}
        for low in baseline:
            if low not in real_of:
                if low in pending_paths:
                    continue
                log("ИСЧЕЗ: %s — попытка восстановления" % low)
                clean = restore_from_index(low)
                if clean is not None:
                    baseline[low] = clean
                else:
                    append_pending({"path": low,
                                    "time": datetime.now().isoformat(timespec="seconds")})
                    pending_paths.add(low)
        try:
            BASELINE.write_text(json.dumps(baseline, ensure_ascii=False, indent=1),
                                encoding="utf-8")
        except OSError:
            pass
        time.sleep(CHECK_INTERVAL)


def main():
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "monitor"
    actions = {
        "init":        cmd_init,
        "init-system": cmd_init_system,
        "install":     cmd_install,
        "status":      cmd_status,
        "verify":      cmd_verify,
        "refresh":     cmd_refresh,
        "unlock":      cmd_unlock,
        "monitor":     cmd_monitor,
    }
    action = actions.get(cmd)
    if action is None:
        print(__doc__)
    else:
        action()


if __name__ == "__main__":
    main()
