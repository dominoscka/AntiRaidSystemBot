import logging
import os
import sqlite3
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telegram import (
    Update,
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ChatJoinRequest,
)
from telegram.constants import ChatMemberStatus, ChatType
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ChatMemberHandler,
    ChatJoinRequestHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
    AIORateLimiter,
)
from telegram.ext.filters import ChatType as ChatTypeFilter

# ================== НАСТРОЙКИ ==================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DB_PATH = Path(os.getenv("DB_PATH", "antiraid.db"))

# Обязательная подписка на канал (бот должен быть админом канала!)
REQUIRED_CHANNEL = os.getenv("REQUIRED_CHANNEL", "@твой_канал")
CHANNEL_LINK = os.getenv("CHANNEL_LINK", "https://t.me/твой_канал")

# Анти-флуд
FLOOD_LIMIT = 6
FLOOD_WINDOW = 10

# Анти-рейд
RAID_JOIN_LIMIT = 8
RAID_JOIN_WINDOW = 30
RAID_MODE_SECONDS = 300

NEW_ACCOUNT_DAYS = 7
CAPTCHA_TIMEOUT = 120

# Нарастающие наказания по умолчанию (секунды). 6-е нарушение → бан.
DEFAULT_MUTE_STEPS = [
    10 * 60,       # 10 мин
    30 * 60,       # 30 мин
    2 * 60 * 60,   # 2 часа
    12 * 60 * 60,  # 12 часов
    24 * 60 * 60,  # 24 часа
]
VIOLATION_RESET_DAYS = 30
# ===============================================

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("bot.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("AntiRaidBot")


# ================== БАЗА ДАННЫХ ==================

def db_init():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS banned (
            user_id INTEGER PRIMARY KEY,
            chat_id INTEGER,
            reason TEXT,
            banned_at TEXT
        );
        CREATE TABLE IF NOT EXISTS warns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            chat_id INTEGER,
            reason TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            chat_id INTEGER,
            key TEXT,
            value TEXT,
            PRIMARY KEY (chat_id, key)
        );
        CREATE TABLE IF NOT EXISTS captcha (
            user_id INTEGER,
            chat_id INTEGER,
            answer TEXT,
            expires_at TEXT,
            PRIMARY KEY (user_id, chat_id)
        );
        CREATE TABLE IF NOT EXISTS violations (
            user_id INTEGER,
            chat_id INTEGER,
            count INTEGER DEFAULT 0,
            last_at TEXT,
            PRIMARY KEY (user_id, chat_id)
        );
        CREATE INDEX IF NOT EXISTS idx_banned_user ON banned(user_id);
        CREATE INDEX IF NOT EXISTS idx_warns_user_chat ON warns(user_id, chat_id);
        CREATE INDEX IF NOT EXISTS idx_violations_user_chat ON violations(user_id, chat_id);
    """)
    conn.commit()
    conn.close()


def db_exec(query: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    conn.commit()
    conn.close()


def db_fetchone(query: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    row = c.fetchone()
    conn.close()
    return row


def db_fetchall(query: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    return rows


# ================== НАСТРОЙКИ ЧАТА ==================

def get_setting(chat_id: int, key: str, default=None):
    row = db_fetchone(
        "SELECT value FROM settings WHERE chat_id = ? AND key = ?",
        (chat_id, key),
    )
    return row[0] if row else default


def set_setting(chat_id: int, key: str, value: str):
    db_exec(
        "INSERT OR REPLACE INTO settings(chat_id, key, value) VALUES (?, ?, ?)",
        (chat_id, key, value),
    )


def get_mute_steps(chat_id: int) -> list[int]:
    raw = get_setting(chat_id, "mute_steps")
    if not raw:
        return DEFAULT_MUTE_STEPS
    try:
        steps = [int(s) for s in raw.split(",") if s.strip()]
        return steps if steps else DEFAULT_MUTE_STEPS
    except Exception:
        return DEFAULT_MUTE_STEPS


# ================== БАНЫ ==================

def is_banned_globally(user_id: int) -> bool:
    return db_fetchone("SELECT 1 FROM banned WHERE user_id = ?", (user_id,)) is not None


def add_ban(user_id: int, chat_id: int, reason: str):
    db_exec(
        "INSERT OR REPLACE INTO banned(user_id, chat_id, reason, banned_at) VALUES (?, ?, ?, ?)",
        (user_id, chat_id, reason, datetime.now(timezone.utc).isoformat()),
    )


# ================== НАРУШЕНИЯ ==================

def get_violation_count(user_id: int, chat_id: int) -> int:
    row = db_fetchone(
        "SELECT count, last_at FROM violations WHERE user_id = ? AND chat_id = ?",
        (user_id, chat_id),
    )
    if not row:
        return 0
    count, last_at_s = row
    if last_at_s:
        try:
            last_at = datetime.fromisoformat(last_at_s)
            if (utcnow() - last_at).days >= VIOLATION_RESET_DAYS:
                db_exec(
                    "DELETE FROM violations WHERE user_id = ? AND chat_id = ?",
                    (user_id, chat_id),
                )
                return 0
        except Exception:
            pass
    return count


def increment_violation(user_id: int, chat_id: int) -> int:
    current = get_violation_count(user_id, chat_id)
    new_count = current + 1
    db_exec(
        "INSERT OR REPLACE INTO violations(user_id, chat_id, count, last_at) "
        "VALUES (?, ?, ?, ?)",
        (user_id, chat_id, new_count, utcnow().isoformat()),
    )
    return new_count


def reset_violations(user_id: int, chat_id: int):
    db_exec(
        "DELETE FROM violations WHERE user_id = ? AND chat_id = ?",
        (user_id, chat_id),
    )


def avg_mute_seconds(chat_id: int) -> int:
    steps = get_mute_steps(chat_id)
    rows = db_fetchall("SELECT count FROM violations WHERE chat_id = ?", (chat_id,))
    if not rows:
        return 0
    total = 0
    for (cnt,) in rows:
        for i in range(1, min(cnt, len(steps)) + 1):
            total += steps[i - 1]
    return total // len(rows)


# ================== КЭШИ И ХЕЛПЕРЫ ==================

user_flood: dict[int, list[datetime]] = defaultdict(list)
chat_joins: dict[int, list[datetime]] = defaultdict(list)
raid_mode_until: dict[int, datetime] = {}
admin_cache: dict[int, dict[int, str]] = {}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_duration(seconds: int) -> str:
    if seconds < 60:
