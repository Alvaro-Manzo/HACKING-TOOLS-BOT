# -*- coding: utf-8 -*-
import os
import json
import random
import string
import subprocess
import requests
import socket
import ssl
import hashlib
import base64
import logging
import asyncio
import re
from urllib.parse import quote_plus, urlparse
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
import matplotlib.pyplot as plt
import ipaddress
import aiohttp
from datetime import time
from datetime import timedelta

# --- Dependencias (instalar con: pip install python-whois dnspython pandas openpyxl requests beautifulsoup4 python-telegram-bot) ---
import dns.resolver
import whois
import pandas as pd
from bs4 import BeautifulSoup
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application, 
    CallbackQueryHandler, 
    MessageHandler, 
    CommandHandler,
    ContextTypes, 
    filters,
    ConversationHandler
)

# --- CONFIGURACIÓN PRINCIPAL ---
TOKEN = "YOUR_BOT_TOKEN_HERE"
OWNER_ID = YOUR ID 
OWNER_USERNAME = "YOUR @"
DB_PATH = "toolbox_db.json"
KEY_LENGTH = 5
KEY_PREFIX = "VIP-"
ITEMS_PER_PAGE = 6

# --- Emojis para la Interfaz ---
EMOJI = {
    "BOT": "🤖", "TOOL": "🛠️", "PREMIUM": "💎", "BASIC": " B ", "PROFILE": "👤",
    "KEY": "🔑", "ADMIN": "👑", "HELP": "ℹ️", "EXIT": "🚪", "BACK": "⬅️",
    "SUCCESS": "✅", "ERROR": "❌", "WAIT": "⏳", "INFO": "💡", "PAGE": "📄",
    "NEXT": "➡️", "PREV": "⬅️", "LOCK": "🔒", "STATS": "📊", "EXPORT": "📥", "CLEAN": "🗑️"
}

# --- SISTEMA DE CRÉDITOS ---
CREDITS_COST = {
    "hash": 1,       # Herramientas básicas: 1 crédito
    "ip": 1,
    "ping": 1,
    "http": 1,
    "base64": 1,
    "password": 1,
    "ports_fast": 2, # Herramientas premium: 2-5 créditos
    "ports_full": 3,
    "vuln_scan": 5,
    "dns": 2,
    "whois": 2,
    "subdomain": 3,
    "dirsearch": 4,
    "tech_detect": 2,
    "reverseip": 3,
    "tls": 2,
    "cve_search": 3,
    "dorking": 2
}

COMMANDS_INFO = {
    "👤 Comandos de Usuario": {
        "/start": "Inicia el bot y muestra el menú principal",
        "/redeem": "Canjea una key VIP (Ejemplo: /redeem VIP-ABC12)",
        "/daily": "Muestra las tareas diarias y recompensas",
        "/top": "Muestra el ranking de usuarios más activos",
        "/profile": "Muestra tu perfil y estadísticas",
        "/help": "Muestra este mensaje de ayuda"
    },
    "💎 Comandos Premium": {
        "🔌 Scan": "Escaneo de puertos y vulnerabilidades",
        "🔍 DNS": "Consultas DNS y subdominios",
        "📁 DirSearch": "Búsqueda de directorios",
        "💻 Tech": "Detección de tecnologías web",
        "🔒 SSL": "Información de certificados SSL",
        "⚠️ CVE": "Búsqueda de vulnerabilidades"
    },
    "👑 Comandos de Admin": {
        "/key": "Genera una key premium (Solo Owner)",
        "/debug": "Muestra información detallada del bot",
        "/broadcast": "Envía mensaje a todos los usuarios",
        "/report": "Genera reporte de uso",
        "/stats": "Muestra estadísticas del bot",
        "/addgroup": "Añade el bot a un grupo"
    }
}


# --- DIRECTORIOS Y ARCHIVOS COMUNES A BUSCAR ---
COMMON_PATHS = [
    # Archivos de configuración
    ".env", "config.php", "wp-config.php", ".htaccess", "robots.txt",
    "sitemap.xml", ".git/HEAD", ".gitignore", "composer.json",
    
    # Directorios administrativos
    "admin/", "administrator/", "wp-admin/", "panel/", "webadmin/",
    "dashboard/", "cpanel/", "phpmyadmin/",
    
    # Directorios comunes
    "backup/", "bak/", "old/", "logs/", "temp/", "test/",
    "upload/", "uploads/", "images/", "img/", "css/", "js/",
    
    # Archivos sensibles
    "phpinfo.php", "info.php", "test.php", "database.sql",
    ".htpasswd", "web.config", "humans.txt", "error_log",
    
    # CMS y frameworks
    "wp-login.php", "wp-content/", "wp-includes/",
    "joomla/", "drupal/", "vendor/", "node_modules/",
    
    # Documentación y readme
    "README.md", "CHANGELOG.md", "LICENSE", "CONTRIBUTING.md",
    "docs/", "documentation/", "manual/", "wiki/"
]

async def show_commands(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /comandos - Muestra todos los comandos disponibles"""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    is_owner = user["plan"] == "OWNER"
    
    text = "📚 *LISTA DE COMANDOS*\n\n"
    
    # Comandos de Usuario
    text += "*👤 Comandos de Usuario*\n"
    for cmd, desc in COMMANDS_INFO["👤 Comandos de Usuario"].items():
        # Escapa los caracteres especiales en la descripción
        escaped_desc = escape_md(desc)
        text += f"`{cmd}` \\- {escaped_desc}\n"
    text += "\n"
    
    # Comandos Premium
    text += "*💎 Herramientas Premium*\n"
    for cmd, desc in COMMANDS_INFO["💎 Comandos Premium"].items():
        # Escapa los caracteres especiales en el comando y descripción
        escaped_cmd = escape_md(cmd)
        escaped_desc = escape_md(desc)
        text += f"`{escaped_cmd}` \\- {escaped_desc}\n"
    text += "\n"
    
    # Comandos de Admin (solo para owner)
    if is_owner:
        text += "*👑 Comandos de Admin*\n"
        for cmd, desc in COMMANDS_INFO["👑 Comandos de Admin"].items():
            # Escapa los caracteres especiales en la descripción
            escaped_desc = escape_md(desc)
            text += f"`{cmd}` \\- {escaped_desc}\n"
    
    text += f"\n💡 *Tip:* Usa /help para más información"
    
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        disable_web_page_preview=True
    )

async def run_dirsearch_pro(base_url: str) -> str:
    """
    Realiza una búsqueda de directorios y archivos comunes en una URL.
    
    Args:
        base_url (str): La URL base donde buscar (ej: https://ejemplo.com)
        
    Returns:
        str: Resultado formateado con los directorios/archivos encontrados
    """
    found = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    async def check_path(path: str):
        """Verifica si una ruta específica existe en el servidor."""
        try:
            # Construye la URL completa
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            
            # Realiza la petición HEAD (más rápida que GET)
            async with asyncio.timeout_at(asyncio.get_event_loop().time() + 5):
                response = await asyncio.to_thread(
                    requests.head, 
                    url, 
                    headers=headers,
                    allow_redirects=False,
                    timeout=4,
                    verify=False  # Ignora errores SSL para pruebas
                )
                
                # Analiza el código de respuesta
                if response.status_code < 404:
                    status = "✅" if response.status_code == 200 else "⚠️"
                    found.append(f"{status} `{path}` \\- `{response.status_code}`")
                    
        except (requests.RequestException, asyncio.TimeoutError):
            pass  # Ignora errores de conexión
        except Exception as e:
            logger.error(f"Error checking {path}: {e}")

    try:
        # Crea tareas para verificar cada ruta en paralelo
        tasks = [check_path(path) for path in COMMON_PATHS]
        await asyncio.gather(*tasks)
        
        # Prepara el resultado
        if not found:
            return f"{EMOJI['ERROR']} No se encontraron rutas accesibles\\."
        
        # Ordena los resultados (primero los 200 OK)
        found.sort(reverse=True)
        
        return (
            f"{EMOJI['SUCCESS']} *Directorios y archivos encontrados* "
            f"\\({len(found)} de {len(COMMON_PATHS)}\\):\n\n" + 
            "\n".join(found)
        )
        
    except Exception as e:
        logger.error(f"Error en dirsearch: {e}")
        return f"{EMOJI['ERROR']} Error ejecutando la búsqueda: {escape_md(str(e))}"


# --- Estados para ConversationHandler ---
WAITING_KEY, WAITING_TOOL_ARG = range(2)

# --- CONFIGURACIÓN DE LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- LÓGICA DE BASE DE DATOS ---
def read_db() -> Dict[str, Any]:
    if not os.path.exists(DB_PATH):
        with open(DB_PATH, "w", encoding='utf-8') as f: json.dump({"users": {}, "keys": {}, "audit": []}, f, indent=2)
    try:
        with open(DB_PATH, "r", encoding='utf-8') as f: return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError): return {"users": {}, "keys": {}, "audit": []}

def write_db(db: Dict[str, Any]):
    try:
        with open(DB_PATH, "w", encoding='utf-8') as f: json.dump(db, f, indent=2, ensure_ascii=False)
    except Exception as e: logger.error(f"Error escribiendo DB: {e}")

def get_or_create_user(uid: int, uname: Optional[str]) -> Dict[str, Any]:
    db = read_db()
    uid_str, username = str(uid), uname or f"user_{uid}"
    if uid_str not in db["users"]:
        db["users"][uid_str] = {
            "username": username,
            "plan": "OWNER" if uid == OWNER_ID else "FREE",
            "credits": 999999 if uid == OWNER_ID else 0,  # Owner tiene créditos infinitos
            "created_at": datetime.now().isoformat()
        }
    db["users"][uid_str].update({
        "last_activity": datetime.now().isoformat(),
        "username": username
    })
    write_db(db)
    return db["users"][uid_str]

async def add_credits(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /key <cantidad> - Solo para OWNER"""
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text(f"{EMOJI['ERROR']} Solo el owner puede generar keys\\.")
        return
        
    try:
        amount = int(context.args[0])
        if amount <= 0: raise ValueError
        
        key = gen_key()
        db = read_db()
        db["keys"][key] = {"type": "CREDITS", "amount": amount}
        write_db(db)
        
        await update.message.reply_text(
            f"{EMOJI['SUCCESS']} Key generada con {amount} créditos:\n`{key}`",
            parse_mode=ParseMode.MARKDOWN_V2
        )
    except (IndexError, ValueError):
        await update.message.reply_text(
            f"{EMOJI['ERROR']} Uso: /key <cantidad>\\. Ejemplo: `/key 50`",
            parse_mode=ParseMode.MARKDOWN_V2
        )

async def redeem_credits(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /redeem <key> - Canjear key de créditos"""
    try:
        key = context.args[0].upper()  # La key ya no necesita strip() porque puede contener -
        if not key.startswith(KEY_PREFIX):
            await update.message.reply_text(f"{EMOJI['ERROR']} Formato de key inválido\\. Debe comenzar con VIP\\-")
            return
            
        db = read_db()
        if key not in db["keys"]:
            await update.message.reply_text(f"{EMOJI['ERROR']} Key inválida o ya utilizada\\.")
            return
            
        key_data = db["keys"][key]
        if key_data.get("type") != "CREDITS":
            await update.message.reply_text(f"{EMOJI['ERROR']} Esta key no es de créditos\\.")
            return
            
        user_id = str(update.effective_user.id)
        db["users"][user_id]["credits"] = db["users"][user_id].get("credits", 0) + key_data["amount"]
        del db["keys"][key]
        write_db(db)
        
        await update.message.reply_text(
            f"{EMOJI['SUCCESS']} ¡Has recibido {key_data['amount']} créditos\\!",
            parse_mode=ParseMode.MARKDOWN_V2
        )
    except (IndexError, KeyError):
        await update.message.reply_text(
            f"{EMOJI['ERROR']} Uso: /redeem <key>\\. Ejemplo: `/redeem VIP\\-ABC12`",
            parse_mode=ParseMode.MARKDOWN_V2
        )


# --- UTILIDADES ---
def escape_md(text: str) -> str:
    if not isinstance(text, str): text = str(text)
    return re.sub(f'([{re.escape(r"_*[]()~`>#+-=|{}.!")}])', r'\\\1', text)

def gen_key() -> str:
    """Genera una key con formato VIP-XXXXX"""
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=KEY_LENGTH))
    return f"{KEY_PREFIX}{random_part}"

def validate_input(input_str: str, input_type: str) -> Tuple[bool, str]:
    if not (input_str := input_str.strip()): return False, f"{EMOJI['ERROR']} La entrada no puede estar vacía"
    if input_type == "ip":
        try: socket.inet_aton(input_str); return True, input_str
        except socket.error: return False, f"{EMOJI['ERROR']} Formato de IP inválido \\(ej: 8\\.8\\.8\\.8\\)"
    elif input_type == "domain":
        if len(input_str) < 3 or '.' not in input_str: return False, f"{EMOJI['ERROR']} Formato de dominio inválido \\(ej: google\\.com\\)"
        return True, input_str
    elif input_type == "url":
        if not re.match(r'https?://', input_str): input_str = 'https://' + input_str
        return True, input_str
    elif input_type == "number":
        if not input_str.isdigit() or not (8 <= int(input_str) <= 64): return False, f"{EMOJI['ERROR']} Ingresa un número entre 8 y 64"
        return True, input_str
    return True, input_str

# --- DEFINICIÓN DE HERRAMIENTAS ---
TOOL_CATEGORIES = {
    f"{EMOJI['BASIC']} HERRAMIENTAS BÁSICAS": [
        ("hash", "🔧 Hash", "Genera hashes MD5, SHA1, SHA256", "text"),
        ("ip", "📍 Info IP", "Obtiene GeoIP y datos de una IP", "ip"),
        ("ping", "📡 Ping", "Mide la latencia a un host", "domain"),
        ("http", "🌐 Headers HTTP", "Muestra cabeceras de una URL", "url"),
        ("base64", "🔠 Base64", "Codifica o decodifica texto", "text"),
        ("password", "🔐 Gen. Pass", "Crea contraseñas seguras", "number")
    ],
    f"{EMOJI['PREMIUM']} HERRAMIENTAS PRO MASTER ULTIMATE ": [
        ("ports_fast", "🔌 Scan Rápido", "Top 100 puertos (Nmap)", "ip"),
        ("ports_full", "🔌 Scan Completo", "Top 1000 puertos y versiones (Nmap)", "ip"),
        ("vuln_scan", "💥 Scan CVEs (Nmap)", "Busca vulnerabilidades activamente", "ip"),
        ("dns", "🔍 Consulta DNS", "Obtiene registros DNS", "domain"),
        ("whois", "📋 Info WHOIS", "Información de registro del dominio", "domain"),
        ("subdomain", "🌐 Subdominios", "Encuentra subdominios", "domain"),
        ("dirsearch", "📁 DirSearch Pro", "Busca directorios con wordlist", "url"),
        ("tech_detect", "💻 Tech Detect", "Detecta tecnologías web", "url"),
        ("reverseip", "🔄 IP Reversa", "Dominios en la misma IP", "ip"),
        ("tls", "🔒 Info TLS/SSL", "Datos del certificado de seguridad", "domain"),
        ("cve_search", "⚠️ Buscador CVE", "Busca en base de datos de CVEs", "text"),
        ("dorking", "🕵️ Google Dorking", "Búsquedas avanzadas", "text")
    ]
}

# --- LÓGICA DE HERRAMIENTAS ---
async def execute_command(cmd: str, timeout: int) -> str:
    try:
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout.decode('utf-8', 'ignore').strip() if process.returncode == 0 else f"Error: {stderr.decode('utf-8', 'ignore').strip()}"
    except asyncio.TimeoutError: return f"Timeout de {timeout}s excedido."
    except Exception as e: return f"Error al ejecutar comando: {e}"

async def get_parsed_whois(domain: str) -> str:
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        if not w.domain_name: return "No se pudo obtener información WHOIS."
        info = {"Dominio": w.domain_name, "Registrador": w.registrar, "Creación": w.creation_date, "Expiración": w.expiration_date, "Servidores DNS": w.name_servers}
        return "\n".join([f"*{k}:* {escape_md(v)}" for k, v in info.items() if v])
    except Exception: return "No se pudo procesar la información WHOIS."

async def run_dirsearch_pro(base_url: str) -> str:
    wordlist = [
        ".htaccess", ".htpasswd", ".env", "admin/", "login/", "dashboard/", "api/", "test/", "backup/", "config/",
        "uploads/", "vendor/", "phpinfo.php", "test.php", "info.php", "robots.txt", "sitemap.xml", "wp-admin/",
        "wp-login.php", "xmlrpc.php", "README.md", "LICENSE", ".git/", ".svn/", "docker-compose.yml"
    ]
    found = []
    async def check(path):
        try:
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            async with asyncio.timeout(5):
                r = await asyncio.to_thread(requests.head, url, allow_redirects=False, timeout=4)
                if r.status_code < 400: found.append(f"`{path}` \\- `{r.status_code}`")
        except (requests.RequestException, asyncio.TimeoutError): pass
    await asyncio.gather(*(check(p) for p in wordlist))
    return f"{EMOJI['SUCCESS']} *{len(found)} Rutas encontradas:*\n" + "\n".join(found) if found else "No se encontraron rutas comunes."

async def run_tech_detect(url: str) -> str:
    try:
        async with asyncio.timeout(10):
            r = await asyncio.to_thread(requests.get, url, timeout=8)
        tech = set()
        if "server" in r.headers: tech.add(f"Server: {r.headers['server']}")
        if "X-Powered-By" in r.headers: tech.add(f"Backend: {r.headers['X-Powered-By']}")
        if "wp-content" in r.text: tech.add("CMS: WordPress")
        if "Joomla" in r.text: tech.add("CMS: Joomla")
        if "Drupal" in r.text: tech.add("CMS: Drupal")
        if "react" in r.text: tech.add("Frontend: React")
        if "vue" in r.text: tech.add("Frontend: Vue.js")
        if "cloudflare" in r.headers.get("server", ""): tech.add("CDN: Cloudflare")
        return f"{EMOJI['SUCCESS']} *Tecnologías detectadas:*\n" + "\n".join([f"`{escape_md(t)}`" for t in tech]) if tech else "No se detectaron tecnologías específicas."
    except Exception as e: return f"{EMOJI['ERROR']} No se pudo analizar la URL: {escape_md(str(e))}"


# --- LÓGICA DE USUARIO Y ADMIN ---
def canjear_key(user_id: int, key: str) -> str:
    db = read_db()
    if (key := key.strip().upper()) not in db.get("keys", {}): return f"{EMOJI['ERROR']} Key inválida o ya utilizada\\."
    plan = db["keys"][key]
    db["users"][str(user_id)]["plan"] = plan
    db.get("audit", []).append({"user_id": user_id, "key": key, "timestamp": datetime.now().isoformat(), "action": "key_redeemed"})
    del db["keys"][key]
    write_db(db)
    return f"{EMOJI['SUCCESS']} ¡Key canjeada\\! Tu plan ahora es *{escape_md(plan)}*\\."

def export_excel() -> str:
    try:
        db = read_db()
        with pd.ExcelWriter("toolbox_data.xlsx", engine='openpyxl') as writer:
            pd.DataFrame(db["users"].values()).to_excel(writer, sheet_name='Usuarios', index=False)
            pd.DataFrame(list(db.get("keys", {}).items()), columns=['Key', 'Plan']).to_excel(writer, sheet_name='Keys', index=False)
            pd.DataFrame(db.get("audit", [])).to_excel(writer, sheet_name='Auditoría', index=False)
        return f"{EMOJI['SUCCESS']} Excel exportado: `toolbox_data.xlsx`"
    except Exception as e: return f"{EMOJI['ERROR']} Error al exportar: {escape_md(str(e))}"

# --- TAREAS DIARIAS ---
DAILY_TASKS = {
    "use_tools": {"desc": "Usar 3 herramientas", "reward": 10, "max": 3},
    "invite_user": {"desc": "Invitar 1 usuario", "reward": 20, "max": 1},
    "try_premium": {"desc": "Usar herramienta premium", "reward": 15, "max": 1}
}

async def check_daily_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /daily - Muestra y verifica tareas diarias"""
    user_id = str(update.effective_user.id)
    db = read_db()
    
    if "daily_tasks" not in db["users"][user_id]:
        db["users"][user_id]["daily_tasks"] = {
            "last_reset": datetime.now().date().isoformat(),
            "tasks": {task: 0 for task in DAILY_TASKS}
        }
    
    # Reset diario
    if db["users"][user_id]["daily_tasks"]["last_reset"] < datetime.now().date().isoformat():
        db["users"][user_id]["daily_tasks"]["tasks"] = {task: 0 for task in DAILY_TASKS}
        db["users"][user_id]["daily_tasks"]["last_reset"] = datetime.now().date().isoformat()
    
    text = "📋 *Tareas Diarias*\n\n"
    for task, info in DAILY_TASKS.items():
        progress = db["users"][user_id]["daily_tasks"]["tasks"].get(task, 0)
        text += f"{'✅' if progress >= info['max'] else '⬜'} {info['desc']}\n"
        text += f"Progreso: {progress}/{info['max']} \\- Recompensa: {info['reward']} créditos\n\n"
    
    write_db(db)
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)

# --- PROTECCIÓN DE IPS ---
BLOCKED_IPS = set()  # IPs bloqueadas
MAX_FAILS = 3  # intentos fallidos máximos

async def check_ip_safety(ip: str) -> bool:
    """Verifica si una IP es segura de escanear"""
    try:
        # Verifica si es IP privada
        if ipaddress.ip_address(ip).is_private:
            return False
            
        # Verifica en lista negra
        if ip in BLOCKED_IPS:
            return False
            
        # Verifica en AbuseIPDB (requiere API key)
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip},
                headers={"Key": "TU_API_KEY", "Accept": "application/json"},
            ) as response:
                data = await response.json()
                return data.get("data", {}).get("abuseConfidenceScore", 0) < 50
                
    except Exception as e:
        logger.error(f"Error verificando IP {ip}: {e}")
        return False

# --- LOGGING MEJORADO ---
import logging.handlers
import traceback

def setup_logging():
    """Configura logging avanzado"""
    log_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Log principal
    main_handler = logging.handlers.RotatingFileHandler(
        'bot.log',
        maxBytes=1024*1024,  # 1MB
        backupCount=5
    )
    main_handler.setFormatter(log_format)
    
    # Log de errores
    error_handler = logging.handlers.RotatingFileHandler(
        'error.log',
        maxBytes=1024*1024,
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(log_format)
    
    # Configura logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(main_handler)
    logger.addHandler(error_handler)
    
    return logger


# --- ESTADÍSTICAS EN TIEMPO REAL ---
class BotStats:
    def __init__(self):
        self.commands_today = 0
        self.errors_today = 0
        self.active_users = set()
        self.start_time = datetime.now()
        
    def add_command(self, user_id: int):
        self.commands_today += 1
        self.active_users.add(user_id)
        
    def add_error(self):
        self.errors_today += 1
        
    def get_uptime(self):
        return datetime.now() - self.start_time
        
    def reset_daily(self):
        self.commands_today = 0
        self.errors_today = 0
        self.active_users.clear()

bot_stats = BotStats()

# Comando para ver estadísticas
async def get_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
        
    uptime = bot_stats.get_uptime()
    text = (
        f"📊 *Estadísticas del Bot*\n\n"
        f"⏱️ Uptime: `{uptime.days}d {uptime.seconds//3600}h`\n"
        f"📝 Comandos hoy: `{bot_stats.commands_today}`\n"
        f"👥 Usuarios activos: `{len(bot_stats.active_users)}`\n"
        f"❌ Errores hoy: `{bot_stats.errors_today}`"
    )
    
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2
    )


# --- SISTEMA DE AUTOLIMPIEZA ---
async def auto_maintenance(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Limpieza automática de datos antiguos y mantenimiento"""
    try:
        db = read_db()
        now = datetime.now()
        
        # Limpia usuarios inactivos (no premium)
        inactive_threshold = now - timedelta(days=30)
        db["users"] = {
            uid: user for uid, user in db["users"].items()
            if user.get("plan") in ["PREMIUM", "OWNER"] or 
            datetime.fromisoformat(user.get("last_activity", "2020-01-01")) > inactive_threshold
        }
        
        # Limpia logs antiguos
        db["audit"] = [
            log for log in db["audit"] 
            if (now - datetime.fromisoformat(log["timestamp"])).days < 7
        ]
        
        # Limpia keys expiradas
        if "key_expiry" in db:
            db["keys"] = {
                k: v for k, v in db["keys"].items()
                if k not in db["key_expiry"] or 
                datetime.fromisoformat(db["key_expiry"][k]) > now
            }
        
        write_db(db)
        logger.info("Mantenimiento automático completado")
    except Exception as e:
        logger.error(f"Error en mantenimiento: {e}")

# --- PROTECCIÓN ANTI-FLOOD ---
from collections import defaultdict
from datetime import timedelta

FLOOD_LIMIT = 5  # máximo de comandos por minuto
FLOOD_TIME = 60  # tiempo en segundos

class FloodProtection:
    def __init__(self):
        self.usage = defaultdict(list)
    
    def can_execute(self, user_id: int) -> bool:
        now = datetime.now()
        self.usage[user_id] = [
            time for time in self.usage[user_id]
            if now - time < timedelta(seconds=FLOOD_TIME)
        ]
        
        if len(self.usage[user_id]) >= FLOOD_LIMIT:
            return False
            
        self.usage[user_id].append(now)
        return True

flood_protection = FloodProtection()


async def run_tool(tool_name: str, arg: str, user_id: int) -> str:
    if not flood_protection.can_execute(user_id):
        return f"{EMOJI['ERROR']} Demasiadas peticiones\\. Espera 1 minuto\\."
    try:
        if tool_name == "hash": return f"*MD5:* `{hashlib.md5(arg.encode()).hexdigest()}`\n*SHA1:* `{hashlib.sha1(arg.encode()).hexdigest()}`\n*SHA256:* `{hashlib.sha256(arg.encode()).hexdigest()}`"
        elif tool_name == "ip":
            resp = await asyncio.to_thread(requests.get, f"https://ipinfo.io/{arg}/json", timeout=5)
            return "\n".join([f"*{k.capitalize()}:* {escape_md(v)}" for k, v in resp.json().items()])
        elif tool_name == "ping": return f"```\n{escape_md(await execute_command(f'ping -c 4 {arg}', 15))}\n```"
        elif tool_name == "http":
            resp = await asyncio.to_thread(requests.get, arg, timeout=10, allow_redirects=True)
            headers = f"*Status:* `{resp.status_code}`\n*URL Final:* `{escape_md(resp.url)}`\n\n*Headers:*\n"
            return headers + "\n".join([f"*{k}:* `{escape_md(v)}`" for k, v in list(resp.headers.items())[:15]])
        elif tool_name == "base64":
            try: return f"*Decodificado:*\n`{escape_md(base64.b64decode(arg).decode('utf-8', 'ignore'))}`"
            except: return f"*Codificado:*\n`{base64.b64encode(arg.encode()).decode()}`"
        elif tool_name == "password":
            chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
            return f"Contraseña de {int(arg)} caracteres:\n`{escape_md(''.join(random.choices(chars, k=int(arg))))}`"
        elif tool_name == "ports_fast": return f"```\n{escape_md(await execute_command(f'nmap -F {arg}', 60))}\n```"
        elif tool_name == "ports_full": return f"```\n{escape_md(await execute_command(f'nmap -sV {arg}', 300))}\n```"
        elif tool_name == "vuln_scan": return f"```\n{escape_md(await execute_command(f'nmap --script vuln {arg}', 600))}\n```"
        elif tool_name == "dns":
            results = []
            for r_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = await asyncio.to_thread(dns.resolver.resolve, arg, r_type)
                    if records := [escape_md(str(r)) for r in answers]: results.append(f"*{r_type}:* {', '.join(records)}")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN): continue
            return "\n".join(results) or "No se encontraron registros DNS."
        elif tool_name == "whois": return await get_parsed_whois(arg)
        elif tool_name == "subdomain":
            resp = await asyncio.to_thread(requests.get, f"https://api.hackertarget.com/hostsearch/?q={arg}", timeout=20)
            if "error" in resp.text: return f"{EMOJI['ERROR']} No se pudieron obtener subdominios."
            subs = resp.text.strip().split('\n')
            return f"{EMOJI['SUCCESS']} *{len(subs)} Subdominios encontrados:*\n`" + '`\n`'.join([escape_md(s.split(',')[0]) for s in subs]) + "`"
        elif tool_name == "dirsearch": return await run_dirsearch_pro(arg)
        elif tool_name == "tech_detect": return await run_tech_detect(arg)
        elif tool_name == "reverseip":
            resp = await asyncio.to_thread(requests.get, f"https://api.hackertarget.com/reverseiplookup/?q={arg}", timeout=20)
            if "error" in resp.text: return f"{EMOJI['ERROR']} No se pudieron obtener dominios."
            return f"{EMOJI['SUCCESS']} *Dominios en la misma IP:*\n`" + escape_md(resp.text.replace("\n", "`\n`")) + "`"
        elif tool_name == "tls":
            context = ssl.create_default_context()
            async with asyncio.timeout(10):
                conn = await asyncio.to_thread(context.wrap_socket, socket.socket(socket.AF_INET), server_hostname=arg)
                conn.connect((arg, 443)); cert = conn.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer', [])); subject = dict(x[0] for x in cert.get('subject', []))
            return "\n".join([f"*Sujeto:* {escape_md(subject.get('commonName'))}", f"*Emisor:* {escape_md(issuer.get('commonName'))}", f"*Válido desde:* {escape_md(cert.get('notBefore'))}", f"*Válido hasta:* {escape_md(cert.get('notAfter'))}"])
        elif tool_name == "cve_search":
            resp = await asyncio.to_thread(requests.get, f"https://cve.circl.lu/api/search/{arg}", timeout=10)
            data = resp.json().get("data", [])
            if not data: return f"{EMOJI['ERROR']} No se encontraron CVEs para ese término."
            info = [f"*{escape_md(c.get('id'))}:* {escape_md(c.get('summary', ''))[:80]}..." for c in data[:10]]
            return f"{EMOJI['SUCCESS']} *CVEs encontrados:*\n" + "\n".join(info)
        elif tool_name == "dorking":
            dorks = {"Archivos Log": "inurl:log", "Directorios Expuestos": "intitle:\"index of\"", "Archivos Config": "ext:xml | ext:conf | ext:ini", "Bases de Datos": "ext:sql | ext:dbf | ext:mdb", "Login Pages": "inurl:login"}
            links = [f"[{name}]({'https://www.google.com/search?q=' + quote_plus(f'site:{arg} {dork}')})" for name, dork in dorks.items()]
            return f"{EMOJI['SUCCESS']} *Enlaces de Google Dorking:*\n" + "\n".join(links)
    except Exception as e:
        logger.error(f"Error en run_tool '{tool_name}': {e}")
        return f"{EMOJI['ERROR']} Error inesperado: {escape_md(str(e))}"


# --- SISTEMA DE RANKINGS ---
async def get_rankings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /top - Muestra rankings"""
    db = read_db()
    
    # Top por uso de herramientas
    tool_usage = {}
    for log in db["audit"]:
        if "tool" in log:
            tool_usage[log["user_id"]] = tool_usage.get(log["user_id"], 0) + 1
    
    top_users = sorted(tool_usage.items(), key=lambda x: x[1], reverse=True)[:10]
    
    text = "🏆 *TOP 10 USUARIOS*\n\n"
    for i, (uid, uses) in enumerate(top_users, 1):
        username = db["users"][str(uid)]["username"]
        text += f"{i}\\. @{escape_md(username)}: {uses} usos\n"
    
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)

# --- SISTEMA DE LOGROS ---
ACHIEVEMENTS = {
    "explorer": {"name": "🔍 Explorador", "desc": "Usar 5 herramientas diferentes", "req": 5},
    "hacker": {"name": "💻 Hacker", "desc": "Usar 20 herramientas", "req": 20},
    "premium": {"name": "💎 Premium", "desc": "Obtener plan premium", "req": 1},
    "social": {"name": "👥 Social", "desc": "Referir 3 usuarios", "req": 3}
}

from typing import List
async def check_achievements(user_id: str) -> list[str]:
    """Verifica y otorga logros"""
    db = read_db()
    user = db["users"][user_id]
    if "achievements" not in user: user["achievements"] = []
    
    new_achievements = []
    tools_used = len(set(log["tool"] for log in db["audit"] if log["user_id"] == user_id))
    
    if tools_used >= 5 and "explorer" not in user["achievements"]:
        user["achievements"].append("explorer")
        new_achievements.append(ACHIEVEMENTS["explorer"]["name"])
        
    if len([log for log in db["audit"] if log["user_id"] == user_id]) >= 20 and "hacker" not in user["achievements"]:
        user["achievements"].append("hacker")
        new_achievements.append(ACHIEVEMENTS["hacker"]["name"])

    
    write_db(db)
    return new_achievements

# --- SISTEMA DE REFERIDOS ---
REFERRAL_BONUS = 50  # Créditos por referido

async def handle_start_with_ref(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Maneja /start code - Sistema de referidos"""
    try:
        ref_code = context.args[0] if context.args else None
        user_id = str(update.effective_user.id)
        
        if ref_code and ref_code != user_id:
            db = read_db()
            if user_id not in db["users"]:  # Solo nuevos usuarios
                # Bonus para el referido
                db["users"][user_id] = get_or_create_user(update.effective_user.id, update.effective_user.username)
                db["users"][user_id]["credits"] += REFERRAL_BONUS
                # Bonus para quien refirió
                db["users"][ref_code]["credits"] += REFERRAL_BONUS
                write_db(db)
                await update.message.reply_text(f"🎁 ¡Bienvenido! Recibiste {REFERRAL_BONUS} créditos por usar un código de referido!")
    except Exception as e:
        logger.error(f"Error en referido: {e}")
    await start(update, context)

# --- MODO DEBUG ---
async def debug_mode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /debug - Información detallada para el owner"""
    if update.effective_user.id != OWNER_ID:
        return
        
    db = read_db()
    stats = {
        "Usuarios totales": len(db["users"]),
        "Usuarios premium": len([u for u in db["users"].values() if u["plan"] == "PREMIUM"]),
        "Keys activas": len(db["keys"]),
        "Usos totales": len(db["audit"]),
        "Herramientas más usadas": {},
        "Errores recientes": []
    }
    
    # Análisis de herramientas
    for log in db["audit"]:
        if "tool" in log:
            stats["Herramientas más usadas"][log["tool"]] = stats["Herramientas más usadas"].get(log["tool"], 0) + 1
    
    text = "🔧 *Modo Debug*\n\n"
    for k, v in stats.items():
        text += f"*{escape_md(k)}:*\n`{escape_md(str(v))}`\n\n"
    
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)
    
async def backup_db(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        backup_path = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        db = read_db()
        
        # Asegura que el directorio de backup existe
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, backup_path)
        
        with open(backup_path, 'w', encoding='utf-8') as f:
            json.dump(db, f, indent=2)
        
        await context.bot.send_document(
            chat_id=OWNER_ID,
            document=open(backup_path, 'rb'),
            caption=f"📦 Backup automático\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        # Limpia backups antiguos
        for f in os.listdir(backup_dir):
            if f.startswith("backup_") and f.endswith(".json"):
                file_path = os.path.join(backup_dir, f)
                if (datetime.now() - datetime.fromtimestamp(os.path.getctime(file_path))).days > 7:
                    os.remove(file_path)
                    
    except Exception as e:
        logger.error(f"Error en backup: {e}")
        # Notifica al owner del error
        try:
            await context.bot.send_message(
                chat_id=OWNER_ID,
                text=f"❌ Error en backup: {str(e)}"
            )
        except Exception:
            pass


async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /broadcast - Envía mensaje a todos los usuarios"""
    if update.effective_user.id != OWNER_ID:
        return
        
    try:
        message = " ".join(context.args)
        if not message:
            await update.message.reply_text("Uso: /broadcast <mensaje>")
            return
            
        db = read_db()
        failed = 0
        sent = 0
        
        for user_id in db["users"]:
            try:
                await context.bot.send_message(
                    chat_id=int(user_id),
                    text=f"📢 *Anuncio*\n\n{message}",
                    parse_mode=ParseMode.MARKDOWN_V2
                )
                sent += 1
            except Exception:
                failed += 1
                
        await update.message.reply_text(
            f"✅ Mensaje enviado a {sent} usuarios\n❌ Fallidos: {failed}"
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

async def generate_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /report - Genera reporte de uso"""
    if update.effective_user.id != OWNER_ID:
        return
        
    db = read_db()
    today = datetime.now().date()
    
    # Estadísticas de uso
    stats = {
        "users": {
            "total": len(db["users"]),
            "active_today": 0,
            "premium": len([u for u in db["users"].values() if u.get("plan") == "PREMIUM"])
        },
        "tools": {},
        "errors": {}
    }
    
    # Análisis de logs
    for log in db.get("audit", []):
        log_date = datetime.fromisoformat(log["timestamp"]).date()
        if log_date == today:
            stats["users"]["active_today"] += 1
            if "tool" in log:
                stats["tools"][log["tool"]] = stats["tools"].get(log["tool"], 0) + 1
    
    # Genera gráfico
    plt.figure(figsize=(10, 5))
    tools = list(stats["tools"].keys())
    uses = list(stats["tools"].values())
    plt.bar(tools, uses)
    plt.title("Uso de Herramientas (Hoy)")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("report.png")
    
    # Envía reporte
    await update.message.reply_photo(
        photo=open("report.png", "rb"),
        caption=f"📊 *Reporte Diario*\n\n"
                f"👥 *Usuarios*:\n"
                f"Total: {stats['users']['total']}\n"
                f"Activos hoy: {stats['users']['active_today']}\n"
                f"Premium: {stats['users']['premium']}\n\n"
                f"🛠️ *Herramientas más usadas*:\n" +
                "\n".join([f"{k}: {v}" for k,v in sorted(stats["tools"].items(), key=lambda x: x[1], reverse=True)]),
        parse_mode=ParseMode.MARKDOWN_V2
    )
async def add_to_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /addgroup - Añade el bot a un grupo de trabajo"""
    if update.effective_chat.type not in ['group', 'supergroup']:
        await update.message.reply_text("Este comando solo funciona en grupos.")
        return
        
    chat_id = str(update.effective_chat.id)
    db = read_db()
    
    if "groups" not in db: db["groups"] = {}
    db["groups"][chat_id] = {
        "name": update.effective_chat.title,
        "added_by": update.effective_user.id,
        "added_at": datetime.now().isoformat(),
        "settings": {
            "allow_basic": True,
            "allow_premium": False,
            "require_approval": True
        }
    }
    
    write_db(db)
    await update.message.reply_text("✅ Grupo configurado correctamente.")
# --- SISTEMA DE NIVELES ---
LEVEL_XP = {
    1: 100,    # Nivel 1: 100 XP
    2: 300,    # Nivel 2: 300 XP
    3: 600,    # Nivel 3: 600 XP
    4: 1000,   # Nivel 4: 1000 XP
    5: 2000,   # Nivel 5: 2000 XP
}

async def add_xp(user_id: str, xp: int) -> tuple[int, int]:
    """Añade XP al usuario y retorna (nivel_anterior, nivel_nuevo)"""
    db = read_db()
    user = db["users"][user_id]
    
    if "xp" not in user: user["xp"] = 0
    if "level" not in user: user["level"] = 1
    
    old_level = user["level"]
    user["xp"] += xp
    
    # Calcula nuevo nivel
    while user["level"] < len(LEVEL_XP) and user["xp"] >= LEVEL_XP[user["level"]]:
        user["level"] += 1
    
    write_db(db)
    return old_level, user["level"]

# Add this near other command functions
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /help - Muestra ayuda detallada"""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    is_owner = user["plan"] == "OWNER"
    
    help_text = (
        f"🤖 *ETHICAL HACKING BOT HELP*\n\n"
        
        f"*📚 Comandos Básicos*\n"
        f"`/start` \\- Inicia el bot\n"
        f"`/help` \\- Muestra esta ayuda\n"
        f"`/profile` \\- Tu perfil y estadísticas\n"
        f"`/redeem` \\- Canjear key VIP\n"
        f"`/daily` \\- Tareas diarias\n"
        f"`/top` \\- Ranking de usuarios\n\n"
        
        f"*💎 Sistema VIP*\n"
        f"• Las herramientas premium requieren créditos\n"
        f"• Consigue créditos con keys VIP\n"
        f"• Las keys tienen el formato `VIP\\-XXXXX`\n\n"
        
        f"*🛠️ Herramientas Disponibles*\n"
        f"• Herramientas básicas: `1` crédito\n"
        f"• Escaneos rápidos: `2` créditos\n" 
        f"• Análisis completos: `3\\-5` créditos\n\n"
    )
    
    if is_owner:
        help_text += (
            f"*👑 Comandos de Admin*\n"
            f"`/key <cantidad>` \\- Genera key con créditos\n"
            f"`/debug` \\- Información detallada\n"
            f"`/broadcast` \\- Mensaje masivo\n"
            f"`/report` \\- Genera reporte\n"
            f"`/stats` \\- Estadísticas del bot\n\n"
        )
    
    help_text += (
        f"*👨‍💻 Desarrollador*\n"
        f"Alvaro \\- @{escape_md(OWNER_USERNAME)}\n\n"
        f"*⚠️ Disclaimer*\n"
        f"Este bot es solo para pruebas autorizadas\\."
    )

    markup = InlineKeyboardMarkup([[
        InlineKeyboardButton(f"{EMOJI['TOOL']} Ver Herramientas", callback_data="tools_menu"),
        InlineKeyboardButton(f"{EMOJI['BACK']} Menú Principal", callback_data="volver_main")
    ]])

    await update.message.reply_text(
        help_text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=markup,
        disable_web_page_preview=True
    )

# Add this function before main()
async def perfil_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /profile - Muestra el perfil del usuario"""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    created = escape_md(user.get("created_at", "N/A")[:16])
    
    # Get user statistics
    db = read_db()
    tools_used = len([log for log in db.get("audit", []) if log.get("user_id") == update.effective_user.id])
    unique_tools = len(set(log.get("tool", "") for log in db.get("audit", []) 
                        if log.get("user_id") == update.effective_user.id))
    
    profile_text = (
        f"{EMOJI['PROFILE']} *Tu Perfil*\n\n"
        f"*👤 Usuario:* @{escape_md(user['username'])}\n"
        f"*💎 Plan:* `{escape_md(user['plan'])}`\n"
        f"*💰 Créditos:* `{user.get('credits', 0)}`\n"
        f"*📅 Miembro desde:* `{created}`\n\n"
        f"*📊 Estadísticas*\n"
        f"*🛠️ Herramientas usadas:* `{tools_used}`\n"
        f"*🔧 Herramientas únicas:* `{unique_tools}`\n"
        f"*⭐️ Nivel:* `{user.get('level', 1)}`\n"
        f"*📈 XP:* `{user.get('xp', 0)}`\n\n"
        f"*🏆 Logros Desbloqueados:* `{len(user.get('achievements', []))}`"
    )
    
    markup = InlineKeyboardMarkup([[
        InlineKeyboardButton(f"{EMOJI['TOOL']} Herramientas", callback_data="tools_menu"),
        InlineKeyboardButton(f"{EMOJI['BACK']} Menú", callback_data="volver_main")
    ]])
    
    await update.message.reply_text(
        profile_text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=markup
    )


# --- HANDLERS DE TELEGRAM ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    text = f"Hola, @{escape_md(user['username'])}\n\n{EMOJI['BOT']} Soy tu *Asistente de Hacking Ético*\\.\n\n*Tu Plan Actual:* `{escape_md(user['plan'])}`\n\nElige una opción para comenzar 👇"
    await (update.message or update.callback_query.message).reply_text(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=menu_principal(user["plan"]))

def menu_principal(plan: str) -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(f"{EMOJI['TOOL']} Herramientas", callback_data="tools_menu")],
        [InlineKeyboardButton(f"{EMOJI['KEY']} Canjear Key", callback_data="canjear_menu"), InlineKeyboardButton(f"{EMOJI['PROFILE']} Mi Perfil", callback_data="perfil")],
    ]
    if plan == "OWNER": buttons.append([InlineKeyboardButton(f"{EMOJI['ADMIN']} Panel de Admin", callback_data="panel_admin")])
    buttons.append([InlineKeyboardButton(f"{EMOJI['HELP']} Ayuda", callback_data="ayuda"), InlineKeyboardButton(f"{EMOJI['EXIT']} Salir", callback_data="salir")])
    return InlineKeyboardMarkup(buttons)

def menu_tools(plan: str, page: int = 0, category: str = f"{EMOJI['BASIC']} HERRAMIENTAS BÁSICAS") -> InlineKeyboardMarkup:
    tools = TOOL_CATEGORIES.get(category, [])
    total_pages = max(1, (len(tools) + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    page_tools = tools[page * ITEMS_PER_PAGE:(page + 1) * ITEMS_PER_PAGE]
    
    rows = [
        [InlineKeyboardButton(f"{EMOJI['LOCK']} {label}" if category.startswith(EMOJI['PREMIUM']) and plan not in ["PREMIUM", "OWNER"] else label, 
                              callback_data="premium_lock" if category.startswith(EMOJI['PREMIUM']) and plan not in ["PREMIUM", "OWNER"] else f"run_{tool}")]
        for tool, label, _, _ in page_tools
    ]
    
    nav_buttons = []
    if page > 0: nav_buttons.append(InlineKeyboardButton(EMOJI['PREV'], callback_data=f"page_{category}_{page-1}"))
    if (page + 1) * ITEMS_PER_PAGE < len(tools): nav_buttons.append(InlineKeyboardButton(EMOJI['NEXT'], callback_data=f"page_{category}_{page+1}"))
    if nav_buttons: rows.append(nav_buttons)
    
    categories = list(TOOL_CATEGORIES.keys())
    current_idx = categories.index(category)
    other_cat = categories[1-current_idx]
    rows.append([InlineKeyboardButton(f"Ir a {other_cat}", callback_data=f"cat_{other_cat}_0")])
    rows.append([InlineKeyboardButton(f"{EMOJI['BACK']} Menú Principal", callback_data="volver_main")])
    return InlineKeyboardMarkup(rows)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[int]:
    query = update.callback_query
    await query.answer()
    data = query.data
    user = get_or_create_user(query.from_user.id, query.from_user.username)
    plan = user["plan"]
    
    if data == "volver_main":
        await query.message.delete()
        await start(update, context)
        return
    
    text, markup, next_state = "", None, None
    
    if data == "tools_menu":
        text, markup = f"{EMOJI['TOOL']} *Herramientas*\n\nElige una categoría para ver las herramientas disponibles\\.", menu_tools(plan)
    elif data.startswith("page_") or data.startswith("cat_"):
        parts = data.split("_"); category, page = "_".join(parts[1:-1]), int(parts[-1])
        text, markup = f"*{escape_md(category)}*\n\nElige una herramienta para ejecutarla\\.", menu_tools(plan, page, category)
    elif data == "panel_admin" and plan == "OWNER":
        db = read_db()
        text = f"{EMOJI['ADMIN']} *Panel de Administración*\n\n{EMOJI['STATS']} *Usuarios:* {len(db['users'])}\n{EMOJI['KEY']} *Keys disponibles:* {len(db['keys'])}"
        markup = InlineKeyboardMarkup([
            [InlineKeyboardButton(f"{EMOJI['KEY']} Generar Key", callback_data="admin_genkey"), InlineKeyboardButton(f"{EMOJI['EXPORT']} Exportar", callback_data="admin_excel")],
            [InlineKeyboardButton(f"{EMOJI['CLEAN']} Limpiar Logs", callback_data="admin_clean"), InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]
        ])
    elif data == "admin_genkey" and plan == "OWNER":
        key = gen_key(); db = read_db(); db["keys"][key] = "PREMIUM"; write_db(db)
        await query.answer(f"Key generada: {key}", show_alert=True)
        return
    elif data == "admin_excel" and plan == "OWNER":
        await query.answer(export_excel(), show_alert=True)
        return
    elif data == "admin_clean" and plan == "OWNER":
        db = read_db(); db["audit"] = db.get("audit", [])[-100:]; write_db(db)
        await query.answer("Logs de auditoría limpiados.", show_alert=True)
        return
    elif data == "canjear_menu":
        text, next_state = f"{EMOJI['KEY']} *Canjear Key Premium*\n\nPor favor, envía tu key para activar el plan PREMIUM\\.", WAITING_KEY
    elif data == "perfil":
        created = escape_md(user.get("created_at", "N/A")[:16])
        text, markup = f"{EMOJI['PROFILE']} *Tu Perfil*\n\n*Usuario:* @{escape_md(user['username'])}\n*Plan:* `{escape_md(plan)}`\n*Miembro desde:* `{created}`", InlineKeyboardMarkup([[InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]])
    elif data == "ayuda":
        text, markup = f"{EMOJI['HELP']} *Ayuda y Soporte*\n\nEste bot ofrece herramientas de hacking ético\\. Para obtener una *key premium* o si necesitas ayuda, contacta al owner: @{escape_md(OWNER_USERNAME)}", InlineKeyboardMarkup([[InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]])
    elif data.startswith("run_"):
        tool = data.split("_", 1)[1]
        tool_info = next((t for cat in TOOL_CATEGORIES.values() for t in cat if t[0] == tool), None)
        if tool_info:
            context.user_data.update({"current_tool": tool, "input_type": tool_info[3]})
            text, next_state = f"*{escape_md(tool_info[1])}*\n_{escape_md(tool_info[2])}_\n\nPor favor, ingresa el parámetro requerido:", WAITING_TOOL_ARG
    elif data == "premium_lock":
        await query.answer(f"🔒 Esta es una herramienta PREMIUM. Necesitas una key.", show_alert=True)
        return
    elif data == "salir":
        await query.edit_message_text(f"👋 ¡Hasta luego, {escape_md(user['username'])}\\!", parse_mode=ParseMode.MARKDOWN_V2)
        return
    
    if text: await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=markup, disable_web_page_preview=True)
    return next_state

async def text_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, state: int) -> Optional[int]:
    user_input = update.message.text.strip()
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    
    if state == WAITING_KEY:
        result_text = canjear_key(user['username'], user_input)
        await update.message.reply_text(
            result_text, 
            parse_mode=ParseMode.MARKDOWN_V2, 
            reply_markup=menu_principal(get_or_create_user(update.effective_user.id, None)["plan"])
        )
        return ConversationHandler.END
    
    elif state == WAITING_TOOL_ARG:
        tool = context.user_data.get("current_tool")
        cost = CREDITS_COST.get(tool, 1)
        
        if user["plan"] != "OWNER":
            if user.get("credits", 0) < cost:
                await update.message.reply_text(
                    f"{EMOJI['ERROR']} Necesitas {cost} créditos para usar esta herramienta\\. "
                    f"Te quedan: {user.get('credits', 0)} créditos\\.",
                    parse_mode=ParseMode.MARKDOWN_V2
                )
                return ConversationHandler.END
        
        is_valid, validated_input = validate_input(user_input, context.user_data.get("input_type"))
        if not is_valid:
            await update.message.reply_text(validated_input, parse_mode=ParseMode.MARKDOWN_V2)
            return WAITING_TOOL_ARG
        
        msg = await update.message.reply_text(
            f"{EMOJI['WAIT']} Ejecutando herramienta\\.\\.\\.", 
            parse_mode=ParseMode.MARKDOWN_V2
        )
        
        result = await run_tool(tool, validated_input, update.effective_user.id)
        
        if user["plan"] != "OWNER":
            db = read_db()
            db["users"][str(update.effective_user.id)]["credits"] -= cost
            write_db(db)
        
        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton(f"{EMOJI['TOOL']} Más Herramientas", callback_data="tools_menu"),
            InlineKeyboardButton(f"{EMOJI['BACK']} Menú", callback_data="volver_main")
        ]])
        
        await msg.edit_text(
            f"{EMOJI['SUCCESS']} *Resultado para* `{escape_md(validated_input)}`"
            f"\n\\(\\-{cost} créditos\\)\n\n{result}",
            parse_mode=ParseMode.MARKDOWN_V2,
            reply_markup=markup
        )
        
        if new_achievements := await check_achievements(str(update.effective_user.id)):
            await update.message.reply_text(
                f"🎉 *¡Nuevos logros!*\n\n" + "\n".join(new_achievements),
                parse_mode=ParseMode.MARKDOWN_V2
            )
    
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text(f"{EMOJI['INFO']} Operación cancelada\\.", parse_mode=ParseMode.MARKDOWN_V2)
    await start(update, context)
    return ConversationHandler.END

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Exception while handling an update:", exc_info=context.error)
    if update and isinstance(update, Update) and update.effective_message:
        try: await update.effective_message.reply_text(f"{EMOJI['ERROR']} Ocurrió un error inesperado\\. Intenta con /start\\.", parse_mode=ParseMode.MARKDOWN_V2)
        except Exception as e: logger.error(f"Error enviando mensaje de error al usuario: {e}")

def main() -> None:
    if not TOKEN: 
        logger.critical("El TOKEN del bot no está configurado.")
        return
    
    # Construye la aplicación con job_queue habilitado
    application = (
        Application.builder()
        .token(TOKEN)
        .connect_timeout(30)
        .read_timeout(30)
        .build()
    )
    
    # Añade los handlers
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^run_|^canjear_menu$")],
        states={
            WAITING_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: text_input_handler(u, c, WAITING_KEY))],
            WAITING_TOOL_ARG: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: text_input_handler(u, c, WAITING_TOOL_ARG))]
        },
        fallbacks=[CommandHandler("cancel", cancel), CommandHandler("start", start)],
        per_message=False
    )
    
    # Añade todos los handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(conv_handler)
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_error_handler(error_handler)
    application.add_handler(CommandHandler("key", add_credits))
    application.add_handler(CommandHandler("redeem", redeem_credits))
    application.add_handler(CommandHandler("top", get_rankings))
    application.add_handler(CommandHandler("daily", check_daily_tasks))
    application.add_handler(CommandHandler("debug", debug_mode))
    application.add_handler(CommandHandler("addgroup", add_to_group))
    application.add_handler(CommandHandler("report", generate_report))
    application.add_handler(CommandHandler("broadcast", broadcast))
    application.add_handler(CommandHandler("stats", get_stats))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("profile", perfil_command))
    application.add_handler(CommandHandler("comandos", show_commands))

    # Configura las tareas programadas
    if application.job_queue:
        application.job_queue.run_repeating(auto_maintenance, interval=86400)  # cada 24h
        application.job_queue.run_repeating(backup_db, interval=43200)  # cada 12h
        application.job_queue.run_daily(
            lambda ctx: bot_stats.reset_daily(),
            time=time(hour=0, minute=0)
        )
    else:
        logger.warning("Job queue no disponible. Las tareas programadas no funcionarán.")
    
    logger.info(f"{EMOJI['BOT']} Bot de Hacking Ético iniciado. Presiona Ctrl+C para detener.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
