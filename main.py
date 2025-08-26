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

# matplotlib: librería para gráficos. En servidores sin GUI (headless) se necesita usar un backend sin display.
# Usamos 'Agg' para poder generar imágenes (PNG) sin una pantalla física.
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

import ipaddress
import aiohttp
from datetime import time
from datetime import timedelta
import shutil  # Para comprobar herramientas del sistema (ej: nmap) con shutil.which

# Carga variables de entorno desde .env (si está disponible)
# python-dotenv: Permite definir variables en un archivo .env y cargarlas al entorno.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# --- Dependencias externas usadas ---
# dns.resolver (dnspython): consultas DNS
# whois (python-whois): información de registro de dominios
# pandas: exportación a Excel, análisis ligero
# bs4 (BeautifulSoup): reservado para parsing HTML (no intrusivo aquí)
# python-telegram-bot: SDK oficial para bots de Telegram
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
# Nota: Por seguridad, lo ideal es definir TELEGRAM_TOKEN y OWNER_ID en variables de entorno.
# Para no romper tu configuración actual, dejo el token hardcoded como fallback.
TOKEN = "YOUR_TOKEN_HERE"

# OWNER_ID debe ser int para comparaciones correctas con Telegram (que usa IDs int).
OWNER_ID = YOUR_ID_HERE
OWNER_USERNAME = "YOUR_USERNAME_HERE"
DB_PATH = "toolbox_db.json"
BIN_CSV_PATH = "bin-list-data.csv"  # Base local de BINs (nuevo)
KEY_LENGTH = 5
KEY_PREFIX = "VIP-"
ITEMS_PER_PAGE = 6

# Claves externas
ABUSE_IPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

# --- Emojis para la Interfaz ---
EMOJI = {
    "BOT": "🤖", "TOOL": "🛠️", "PREMIUM": "💎", "BASIC": " B ", "PROFILE": "👤",
    "KEY": "🔑", "ADMIN": "👑", "HELP": "ℹ️", "EXIT": "🚪", "BACK": "⬅️",
    "SUCCESS": "✅", "ERROR": "❌", "WAIT": "⏳", "INFO": "💡", "PAGE": "📄",
    "NEXT": "➡️", "PREV": "⬅️", "LOCK": "🔒", "STATS": "📊", "EXPORT": "📥", "CLEAN": "🗑️"
}

# --- SISTEMA DE CRÉDITOS ---
# Cuántos créditos cuesta cada herramienta
CREDITS_COST = {
    "hash": 1,
    "ip": 1,
    "ping": 1,
    "http": 1,
    "base64": 1,
    "password": 1,
    "ports_fast": 2,
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
    ".env", "config.php", "wp-config.php", ".htaccess", "robots.txt",
    "sitemap.xml", ".git/HEAD", ".gitignore", "composer.json",
    "admin/", "administrator/", "wp-admin/", "panel/", "webadmin/",
    "dashboard/", "cpanel/", "phpmyadmin/",
    "backup/", "bak/", "old/", "logs/", "temp/", "test/",
    "upload/", "uploads/", "images/", "img/", "css/", "js/",
    "phpinfo.php", "info.php", "test.php", "database.sql",
    ".htpasswd", "web.config", "humans.txt", "error_log",
    "wp-login.php", "wp-content/", "wp-includes/",
    "joomla/", "drupal/", "vendor/", "node_modules/",
    "README.md", "CHANGELOG.md", "LICENSE", "CONTRIBUTING.md",
    "docs/", "documentation/", "manual/", "wiki/"
]

async def show_commands(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Muestra todos los comandos /comandos.
    - Qué: Ayuda rápida con comandos agrupados.
    - Para qué: Guía de navegación para usuarios.
    - Cómo: Construye texto con Markdown V2 escapado y lo envía al chat.
    """
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    is_owner = user["plan"] == "OWNER"
    
    text = "📚 *LISTA DE COMANDOS*\n\n"
    text += "*👤 Comandos de Usuario*\n"
    for cmd, desc in COMMANDS_INFO["👤 Comandos de Usuario"].items():
        escaped_desc = escape_md(desc)
        text += f"`{cmd}` \\- {escaped_desc}\n"
    text += "\n"
    
    text += "*💎 Herramientas Premium*\n"
    for cmd, desc in COMMANDS_INFO["💎 Comandos Premium"].items():
        escaped_cmd = escape_md(cmd)
        escaped_desc = escape_md(desc)
        text += f"`{escaped_cmd}` \\- {escaped_desc}\n"
    text += "\n"
    
    if is_owner:
        text += "*👑 Comandos de Admin*\n"
        for cmd, desc in COMMANDS_INFO["👑 Comandos de Admin"].items():
            escaped_desc = escape_md(desc)
            text += f"`{cmd}` \\- {escaped_desc}\n"
    
    text += f"\n💡 *Tip:* Usa /help para más información"
    
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        disable_web_page_preview=True
    )

async def run_dirsearch_pro(base_url: str) -> str:
    """Dirsearch básico:
    - Qué: Verifica rutas/directorios comunes por HEAD (HTTP).
    - Para qué: Descubrir contenido expuesto sin wordlist pesada.
    - Cómo: Usa requests.head (en hilo) con límite de concurrencia; ignora SSL (testing).
    """
    found = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    sem = asyncio.Semaphore(10)  # limita 10 concurrentes

    # Silenciamos warnings de verify=False localmente
    try:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    except Exception:
        pass

    async def check_path(path: str):
        async with sem:
            try:
                url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                response = await asyncio.to_thread(
                    requests.head,
                    url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=4,
                    verify=False
                )
                if response.status_code < 404:
                    status = "✅" if response.status_code == 200 else "⚠️"
                    found.append(f"{status} `{escape_md(path)}` \\- `{response.status_code}`")
            except requests.RequestException:
                pass
            except Exception as e:
                logger.error(f"Error checking {path}: {e}")

    try:
        tasks = [check_path(path) for path in COMMON_PATHS]
        await asyncio.gather(*tasks)

        if not found:
            return f"{EMOJI['ERROR']} No se encontraron rutas accesibles\\."

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
logger = logging.getLogger(__name__)

# --- CARGA LOCAL DE BIN LIST ---
BIN_DB: Dict[str, Dict[str, Any]] = {}
_BIN_DB_LOADED = False

def _standardize_bin_row(row: Dict[str, Any]) -> Dict[str, str]:
    """Normaliza una fila del CSV a claves comunes: country, bank, scheme, type, brand, alpha2.
    Intenta mapear nombres de columnas frecuentes en datasets públicos de BIN.
    """
    # Convertimos claves a minúsculas para búsqueda flexible
    lower = {str(k).lower(): ("" if row[k] is None else str(row[k])) for k in row.keys()}
    def pick(*candidates: str) -> str:
        for name in candidates:
            if name in lower and lower[name]:
                return lower[name]
        return ""
    return {
        "country": pick("country_name", "country", "country_name_iso", "countryname"),
        "alpha2": pick("country_alpha2", "alpha_2", "alpha2", "countrycode", "country_iso", "iso"),
        "bank": pick("bank_name", "bank", "issuer", "institution"),
        "scheme": pick("scheme", "brand", "card_brand", "network"),
        "brand": pick("brand", "sub_brand", "card_type"),
        "type": pick("type", "card_category", "category")
    }

def load_bin_db() -> None:
    """Carga el CSV local de BINs en memoria (diccionario por BIN de 6 dígitos).
    Usa pandas por eficiencia; se ejecuta una sola vez perezosamente.
    """
    global BIN_DB, _BIN_DB_LOADED
    if _BIN_DB_LOADED:
        return
    try:
        if not os.path.exists(BIN_CSV_PATH):
            _BIN_DB_LOADED = True
            return
        # Intentamos leer con pandas; inferimos separador automáticamente si es posible
        df = pd.read_csv(BIN_CSV_PATH, dtype=str, low_memory=False)
        # Detectar columna BIN
        bin_col = None
        for c in df.columns:
            cl = str(c).lower()
            if cl in ("bin", "iin", "id", "bin6"):
                bin_col = c
                break
        if bin_col is None:
            # Heurística: primera columna si contiene 6 dígitos en la mayoría de filas
            for c in df.columns:
                series = df[c].astype(str).str.fullmatch(r"\d{6}", na=False)
                if series.mean() > 0.5:
                    bin_col = c
                    break
        if bin_col is None:
            _BIN_DB_LOADED = True
            return
        # Construimos diccionario
        for _, r in df.iterrows():
            b = str(r[bin_col]).strip()
            if not b or not re.fullmatch(r"\d{6}", b):
                continue
            info = _standardize_bin_row(r.to_dict())
            BIN_DB[b] = info
        _BIN_DB_LOADED = True
        logger.info(f"BIN DB cargada: {len(BIN_DB)} registros")
    except Exception as e:
        _BIN_DB_LOADED = True
        logger.error(f"No se pudo cargar BIN CSV: {e}")

def get_local_bin_info(bin_code: str) -> Dict[str, str]:
    """Busca información de BIN en la base local.
    Retorna dict con claves estándar o {} si no hay coincidencia.
    """
    try:
        load_bin_db()
        return BIN_DB.get(bin_code, {})
    except Exception:
        return {}

# --- LÓGICA DE BASE DE DATOS ---
def read_db() -> Dict[str, Any]:
    """Lee o inicializa la base de datos en JSON.
    - Qué: Almacena users, keys y audit.
    - Para qué: Persistencia ligera sin servidor.
    - Cómo: JSON en disco con manejo básico de errores.
    """
    if not os.path.exists(DB_PATH):
        with open(DB_PATH, "w", encoding='utf-8') as f:
            json.dump({"users": {}, "keys": {}, "audit": []}, f, indent=2)
    try:
        with open(DB_PATH, "r", encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"users": {}, "keys": {}, "audit": []}

def write_db(db: Dict[str, Any]):
    """Persistencia segura con logging de errores."""
    try:
        with open(DB_PATH, "w", encoding='utf-8') as f:
            json.dump(db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error escribiendo DB: {e}")

def get_or_create_user(uid: int, uname: Optional[str]) -> Dict[str, Any]:
    """Crea o actualiza un usuario:
    - plan: OWNER (dueño) o FREE/PREMIUM
    - credits: Owner infinito, el resto comienza en 0.
    """
    db = read_db()
    uid_str, username = str(uid), uname or f"user_{uid}"
    if uid_str not in db["users"]:
        db["users"][uid_str] = {
            "username": username,
            "plan": "OWNER" if uid == OWNER_ID else "FREE",
            "credits": 999999 if uid == OWNER_ID else 0,
            "created_at": datetime.now().isoformat()
        }
    db["users"][uid_str].update({
        "last_activity": datetime.now().isoformat(),
        "username": username
    })
    write_db(db)
    return db["users"][uid_str]

async def add_credits(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /key <cantidad> (solo OWNER)
    - Qué: Genera una key que añade créditos a quien la canjee.
    - Para qué: Sistema de monetización/recompensas.
    - Cómo: Se guarda en DB como {'type':'CREDITS','amount':N}.
    """
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text(f"{EMOJI['ERROR']} Solo el owner puede generar keys\\.")
        return
    try:
        amount = int(context.args[0])
        if amount <= 0:
            raise ValueError
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
    """Comando /redeem <key>: Suma créditos al usuario si la key es válida."""
    try:
        key = context.args[0].upper()
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
    """Escapa caracteres especiales para Markdown V2 de Telegram."""
    if not isinstance(text, str):
        text = str(text)
    specials = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(specials)}])', r'\\\1', text)

def escape_html(text: str) -> str:
    """Escapa <, >, & para HTML; evita errores de parseo en ParseMode.HTML."""
    if not isinstance(text, str):
        text = str(text)
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )

def truncate_message(text: str, max_length: int = 4000) -> str:
    """Trunca mensajes largos para evitar Message_too_long de Telegram. Optimizado para velocidad."""
    if len(text) <= max_length:
        return text
    
    # Búsqueda optimizada de punto de corte
    truncated = text[:max_length]
    
    # Buscar salto de línea en el 80% final (más eficiente)
    search_start = int(max_length * 0.8)
    last_newline = truncated.rfind('\n', search_start)
    
    if last_newline > search_start:
        truncated = truncated[:last_newline]
    else:
        # Buscar espacio en el 80% final
        last_space = truncated.rfind(' ', search_start)
        if last_space > search_start:
            truncated = truncated[:last_space]
    
    return truncated + f"\n\n... (truncado, {len(text)} caracteres totales)"

async def send_long_message(chat_id: int, text: str, bot, parse_mode=None, reply_markup=None, disable_web_page_preview=True) -> bool:
    """Envía mensajes largos dividiéndolos en partes si es necesario. Optimizado para velocidad."""
    try:
        if len(text) <= 4000:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                parse_mode=parse_mode,
                reply_markup=reply_markup,
                disable_web_page_preview=disable_web_page_preview
            )
            return True
        
        # División optimizada por caracteres en lugar de líneas
        max_length = 4000
        parts = []
        start = 0
        
        while start < len(text):
            end = start + max_length
            
            # Buscar punto de corte natural
            if end < len(text):
                # Buscar último salto de línea en el rango
                last_newline = text.rfind('\n', start, end)
                if last_newline > start + max_length * 0.8:  # Si hay salto en el 80% final
                    end = last_newline
                else:
                    # Buscar último espacio
                    last_space = text.rfind(' ', start, end)
                    if last_space > start + max_length * 0.8:
                        end = last_space
            
            part = text[start:end].strip()
            if part:
                parts.append(part)
            
            start = end
        
        # Enviar todas las partes de forma asíncrona para mayor velocidad
        tasks = []
        for i, part in enumerate(parts):
            part_text = f"{part}\n\n*Parte {i+1} de {len(parts)}*"
            
            if i == len(parts) - 1 and reply_markup:
                # Última parte con botones
                task = bot.send_message(
                    chat_id=chat_id,
                    text=part_text,
                    parse_mode=parse_mode,
                    reply_markup=reply_markup,
                    disable_web_page_preview=disable_web_page_preview
                )
            else:
                # Partes intermedias sin botones
                task = bot.send_message(
                    chat_id=chat_id,
                    text=part_text,
                    parse_mode=parse_mode,
                    disable_web_page_preview=disable_web_page_preview
                )
            
            tasks.append(task)
        
        # Ejecutar todas las tareas de envío
        await asyncio.gather(*tasks, return_exceptions=True)
        return True
            
    except Exception as e:
        logger.error(f"Error enviando mensaje largo: {e}")
        return False

def alpha2_to_flag(alpha2: str) -> str:
    """Convierte un código de país ISO alpha-2 (p.ej. 'US') en emoji de bandera.
    Si no es válido, retorna cadena vacía.
    """
    try:
        code = (alpha2 or "").upper()
        if len(code) != 2 or not code.isalpha():
            return ""
        base = 127397  # Regional Indicator Symbol Letter A offset
        return chr(ord(code[0]) + base) + chr(ord(code[1]) + base)
    except Exception:
        return ""

def gen_key() -> str:
    """Genera una key con formato VIP-XXXXX (letras y números)."""
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=KEY_LENGTH))
    return f"{KEY_PREFIX}{random_part}"

def validate_input(input_str: str, input_type: str) -> Tuple[bool, str]:
    """Valida argumentos de herramientas:
    - ip: formato IPv4
    - domain: incluye '.'
    - url: antepone https:// si falta
    - number: 8..64
    """
    if not (input_str := input_str.strip()):
        return False, f"{EMOJI['ERROR']} La entrada no puede estar vacía"
    if input_type == "ip":
        try:
            socket.inet_aton(input_str)
            return True, input_str
        except socket.error:
            return False, f"{EMOJI['ERROR']} Formato de IP inválido \\(ej: 8\\.8\\.8\\.8\\)"
    elif input_type == "domain":
        if len(input_str) < 3 or '.' not in input_str:
            return False, f"{EMOJI['ERROR']} Formato de dominio inválido \\(ej: google\\.com\\)"
        return True, input_str
    elif input_type == "url":
        if not re.match(r'https?://', input_str):
            input_str = 'https://' + input_str
        return True, input_str
    elif input_type == "number":
        if not input_str.isdigit() or not (8 <= int(input_str) <= 64):
            return False, f"{EMOJI['ERROR']} Ingresa un número entre 8 y 64"
        return True, input_str
    return True, input_str

# --- DEFINICIÓN DE HERRAMIENTAS ---
TOOL_CATEGORIES = {
    f"{EMOJI['BASIC']} HERRAMIENTAS BÁSICAS": [
        ("hash", "🔧 Hash", "Genera hashes MD5, SHA1, SHA256", "text"),
        ("ip", "📍 Info IP", "Obtiene GeoIP y datos de una IP", "ip"),
        ("ping", "📡 Ping", "Mide la latencia a un host", "domain"),
        ("http", "🌐 Headers HTTP", "Muestra cabeceras de una URL", "url"),
        ("sec_headers", "🛡️ Seguridad Web", "Analiza cabeceras de seguridad", "url"),
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
    ],
    # Nueva categoría educativa de OSINT (no intrusiva):
    f"{EMOJI['BASIC']} OSINT EDUCATIVO": [
        ("osint_email", "✉️ OSINT Email", "Búsqueda segura de exposición de email", "text"),
        ("osint_phone", "📞 OSINT Teléfono", "Info pública y validación de teléfono", "text"),
        ("osint_username", "👤 OSINT Usuario", "Búsqueda por nombre de usuario", "text"),
        ("exif", "🖼️ Meta Imagen", "Lee metadatos EXIF de imagen (URL)", "url")
    ]
}

# --- LÓGICA DE HERRAMIENTAS ---
async def execute_command(cmd: str, timeout: int) -> str:
    """Ejecuta un comando del sistema de forma asíncrona con timeout."""
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return stdout.decode('utf-8', 'ignore').strip() if process.returncode == 0 else f"Error: {stderr.decode('utf-8', 'ignore').strip()}"
    except asyncio.TimeoutError:
        return f"Timeout de {timeout}s excedido."
    except Exception as e:
        return f"Error al ejecutar comando: {e}"

def ensure_nmap() -> Optional[str]:
    """Verifica si nmap está instalado y accesible.
    - Devuelve None si todo ok, o un string con el error para mostrar al usuario.
    """
    if shutil.which("nmap") is None:
        return f"{EMOJI['ERROR']} nmap no está instalado en el sistema o no está en PATH\\."
    return None

async def get_parsed_whois(domain: str) -> str:
    """Obtiene y resume datos WHOIS:
    - Dominio, registrador, fechas y DNS.
    """
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        if not w.domain_name:
            return "No se pudo obtener información WHOIS."
        info = {
            "Dominio": w.domain_name,
            "Registrador": w.registrar,
            "Creación": w.creation_date,
            "Expiración": w.expiration_date,
            "Servidores DNS": w.name_servers
        }
        return "\n".join([f"*{k}:* {escape_md(v)}" for k, v in info.items() if v])
    except Exception:
        return "No se pudo procesar la información WHOIS."

async def run_tech_detect(url: str) -> str:
    """Detecta señales de tecnologías en headers y HTML:
    - Busca CMS, frameworks frontend y CDNs comunes.
    """
    try:
        r = await asyncio.to_thread(requests.get, url, timeout=8)
        if not r.ok:
            return f"{EMOJI['ERROR']} HTTP {r.status_code} al acceder a la URL."
        text_lower = r.text.lower()
        tech = set()
        if "server" in r.headers:
            tech.add(f"Server: {r.headers['server']}")
        if "X-Powered-By" in r.headers:
            tech.add(f"Backend: {r.headers['X-Powered-By']}")
        if "wp-content" in r.text:
            tech.add("CMS: WordPress")
        if "joomla" in text_lower:
            tech.add("CMS: Joomla")
        if "drupal" in text_lower:
            tech.add("CMS: Drupal")
        if "react" in text_lower:
            tech.add("Frontend: React")
        if "vue" in text_lower:
            tech.add("Frontend: Vue.js")
        if "cloudflare" in r.headers.get("server", "").lower():
            tech.add("CDN: Cloudflare")
        return f"{EMOJI['SUCCESS']} *Tecnologías detectadas:*\n" + "\n".join([f"`{escape_md(t)}`" for t in tech]) if tech else "No se detectaron tecnologías específicas."
    except Exception as e:
        return f"{EMOJI['ERROR']} No se pudo analizar la URL: {escape_md(str(e))}"

# --- OSINT EDUCATIVO ---
def _rate_header(value: Optional[str], good_contains: list[str], bad_contains: list[str]) -> str:
    """Puntúa un header según patrones buenos/malos y devuelve una nota breve."""
    if not value:
        return "ausente"
    vlow = value.lower()
    for bad in bad_contains:
        if bad and bad in vlow:
            return f"débil ({bad})"
    for good in good_contains:
        if good and good in vlow:
            return f"ok ({good})"
    return "presente"

async def analyze_security_headers(url: str) -> str:
    """Analiza cabeceras de seguridad comunes y da recomendaciones (sin APIs)."""
    try:
        r = await asyncio.to_thread(requests.get, url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}

        def h(name: str) -> Optional[str]:
            return headers.get(name.lower())

        report = []
        # HSTS
        hsts = h("strict-transport-security")
        hsts_note = _rate_header(hsts, ["max-age"], [])
        if not hsts:
            report.append("- Strict-Transport-Security: faltante (recom: HSTS con max-age>=15552000)")
        else:
            report.append(f"- Strict-Transport-Security: {escape_md(hsts)} ({hsts_note})")

        # CSP
        csp = h("content-security-policy")
        csp_note = _rate_header(csp, ["default-src", "script-src"], ["unsafe-inline", "*"])
        if not csp:
            report.append("- Content-Security-Policy: faltante (mitiga XSS, recom: default-src 'self')")
        else:
            report.append(f"- Content-Security-Policy: {escape_md(csp)} ({csp_note})")

        # X-Frame-Options
        xfo = h("x-frame-options")
        if not xfo:
            report.append("- X-Frame-Options: faltante (recom: DENY o SAMEORIGIN)")
        else:
            report.append(f"- X-Frame-Options: {escape_md(xfo)}")

        # X-Content-Type-Options
        xcto = h("x-content-type-options")
        if not xcto:
            report.append("- X-Content-Type-Options: faltante (recom: nosniff)")
        else:
            report.append(f"- X-Content-Type-Options: {escape_md(xcto)}")

        # Referrer-Policy
        refpol = h("referrer-policy")
        if not refpol:
            report.append("- Referrer-Policy: faltante (recom: no-referrer o same-origin)")
        else:
            report.append(f"- Referrer-Policy: {escape_md(refpol)}")

        # Permissions-Policy
        ppol = h("permissions-policy") or h("feature-policy")
        if not ppol:
            report.append("- Permissions-Policy: faltante (controla APIs del navegador)")
        else:
            report.append(f"- Permissions-Policy: {escape_md(ppol)}")

        return f"{EMOJI['SUCCESS']} *Seguridad de cabeceras para* `{escape_md(r.url)}`:\n" + "\n".join(report)
    except Exception as e:
        return f"{EMOJI['ERROR']} Falló análisis de cabeceras: {escape_md(str(e))}"

async def exif_from_image(url: str) -> str:
    """Descarga una imagen por URL y muestra metadatos EXIF básicos (sin APIs)."""
    try:
        r = await asyncio.to_thread(requests.get, url, timeout=10)
        if not r.ok:
            return f"{EMOJI['ERROR']} No se pudo descargar la imagen: HTTP {r.status_code}"
        from PIL import Image
        from io import BytesIO
        img = Image.open(BytesIO(r.content))
        exif = getattr(img, "_getexif", lambda: None)()
        if not exif:
            return f"{EMOJI['INFO']} La imagen no contiene EXIF disponible."
        # Convertir tags EXIF
        try:
            from PIL.ExifTags import TAGS
            items = []
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, str(tag_id))
                # Evita binarios largos
                svalue = str(value)
                if len(svalue) > 200:
                    svalue = svalue[:200] + "..."
                items.append(f"*{escape_md(tag)}:* {escape_md(svalue)}")
            return f"{EMOJI['SUCCESS']} *Metadatos EXIF*:\n" + "\n".join(items[:25])
        except Exception:
            return f"{EMOJI['INFO']} EXIF presente pero no se pudo decodificar etiquetas."
    except Exception as e:
        return f"{EMOJI['ERROR']} Falló lectura EXIF: {escape_md(str(e))}"
async def osint_email_lookup(email: str) -> str:
    """Consulta educativa de email (ética):
    - Qué: Valida formato, y consulta fuentes públicas no intrusivas.
    - Cómo: Usa haveibeenpwned (si el usuario lo configura) o servicios públicos informativos.
    - Nota: Por defecto, sin API key, damos guías y enlaces útiles.
    """
    try:
        # Validación básica de email
        if not re.fullmatch(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return f"{EMOJI['ERROR']} Email inválido. Ej: nombre@dominio.com"

        # Guías y enlaces educativos (no intrusivos)
        links = [
            ("Comprobación de filtraciones (HIBP)", f"https://haveibeenpwned.com/"),
            ("Búsqueda en leaks paste sites", f"https://www.google.com/search?q=" + quote_plus(f"\"{email}\" site:pastebin.com | site:ghostbin.com | site:rentry.co")),
            ("Búsqueda inversa en Gravatar", f"https://en.gravatar.com/site/check/{quote_plus(email)}"),
            ("Búsqueda en redes sociales", f"https://www.google.com/search?q=" + quote_plus(f"\"{email}\" site:twitter.com | site:linkedin.com | site:facebook.com")),
        ]
        lines = [f"[{name}]({url})" for name, url in links]
        return f"{EMOJI['SUCCESS']} *Recursos OSINT para* `{escape_md(email)}`:\n" + "\n".join(lines)
    except Exception as e:
        return f"{EMOJI['ERROR']} Falló OSINT email: {escape_md(str(e))}"

async def osint_phone_lookup(phone: str) -> str:
    """Consulta educativa de teléfono (ética):
    - Valida patrón básico y comparte recursos públicos no intrusivos.
    """
    try:
        # Normalización básica: quitar espacios y guiones
        normalized = re.sub(r"[\s\-]", "", phone)
        if not re.fullmatch(r"^\+?\d{6,15}$", normalized):
            return f"{EMOJI['ERROR']} Teléfono inválido. Usa formato internacional, ej: +34911223344"

        links = [
            ("Formatear/validar (libphonenumber demo)", "https://libphonenumber.appspot.com/"),
            ("Búsqueda en directorios inversos", "https://www.truecaller.com/"),
            ("Búsqueda web", f"https://www.google.com/search?q=" + quote_plus(f"\"{normalized}\"")),
        ]
        lines = [f"[{name}]({url})" for name, url in links]
        return f"{EMOJI['SUCCESS']} *Recursos OSINT para* `{escape_md(normalized)}`:\n" + "\n".join(lines)
    except Exception as e:
        return f"{EMOJI['ERROR']} Falló OSINT teléfono: {escape_md(str(e))}"

async def osint_username_lookup(username: str) -> str:
    """Consulta educativa de nombre de usuario (ética):
    - Recomendaciones y enlaces para buscar presencia pública.
    """
    try:
        if not re.fullmatch(r"^[A-Za-z0-9_.\-]{3,32}$", username):
            return f"{EMOJI['ERROR']} Usuario inválido (3-32, letras, números, _.-)"
        links = [
            ("Sherlock (GitHub)", "https://github.com/sherlock-project/sherlock"),
            ("Búsqueda en GitHub", f"https://github.com/search?q=" + quote_plus(username)),
            ("Búsqueda en redes", f"https://www.google.com/search?q=" + quote_plus(f"\"{username}\" site:twitter.com | site:instagram.com | site:tiktok.com | site:reddit.com")),
        ]
        lines = [f"[{name}]({url})" for name, url in links]
        return f"{EMOJI['SUCCESS']} *Recursos OSINT para* `{escape_md(username)}`:\n" + "\n".join(lines)
    except Exception as e:
        return f"{EMOJI['ERROR']} Falló OSINT usuario: {escape_md(str(e))}"

# --- LÓGICA DE USUARIO Y ADMIN ---
def canjear_key(user_id: int, key: str) -> str:
    """Canjea una key premium/créditos y audita la acción."""
    db = read_db()
    if (key := key.strip().upper()) not in db.get("keys", {}):
        return f"{EMOJI['ERROR']} Key inválida o ya utilizada\\."
    plan = db["keys"][key]
    db["users"][str(user_id)]["plan"] = plan
    db.get("audit", []).append({"user_id": str(user_id), "key": key, "timestamp": datetime.now().isoformat(), "action": "key_redeemed"})
    del db["keys"][key]
    write_db(db)
    return f"{EMOJI['SUCCESS']} ¡Key canjeada\\! Tu plan ahora es *{escape_md(plan)}*\\."

def export_excel() -> str:
    """Exporta usuarios, keys y auditoría a un Excel con 3 hojas."""
    try:
        db = read_db()
        with pd.ExcelWriter("toolbox_data.xlsx", engine='openpyxl') as writer:
            pd.DataFrame(db["users"].values()).to_excel(writer, sheet_name='Usuarios', index=False)
            pd.DataFrame(list(db.get("keys", {}).items()), columns=['Key', 'Plan']).to_excel(writer, sheet_name='Keys', index=False)
            pd.DataFrame(db.get("audit", [])).to_excel(writer, sheet_name='Auditoría', index=False)
        return f"{EMOJI['SUCCESS']} Excel exportado: `toolbox_data.xlsx`"
    except Exception as e:
        return f"{EMOJI['ERROR']} Error al exportar: {escape_md(str(e))}"

# --- TAREAS DIARIAS ---
DAILY_TASKS = {
    "use_tools": {"desc": "Usar 3 herramientas", "reward": 10, "max": 3},
    "invite_user": {"desc": "Invitar 1 usuario", "reward": 20, "max": 1},
    "try_premium": {"desc": "Usar herramienta premium", "reward": 15, "max": 1}
}

async def check_daily_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /daily: muestra progreso y recompensas de tareas diarias."""
    user_id = str(update.effective_user.id)
    db = read_db()
    
    if "daily_tasks" not in db["users"][user_id]:
        db["users"][user_id]["daily_tasks"] = {
            "last_reset": datetime.now().date().isoformat(),
            "tasks": {task: 0 for task in DAILY_TASKS}
        }
    
    if db["users"][user_id]["daily_tasks"]["last_reset"] < datetime.now().date().isoformat():
        db["users"][user_id]["daily_tasks"]["tasks"] = {task: 0 for task in DAILY_TASKS}
        db["users"][user_id]["daily_tasks"]["last_reset"] = datetime.now().date().isoformat()
    
    text = "📋 *Tareas Diarias*\n\n"
    for task, info in DAILY_TASKS.items():
        progress = db["users"][user_id]["daily_tasks"]["tasks"].get(task, 0)
        text += f"{'✅' if progress >= info['max'] else '⬜'} {escape_md(info['desc'])}\n"
        text += f"Progreso: {progress}/{info['max']} \\- Recompensa: {info['reward']} créditos\n\n"
    
    write_db(db)
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)

# --- PROTECCIÓN DE IPS ---
BLOCKED_IPS = set()
MAX_FAILS = 3

async def check_ip_safety(ip: str) -> bool:
    """Evalúa si una IP es segura para escaneo:
    - Evita privadas/blacklist local.
    - Consulta AbuseIPDB si hay API Key (threshold < 50).
    """
    try:
        if ipaddress.ip_address(ip).is_private:
            return False
        if ip in BLOCKED_IPS:
            return False
        if ABUSE_IPDB_KEY:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip},
                    headers={"Key": ABUSE_IPDB_KEY, "Accept": "application/json"},
                ) as response:
                    data = await response.json()
                    return data.get("data", {}).get("abuseConfidenceScore", 0) < 50
        return True
    except Exception as e:
        logger.error(f"Error verificando IP {ip}: {e}")
        return True

# --- LOGGING MEJORADO ---
import logging.handlers
import traceback

def setup_logging():
    """Configura logging rotativo:
    - bot.log INFO - 1MB x 5 rotaciones
    - error.log ERROR - 1MB x 5 rotaciones
    """
    log_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    main_handler = logging.handlers.RotatingFileHandler(
        'bot.log',
        maxBytes=1024*1024,
        backupCount=5
    )
    main_handler.setFormatter(log_format)
    
    error_handler = logging.handlers.RotatingFileHandler(
        'error.log',
        maxBytes=1024*1024,
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(log_format)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(main_handler)
    logger.addHandler(error_handler)
    
    return logger

# --- ESTADÍSTICAS EN TIEMPO REAL ---
class BotStats:
    """Contador simple en memoria (reinicia a medianoche)."""
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

async def get_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comando /stats (solo OWNER): muestra uptime, comandos, usuarios activos y errores."""
    if update.effective_user.id != OWNER_ID:
        return
        
    uptime = bot_stats.get_uptime()
    text = (
        "Hola patron 👑\n\n"
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
    """Mantenimiento diario:
    - Borra usuarios inactivos no-premium (30 días).
    - Recorta logs de auditoría (>7 días).
    - Limpia keys expiradas (si hay key_expiry).
    """
    try:
        db = read_db()
        now = datetime.now()
        
        inactive_threshold = now - timedelta(days=30)
        db["users"] = {
            uid: user for uid, user in db["users"].items()
            if user.get("plan") in ["PREMIUM", "OWNER"] or 
            datetime.fromisoformat(user.get("last_activity", "2020-01-01")) > inactive_threshold
        }
        
        db["audit"] = [
            log for log in db["audit"] 
            if (now - datetime.fromisoformat(log["timestamp"])).days < 7
        ]
        
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

FLOOD_LIMIT = 5  # máximo de comandos por minuto
FLOOD_TIME = 60  # tiempo en segundos

class FloodProtection:
    """Antispam simple por ventana deslizante de 60s."""
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
    """Router de herramientas:
    - Qué: ejecuta la herramienta por nombre usando el argumento validado.
    - Cómo: Combinación de requests (en hilos) y comandos del sistema con timeouts.
    """
    if not flood_protection.can_execute(user_id):
        return f"{EMOJI['ERROR']} Demasiadas peticiones\\. Espera 1 minuto\\."
    
    try:
        # Validar que la herramienta existe
        if tool_name not in [tool[0] for cat in TOOL_CATEGORIES.values() for tool in cat]:
            return f"{EMOJI['ERROR']} Herramienta '{tool_name}' no encontrada\\."
        
        # Validar argumento
        if not arg or not arg.strip():
            return f"{EMOJI['ERROR']} Argumento requerido para la herramienta\\."
        
        arg = arg.strip()
        if tool_name == "hash":
            return (f"*MD5:* `{hashlib.md5(arg.encode()).hexdigest()}`\n"
                    f"*SHA1:* `{hashlib.sha1(arg.encode()).hexdigest()}`\n"
                    f"*SHA256:* `{hashlib.sha256(arg.encode()).hexdigest()}`")

        elif tool_name == "ip":
            resp = await asyncio.to_thread(requests.get, f"https://ipinfo.io/{arg}/json", timeout=5)
            if not resp.ok:
                return f"{EMOJI['ERROR']} No se pudo obtener IP info: HTTP {resp.status_code}."
            return "\n".join([f"*{escape_md(k.capitalize())}:* {escape_md(v)}" for k, v in resp.json().items()])

        elif tool_name == "ping":
            result = await execute_command(f'ping -c 4 {arg}', 15)
            # Limitar resultado para evitar mensajes muy largos
            if len(result) > 2000:
                result = truncate_message(result, 2000)
            return f"```\n{escape_md(result)}\n```"

        elif tool_name == "http":
            resp = await asyncio.to_thread(requests.get, arg, timeout=10, allow_redirects=True)
            if not resp.ok:
                return f"{EMOJI['ERROR']} Solicitud HTTP falló con estado {resp.status_code}."
            
            # Limitar headers para evitar mensajes muy largos
            headers_list = list(resp.headers.items())[:20]  # Solo primeros 20 headers
            headers_text = (f"*Status:* `{resp.status_code}`\n"
                           f"*URL Final:* `{escape_md(resp.url)}`\n\n*Headers:*\n")
            result = headers_text + "\n".join([f"*{escape_md(k)}:* `{escape_md(v)}`" for k, v in headers_list])
            
            # Si hay más headers, indicarlo
            if len(resp.headers) > 20:
                result += f"\n\n... y {len(resp.headers) - 20} headers más"
            
            return result
        elif tool_name == "sec_headers":
            return await analyze_security_headers(arg)

        elif tool_name == "base64":
            try:
                return f"*Decodificado:*\n`{escape_md(base64.b64decode(arg).decode('utf-8', 'ignore'))}`"
            except Exception:
                return f"*Codificado:*\n`{base64.b64encode(arg.encode()).decode()}`"

        elif tool_name == "password":
            chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
            return f"Contraseña de {int(arg)} caracteres:\n`{escape_md(''.join(random.choices(chars, k=int(arg))))}`"

        elif tool_name == "ports_fast":
            err = ensure_nmap()
            if err:
                return err
            if not await check_ip_safety(arg):
                return f"{EMOJI['ERROR']} IP no segura para escaneo\\."
            
            result = await execute_command(f'nmap -F {arg}', 60)
            # Limitar resultado para evitar mensajes muy largos
            if len(result) > 3000:
                result = truncate_message(result, 3000)
            return f"```\n{escape_md(result)}\n```"

        elif tool_name == "ports_full":
            err = ensure_nmap()
            if err:
                return err
            if not await check_ip_safety(arg):
                return f"{EMOJI['ERROR']} IP no segura para escaneo\\."
            
            result = await execute_command(f'nmap -sV {arg}', 300)
            # Limitar resultado para evitar mensajes muy largos
            if len(result) > 3000:
                result = truncate_message(result, 3000)
            return f"```\n{escape_md(result)}\n```"

        elif tool_name == "vuln_scan":
            err = ensure_nmap()
            if err:
                return err
            if not await check_ip_safety(arg):
                return f"{EMOJI['ERROR']} IP no segura para escaneo\\."
            
            result = await execute_command(f'nmap --script vuln {arg}', 600)
            # Limitar resultado para evitar mensajes muy largos
            if len(result) > 3000:
                result = truncate_message(result, 3000)
            return f"```\n{escape_md(result)}\n```"

        elif tool_name == "dns":
            results = []
            for r_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = await asyncio.to_thread(dns.resolver.resolve, arg, r_type)
                    if records := [escape_md(str(r)) for r in answers]:
                        results.append(f"*{r_type}:* {', '.join(records)}")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
            return "\n".join(results) or "No se encontraron registros DNS."

        elif tool_name == "whois":
            return await get_parsed_whois(arg)

        elif tool_name == "subdomain":
            resp = await asyncio.to_thread(requests.get, f"https://api.hackertarget.com/hostsearch/?q={arg}", timeout=20)
            if "error" in resp.text.lower():
                return f"{EMOJI['ERROR']} No se pudieron obtener subdominios."
            subs = resp.text.strip().split('\n')
            
            # Limitar resultado para evitar mensajes muy largos
            total_subs = len(resp.text.strip().split('\n'))
            if len(subs) > 50:  # Limitar a 50 subdominios
                subs = subs[:50]
                result_text = f"{EMOJI['SUCCESS']} *{total_subs} Subdominios encontrados (mostrando 50):*\n`" + '`\n`'.join([escape_md(s.split(',')[0]) for s in subs]) + "`"
            else:
                result_text = f"{EMOJI['SUCCESS']} *{len(subs)} Subdominios encontrados:*\n`" + '`\n`'.join([escape_md(s.split(',')[0]) for s in subs]) + "`"
            
            return result_text

        elif tool_name == "dirsearch":
            return await run_dirsearch_pro(arg)

        elif tool_name == "tech_detect":
            return await run_tech_detect(arg)

        elif tool_name == "reverseip":
            if not await check_ip_safety(arg):
                return f"{EMOJI['ERROR']} IP no segura para consulta\\."
            resp = await asyncio.to_thread(requests.get, f"https://api.hackertarget.com/reverseiplookup/?q={arg}", timeout=20)
            if "error" in resp.text.lower():
                return f"{EMOJI['ERROR']} No se pudieron obtener dominios."
            
            # Limitar resultado para evitar mensajes muy largos
            domains = resp.text.strip().split('\n')
            total_domains = len(domains)
            if len(domains) > 50:  # Limitar a 50 dominios
                domains = domains[:50]
                result_text = f"{EMOJI['SUCCESS']} *Dominios en la misma IP (mostrando 50 de {total_domains}):*\n`" + "`\n`".join([escape_md(d) for d in domains]) + "`"
            else:
                result_text = f"{EMOJI['SUCCESS']} *Dominios en la misma IP:*\n`" + "`\n`".join([escape_md(d) for d in domains]) + "`"
            
            return result_text

        elif tool_name == "tls":
            # Para dominios: resolvemos IP y validamos seguridad
            try:
                resolved_ip = await asyncio.to_thread(socket.gethostbyname, arg)
                if not await check_ip_safety(resolved_ip):
                    return f"{EMOJI['ERROR']} Host no seguro para consulta TLS\\."
            except Exception:
                pass

            def _fetch_cert(host: str):
                ctx = ssl.create_default_context()
                sock = None
                ssock = None
                try:
                    sock = socket.create_connection((host, 443), timeout=10)
                    ssock = ctx.wrap_socket(sock, server_hostname=host)
                    cert = ssock.getpeercert()
                    return cert
                finally:
                    try:
                        if ssock: ssock.close()
                    except Exception:
                        pass
                    try:
                        if sock: sock.close()
                    except Exception:
                        pass

            try:
                cert = await asyncio.to_thread(_fetch_cert, arg)
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                return "\n".join([
                    f"*Sujeto:* {escape_md(subject.get('commonName'))}",
                    f"*Emisor:* {escape_md(issuer.get('commonName'))}",
                    f"*Válido desde:* {escape_md(cert.get('notBefore'))}",
                    f"*Válido hasta:* {escape_md(cert.get('notAfter'))}"
                ])
            except Exception as e:
                return f"{EMOJI['ERROR']} No se pudo obtener el certificado: {escape_md(str(e))}"

        elif tool_name == "cve_search":
            resp = await asyncio.to_thread(requests.get, f"https://cve.circl.lu/api/search/{arg}", timeout=10)
            if not resp.ok:
                return f"{EMOJI['ERROR']} Búsqueda CVE falló con estado {resp.status_code}."
            data = resp.json().get("data", [])
            if not data:
                return f"{EMOJI['ERROR']} No se encontraron CVEs para ese término."
            
            # Limitar resultados para evitar mensajes muy largos
            max_cves = 15
            if len(data) > max_cves:
                data = data[:max_cves]
                info = [f"*{escape_md(c.get('id'))}:* {escape_md(c.get('summary', ''))[:60]}..." for c in data]
                result = f"{EMOJI['SUCCESS']} *CVEs encontrados (mostrando {max_cves} de {len(resp.json().get('data', []))}):*\n" + "\n".join(info)
            else:
                info = [f"*{escape_md(c.get('id'))}:* {escape_md(c.get('summary', ''))[:80]}..." for c in data]
                result = f"{EMOJI['SUCCESS']} *CVEs encontrados:*\n" + "\n".join(info)
            
            return result

        elif tool_name == "dorking":
            dorks = {
                "Archivos Log": "inurl:log",
                "Directorios Expuestos": "intitle:\"index of\"",
                "Archivos Config": "ext:xml | ext:conf | ext:ini",
                "Bases de Datos": "ext:sql | ext:dbf | ext:mdb",
                "Login Pages": "inurl:login"
            }
            links = [f"[{escape_md(name)}]({'https://www.google.com/search?q=' + quote_plus(f'site:{arg} {dork}')})" for name, dork in dorks.items()]
            return f"{EMOJI['SUCCESS']} *Enlaces de Google Dorking:*\n" + "\n".join(links)
        elif tool_name == "exif":
            return await exif_from_image(arg)
        elif tool_name == "osint_email":
            return await osint_email_lookup(arg)
        elif tool_name == "osint_phone":
            return await osint_phone_lookup(arg)
        elif tool_name == "osint_username":
            return await osint_username_lookup(arg)
    except Exception as e:
        logger.error(f"Error en run_tool '{tool_name}': {e}")
        return f"{EMOJI['ERROR']} Error inesperado: {escape_md(str(e))}"

# --- SISTEMA DE RANKINGS ---
async def get_rankings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Comando /top: Top 10 usuarios por uso de herramientas (conteo en audit)."""
    db = read_db()
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
    """Otorga logros al cumplir hitos (herramientas diferentes, total de usos)."""
    db = read_db()
    user = db["users"][user_id]
    if "achievements" not in user:
        user["achievements"] = []
    
    new_achievements = []
    tools_used = len(set(log["tool"] for log in db["audit"] if log.get("user_id") == user_id))
    
    if tools_used >= 5 and "explorer" not in user["achievements"]:
        user["achievements"].append("explorer")
        new_achievements.append(ACHIEVEMENTS["explorer"]["name"])
        
    if len([log for log in db["audit"] if log.get("user_id") == user_id]) >= 20 and "hacker" not in user["achievements"]:
        user["achievements"].append("hacker")
        new_achievements.append(ACHIEVEMENTS["hacker"]["name"])
    
    write_db(db)
    return new_achievements

# --- SISTEMA DE REFERIDOS ---
REFERRAL_BONUS = 50

async def handle_start_with_ref(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/start <code>: si es nuevo y usa código válido, da créditos a ambos usuarios."""
    try:
        ref_code = context.args[0] if context.args else None
        user_id = str(update.effective_user.id)
        
        if ref_code and ref_code != user_id:
            db = read_db()
            if user_id not in db["users"]:
                db["users"][user_id] = get_or_create_user(update.effective_user.id, update.effective_user.username)
                db["users"][user_id]["credits"] += REFERRAL_BONUS
                db["users"][ref_code]["credits"] += REFERRAL_BONUS
                write_db(db)
                await update.message.reply_text(f"🎁 ¡Bienvenido! Recibiste {REFERRAL_BONUS} créditos por usar un código de referido!")
    except Exception as e:
        logger.error(f"Error en referido: {e}")
    await start(update, context)

# --- MODO DEBUG ---
async def debug_mode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/debug (OWNER): overview de usuarios, keys, usos y top herramientas."""
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
    
    for log in db["audit"]:
        if "tool" in log:
            stats["Herramientas más usadas"][log["tool"]] = stats["Herramientas más usadas"].get(log["tool"], 0) + 1
    
    text = "🔧 *Modo Debug*\n\n"
    for k, v in stats.items():
        text += f"*{escape_md(k)}:*\n`{escape_md(str(v))}`\n\n"
    
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)
    
async def backup_db(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Tarea programada: backup periódico del JSON, envío a OWNER y limpieza de backups >7 días."""
    try:
        backup_path = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        db = read_db()
        
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
        
        for f in os.listdir(backup_dir):
            if f.startswith("backup_") and f.endswith(".json"):
                file_path = os.path.join(backup_dir, f)
                if (datetime.now() - datetime.fromtimestamp(os.path.getctime(file_path))).days > 7:
                    os.remove(file_path)
                    
    except Exception as e:
        logger.error(f"Error en backup: {e}")
        try:
            await context.bot.send_message(
                chat_id=OWNER_ID,
                text=f"❌ Error en backup: {str(e)}"
            )
        except Exception:
            pass

async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/broadcast <mensaje> (OWNER): envía mensaje a todos los usuarios."""
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
                    text=f"📢 *Anuncio*\n\n{escape_md(message)}",
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
    """/report (OWNER): genera y envía una imagen con barras de uso de herramientas hoy."""
    if update.effective_user.id != OWNER_ID:
        return
        
    db = read_db()
    today = datetime.now().date()
    
    stats = {
        "users": {
            "total": len(db["users"]),
            "active_today": 0,
            "premium": len([u for u in db["users"].values() if u.get("plan") == "PREMIUM"])
        },
        "tools": {},
        "errors": {}
    }
    
    for log in db.get("audit", []):
        log_date = datetime.fromisoformat(log["timestamp"]).date()
        if log_date == today:
            stats["users"]["active_today"] += 1
            if "tool" in log:
                stats["tools"][log["tool"]] = stats["tools"].get(log["tool"], 0) + 1
    
    plt.figure(figsize=(10, 5))
    tools = list(stats["tools"].keys())
    uses = list(stats["tools"].values())
    plt.bar(tools, uses)
    plt.title("Uso de Herramientas (Hoy)")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("report.png")
    
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
    """/addgroup: registra chat de grupo con ajustes por defecto."""
    if update.effective_chat.type not in ['group', 'supergroup']:
        await update.message.reply_text("Este comando solo funciona en grupos.")
        return
        
    chat_id = str(update.effective_chat.id)
    db = read_db()
    
    if "groups" not in db:
        db["groups"] = {}
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
    1: 100,
    2: 300,
    3: 600,
    4: 1000,
    5: 2000,
}

async def add_xp(user_id: str, xp: int) -> tuple[int, int]:
    """Añade XP al usuario y sube nivel si corresponde."""
    db = read_db()
    user = db["users"][user_id]
    
    if "xp" not in user:
        user["xp"] = 0
    if "level" not in user:
        user["level"] = 1
    
    old_level = user["level"]
    user["xp"] += xp
    
    while user["level"] < len(LEVEL_XP) and user["xp"] >= LEVEL_XP[user["level"]]:
        user["level"] += 1
    
    write_db(db)
    return old_level, user["level"]

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/help: muestra ayuda de comandos y conceptos clave."""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    is_owner = user["plan"] == "OWNER"
    
    help_text = (
        f"🤖 *COMANDOS HACKERS*\n\n"
        f"*📚 Comandos Básicos*\n"
        f"`/start` \\- Inicia el bot\n"
        f"`/help` \\- Muestra esta ayuda\n"
        f"`/profile` \\- Tu perfil y estadísticas\n"
        f"`/redeem` \\- Canjear key VIP\n"
        f"`/daily` \\- Tareas diarias\n"
        f"`/top` \\- Ranking de usuarios\n"
        f"`/gen` \\- Generador por BIN\n\n"
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
            f"*👑 Comandos de patron*\n"
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

async def perfil_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/profile: muestra datos de usuario, créditos y estadísticas."""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    created = escape_md(user.get("created_at", "N/A")[:16])
    
    db = read_db()
    tools_used = len([log for log in db.get("audit", []) if log.get("user_id") == str(update.effective_user.id)])
    unique_tools = len(set(log.get("tool", "") for log in db.get("audit", []) 
                        if log.get("user_id") == str(update.effective_user.id)))
    
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
    """/start: mensaje de bienvenida con menú principal."""
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    text = (
    f"Hola, @{escape_md(user['username'])}\n\n"
    f"{EMOJI['BOT']} *SOY UNA CAJA DE HERRAMIENTAS HACKERS*\n\n"
    f"*Tu Plan Actual:* `{escape_md(user['plan'])}`\n\n"
    f"Elige una opción para comenzar 👇"
)
    await (update.message or update.callback_query.message).reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=menu_principal(user["plan"])
    )

def menu_principal(plan: str) -> InlineKeyboardMarkup:
    """Construye teclado principal con navegación rápida."""
    buttons = [
        [InlineKeyboardButton(f"{EMOJI['TOOL']} Herramientas", callback_data="tools_menu")],
        [InlineKeyboardButton(f"{EMOJI['KEY']} Canjear Key", callback_data="canjear_menu"), InlineKeyboardButton(f"{EMOJI['PROFILE']} Mi Perfil", callback_data="perfil")],
    ]
    if plan == "OWNER":
        buttons.append([InlineKeyboardButton(f"{EMOJI['ADMIN']} Panel de Admin", callback_data="panel_admin")])
    buttons.append([InlineKeyboardButton(f"{EMOJI['HELP']} Ayuda", callback_data="ayuda"), InlineKeyboardButton(f"{EMOJI['EXIT']} Salir", callback_data="salir")])
    return InlineKeyboardMarkup(buttons)

def menu_tools(plan: str, page: int = 0, category: str = f"{EMOJI['BASIC']} HERRAMIENTAS BÁSICAS") -> InlineKeyboardMarkup:
    """Lista paginada de herramientas según categoría y plan."""
    tools = TOOL_CATEGORIES.get(category, [])
    total_pages = max(1, (len(tools) + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    page_tools = tools[page * ITEMS_PER_PAGE:(page + 1) * ITEMS_PER_PAGE]
    
    rows = [
        [InlineKeyboardButton(
            f"{EMOJI['LOCK']} {label}" if category.startswith(EMOJI['PREMIUM']) and plan not in ["PREMIUM", "OWNER"] else label,
            callback_data="premium_lock" if category.startswith(EMOJI['PREMIUM']) and plan not in ["PREMIUM", "OWNER"] else f"run_{tool}"
        )]
        for tool, label, _, _ in page_tools
    ]
    
    nav_buttons = []
    if page > 0:
        nav_buttons.append(InlineKeyboardButton(EMOJI['PREV'], callback_data=f"page_{category}_{page-1}"))
    if (page + 1) * ITEMS_PER_PAGE < len(tools):
        nav_buttons.append(InlineKeyboardButton(EMOJI['NEXT'], callback_data=f"page_{category}_{page+1}"))
    if nav_buttons:
        rows.append(nav_buttons)
    
    categories = list(TOOL_CATEGORIES.keys())
    current_idx = categories.index(category)
    other_cat = categories[1-current_idx]
    rows.append([InlineKeyboardButton(f"Ir a {other_cat}", callback_data=f"cat_{other_cat}_0")])
    rows.append([InlineKeyboardButton(f"{EMOJI['BACK']} Menú Principal", callback_data="volver_main")])
    return InlineKeyboardMarkup(rows)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[int]:
    """Gestiona todos los botones de navegación y acciones (menos 'regen_', que tiene handler propio)."""
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
        try:
            db = read_db()
            text = f"{EMOJI['ADMIN']} *Panel de Administración*\n\n{EMOJI['STATS']} *Usuarios:* {len(db.get('users', {}))}\n{EMOJI['KEY']} *Keys disponibles:* {len(db.get('keys', {}))}"
            markup = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"{EMOJI['KEY']} Generar Key", callback_data="admin_genkey"), InlineKeyboardButton(f"{EMOJI['EXPORT']} Exportar", callback_data="admin_excel")],
                [InlineKeyboardButton(f"{EMOJI['CLEAN']} Limpiar Logs", callback_data="admin_clean"), InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]
            ])
        except Exception as e:
            logger.error(f"Error en panel_admin: {e}")
            text = f"{EMOJI['ERROR']} Error al cargar el panel de administración\\."
            markup = InlineKeyboardMarkup([[InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]])
    elif data == "admin_genkey" and plan == "OWNER":
        try:
            key = gen_key()
            db = read_db()
            db["keys"][key] = "PREMIUM"
            write_db(db)
            await query.answer(f"Key generada: {key}", show_alert=True)
        except Exception as e:
            logger.error(f"Error generando key: {e}")
            await query.answer("Error al generar la key", show_alert=True)
        return
    elif data == "admin_excel" and plan == "OWNER":
        try:
            result = export_excel()
            await query.answer(result, show_alert=True)
        except Exception as e:
            logger.error(f"Error exportando Excel: {e}")
            await query.answer("Error al exportar", show_alert=True)
        return
    elif data == "admin_clean" and plan == "OWNER":
        try:
            db = read_db()
            db["audit"] = db.get("audit", [])[-100:]
            write_db(db)
            await query.answer("Logs de auditoría limpiados.", show_alert=True)
        except Exception as e:
            logger.error(f"Error limpiando logs: {e}")
            await query.answer("Error al limpiar logs", show_alert=True)
        return
    elif data == "canjear_menu":
        text, next_state = f"{EMOJI['KEY']} *Canjear Key Premium*\n\nPor favor, envía tu key para activar el plan PREMIUM\\.", WAITING_KEY
    elif data == "perfil":
        created = escape_md(user.get("created_at", "N/A")[:16])
        text, markup = f"{EMOJI['PROFILE']} *Tu Perfil*\n\n*Usuario:* @{escape_md(user['username'])}\n*Plan:* `{escape_md(plan)}`\n*Miembro desde:* `{created}`", InlineKeyboardMarkup([[InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]])
    elif data == "ayuda":
        text, markup = f"{EMOJI['HELP']} *Ayuda y Soporte*\n\nEste bot ofrece herramientas de hacking \\. Para obtener una *key premium* o si necesitas ayuda, contacta al owner: @{escape_md(OWNER_USERNAME)}", InlineKeyboardMarkup([[InlineKeyboardButton(f"{EMOJI['BACK']} Volver", callback_data="volver_main")]])
    elif data.startswith("run_"):
        tool = data.split("_", 1)[1]
        tool_info = next((t for cat in TOOL_CATEGORIES.values() for t in cat if t[0] == tool), None)
        if tool_info:
            # Guardamos estado de la herramienta seleccionada
            context.user_data.update({"current_tool": tool, "input_type": tool_info[3]})

            # Texto amigable optimizado (más corto y rápido)
            input_type = tool_info[3]
            cost = CREDITS_COST.get(tool, 1)
            
            # Construir mensaje más eficiente
            text_parts = [
                f"*{escape_md(tool_info[1])}*",
                f"_{escape_md(tool_info[2])}_",
                f"📝 Formato: `{escape_md(input_type)}`"
            ]
            
            if plan != "OWNER":
                text_parts.append(f"💰 Costo: {cost} crédito(s) - Saldo: {user.get('credits', 0)}")
            
            text_parts.extend([
                "⚠️ Uso ético y educativo",
                "✍️ Envía el parámetro o /cancel"
            ])
            
            text = "\n".join(text_parts)
            next_state = WAITING_TOOL_ARG
    elif data == "premium_lock":
        await query.answer(f"🔒 Esta es una herramienta PREMIUM. Necesitas una key.", show_alert=True)
        return
    elif data == "salir":
        await query.edit_message_text(f"👋 ¡Hasta luego, {escape_md(user['username'])}\\!", parse_mode=ParseMode.MARKDOWN_V2)
        return
    
    if text:
        try:
            await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=markup, disable_web_page_preview=True)
        except TelegramError:
            # Fallback: sin parseo para evitar errores por caracteres especiales
            await query.edit_message_text(text, reply_markup=markup, disable_web_page_preview=True)
    return next_state

async def text_input_handler(update: Update, context: ContextTypes.DEFAULT_TYPE, state: int) -> Optional[int]:
    """Maneja las entradas de texto para canje de keys y ejecución de herramientas."""
    user_input = update.message.text.strip()
    user = get_or_create_user(update.effective_user.id, update.effective_user.username)
    
    if state == WAITING_KEY:
        result_text = canjear_key(update.effective_user.id, user_input)
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
        
        try:
            result = await run_tool(tool, validated_input, update.effective_user.id)
            trimmed = result.strip()
            success = not (trimmed.startswith(EMOJI['ERROR']) or trimmed.startswith("Error") or trimmed.startswith("Timeout"))

            db = read_db()
            if "audit" not in db:
                db["audit"] = []
            db["audit"].append({
                "user_id": str(update.effective_user.id),
                "tool": tool,
                "input": validated_input,
                "timestamp": datetime.now().isoformat(),
                "action": "tool_used",
                "success": bool(success)
            })

            remaining = None
            if user["plan"] != "OWNER" and success:
                user_id_str = str(update.effective_user.id)
                if user_id_str not in db["users"]:
                    # Crear usuario si no existe
                    db["users"][user_id_str] = {
                        "username": user.get("username", f"user_{update.effective_user.id}"),
                        "plan": user.get("plan", "FREE"),
                        "credits": 0,
                        "created_at": datetime.now().isoformat()
                    }
                db["users"][user_id_str]["credits"] = db["users"][user_id_str].get("credits", 0) - cost
                remaining = db["users"][user_id_str]["credits"]
            write_db(db)
        except Exception as e:
            logger.error(f"Error ejecutando herramienta '{tool}': {e}")
            result = f"{EMOJI['ERROR']} Error inesperado al ejecutar la herramienta: {str(e)}"
            success = False
            remaining = user.get("credits", 0)

        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton(f"{EMOJI['TOOL']} Más Herramientas", callback_data="tools_menu"),
            InlineKeyboardButton(f"{EMOJI['BACK']} Menú", callback_data="volver_main")
        ]])

        suffix = ""
        if user["plan"] != "OWNER":
            if success:
                suffix = f"\n\\(\\-{cost} créditos\\) \\— Saldo: `{remaining}`"
            else:
                suffix = f"\n\\(sin cargos\\)"

        # Construir mensaje completo optimizado
        full_message = f"{EMOJI['SUCCESS']} *Resultado para* `{escape_md(validated_input)}`{suffix}\n\n{result}"
        
        # Verificar longitud del mensaje antes de enviar
        if len(full_message) > 4000:
            # Mensaje muy largo, usar función de división automática
            try:
                await msg.delete()
                await send_long_message(
                    chat_id=update.effective_chat.id,
                    text=full_message,
                    bot=context.bot,
                    parse_mode=ParseMode.MARKDOWN_V2,
                    reply_markup=markup,
                    disable_web_page_preview=True
                )
            except Exception as e:
                logger.error(f"Error enviando mensaje largo: {e}")
                # Fallback: enviar mensaje truncado
                truncated = truncate_message(full_message, 4000)
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=truncated,
                    reply_markup=markup,
                    disable_web_page_preview=True
                )
        else:
            # Mensaje normal, editar el existente
            try:
                await msg.edit_text(
                    full_message,
                    parse_mode=ParseMode.MARKDOWN_V2,
                    reply_markup=markup,
                    disable_web_page_preview=True
                )
            except TelegramError as e:
                if "Message_too_long" in str(e):
                    # Error inesperado de longitud, usar división
                    await msg.delete()
                    await send_long_message(
                        chat_id=update.effective_chat.id,
                        text=full_message,
                        bot=context.bot,
                        parse_mode=ParseMode.MARKDOWN_V2,
                        reply_markup=markup,
                        disable_web_page_preview=True
                    )
                else:
                    # Otro error, fallback sin parseo
                    try:
                        await msg.edit_text(
                            f"Resultado para: {validated_input}{suffix}\n\n{result}",
                            reply_markup=markup,
                            disable_web_page_preview=True
                        )
                    except Exception:
                        # Último recurso: enviar nuevo mensaje
                        await msg.delete()
                        await context.bot.send_message(
                            chat_id=update.effective_chat.id,
                            text=f"Resultado para: {validated_input}{suffix}\n\n{result}",
                            reply_markup=markup,
                            disable_web_page_preview=True
                        )
        
        if new_achievements := await check_achievements(str(update.effective_user.id)):
            await update.message.reply_text(
                f"🎉 *¡Nuevos logros!*\n\n" + "\n".join(new_achievements),
                parse_mode=ParseMode.MARKDOWN_V2
            )
    
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/cancel: limpia estado de usuario y regresa al menú principal."""
    context.user_data.clear()
    try:
        await update.message.reply_text(
            f"{EMOJI['INFO']} Operación cancelada\\.",
            parse_mode=ParseMode.MARKDOWN_V2
        )
    except Exception:
        pass
    await start(update, context)
    return ConversationHandler.END

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Manejador global de errores: notifica al usuario y reporta al OWNER con detalles."""
    logger.error("Exception while handling an update:", exc_info=context.error)
    # Mensaje genérico al usuario
    if update and isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                f"{EMOJI['ERROR']} Ocurrió un error inesperado. Intenta con /start.")
        except Exception as e:
            logger.error(f"Error enviando mensaje de error al usuario: {e}")
    # Reporte detallado al OWNER
    try:
        tb = traceback.format_exc()
        details = (
            f"⚠️ Exception report\n"
            f"Error: {type(context.error).__name__}: {context.error}\n\n"
            f"Traceback:\n{tb[:1500]}"
        )
        await context.bot.send_message(chat_id=OWNER_ID, text=details)
    except Exception as e:
        logger.error(f"No se pudo notificar al OWNER: {e}")

def luhn_checksum(card_number: str) -> bool:
    """Valida un número por Luhn (tarjetas)."""
    digits = [int(d) for d in card_number if d.isdigit()]
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

def luhn_check_digit(number_without_check: str) -> int:
    """Calcula el dígito de control Luhn para un número sin el último dígito."""
    digits = [int(d) for d in number_without_check if d.isdigit()]
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10

def generate_from_mask(mask: str) -> str:
    """Genera un PAN válido (12..19) respetando máscara [0-9x]:
    - Último 'x': se calcula check digit exacto.
    - Último fijo: se prueban combinaciones hasta dar válido.
    """
    mask = mask.strip()
    if not re.fullmatch(r"[0-9x]{12,19}", mask):
        raise ValueError("La máscara debe tener entre 12 y 19 caracteres, solo dígitos y 'x'.")

    rng = random.Random()

    if mask[-1] == 'x':
        filled = list(mask)
        for i in range(len(filled) - 1):
            if filled[i] == 'x':
                filled[i] = str(rng.randint(0, 9))
        check = luhn_check_digit(''.join(filled[:-1]))
        filled[-1] = str(check)
        return ''.join(filled)

    for _ in range(2000):
        cand = [c if c != 'x' else str(rng.randint(0, 9)) for c in mask]
        pan = ''.join(cand)
        if luhn_checksum(pan):
            return pan
    raise ValueError("No fue posible generar un número válido con la máscara dada.")

def generate_luhn(bin_part: str) -> str:
    """Compatibilidad: genera usando máscara con 'x' (ej: 416916xxxxxx)."""
    return generate_from_mask(bin_part)

def default_pan_length_for_iin(iin: str) -> int:
    """Heurística de longitud por IIN:
    Visa: 16 (13/19 posibles) | MC: 16 | Amex: 15 | Diners: 14 | Discover/JCB: 16 | Otros: 16
    """
    try:
        if not iin or not iin[0].isdigit():
            return 16
        first = int(iin[0])
        first2 = int(iin[:2]) if len(iin) >= 2 else -1
        first3 = int(iin[:3]) if len(iin) >= 3 else -1
        first4 = int(iin[:4]) if len(iin) >= 4 else -1

        if first2 in (34, 37):  # Amex
            return 15
        if 300 <= first3 <= 305 or first2 in (36,) or 38 <= first2 <= 39:  # Diners
            return 14
        if 51 <= first2 <= 55 or (2221 <= first4 <= 2720):  # MasterCard
            return 16
        if first4 == 6011 or first2 == 65 or (644 <= first3 <= 649):  # Discover
            return 16
        if 3528 <= first4 <= 3589:  # JCB
            return 16
        if first == 4:  # Visa
            return 16
        return 16
    except Exception:
        return 16

async def get_bin_info(bin_code: str) -> dict:
    """Obtiene información del BIN desde fuente local y, como respaldo, desde binlist.net.
    Prioriza CSV local para evitar N/A y depender menos de red.
    Campos devueltos: country, flag, bank, scheme, type, brand
    """
    try:
        # 1) Intentar base local
        local = get_local_bin_info(bin_code)
        result = {}
        if local:
            # Mapea campos; si no hay país, dejamos para API
            if local.get("country"):
                result["country"] = local.get("country", "")
            if local.get("bank"):
                result["bank"] = local.get("bank", "")
            if local.get("scheme"):
                result["scheme"] = local.get("scheme", "")
            if local.get("type"):
                result["type"] = local.get("type", "")
            if local.get("brand"):
                result["brand"] = local.get("brand", "")
            # No solemos tener bandera en CSV; usamos alpha2 si existe para marcar flag simple
            alpha2 = (local.get("alpha2") or "").upper()
            if alpha2:
                result["flag"] = f"[{alpha2}]"

        # 2) Si faltan datos críticos, completar desde API
        need_api = not result or not result.get("country") or not result.get("bank")
        if need_api:
            try:
                resp = await asyncio.to_thread(requests.get, f"https://lookup.binlist.net/{bin_code}", timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                result.setdefault("country", data.get("country", {}).get("name", ""))
                result.setdefault("flag", data.get("country", {}).get("emoji", ""))
                result.setdefault("bank", data.get("bank", {}).get("name", ""))
                result.setdefault("scheme", data.get("scheme", ""))
                result.setdefault("type", data.get("type", ""))
                result.setdefault("brand", data.get("brand", ""))
            except Exception as e:
                logger.error(f"Error al obtener datos del BIN desde API: {e}")
                return {}

        # Completar bandera a partir de alpha2 si no hay
        if not result.get("flag"):
            alpha2 = local.get("alpha2") if 'local' in locals() else ""
            flag = alpha2_to_flag(alpha2)
            if flag:
                result["flag"] = flag
        # 3) Normaliza N/A -> vacío para no mostrar "N/A"
        for k in ["country", "flag", "bank", "scheme", "type", "brand"]:
            if result.get(k, "").strip().upper() == "N/A":
                result[k] = ""
        return result
    except Exception:
        return {}

def _validate_month_year(mes: str, anio: str) -> Tuple[bool, str, str]:
    """Valida mes y año:
    - mes: '01'..'12'
    - año: 'YY' (20YY) o 'YYYY'
    Devuelve (ok, mes_fmt, anio_fmt).
    """
    if not re.fullmatch(r"\d{2}", mes):
        return False, mes, anio
    m = int(mes)
    if m < 1 or m > 12:
        return False, mes, anio
    if re.fullmatch(r"\d{2}", anio):
        return True, f"{m:02d}", f"20{anio}"
    if re.fullmatch(r"\d{4}", anio):
        return True, f"{m:02d}", anio
    return False, mes, anio

async def gen_card_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/gen <bin>/<MM/YY>: genera 10 tarjetas válidas por Luhn.
    - Cada tarjeta en su propia línea como <code>...</code> para copiar una a una.
    """
    try:
        if not context.args or len(context.args) < 1:
            await update.message.reply_text("Uso: /gen <bin>/<MM/YY>\nEjemplo: /gen 512107981134xxxx/06/30")
            return
        arg = context.args[0]
        match = re.match(r"^(\d{6,})(x*)[/](\d{2})/(\d{2,4})$", arg)
        if not match:
            await update.message.reply_text("Formato inválido. Ejemplo: /gen 512107981134xxxx/06/30")
            return

        bin_part = match.group(1) + match.group(2)
        if len(bin_part) < 12:
            bin_part = bin_part + ('x' * (12 - len(bin_part)))
        if 'x' in bin_part:
            target_len = default_pan_length_for_iin(bin_part)
            target_len = max(12, min(19, target_len))
            if len(bin_part) < target_len:
                bin_part = bin_part + ('x' * (target_len - len(bin_part)))
        if len(bin_part) > 19:
            bin_part = bin_part[:19]

        mes = match.group(3)
        anio = match.group(4)
        ok_date, mes_fmt, anio_fmt = _validate_month_year(mes, anio)
        if not ok_date:
            await update.message.reply_text("Fecha inválida. Formato esperado: MM/YY (o MM/YYYY) con mes 01..12.")
            return

        bin_code = match.group(1)
        cards = []
        for _ in range(10):
            cc = generate_luhn(bin_part)
            cvv = str(random.randint(100, 999))
            cards.append(f"<code>{escape_html(cc)}|{escape_html(mes_fmt)}|{escape_html(anio_fmt)}|{escape_html(cvv)}</code>")
        card_text = "\n".join(cards)

        bin_info = await get_bin_info(bin_code)
        bin_info_text = (
            f"• País » {bin_info.get('country', 'N/A')} [{bin_info.get('flag', '')}]\n"
            f"• Banco » {bin_info.get('bank', 'N/A')}\n"
            f"• Data » {bin_info.get('scheme', 'N/A').upper()} - {bin_info.get('brand', 'N/A').upper()} - {bin_info.get('type', 'N/A').upper()}"
        )
        msg = (
            "[ネ] Generador ccs\n"
            "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
            f"• Format » {escape_html(bin_part)}/{escape_html(mes_fmt)}/{escape_html(anio_fmt)}\n"
            "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
            f"{card_text}\n"
            "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
            f"{escape_html(bin_info_text)}\n"
            "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
            f"• By » @{escape_html(OWNER_USERNAME)} ↝ [premium]"
        )
        markup = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔄 Regenerar", callback_data=f"regen_{bin_part}_{mes_fmt}_{anio_fmt[-2:]}")
        ]])
        await update.message.reply_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=markup
        )
    except Exception as e:
        await update.message.reply_text(f"Error: {escape_md(str(e))}", parse_mode=ParseMode.MARKDOWN_V2)

async def regen_card_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Callback de regeneración:
    - callback_data: regen_<mask>_<MM>_<YY|YYYY>
    """
    query = update.callback_query
    await query.answer()
    data = query.data
    match = re.match(r"regen_(\d{6,}x*)_([0-9]{2})_([0-9]{2,4})", data)
    if not match:
        await query.edit_message_text("Error en los parámetros.")
        return
    bin_part = match.group(1)
    if len(bin_part) < 12:
        bin_part = bin_part + ('x' * (12 - len(bin_part)))
    if 'x' in bin_part:
        target_len = default_pan_length_for_iin(bin_part)
        target_len = max(12, min(19, target_len))
        if len(bin_part) < target_len:
            bin_part = bin_part + ('x' * (target_len - len(bin_part)))
    if len(bin_part) > 19:
        bin_part = bin_part[:19]
    mes = match.group(2)
    anio = match.group(3)
    ok_date, mes_fmt, anio_fmt = _validate_month_year(mes, anio)
    if not ok_date:
        await query.edit_message_text("Fecha inválida en regeneración.")
        return

    bin_code = bin_part[:6]
    cards = []
    for _ in range(10):
        cc = generate_luhn(bin_part)
        cvv = str(random.randint(100, 999))
        cards.append(f"<code>{escape_html(cc)}|{escape_html(mes_fmt)}|{escape_html(anio_fmt)}|{escape_html(cvv)}</code>")
    card_text = "\n".join(cards)
    bin_info = await get_bin_info(bin_code)
    bin_info_text = (
        f"• País » {bin_info.get('country', 'N/A')} [{bin_info.get('flag', '')}]\n"
        f"• Banco » {bin_info.get('bank', 'N/A')}\n"
        f"• Data » {bin_info.get('scheme', 'N/A').upper()} - {bin_info.get('brand', 'N/A').upper()} - {bin_info.get('type', 'N/A').upper()}"
    )
    msg = (
        "[ア] Generador ccs\n"
        "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
        f"• Format » {escape_html(bin_part)}/{escape_html(mes_fmt)}/{escape_html(anio_fmt)}\n"
        "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
        f"{card_text}\n"
        "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
        f"{escape_html(bin_info_text)}\n"
        "━ ━ ━ ━ ━ ━ ━ ━ ━\n"
        f"• By » @{escape_html(OWNER_USERNAME)} ↝ [premium]"
    )
    markup = InlineKeyboardMarkup([[
        InlineKeyboardButton("🔄 Regenerar", callback_data=f"regen_{bin_part}_{mes_fmt}_{anio_fmt[-2:]}")
    ]])
    await query.edit_message_text(
        msg,
        parse_mode=ParseMode.HTML,
        reply_markup=markup
    )

def main() -> None:
    """Punto de entrada: construye la app, registra handlers y jobs, arranca polling."""
    global logger
    logger = setup_logging()
    if not TOKEN:
        logger.critical("El TELEGRAM_TOKEN no está configurado (ni env ni fallback).")
        return
     
    application = (
        Application.builder()
        .token(TOKEN)
        .connect_timeout(30)
        .read_timeout(30)
        .build()
    )
    
    # Conversación para entrada de texto de herramientas y canje de key
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^run_|^canjear_menu$")],
        states={
            WAITING_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: text_input_handler(u, c, WAITING_KEY))],
            WAITING_TOOL_ARG: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: text_input_handler(u, c, WAITING_TOOL_ARG))]
        },
        fallbacks=[CommandHandler("cancel", cancel), CommandHandler("start", start)],
        per_message=False
    )
    
    # Orden de handlers: el específico de 'regen_' debe ir antes del genérico
    application.add_handler(CommandHandler("start", start))
    application.add_handler(conv_handler)
    application.add_handler(CallbackQueryHandler(regen_card_callback, pattern=r"^regen_"))
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
    application.add_handler(CommandHandler("gen", gen_card_command))

    # Tareas programadas (job_queue)
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
    print("Iniciando bot...")
    main()
