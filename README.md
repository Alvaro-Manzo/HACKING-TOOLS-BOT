# 🛡️ Bot de Hacking Ético para Telegram

Bot avanzado de Telegram para hacking ético y análisis de seguridad, desarrollado por Alvaro Manzo.

## ⚠️ Aviso Legal

Esta herramienta está diseñada exclusivamente para propósitos educativos y pruebas de seguridad autorizadas. Cualquier uso malicioso está prohibido y el usuario asume toda la responsabilidad de sus acciones.

## 🚀 Características

- **Herramientas de Reconocimiento**
  - Escaneo de Puertos
  - Enumeración DNS
  - Búsqueda de Subdominios
  - Análisis SSL/TLS
  - Consulta WHOIS
  - Escaneo de Directorios
  - Detección de Tecnologías
  - IP Reversa

- **Análisis de Seguridad**
  - Búsqueda de CVEs
  - Google Dorking Automático
  - Escaneo de Vulnerabilidades
  - Detección de Tecnologías Web
  - Análisis de Headers HTTP

- **Características Avanzadas**
  - Sistema de Créditos
  - Planes Premium
  - Tareas Diarias
  - Sistema de Logros
  - Ranking de Usuarios
  - Panel de Administrador

## 💻 Instalación

```bash
# Clonar repositorio
git clone https://github.com/alvaromanzo/hacking-tools-bot

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus tokens
```

## 🔧 Configuración

1. Obtener token de bot en [@BotFather](https://t.me/BotFather)
2. Configurar tu ID de Telegram como OWNER_ID
3. Configurar API keys adicionales si se necesitan

## 🛠️ Uso

```bash
python main.py
```

### Comandos Disponibles
- `/start` - Inicia el bot
- `/key <cantidad>` - (Admin) Genera keys de créditos
- `/redeem` - Canjea créditos
- `/daily` - Muestra tareas diarias
- `/top` - Ver ranking
- `/debug` - (Admin) Muestra estadísticas detalladas

## 📚 Requisitos

- Python 3.7+
- nmap
- Paquetes Python en requirements.txt

## 👤 Autor

**Alvaro Manzo**
- GitHub: [@alvaromanzo](https://github.com/Alvaro-Manzo)
- Telegram: [@alvarito_y](https://t.me/alvarito_y)

## 📝 Licencia

Licencia MIT - ver archivo [LICENSE](LICENSE)
