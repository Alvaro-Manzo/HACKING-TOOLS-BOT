Bot de Herramientas Hackers para Telegram
Bot de Telegram multifunción orientado a hacking ético, automatización y utilidades técnicas, desarrollado en Python con python-telegram-bot y distribución modular. Permite a usuarios (y administradores) acceder fácilmente a herramientas básicas y premium, gestionar créditos/tareas, generar tarjetas válidas por Luhn y administrar comunidades o grupos.

Características Principales
Menú interactivo (InlineKeyboard) y navegación paginada de herramientas.

Sistema de créditos y keys VIP para herramientas premium.

Generador de tarjetas Luhn (con BIN/máscara y fechas).

Panel administrativo: creación de keys, stats, backups automáticos, limpieza de logs y exportación.

Sistema de logros, niveles y auditoría de usos.

Automantenimiento y backups configurables.

Respuestas seguras (MarkdownV2 y HTML correctamente escapado).

Gestión robusta de errores y notificación directa al owner.

Soporte grupal, registro y ajustes para grupos.

Multiidioma listo para español y fácil de internacionalizar.

Diseñado para despliegue rápido en entornos multiusuario.

Instalación
1. Prerrequisitos
Python 3.10+ recomendado.

Crea un bot con @BotFather y consigue el token.

Instala requirements:

bash
pip install python-telegram-bot matplotlib filelock requests
2. Clona y configura
bash
git clone https://github.com/tuusuario/telegram-hacker-tools-bot.git
cd telegram-hacker-tools-bot
Copia .env.example a .env y pon tus datos principales:

text
TELEGRAM_TOKEN=xxxxxxxxx:AA...
OWNER_ID=123456789
OWNER_USERNAME=mitusuario
3. Ejecuta el bot
bash
python main.py
# O si usas procesos:
python3 main.py
El bot iniciará y mostrará el menú principal.

Uso rápido
Comando /start: Muestra el menú y tus créditos.

Comando /gen BINxxxx/06/28: Genera tarjetas válidas para el BIN dado y fecha.

Comando /help: Lista de comandos clave y explicación de herramientas.

Panel de admin: Solo para OWNER (definido en ENV).

Comandos destacados
Comando	Descripción
/start	Inicia e interactúa con el menú principal
/help	Muestra ayuda completa
/gen	Genera tarjetas válidas por BIN/máscara, ejemplo: /gen 457456xxxxxxx/07/26
/profile	Tu perfil y estadísticas
/redeem	Canjea una key premium
/top	Ranking de usuarios
/debug	(OWNER) Resumen de usuarios, usages y top herramientas
/broadcast	(OWNER) Mensaje masivo
/report	(OWNER) Genera gráfico de uso diario
/addgroup	Registra el grupo en la base de datos
Estructura del código
main.py: Contiene toda la lógica de comandos, handlers, utilidades, generación Luhn, menús y backup.

Base de datos: Usando archivo db.json, seguro por filelock. Soporta backup y limpieza automática.

Extensiones: Puedes agregar nuevas herramientas o categorías editando la constante TOOL_CATEGORIES.

Consideraciones de seguridad
Uso únicamente ético y educativo. Cada herramienta incluye nota de advertencia.

El OWNER recibe reporte de errores y accesos críticos en tiempo real.

Las operaciones críticas de la base usan filelock para evitar corrupción en modo multiusuario.

Protege tu token y la base; no compartas ni subas estos datos a repositorios públicos.

Personalización y extensión
Para agregar herramientas nuevas, edita la constante TOOL_CATEGORIES y añade el handler correspondiente.

Puedes migrar la base de datos de JSON a SQLite para despliegues mayores.

El sistema está preparado para nuevas traducciones y soporte multiidioma.

Créditos
Bot desarrollado por Alvaro Manzo.
Framework: python-telegram-bot.
Inspirado en proyectos de ethical hacking y automatización.

Licencia
Uso educativo, ético y con fines de ciberseguridad controlada.
Consulta el archivo LICENSE para términos completos.

¿Dudas, propuestas, bugs? Escribe al owner vía Telegram o abre un issue en el repositorio.
