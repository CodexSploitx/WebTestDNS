# 🌐 Web & DNS Verifier

**Web & DNS Verifier** es una herramienta de línea de comandos (CLI) escrita en Python que permite realizar un análisis rápido y visual del estado de un sitio web. Verifica la disponibilidad HTTP, la validez del certificado SSL y los registros DNS principales, presentando los resultados en una interfaz de terminal moderna y fácil de leer gracias a la librería `rich`.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## ✨ Características

La herramienta realiza tres tipos de verificaciones principales:

1.  **📡 Estado HTTP/HTTPS**:

    - Código de estado (200, 301, 404, 500, etc.).
    - Latencia de la respuesta (tiempo de carga).
    - Número de redirecciones.
    - URL final (útil para detectar redirecciones).
    - Información del servidor (header `Server`).

2.  **🔒 Certificado SSL/TLS**:

    - Validez del certificado.
    - Fecha de expiración.
    - Días restantes para la caducidad (con indicadores de color: verde > 30 días, amarillo < 30 días, rojo < 7 días).
    - Emisor del certificado (Autoridad de Certificación).

3.  **🗂️ Registros DNS**:
    - Recupera y muestra registros: **A**, **AAAA**, **MX**, **NS**, **TXT**.
    - Muestra múltiples valores si existen.

## 📋 Requisitos

- Python 3.10 o superior.
- Conexión a Internet.

## 🚀 Instalación

1.  **Clonar el repositorio** (o descargar los archivos):

    ```bash
    git clone <tu-repositorio>
    cd webTestDNS
    ```

2.  **Crear un entorno virtual (Recomendado)**:

    ```bash
    # En Windows
    python -m venv .venv
    .venv\Scripts\activate

    # En macOS/Linux
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Instalar las dependencias**:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Uso

Puedes usar la herramienta de dos formas:

### 1. Modo Interactivo

Simplemente ejecuta el script sin argumentos. Te pedirá que ingreses la URL.

```bash
python main.py
```

_Luego ingresa la URL cuando se te solicite, por ejemplo: `google.com`_

### 2. Argumento de Línea de Comandos

Pasa la URL directamente como argumento para un análisis más rápido.

```bash
python main.py google.com
```

o

```bash
python main.py https://www.ejemplo.com
```

## 📂 Estructura del Proyecto

```text
webTestDNS/
├── main.py           # Código fuente principal
├── requirements.txt  # Lista de dependencias
└── README.md         # Documentación
```

## 🛠️ Tecnologías Utilizadas

- **[Rich](https://github.com/Textualize/rich)**: Para la interfaz de terminal hermosa y tablas formateadas.
- **[Requests](https://requests.readthedocs.io/)**: Para realizar las peticiones HTTP.
- **[dnspython](https://www.dnspython.org/)**: Para las consultas de registros DNS.

## 📝 Notas

- Si un dominio no tiene ciertos registros DNS (por ejemplo, no tiene IPv6/AAAA), la herramienta mostrará "No records found" en gris.
- Los errores de conexión o tiempos de espera se manejarán y mostrarán en rojo en la tabla correspondiente.

---

Creado con ❤️ por CodexSploitx
