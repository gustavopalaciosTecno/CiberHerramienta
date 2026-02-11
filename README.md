# 🛡️ CiberHerramienta Todo-en-Uno💪

Una aplicación interactiva desarrollada con Streamlit para realizar tareas esenciales de ciberseguridad desde una interfaz web intuitiva.
Esta aplicación es de uso público y no me hago cargo si la herramienta tenga un mal uso.

🚀 Funcionalidades

🌐 Escáner de Puertos y Riesgos**: Analiza direcciones IP para detectar puertos abiertos y advierte sobre vulnerabilidades críticas (como puertos FTP, Telnet o SMB abiertos).
🔍 Análisis de Malware (Hashing)**: Permite subir archivos (.exe, .pdf, etc.) para calcular su firma SHA256 y compararla automáticamente con una lista negra de amenazas conocidas.
🛡️ Generador de Contraseñas Seguras**: Crea claves robustas de forma aleatoria con control total sobre la longitud y el tipo de caracteres, garantizando que tus credenciales nunca salgan del navegador.
✅ Verificación de Integridad**: Herramienta manual para comparar el hash de un archivo descargado con su hash oficial.

🛠️ Tecnologías utilizadas

Python**: Lenguaje principal.
Streamlit**: Framework para la interfaz web.
Socket & Hashlib**: Para el análisis de red y criptografía.
Git & GitHub**: Para el control de versiones y despliegue.

📦 Instalación y Uso Local

1. Clona este repositorio.
2. Crea un entorno virtual e instala las dependencias:
   ```bash
   pip install -r requirements.txt
