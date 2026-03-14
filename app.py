import streamlit as st
import socket
import hashlib
import random
import string
import requests

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="CiberHerramienta Educativa - Néstor Gustavo Palacios Meyer",
    page_icon="🛡️",
    layout="wide"
)

# --- CSS PERSONALIZADO ---
st.markdown("""
    <style>
    /* Ajuste de ancho para móviles */
    @media (max-width: 640px) {
        [data-testid="stSidebar"] {
            width: 100vw !important;
        }
    }

    /* Texto al lado de las flechas de cierre */
    [data-testid="stSidebarNavSeparator"] + div button::before {
        content: "Deslizar acá ⬅️ ";
        font-size: 14px;
        color: #808495;
        margin-right: 10px;
        vertical-align: middle;
    }

    /* Asegurar que el logo esté centrado */
    [data-testid="stSidebar"] [data-testid="stImage"] {
        text-align: center;
        display: block;
        margin-left: auto;
        margin-right: auto;
        padding-top: 20px;
    }

    /* Estilo para los botones */
    .stButton>button {
        width: 100%;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Panel de Ciberseguridad Educativo")
st.markdown("---")

# --- BARRA LATERAL ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
st.sidebar.markdown("<h3 style='text-align: center;'>Menú de Herramientas</h3>", unsafe_allow_html=True)
menu = ["Inicio", "Escáner de Puertos", "Auditoría de Cabeceras", "Hash de Archivo", "Gestor Seguro"]
choice = st.sidebar.selectbox("Selecciona una opción:", menu)

st.sidebar.markdown("---")
st.sidebar.info("🚀 **Desarrollado por:**\nGustavo Palacios Meyer")

# --- SECCIÓN: INICIO ---
if choice == "Inicio":
    st.subheader("🤫 Bienvenido al panel")
    col1, col2 = st.columns([2, 1])
    with col1:
        st.write("""
        Esta aplicación es una plataforma educativa diseñada para simular y comprender el funcionamiento 
        de herramientas básicas de ciberseguridad. 

        **Desarrollado por:** Gustavo Palacios Meyer.

        ### ¿Qué puedes hacer aquí?
        * **Analizar Puertos:** Entender qué servicios están expuestos en un servidor.
        * **Auditar Web:** Verificar si un sitio web utiliza cabeceras de protección modernas.
        * **Verificar Integridad:** Analizar archivos mediante algoritmos de hashing.
        * **Seguridad de Acceso:** Generar contraseñas robustas con alta entropía.
        """)
    with col2:
        st.info(
            "**Nota Educativa:** El uso de estas herramientas contra sistemas sin autorización es ilegal. Úsalas solo en entornos controlados o con permiso.")

# --- SECCIÓN: ESCÁNER DE PUERTOS ---
elif choice == "Escáner de Puertos":
    st.subheader("🌐 Escáner de Puertos y Riesgos")
    st.write("Esta herramienta intenta conectar con puertos específicos para ver si responden.")

    target = st.text_input("Ingresa IP o Dominio (ej: google.com o 127.0.0.1)", "127.0.0.1")

    vulnerable_ports = {
        21: "FTP (Protocolo de Transferencia de Archivos) - Muy propenso a interceptación si no es FTPS.",
        22: "SSH (Secure Shell) - Es seguro, pero suele recibir ataques de fuerza bruta constantes.",
        23: "Telnet - ¡Peligro! Envía contraseñas y datos en texto plano.",
        80: "HTTP - Tráfico web sin cifrar. Se recomienda usar el 443 (HTTPS).",
        443: "HTTPS - Puerto seguro para navegación web cifrada.",
        445: "SMB - Utilizado para compartir archivos en red; vulnerable a exploits como WannaCry.",
        8080: "HTTP Alternativo - Usado comúnmente en servidores de desarrollo o proxies."
    }

    if st.button("Iniciar Escaneo"):
        try:
            # Resolución de DNS (Funciona para dominios e IPs)
            target_ip = socket.gethostbyname(target)
            st.info(f"Resolviendo objetivo: **{target}** ➔ IP: **{target_ip}**")

            ports_to_scan = [21, 22, 23, 80, 443, 445, 8080]
            progress_bar = st.progress(0)

            for i, port in enumerate(ports_to_scan):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.6)  # Tiempo de espera para respuesta
                result = sock.connect_ex((target_ip, port))

                if result == 0:
                    if port in vulnerable_ports:
                        st.error(f"🚨 **Puerto {port} ABIERTO** - {vulnerable_ports[port]}")
                    else:
                        st.warning(f"⚠️ **Puerto {port} ABIERTO** - Servicio desconocido detectado.")
                else:
                    st.write(f"✅ Puerto {port}: Cerrado.")

                sock.close()
                progress_bar.progress((i + 1) / len(ports_to_scan))

        except socket.gaierror:
            st.error("❌ Error: No se pudo resolver el dominio. Revisa la ortografía o tu conexión.")
        except Exception as e:
            st.error(f"❌ Error inesperado: {e}")

# --- SECCIÓN: AUDITORÍA DE CABECERAS HTTP ---
elif choice == "Auditoría de Cabeceras":
    st.subheader("🛡️ Análisis de Cabeceras de Seguridad")
    st.write("Analiza si un servidor web implementa medidas de protección contra ataques como XSS o Clickjacking.")

    url = st.text_input("URL del sitio (debe incluir http:// o https://)", "https://")

    security_headers = {
        "Content-Security-Policy": "Controla qué recursos puede cargar el navegador, mitigando ataques de Inyección (XSS).",
        "Strict-Transport-Security": "Fuerza la conexión por HTTPS, evitando ataques de intercepción (Man-in-the-Middle).",
        "X-Frame-Options": "Protege contra el **Clickjacking** al evitar que el sitio sea embebido en frames ajenos.",
        "X-Content-Type-Options": "Evita que el navegador 'adivine' el tipo de archivo, mitigando la ejecución de scripts ocultos.",
        "Referrer-Policy": "Controla cuánta información se comparte al hacer clic en enlaces hacia otros sitios."
    }

    if st.button("Analizar Cabeceras"):
        if not url.startswith("http"):
            st.warning("La URL debe comenzar con http:// o https://")
        else:
            try:
                with st.spinner("Analizando respuesta del servidor..."):
                    response = requests.get(url, timeout=10)
                    headers = response.headers

                st.write(f"### Resultados para: {url}")
                st.markdown("---")

                for header, info in security_headers.items():
                    if header in headers:
                        st.success(f"✅ **{header}**: Presente")
                        with st.expander("Ver valor y explicación"):
                            st.code(headers[header], language="text")
                            st.write(info)
                    else:
                        st.error(f"❌ **{header}**: Faltante")
                        st.info(f"**¿Por qué es importante?** {info}")
            except Exception as e:
                st.error(f"No se pudo conectar con el sitio: {e}")

# --- SECCIÓN: HASH DE ARCHIVO ---
elif choice == "Hash de Archivo":
    st.subheader("🔍 Análisis de Integridad (SHA-256)")
    st.write("Sube un archivo para obtener su huella digital única y compararla con amenazas.")

    malware_db = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Archivo de prueba EICAR (Falso positivo seguro)",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Archivo vacío (Empty File)"
    }

    uploaded_file = st.file_uploader("Elige un archivo...")

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        st.markdown("### Hash Resultante:")
        st.code(sha256_hash, language="text")

        if sha256_hash in malware_db:
            st.error(
                f"🚨 **¡ALERTA!** Este hash coincide con una entrada en nuestra base de datos: {malware_db[sha256_hash]}")
        else:
            st.success("✅ El archivo no coincide con ninguna amenaza conocida en la base local.")

# --- SECCIÓN: GESTOR SEGURO ---
# --- SECCIÓN: GESTOR SEGURO ---
elif choice == "Gestor Seguro":
    st.subheader("🛡️ Generador de Contraseñas Robustas")
    st.write("Configura los parámetros para crear una contraseña con alta entropía.")

    col_a, col_b = st.columns(2)
    with col_a:
        longitud = st.slider("Longitud de la contraseña", 8, 64, 16)
        incluir_mayus = st.checkbox("Incluir Mayúsculas (A-Z)", value=True)
        incluir_minus = st.checkbox("Incluir Minúsculas (a-z)", value=True)
    with col_b:
        incluir_nums = st.checkbox("Incluir Números (0-9)", value=True)
        incluir_simbolos = st.checkbox("Incluir Símbolos (!@#$...)", value=True)

    # Construcción del pool de caracteres basada en la selección
    caracteres_disponibles = ""
    if incluir_mayus: caracteres_disponibles += string.ascii_uppercase
    if incluir_minus: caracteres_disponibles += string.ascii_lowercase
    if incluir_nums: caracteres_disponibles += string.digits
    if incluir_simbolos: caracteres_disponibles += string.punctuation

    if st.button("Generar Contraseña"):
        if not caracteres_disponibles:
            st.error("❌ Debes seleccionar al menos un tipo de carácter.")
        else:
            # Generación segura
            password = "".join(random.choice(caracteres_disponibles) for _ in range(longitud))

            st.markdown("---")
            st.write("### Tu contraseña generada:")

            # El componente st.code ya trae el botón de "copiar" integrado por defecto
            st.code(password, language="text")
            st.caption("Usa el botón de la esquina superior derecha del cuadro gris para copiar.")

            # Análisis de seguridad visual
            if longitud >= 16 and (incluir_mayus + incluir_minus + incluir_nums + incluir_simbolos >= 3):
                st.success("Nivel de seguridad: **Muy Fuerte** ✅")
            elif longitud >= 12:
                st.info("Nivel de seguridad: **Medio**")
            else:
                st.warning("Nivel de seguridad: **Bajo** (se recomienda aumentar la longitud)")

# Pie de página
st.markdown("---")
st.caption("Desarrollado para fines académicos. La seguridad es un proceso, no un producto.")
st.caption("serviciospalaciosweb.com &copy; Derechos Reservados")