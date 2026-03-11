import streamlit as st
import socket
import hashlib
import random
import string

# Configuración de la página
st.set_page_config(page_title="CiberHerramienta Básica", layout="wide")

st.title("🛡️ Panel de Ciberseguridad Educativo")
st.markdown("---")

# --- BARRA LATERAL (MODIFICADA) ---
st.sidebar.markdown("### 🖱️ Clic acá para ver las herramientas u opciones") # Título añadido
menu = ["Inicio", "Escáner de Puertos", "Hash de Archivo", "Gestor Seguro"]
choice = st.sidebar.selectbox("Selecciona una opción:", menu)

# --- INICIO ---
if choice == "Inicio":
    st.subheader("🤫Bienvenido al panel")

    st.write("Esta app es educativa y simula herramientas básicas de ciberseguridad hecha por Gustavo Palacios Meyer.")

# --- ESCÁNER DE PUERTOS (Simulado/Básico) ---
elif choice == "Escáner de Puertos":
    st.subheader("🌐 Escáner de Puertos y Riesgos")
    target = st.text_input("IP o Dominio a escanear", "127.0.0.1")

    # Diccionario de vulnerabilidades conocidas
    vulnerable_ports = {
        21: "FTP (File Transfer Protocol) - Puede permitir acceso anónimo inseguro.",
        22: "SSH (Secure Shell) - Riesgo de ataques de fuerza bruta.",
        23: "Telnet - Protocolo obsoleto y NO cifrado.",
        80: "HTTP - Web no segura (sin cifrado SSL).",
        445: "SMB (Server Message Block) - Propenso a vulnerabilidades graves (ej. WannaCry)."
    }

    if st.button("Escanear y Analizar"):
        st.write(f"Analizando {target}...")

        # Puertos a revisar (incluimos los críticos)
        ports_to_scan = [21, 22, 23, 80, 443, 8080, 445]

        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex((target, port))

            if result == 0:
                # Puerto ABIERTO
                if port in vulnerable_ports:
                    st.error(f"🚨 **Puerto {port} ABIERTO** - ¡PELIGRO! {vulnerable_ports[port]}")
                else:
                    st.warning(f"⚠️ **Puerto {port} ABIERTO** - Servicio corriendo.")
            else:
                # Puerto CERRADO
                st.write(f"✅ Puerto {port}: Cerrado.")

            sock.close()

# --- ANÁLISIS DE MALWARE (Simulado por Hashing) ---
elif choice == "Hash de Archivo":
    st.subheader("🔍 Análisis de Integridad y Malware")
    st.write("Calcula el hash SHA256 y verifica si coincide con amenazas conocidas.")

    # 1. Base de datos de ejemplo (Lista Negra)
    # El hash de EICAR es real, los otros son ejemplos educativos
    malware_db = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Archivo de prueba EICAR (Seguro)",
        "24d004a104d4d54034dbcffc2a1c1a3e86c321d3f9e2e604f5f5e3a3f5a1a3b2": "Posible variante de WannaCry",
        "5f34d658a0873ed782362f688a44d8c6b39d17d52f638848d6139783962657e4": "Trojan.Generic.Ejemplo"
    }

    uploaded_file = st.file_uploader("Sube un archivo (.exe, .pdf, .zip, etc.)", type=None)

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        st.markdown("---")
        st.write("**Resultado del Análisis:**")
        st.code(sha256_hash, language="text")

        # 2. Lógica de comparación
        if sha256_hash in malware_db:
            st.error(f"⚠️ ¡ALERTA! Este archivo coincide con una amenaza conocida: **{malware_db[sha256_hash]}**")
            st.warning("Se recomienda no ejecutar este archivo y eliminarlo.")
        else:
            st.success("✅ El hash no coincide con ninguna amenaza en nuestra base de datos local.")
            st.info(
                "Nota: Esto no garantiza que el archivo sea 100% seguro, solo que no está en la lista negra actual.")

    # 3. Función extra: Comparar con un hash específico
    with st.expander("Comparar con un hash manual"):
        hash_manual = st.text_input("Pega aquí el hash que esperas (ej. de la web oficial)")
        if hash_manual:
            if hash_manual.lower() == sha256_hash.lower():
                st.success("✨ ¡Coincidencia perfecta! El archivo es auténtico.")
            else:
                st.error("❌ Los hashes no coinciden. El archivo podría estar modificado.")

# --- GESTOR DE CONTRASEÑAS (Educativo) ---
elif choice == "Gestor Seguro":
    st.subheader("🛡️ Generador de Contraseñas Seguras")
    st.write("Crea contraseñas robustas de forma aleatoria sin que salgan de tu navegador.")

    col1, col2 = st.columns(2)

    with col1:
        longitud = st.slider("Longitud de la contraseña", 8, 32, 16)
        # Añadimos checkbox de minúsculas para control total
        incluir_minus = st.checkbox("Incluir Minúsculas", value=True)
        incluir_mayus = st.checkbox("Incluir Mayúsculas", value=True)
        incluir_numeros = st.checkbox("Incluir Números", value=True)
        incluir_especiales = st.checkbox("Incluir Símbolos (!@#$)", value=True)

    # --- Lógica de generación corregida ---
    caracteres = ""  # Empezamos con la cadena vacía

    if incluir_minus:
        caracteres += string.ascii_lowercase
    if incluir_mayus:
        caracteres += string.ascii_uppercase
    if incluir_numeros:
        caracteres += string.digits
    if incluir_especiales:
        caracteres += string.punctuation

    if st.button("Generar Contraseña"):
        # Verificamos que al menos una opción esté seleccionada para evitar error
        if caracteres == "":
            st.error("Por favor, selecciona al menos un tipo de carácter.")
        else:
            # Generar contraseña aleatoria segura
            password = ''.join(random.choice(caracteres) for i in range(longitud))

            st.markdown("---")
            st.write("Tu contraseña generada:")
            st.code(password, language="text")

            # Feedback de seguridad
            if longitud < 12:
                st.warning("Nivel de seguridad: Débil (se recomiendan al menos 12 caracteres)")
            elif len(set(caracteres)) < 30:
                st.info("Nivel de seguridad: Medio (añade más tipos de caracteres)")
            else:
                st.success("Nivel de seguridad: Fuerte ✅")