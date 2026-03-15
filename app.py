import streamlit as st
import socket
import hashlib
import random
import string
import requests
from fpdf import FPDF
from datetime import datetime

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="CiberHerramienta Educativa - Néstor Gustavo Palacios Meyer",
    page_icon="🛡️",
    layout="wide"
)


# --- FUNCIÓN PARA GENERAR PDF ---
def generar_pdf(titulo_reporte, contenido_dict):
    pdf = FPDF()
    pdf.add_page()

    # Encabezado
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt=titulo_reporte, ln=True, align='C')

    # Metadatos
    pdf.set_font("Arial", size=10)
    fecha_actual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.cell(200, 10, txt=f"Fecha de análisis: {fecha_actual}", ln=True, align='C')
    pdf.cell(200, 10, txt="Desarrollado por: Gustavo Palacios Meyer", ln=True, align='C')
    pdf.ln(10)

    # Cuerpo
    pdf.set_font("Arial", size=12)
    # Dentro de tu función generar_pdf, cambia el bucle por esto:
    for clave, valor in contenido_dict.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.multi_cell(0, 10, txt=str(clave).encode('latin-1', 'replace').decode('latin-1'))
        pdf.set_font("Arial", size=11)
        # Limpiamos caracteres que FPDF no soporta bien
        texto_limpio = str(valor).encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, txt=texto_limpio)
        pdf.ln(2)

    pdf.ln(10)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 10, txt="serviciospalaciosweb.com - Fin Educativo", ln=True, align='C')

    return pdf.output(dest='S').encode('latin-1')


# --- CSS PERSONALIZADO ---
st.markdown("""
    <style>
    @media (max-width: 640px) { [data-testid="stSidebar"] { width: 100vw !important; } }
    [data-testid="stSidebarNavSeparator"] + div button::before {
        content: "Deslizar acá ⬅️ "; font-size: 14px; color: #808495; margin-right: 10px; vertical-align: middle;
    }
    [data-testid="stSidebar"] [data-testid="stImage"] { text-align: center; display: block; margin: 20px auto 0; }
    .stButton>button { width: 100%; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Panel de Ciberseguridad Educativo")
st.markdown("---")

# --- BARRA LATERAL ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
st.sidebar.markdown("<h3 style='text-align: center;'>Menú de Herramientas</h3>", unsafe_allow_html=True)
menu = ["Inicio", "Escáner de Puertos", "Auditoría de Cabeceras", "Auditoría de Inyección","Laboratorio SQL","Hash de Archivo", "Gestor Seguro"]
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
    * **Auditoría XSS:** Detectar vulnerabilidades de inyección de scripts en parámetros URL.
    * **Laboratorio SQL:** Aprender a proteger bases de datos contra ataques de inyección (Fines educativos).
    * **Verificar Integridad:** Analizar archivos mediante algoritmos de hashing.
    * **Seguridad de Acceso:** Generar contraseñas robustas con alta entropía.
    * **Reportes Profesionales:** Generar documentos PDF detallados con los resultados del análisis.
        """)
    with col2:
        st.info(
            "**Nota Educativa:** El uso de estas herramientas contra sistemas sin autorización es ilegal. Úsalas solo en entornos controlados o con permiso.")

# --- SECCIÓN: ESCÁNER DE PUERTOS (CON EXPLICACIONES EDUCATIVAS) ---
elif choice == "Escáner de Puertos":
    st.subheader("🌐 Escáner de Puertos y Riesgos")

    # Diccionario de referencia para las explicaciones
    explicaciones_puertos = {
        21: "FTP - Transferencia de archivos. Si no está cifrado (FTPS), las credenciales viajan en texto plano y pueden ser interceptadas.",
        22: "SSH - Acceso remoto seguro. Es el estándar, pero suele recibir ataques constantes de fuerza bruta.",
        23: "Telnet - Comunicación obsoleta y no cifrada. ¡Extremadamente inseguro!",
        80: "HTTP - Tráfico web sin cifrar. Cualquier dato enviado es visible. Se recomienda migrar al puerto 443.",
        443: "HTTPS - Tráfico web cifrado. Es el puerto más seguro y estándar para navegación moderna.",
        445: "SMB - Compartición de archivos en Windows. Si está expuesto a internet, es muy vulnerable a exploits (como WannaCry).",
        8080: "HTTP Proxy/Alternativo - Comúnmente usado en servidores de desarrollo o paneles de administración."
    }

    target_input = st.text_input("Ingresa IP, Dominio o URL completa", "127.0.0.1")

    if st.button("Iniciar Escaneo"):
        try:
            # Limpieza de la URL
            clean_target = target_input.replace("https://", "").replace("http://", "").split('/')[0].strip()
            target_ip = socket.gethostbyname(clean_target)
            st.info(f"Objetivo detectado: **{clean_target}** (IP: {target_ip})")

            puertos = [21, 22, 23, 80, 443, 445, 8080]
            resultados_pdf = {"Objetivo": clean_target, "IP": target_ip}

            # Añadimos una barra de progreso para mejorar la experiencia
            progress_bar = st.progress(0)

            for i, port in enumerate(puertos):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.7)  # Tiempo de espera para la respuesta
                result = sock.connect_ex((target_ip, port))

                # Buscamos la explicación en nuestro diccionario
                info_puerto = explicaciones_puertos.get(port, "Servicio desconocido o personalizado.")

                if result == 0:
                    # Puerto Abierto
                    estado_texto = f"ABIERTO - {info_puerto}"
                    st.error(f"🚨 **Puerto {port}: ABIERTO**\n\n_{info_puerto}_")
                else:
                    # Puerto Cerrado
                    estado_texto = "Cerrado"
                    st.write(f"✅ Puerto {port}: Cerrado")

                # Guardamos la información detallada para el PDF
                resultados_pdf[f"Puerto {port}"] = estado_texto

                sock.close()
                progress_bar.progress((i + 1) / len(puertos))

            st.markdown("---")
            # Generamos el PDF con las descripciones incluidas
            pdf_data = generar_pdf("Reporte de Auditoría de Puertos", resultados_pdf)
            st.download_button(
                label="📥 Descargar Reporte PDF Detallado",
                data=pdf_data,
                file_name=f"auditoria_puertos_{clean_target}.pdf",
                mime="application/pdf"
            )

        except socket.gaierror:
            st.error("❌ No se pudo resolver el dominio. Verifica la dirección ingresada.")
        except Exception as e:
            st.error(f"Error inesperado: {e}")

# --- SECCIÓN: AUDITORÍA DE CABECERAS ---
elif choice == "Auditoría de Cabeceras":
    st.subheader("🛡️ Análisis de Cabeceras de Seguridad")
    url = st.text_input("URL (con http/https)", "https://")

    if st.button("Analizar Cabeceras"):
        if url.startswith("http"):
            try:
                response = requests.get(url, timeout=10)
                headers = response.headers
                h_interes = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                             "X-Content-Type-Options"]
                resultados_pdf = {"URL": url}

                for h in h_interes:
                    val = headers.get(h, "FALTANTE")
                    resultados_pdf[h] = val
                    if val != "FALTANTE":
                        st.success(f"✅ {h}")
                    else:
                        st.error(f"❌ {h}")

                st.download_button("📥 Descargar Reporte PDF", data=generar_pdf("Auditoria Web", resultados_pdf),
                                   file_name="cabeceras.pdf")
            except Exception as e:
                st.error(f"Error: {e}")

# --- SECCIÓN: AUDITORÍA DE INYECCIÓN (XSS) ---
elif choice == "Auditoría de Inyección":
    st.subheader("💉 Prueba de Vulnerabilidad XSS (Reflejado)")
    st.write("""
    Esta herramienta verifica si un parámetro de una URL (como una búsqueda) es vulnerable a Cross-Site Scripting.
    **Uso:** Ingresa la URL completa incluyendo el parámetro, por ejemplo: `http://tusitio.com/buscar.php?q=`
    """)

    target_url = st.text_input("URL del objetivo con parámetro", "http://")

    if st.button("Ejecutar Escaneo de Inyección"):
        if not target_url.startswith("http"):
            st.warning("Por favor, ingresa una URL válida que comience con http:// o https://")
        elif "=" not in target_url:
            st.error("La URL debe contener un parámetro (ejemplo: ?id= o ?q=) para probar la inyección.")
        else:
            try:
                # Payloads de prueba (scripts inofensivos para detectar vulnerabilidad)
                payloads = [
                    "<script>alert('XSS')</script>",
                    "'\"><script>alert(1)</script>",
                    "<img src=x onerror=alert('XSS')>"
                ]

                vulnerable = False
                resultados_pdf = {"URL Base": target_url}

                # 1. Definimos un User-Agent para que no nos bloqueen por parecer un robot
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }
                # Aseguramos que la URL no tenga espacios y que termine lista para el payload
                target_url = target_url.strip()
                if not target_url.endswith("=") and "=" in target_url:
                    # Si el usuario puso ?id=123, intentamos inyectar después del valor
                    pass

                try:
                    with st.spinner("Probando payloads..."):
                        for i, payload in enumerate(payloads):
                            test_url = target_url.strip() + payload

                            # 2. Aumentamos el timeout a 20 segundos y agregamos los headers
                            response = requests.get(test_url, headers=headers, timeout=20)

                            if payload in response.text:
                                st.error(f"🚨 **VULNERABILIDAD DETECTADA** con: `{payload}`")
                                vulnerable = True
                                break
                            else:
                                st.write(f"✅ Prueba {i + 1}: El payload fue filtrado.")

                except requests.exceptions.Timeout:
                    st.warning(
                        "⚠️ El servidor tarda demasiado en responder. Es posible que el sitio esté caído o bloqueando la conexión.")
                except requests.exceptions.ConnectionError:
                    st.error("❌ Error de conexión. No se pudo establecer contacto con el servidor.")
                except Exception as e:
                    st.error(f"Error inesperado: {e}")

                if not vulnerable:
                    st.success(
                        "🎉 No se detectaron vulnerabilidades XSS básicas. El sitio parece manejar bien las entradas.")
                    resultados_pdf["Resultado Final"] = "Seguro"
                else:
                    resultados_pdf["Resultado Final"] = "VULNERABLE"

                # Opción de descargar reporte
                st.markdown("---")
                pdf_data = generar_pdf("Reporte de Auditoria XSS", resultados_pdf)
                st.download_button(
                    label="📥 Descargar Reporte de Inyección",
                    data=pdf_data,
                    file_name="auditoria_xss.pdf",
                    mime="application/pdf"
                )

            except Exception as e:
                st.error(f"Error al conectar con el objetivo: {e}")

# --- SECCIÓN: LABORATORIO SQL (EDUCATIVO) ---
elif choice == "Laboratorio SQL":
    st.subheader("🗄️ Laboratorio de Inyección SQL y Prevención")
    st.info("Este módulo es interactivo y educativo. No realiza ataques reales, sino que simula cómo funcionan.")

    st.markdown("""
    ### 1. La Consulta Vulnerable
    Imagina que tienes un sistema de login o un buscador de alumnos en PHP con este código:
    """)

    # Simulación de código vulnerable
    st.code("""
// CÓDIGO INSEGURO
$id = $_GET['id'];
$query = "SELECT nombre, nota FROM alumnos WHERE id = " . $id;
    """, language="php")

    st.markdown("---")
    st.write("### 2. Simular un Ataque")
    input_usuario = st.text_input("Ingresa un ID de alumno (o intenta una inyección)", "1")

    # Lógica de simulación
    query_final = f"SELECT nombre, nota FROM alumnos WHERE id = {input_usuario}"

    st.write("**Consulta que se ejecutaría en MySQL:**")
    st.warning(f"`{query_final}`")

    # Detectar patrones de inyección comunes
    payloads_sql = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "--", ";"]

    if any(p in input_usuario for p in payloads_sql):
        st.error("🚨 **¡Inyección SQL detectada!**")
        st.write("""
        **¿Qué pasó?** Al ingresar comillas o comandos SQL, has modificado la lógica original. 
        Si esto fuera un login, el atacante podría entrar sin contraseña usando `' OR '1'='1`.
        """)

    else:
        st.success("Consulta legítima enviada.")

    st.markdown("---")
    st.markdown("### 3. La Solución Profesional: Sentencias Preparadas (PDO)")
    st.write("Para proteger tu sistema **SGE**, nunca concatenes variables. Usa este estándar:")

    st.code("""
// CÓDIGO SEGURO (USANDO PDO)
$id = $_GET['id'];

// 1. Preparamos la plantilla (con un marcador ?)
$stmt = $pdo->prepare("SELECT nombre, nota FROM alumnos WHERE id = ?");

// 2. Ejecutamos pasando el dato por separado
$stmt->execute([$id]);

$resultado = $stmt->fetch();
    """, language="php")

    st.success(
        "✅ Con este método, el motor de base de datos trata la entrada como **texto**, no como código ejecutable.")

# --- SECCIÓN: HASH DE ARCHIVO (CORREGIDA) ---
elif choice == "Hash de Archivo":
    st.subheader("🔍 Análisis de Integridad (SHA-256)")

    with st.expander("💡 ¿Problemas al subir archivos?"):
        st.info("Usa 'Browse files' o modo incógnito si el 'Drag & Drop' falla por errores de red.")

    st.write("Sube un archivo para obtener su huella digital única y compararla con amenazas.")

    malware_db = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Archivo de prueba EICAR (Falso positivo seguro)",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Archivo vacío (Empty File)"
    }

    uploaded_file = st.file_uploader("Elige un archivo...", type=None, key="hash_uploader")

    if uploaded_file is not None:
        try:
            # 1. PRIMERO calculamos el hash
            with st.spinner("Calculando huella digital..."):
                file_bytes = uploaded_file.getvalue()
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

            # 2. AHORA que tenemos 'sha256_hash', mostramos los resultados y el link
            st.markdown("### Resultado del Análisis:")
            st.info(f"**Nombre:** {uploaded_file.name}")
            st.code(sha256_hash, language="text")

            # Link a VirusTotal usando el hash ya calculado
            st.markdown(f"### [🔍 Consultar este Hash en VirusTotal](https://www.virustotal.com/gui/file/{sha256_hash})")
            st.caption("Verifica si este archivo ha sido analizado por motores de seguridad globales.")

            # 3. Verificación en base de datos local
            if sha256_hash in malware_db:
                st.error(f"🚨 **¡ALERTA!** Este hash coincide con: {malware_db[sha256_hash]}")
                estado_seguridad = f"ALERTA: Coincide con {malware_db[sha256_hash]}"
            else:
                st.success("✅ El archivo no coincide con ninguna amenaza conocida en la base local.")
                estado_seguridad = "Seguro (Sin coincidencias en base local)"

            # 4. Reporte PDF
            resultados_pdf = {
                "Archivo": uploaded_file.name,
                "Tamaño (Bytes)": len(file_bytes),
                "Hash SHA-256": sha256_hash,
                "Resultado": estado_seguridad
            }

            pdf_data = generar_pdf("Reporte de Integridad de Archivo", resultados_pdf)
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_data,
                file_name=f"analisis_{uploaded_file.name}.pdf",
                mime="application/pdf"
            )

        except Exception as e:
            st.error(f"Error al procesar el archivo: {e}")

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