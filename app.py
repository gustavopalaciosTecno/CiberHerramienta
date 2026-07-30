import streamlit as st
import socket
import struct
import hashlib
import random
import string
import requests
from fpdf import FPDF
from datetime import datetime
import json
import base64
import re
from urllib.parse import urlparse

# --- VERIFICACIÓN DE DEPENDENCIAS OPCIONALES ---
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️ dnspython no instalado - Funciones DNS deshabilitadas")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois no instalado - Funciones WHOIS deshabilitadas")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ python-nmap no instalado - Escáner avanzado deshabilitado")

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
    pdf.cell(200, 10, txt="Desarrollado por: Gustavo Palacios Meyer con el apoyo de Inteligencia Artificial.", ln=True,
             align='C')
    pdf.ln(10)

    # Cuerpo
    pdf.set_font("Arial", size=12)
    for clave, valor in contenido_dict.items():
        pdf.set_font("Arial", 'B', 12)
        pdf.multi_cell(0, 10, txt=str(clave).encode('latin-1', 'replace').decode('latin-1'))
        pdf.set_font("Arial", size=11)
        texto_limpio = str(valor).encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, txt=texto_limpio)
        pdf.ln(2)

    pdf.ln(10)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 10, txt="serviciospalaciosweb.com - Fin Educativo", ln=True, align='C')

    return pdf.output(dest='S').encode('latin-1')


# --- FUNCIÓN PARA CONSULTAR VIRUSTOTAL ---
def consultar_virustotal(archivo_hash, api_key=None):
    """
    Consulta VirusTotal usando el hash SHA-256 de un archivo
    Si no se proporciona API key, simula la consulta con información de ejemplo
    """
    if api_key and archivo_hash:
        try:
            url = f"https://www.virustotal.com/api/v3/files/{archivo_hash}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                # Extraer información relevante
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0),
                    "timeout": stats.get('timeout', 0),
                    "total_engines": sum(stats.values())
                }
        except Exception as e:
            st.warning(f"No se pudo conectar con VirusTotal: {e}")
            return None
    return None


# --- FUNCIÓN PARA ANALIZAR ENLACES SOSPECHOSOS ---
def analizar_enlace(url):
    """Analiza un enlace en busca de características sospechosas"""
    riesgos = []
    puntaje_riesgo = 0

    try:
        parsed = urlparse(url)

        # 1. Verificar URL acortadas
        acortadores = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        if any(acortador in url.lower() for acortador in acortadores):
            riesgos.append("⚠️ Enlace acortado - Puede ocultar el destino real")
            puntaje_riesgo += 20

        # 2. Verificar caracteres sospechosos
        if '%' in url:
            riesgos.append("⚠️ Contiene caracteres codificados (%XX) - Posible ofuscación")
            puntaje_riesgo += 15

        # 3. Verificar dominios similares (typosquatting)
        # Esto es una simulación, en la práctica necesitarías una base de datos de dominios conocidos
        patrones_sospechosos = ['-', 'xn--', '.tk', '.ml', '.ga', '.cf']
        if any(patron in parsed.netloc.lower() for patron in patrones_sospechosos):
            riesgos.append("⚠️ Dominio con características sospechosas")
            puntaje_riesgo += 25

        # 4. Verificar HTTPS
        if parsed.scheme != 'https':
            riesgos.append("⚠️ No utiliza HTTPS - Conexión no cifrada")
            puntaje_riesgo += 30

        # 5. IP en lugar de dominio
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
            riesgos.append("⚠️ Usa IP en lugar de dominio - Posible servidor sospechoso")
            puntaje_riesgo += 35

        # 6. Verificar longitud del dominio
        if len(parsed.netloc) > 40:
            riesgos.append("ℹ️ Dominio muy largo - Puede ser de phishing")
            puntaje_riesgo += 10

    except Exception as e:
        riesgos.append(f"Error al analizar: {e}")

    return {
        "riesgos": riesgos,
        "puntaje": min(puntaje_riesgo, 100),
        "nivel": "Alto" if puntaje_riesgo >= 70 else "Medio" if puntaje_riesgo >= 40 else "Bajo"
    }


# --- FUNCIÓN PARA VERIFICAR DNS ---
def verificar_dns(dominio):
    """Verifica registros DNS del dominio"""
    resultados = {}
    try:
        # Registros A
        try:
            respuestas = dns.resolver.resolve(dominio, 'A')
            resultados['A'] = [str(r) for r in respuestas]
        except:
            resultados['A'] = ["No encontrado"]

        # Registros MX
        try:
            respuestas = dns.resolver.resolve(dominio, 'MX')
            resultados['MX'] = [str(r.exchange) for r in respuestas]
        except:
            resultados['MX'] = ["No encontrado"]

        # Registros TXT
        try:
            respuestas = dns.resolver.resolve(dominio, 'TXT')
            resultados['TXT'] = [str(r) for r in respuestas]
        except:
            resultados['TXT'] = ["No encontrado"]

        # Registros NS
        try:
            respuestas = dns.resolver.resolve(dominio, 'NS')
            resultados['NS'] = [str(r) for r in respuestas]
        except:
            resultados['NS'] = ["No encontrado"]

        # SPF (dentro de TXT)
        for txt in resultados.get('TXT', []):
            if 'v=spf1' in txt:
                resultados['SPF'] = "✅ SPF configurado"
                break
        else:
            resultados['SPF'] = "⚠️ SPF no encontrado"

    except Exception as e:
        resultados['error'] = str(e)

    return resultados


# --- FUNCIÓN PARA VERIFICAR SI UN CORREO ES FALSO ---
def verificar_correo_sospechoso(email):
    """Analiza un correo electrónico en busca de características sospechosas"""
    sospechas = []
    puntaje = 0

    if not email or '@' not in email:
        return {"sospechas": ["Correo inválido"], "puntaje": 100, "nivel": "Alto"}

    try:
        local, dominio = email.split('@')

        # 1. VERIFICAR DOMINIOS TEMPORALES/DESECHABLES
        temporales = [
            'temp', 'fake', 'mailinator', 'guerrillamail', '10minutemail',
            'throwaway', 'disposable', 'trashmail', 'spamgourmet'
        ]
        if any(temp in dominio.lower() for temp in temporales):
            sospechas.append("⚠️ Dominio de correo temporal/desechable")
            puntaje += 40

        # 2. VERIFICAR DOMINIOS DE CORREO GRATUITO SOSPECHOSOS
        gratuitos_sospechosos = [
            'libero.it', 'virgilio.it', 'tiscali.it', 'alice.it',
            'yahoo.com', 'hotmail.com', 'outlook.com', 'gmail.com'
        ]
        if dominio.lower() in gratuitos_sospechosos:
            sospechas.append(f"ℹ️ Dominio gratuito ({dominio}) - No necesariamente malicioso")
            puntaje += 5

        # 3. VERIFICAR CARACTERES EXTRAÑOS
        if re.search(r'[^a-zA-Z0-9._-]', local):
            sospechas.append("⚠️ Contiene caracteres especiales inusuales")
            puntaje += 20

        # 4. VERIFICAR NÚMEROS EN EXCESO
        numeros = len(re.findall(r'\d', local))
        if numeros > 4:
            sospechas.append(f"⚠️ Demasiados números ({numeros}) - Posible correo automático")
            puntaje += 15
        elif numeros > 2:
            sospechas.append(f"ℹ️ Contiene {numeros} números - Puede ser generado automáticamente")
            puntaje += 8

        # 5. VERIFICAR LONGITUD DE LA PARTE LOCAL
        if len(local) > 20:
            sospechas.append(f"⚠️ Parte local muy larga ({len(local)} caracteres)")
            puntaje += 10
        elif len(local) > 15:
            sospechas.append(f"ℹ️ Parte local larga ({len(local)} caracteres)")
            puntaje += 5

        # 6. NOMBRES SOSPECHOSOS COMUNES EN PHISHING
        palabras_sospechosas = [
            'admin', 'support', 'security', 'info', 'test',
            'user', 'service', 'help', 'contact', 'webmaster',
            'noreply', 'no-reply', 'system', 'mailer', 'sender'
        ]
        if any(palabra in local.lower() for palabra in palabras_sospechosas):
            sospechas.append(f"⚠️ Nombre común en correos de phishing: '{local}'")
            puntaje += 20

        # 7. VERIFICAR PATRONES DE NOMBRE + APELLIDO + NÚMEROS
        # Ej: villamassimili198038 -> nombre + apellido + números
        if re.match(r'^[a-zA-Z]+[a-zA-Z]+[\d]+$', local):
            sospechas.append("ℹ️ Patrón: nombre+apellido+números - Común en cuentas automáticas")
            puntaje += 10

        # 8. VERIFICAR SI EL DOMINIO TIENE REGISTROS MX (OPCIONAL)
        # Esto requeriría consulta DNS, lo dejamos como opcional

        # 9. VERIFICAR AÑO EN EL CORREO
        anios = re.findall(r'(19|20)\d{2}', local)
        if anios:
            sospechas.append(f"ℹ️ Contiene año(s): {', '.join(anios)} - Puede ser generado")
            puntaje += 5

        # 10. ANÁLISIS DE PATRONES DE SPAM
        # Detectar si el correo parece generado aleatoriamente
        if len(set(local)) < len(local) * 0.3:  # Menos del 30% de caracteres únicos
            sospechas.append("⚠️ Muy pocos caracteres únicos - Posible correo generado")
            puntaje += 25

        # 11. VERIFICAR NOMBRE COMÚN ITALIANO (para este caso específico)
        nombres_comunes = [
            'rossi', 'bianchi', 'ferrari', 'russo', 'esposito',
            'roman', 'ricci', 'marino', 'greco', 'bruno',
            'villamassimili'  # Detectamos este caso específico
        ]
        if any(nombre in local.lower() for nombre in nombres_comunes):
            sospechas.append("ℹ️ Nombre/apellido común - Puede ser cuenta generada")
            puntaje += 5

        # 12. VERIFICAR DOMINIO LIBERO.IT (CASO ESPECÍFICO)
        if 'libero.it' in dominio.lower():
            sospechas.append("ℹ️ Dominio Libero.it - Popular en Italia, usado frecuentemente en spam")
            puntaje += 10

    except Exception as e:
        sospechas.append(f"Error al analizar: {e}")
        puntaje += 50

    # Si no hay sospechas, agregar mensaje positivo
    if not sospechas:
        sospechas.append("✅ Correo aparentemente normal")

    # Calcular nivel de riesgo
    nivel = "Alto" if puntaje >= 70 else "Medio" if puntaje >= 40 else "Bajo"

    return {
        "sospechas": sospechas,
        "puntaje": min(puntaje, 100),
        "nivel": nivel,
        "detalles": {
            "local": local,
            "dominio": dominio,
            "numeros": len(re.findall(r'\d', local)),
            "longitud": len(local)
        }
    }


# --- CSS PERSONALIZADO ---
st.markdown("""
    <style>
    @media (max-width: 640px) { [data-testid="stSidebar"] { width: 100vw !important; } }
    [data-testid="stSidebarNavSeparator"] + div button::before {
        content: "Deslizar acá ⬅️ "; font-size: 14px; color: #808495; margin-right: 10px; vertical-align: middle;
    }
    [data-testid="stSidebar"] [data-testid="stImage"] { text-align: center; display: block; margin: 20px auto 0; }
    .stButton>button { width: 100%; }
    .risk-high { background-color: #ff4444; color: white; padding: 5px 10px; border-radius: 5px; }
    .risk-medium { background-color: #ffaa44; color: black; padding: 5px 10px; border-radius: 5px; }
    .risk-low { background-color: #44aa44; color: white; padding: 5px 10px; border-radius: 5px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Panel de Ciberseguridad Educativo")
st.markdown("---")

# --- BARRA LATERAL ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
st.sidebar.markdown("<h3 style='text-align: center;'>Menú de Herramientas</h3>", unsafe_allow_html=True)
menu = [
    "🏠 Inicio",
    # --- Red y Servidores ---
    "🌐 Escáner de Puertos",
    "🌐 DNS Lookup",
    "🌐 Geolocalización de IPs",
    "🌐 Decodificador de IPs",
    # --- Seguridad Web ---
    "🌍 Auditoría de Cabeceras",
    "🌍 Auditoría de Inyección",
    "🌍 Laboratorio SQL",
    "🌍 Escáner de Directorios",
    "🌍 Scanner de Vulnerabilidades Web",
    "🌍 Verificador SSL",
    # --- Análisis Forense y Archivos ---
    "📁 Análisis de Metadatos",
    "📁 Hash de Archivo",
    "📁 Analizador de código QR",
    "📁 Generador de Reportes",
    # --- Enlaces y Correos ---
    "🔗 Análisis de Enlaces",
    "✉️ Verificador de Correos",
    # --- Gestión y Seguridad ---
    "🛡️ Gestor Seguro",
    "🛡️ Análisis VirusTotal",
    "🛡️ Verificador de Contraseñas",
    "🛡️ Detector de Malware"
]
choice = st.sidebar.selectbox("Selecciona una opción:", menu)

st.sidebar.markdown("---")
st.sidebar.info("🚀 **Desarrollado por:**\nGustavo Palacios Meyer con la ayuda de la Inteligencia Artificial")

# --- SECCIÓN: INICIO ---
if choice == "🏠 Inicio":
    st.subheader("🤫 Bienvenido al panel")
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
            <div style="
                user-select: none; 
                -webkit-user-select: none; 
                -moz-user-select: none; 
                -ms-user-select: none;
                border: 1px solid #4a4a4a;
                padding: 15px;
                border-radius: 10px;
                background-color: rgba(255, 255, 255, 0.05);
                margin-bottom: 20px;
            ">
                <p style="margin-bottom: 0;">Desarrollado por: Gustavo Palacios Meyer con la ayuda de la Inteligencia Artificial.</p>
            </div>

            <h3 style="user-select: none;">¿Qué puedes hacer aquí?</h3>
        """, unsafe_allow_html=True)

        st.markdown("""
        * **Analizar Puertos:** Entender qué servicios están expuestos en un servidor.
        * **Auditar Web:** Verificar si un sitio web utiliza cabeceras de protección modernas.
        * **Auditoría XSS:** Detectar vulnerabilidades de inyección de scripts en parámetros URL.
        * **Laboratorio SQL:** Aprender a proteger bases de datos contra ataques de inyección.
        * **Verificar Integridad:** Analizar archivos mediante algoritmos de hashing.
        * **Escáner de Directorios:** Enumeración de directorios por fuerza bruta.
        * **Has de archivos:** Sube un archivo para obtener su huella digital única y compararla con amenazas.
        * **Análisis VirusTotal:** Verificar archivos y enlaces en bases de datos de amenazas.
        * **Análisis de Enlaces:** Detectar enlaces sospechosos y de phishing.
        * **Verificador de Correos:** Analizar correos electrónicos sospechosos.
        * **DNS Lookup:** Consultar registros DNS de dominios.
        * **Scanner de Vulnerabilidades:** Escaneo completo de seguridad web.
        * **Seguridad de Acceso:** Generar contraseñas robustas.
        * **Decodificador de IPs:** Revelar IPs ocultas tras formatos Hex/Octal.
        * **Gestor seguro:** Configura los parámetros para crear una contraseña con alta entropía.
        * **Reportes Profesionales:** Generar documentos PDF detallados.
        * **Análisis de Malware:** Análisis de Malware con el aval de virustotal.
        """)
    with col2:
        st.info(
            "**Nota Educativa:** El uso de estas herramientas contra sistemas sin autorización es ilegal. Úsalas solo en entornos controlados o con permiso.")

# --- SECCIÓN: ESCÁNER DE PUERTOS ---
elif choice == "🌐 Escáner de Puertos":
    st.subheader("🌐 Escáner de Puertos y Riesgos")

    explicaciones_puertos = {
        21: "FTP - Transferencia de archivos. Si no está cifrado (FTPS), las credenciales viajan en texto plano.",
        22: "SSH - Acceso remoto seguro. Sufre ataques constantes de fuerza bruta.",
        23: "Telnet - Comunicación obsoleta y no cifrada. ¡Extremadamente inseguro!",
        80: "HTTP - Tráfico web sin cifrar. Se recomienda migrar al puerto 443.",
        443: "HTTPS - Tráfico web cifrado. Puertos más seguro y estándar.",
        445: "SMB - Compartición de archivos en Windows. Vulnerable a exploits.",
        8080: "HTTP Proxy/Alternativo - Comúnmente usado en desarrollo."
    }

    target_input = st.text_input("Ingresa IP, Dominio o URL completa", "127.0.0.1")

    if st.button("Iniciar Escaneo"):
        try:
            clean_target = target_input.replace("https://", "").replace("http://", "").split('/')[0].strip()
            target_ip = socket.gethostbyname(clean_target)
            st.info(f"Objetivo detectado: **{clean_target}** (IP: {target_ip})")

            puertos = [21, 22, 23, 80, 443, 445, 8080]
            resultados_pdf = {"Objetivo": clean_target, "IP": target_ip}

            progress_bar = st.progress(0)

            for i, port in enumerate(puertos):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.7)
                result = sock.connect_ex((target_ip, port))

                info_puerto = explicaciones_puertos.get(port, "Servicio desconocido o personalizado.")

                if result == 0:
                    estado_texto = f"ABIERTO - {info_puerto}"
                    st.error(f"🚨 **Puerto {port}: ABIERTO**\n\n_{info_puerto}_")
                else:
                    estado_texto = "Cerrado"
                    st.write(f"✅ Puerto {port}: Cerrado")

                resultados_pdf[f"Puerto {port}"] = estado_texto
                sock.close()
                progress_bar.progress((i + 1) / len(puertos))

            st.markdown("---")
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
elif choice == "🌍 Auditoría de Cabeceras":
    st.subheader("🛡️ Análisis de Cabeceras de Seguridad")
    url = st.text_input("URL (con http/https)", "https://")

    if st.button("Analizar Cabeceras"):
        if url.startswith("http"):
            try:
                response = requests.get(url, timeout=10)
                headers = response.headers
                h_interes = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                             "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
                resultados_pdf = {"URL": url}

                for h in h_interes:
                    val = headers.get(h, "FALTANTE")
                    resultados_pdf[h] = val
                    if val != "FALTANTE":
                        st.success(f"✅ {h}: {val}")
                    else:
                        st.error(f"❌ {h}")

                st.download_button("📥 Descargar Reporte PDF", data=generar_pdf("Auditoria Web", resultados_pdf),
                                   file_name="cabeceras.pdf")
            except Exception as e:
                st.error(f"Error: {e}")

# --- SECCIÓN: AUDITORÍA DE INYECCIÓN ---
elif choice == "🌍 Auditoría de Inyección":
    st.subheader("💉 Prueba de Vulnerabilidad XSS (Reflejado)")
    st.write("""
    Esta herramienta verifica si un parámetro de una URL es vulnerable a Cross-Site Scripting.
    **Uso:** Ingresa la URL completa incluyendo el parámetro, por ejemplo: `http://tusitio.com/buscar.php?q=`
    """)

    target_url = st.text_input("URL del objetivo con parámetro", "http://")

    if st.button("Ejecutar Escaneo de Inyección"):
        if not target_url.startswith("http"):
            st.warning("Por favor, ingresa una URL válida.")
        elif "=" not in target_url:
            st.error("La URL debe contener un parámetro (ejemplo: ?id= o ?q=)")
        else:
            try:
                payloads = [
                    "<script>alert('XSS')</script>",
                    "'\"><script>alert(1)</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>"
                ]

                vulnerable = False
                resultados_pdf = {"URL Base": target_url}
                payloads_exitosos = []

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }

                target_url = target_url.strip()
                if not target_url.endswith("=") and "=" in target_url:
                    pass

                try:
                    with st.spinner("Probando payloads..."):
                        for i, payload in enumerate(payloads):
                            test_url = target_url.strip() + payload
                            response = requests.get(test_url, headers=headers, timeout=20)

                            if payload in response.text:
                                st.error(f"🚨 **VULNERABILIDAD DETECTADA** con: `{payload}`")
                                vulnerable = True
                                payloads_exitosos.append(payload)
                            else:
                                st.write(f"✅ Prueba {i + 1}: El payload fue filtrado.")

                except requests.exceptions.Timeout:
                    st.warning("⚠️ El servidor tarda demasiado en responder.")
                except requests.exceptions.ConnectionError:
                    st.error("❌ Error de conexión.")
                except Exception as e:
                    st.error(f"Error inesperado: {e}")

                if not vulnerable:
                    st.success("🎉 No se detectaron vulnerabilidades XSS básicas.")
                    resultados_pdf["Resultado Final"] = "Seguro"
                else:
                    st.warning(f"⚠️ Vulnerable a XSS con {len(payloads_exitosos)} payloads")
                    resultados_pdf["Resultado Final"] = "VULNERABLE"
                    resultados_pdf["Payloads que funcionaron"] = ", ".join(payloads_exitosos)

                st.markdown("---")
                pdf_data = generar_pdf("Reporte de Auditoria XSS", resultados_pdf)
                st.download_button(
                    label="📥 Descargar Reporte de Inyección",
                    data=pdf_data,
                    file_name="auditoria_xss.pdf",
                    mime="application/pdf"
                )

            except Exception as e:
                st.error(f"Error: {e}")

# --- SECCIÓN: LABORATORIO SQL ---
elif choice == "🌍 Laboratorio SQL":
    st.subheader("🗄️ Laboratorio de Inyección SQL y Prevención")
    st.info("Este módulo es interactivo y educativo. No realiza ataques reales, sino que simula cómo funcionan.")

    st.markdown("""
    ### 1. La Consulta Vulnerable
    Imagina que tienes un sistema de login en PHP con este código:
    """)

    st.code("""
// CÓDIGO INSEGURO
$id = $_GET['id'];
$query = "SELECT nombre, nota FROM alumnos WHERE id = " . $id;
    """, language="php")

    st.markdown("---")
    st.write("### 2. Simular un Ataque")
    input_usuario = st.text_input("Ingresa un ID de alumno (o intenta una inyección)", "1")

    query_final = f"SELECT nombre, nota FROM alumnos WHERE id = {input_usuario}"

    st.write("**Consulta que se ejecutaría en MySQL:**")
    st.warning(f"`{query_final}`")

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
    st.write("Para proteger tu sistema, nunca concatenes variables. Usa este estándar:")

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

# --- SECCIÓN: ESCÁNER DE DIRECTORIOS ---
elif choice == "🌍 Escáner de Directorios":
    st.subheader("📁 Escáner de Directorios Sensibles")
    st.write("Esta herramienta busca rutas comunes que podrían exponer información crítica del servidor.")

    target_web = st.text_input("Ingresa la URL base (ej: https://tusitio.com)", "https://")

    if st.button("Iniciar Escaneo de Rutas"):
        if not target_web.startswith("http"):
            st.error("Por favor, ingresa una URL válida.")
        else:
            rutas_sensibles = [
                "/.env", "/config.php", "/wp-config.php", "/.git/",
                "/backup.sql", "/db.sql", "/admin/", "/phpmyadmin/",
                "/.htaccess", "/server-status", "/robots.txt", "/api/v1/",
                "/.aws/", "/composer.json", "/package.json", "/.ssh/"
            ]

            encontrados = []
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

            with st.spinner("Escaneando directorios..."):
                barra_progreso = st.progress(0)

                for i, ruta in enumerate(rutas_sensibles):
                    url_final = target_web.rstrip('/') + ruta
                    try:
                        response = requests.get(url_final, headers=headers, timeout=5, allow_redirects=False)

                        if response.status_code == 200:
                            if "robots.txt" in url_final:
                                st.info(f"🤖 **Archivo de Rastreo:** {ruta} (Público por diseño)")
                            elif url_final.endswith(".php") and len(response.text.strip()) == 0:
                                st.info(f"✅ **Procesado correctamente:** {ruta} (No hay fuga de texto)")
                            elif response.url.rstrip('/') == target_web.rstrip('/'):
                                pass
                            else:
                                st.warning(f"⚠️ **Encontrado (Público):** {ruta}")
                                encontrados.append(f"{ruta} - Expuesto (200)")
                    except Exception:
                        pass

                    progreso = (i + 1) / len(rutas_sensibles)
                    barra_progreso.progress(progreso)

            st.markdown("---")
            if encontrados:
                st.success(f"Escaneo finalizado. Se detectaron {len(encontrados)} rutas de interés.")
            else:
                st.success("🎉 No se encontraron directorios sensibles comunes expuestos.")

            resultados_dir = {"URL": target_web,
                              "Rutas Detectadas": ", ".join(encontrados) if encontrados else "Ninguna"}
            pdf_data = generar_pdf("Reporte de Escaneo de Directorios", resultados_dir)
            st.download_button("📥 Descargar Reporte de Directorios", pdf_data, "auditoria_directorios.pdf",
                               "application/pdf")

# --- SECCIÓN: HASH DE ARCHIVO ---
elif choice == "📁 Hash de Archivo":
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
            with st.spinner("Calculando huella digital..."):
                file_bytes = uploaded_file.getvalue()
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

            st.markdown("### Resultado del Análisis:")
            st.info(f"**Nombre:** {uploaded_file.name}")
            st.code(sha256_hash, language="text")

            st.markdown(f"### [🔍 Consultar este Hash en VirusTotal](https://www.virustotal.com/gui/file/{sha256_hash})")
            st.caption("Verifica si este archivo ha sido analizado por motores de seguridad globales.")

            if sha256_hash in malware_db:
                st.error(f"🚨 **¡ALERTA!** Este hash coincide con: {malware_db[sha256_hash]}")
                estado_seguridad = f"ALERTA: Coincide con {malware_db[sha256_hash]}"
            else:
                st.success("✅ El archivo no coincide con ninguna amenaza conocida en la base local.")
                estado_seguridad = "Seguro (Sin coincidencias en base local)"

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

# --- SECCIÓN: DECODIFICADOR DE IPs ---
elif choice == "🌐 Decodificador de IPs":
    st.subheader("🕵️‍♂️ Decodificador de IPs Ofuscadas")
    st.write(
        "Esta herramienta revela la IP real detrás de direcciones ofuscadas en formato Hexadecimal, Octal o Decimal (técnicas comunes en Phishing).")

    url_ofuscada = st.text_input("Ingresa la URL o IP sospechosa:", placeholder="Ej: 185.0xC1.0x59.0x9E")

    if st.button("Revelar IP Real"):
        if url_ofuscada:
            try:
                host_sucio = url_ofuscada.replace("https://", "").replace("http://", "").split('/')[0]
                ip_binaria = socket.inet_aton(host_sucio)
                ip_real = socket.inet_ntoa(ip_binaria)

                st.success(f"📍 **IP Real Detectada:** `{ip_real}`")

                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"🔍 [Analizar en VirusTotal](https://www.virustotal.com/gui/ip-address/{ip_real})")
                with col2:
                    st.info(f"🌎 [Geolocalizar IP](https://ipinfo.io/{ip_real})")

            except Exception as e:
                st.error(f"No se pudo decodificar la dirección. Error: {e}")
        else:
            st.warning("Por favor, ingresa una dirección para analizar.")

# --- SECCIÓN: GESTOR SEGURO ---
elif choice == "🛡️ Gestor Seguro":
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

    caracteres_disponibles = ""
    if incluir_mayus: caracteres_disponibles += string.ascii_uppercase
    if incluir_minus: caracteres_disponibles += string.ascii_lowercase
    if incluir_nums: caracteres_disponibles += string.digits
    if incluir_simbolos: caracteres_disponibles += string.punctuation

    if st.button("Generar Contraseña"):
        if not caracteres_disponibles:
            st.error("❌ Debes seleccionar al menos un tipo de carácter.")
        else:
            password = "".join(random.choice(caracteres_disponibles) for _ in range(longitud))

            st.markdown("---")
            st.write("### Tu contraseña generada:")
            st.code(password, language="text")
            st.caption("Usa el botón de la esquina superior derecha del cuadro gris para copiar.")

            # Análisis de seguridad
            if longitud >= 16 and (incluir_mayus + incluir_minus + incluir_nums + incluir_simbolos >= 3):
                st.success("Nivel de seguridad: **Muy Fuerte** ✅")
            elif longitud >= 12:
                st.info("Nivel de seguridad: **Medio**")
            else:
                st.warning("Nivel de seguridad: **Bajo** (se recomienda aumentar la longitud)")

# --- SECCIÓN: ANÁLISIS VIRUSTOTAL ---
elif choice == "🛡️ Análisis VirusTotal":
    st.subheader("🔍 Análisis de Archivos con VirusTotal")
    st.write("""
    Sube un archivo para verificar su reputación en VirusTotal.
    **Nota:** Por razones de seguridad, solo se envía el hash del archivo, no el contenido completo.
    """)

    uploaded_file = st.file_uploader("Selecciona un archivo para analizar", type=None, key="vt_uploader")

    if uploaded_file is not None:
        try:
            # Calcular hash
            file_bytes = uploaded_file.getvalue()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()

            st.info(f"📁 Archivo: **{uploaded_file.name}**")
            st.info(f"🔑 Hash SHA-256: `{sha256_hash}`")

            # Enlace directo a VirusTotal
            st.markdown(f"### [🔍 Ver en VirusTotal](https://www.virustotal.com/gui/file/{sha256_hash})")

            # Intentar consultar la API (con API key opcional)
            api_key = st.text_input("API Key de VirusTotal (opcional)", type="password")

            if st.button("Consultar VirusTotal"):
                with st.spinner("Consultando VirusTotal..."):
                    if api_key:
                        resultado = consultar_virustotal(sha256_hash, api_key)
                        if resultado:
                            col1, col2, col3, col4, col5 = st.columns(5)
                            with col1:
                                st.metric("Malicioso", resultado.get('malicious', 0))
                            with col2:
                                st.metric("Sospechoso", resultado.get('suspicious', 0))
                            with col3:
                                st.metric("Limpiar", resultado.get('harmless', 0))
                            with col4:
                                st.metric("No detectado", resultado.get('undetected', 0))
                            with col5:
                                st.metric("Motores", resultado.get('total_engines', 0))

                            if resultado.get('malicious', 0) > 0:
                                st.error(
                                    f"🚨 **ALERTA:** {resultado['malicious']} motores detectaron este archivo como malicioso")
                            else:
                                st.success("✅ No se detectaron amenazas en VirusTotal")
                        else:
                            st.warning("No se pudo obtener información de VirusTotal")
                    else:
                        st.info(
                            "💡 Para consultar la API de VirusTotal, proporciona una API key. Mientras tanto, usa el enlace para ver los resultados manualmente.")

            # Guardar resultados para PDF
            resultados_pdf = {
                "Archivo": uploaded_file.name,
                "Hash SHA-256": sha256_hash,
                "Enlace VirusTotal": f"https://www.virustotal.com/gui/file/{sha256_hash}",
                "Estado": "Pendiente de verificación (usa el enlace para más información)"
            }

            pdf_data = generar_pdf("Análisis VirusTotal", resultados_pdf)
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_data,
                file_name=f"virustotal_{uploaded_file.name}.pdf",
                mime="application/pdf"
            )

        except Exception as e:
            st.error(f"Error al procesar el archivo: {e}")

# --- SECCIÓN: ANÁLISIS DE ENLACES ---
elif choice == "🔗 Análisis de Enlaces":
    st.subheader("🔗 Analizador de Enlaces Sospechosos")
    st.write("""
    Esta herramienta analiza URLs en busca de características sospechosas comunes en enlaces de phishing.
    """)

    url_analizar = st.text_input("Ingresa la URL a analizar:", placeholder="https://ejemplo.com")

    if st.button("Analizar Enlace"):
        if url_analizar:
            resultado = analizar_enlace(url_analizar)

            # Mostrar nivel de riesgo
            nivel = resultado['nivel']
            color = "risk-high" if nivel == "Alto" else "risk-medium" if nivel == "Medio" else "risk-low"
            st.markdown(f"### Nivel de Riesgo: <span class='{color}'>{nivel} ({resultado['puntaje']}%)</span>",
                        unsafe_allow_html=True)

            # Mostrar riesgos
            st.markdown("### 📋 Hallazgos:")
            for riesgo in resultado['riesgos']:
                st.write(riesgo)

            # Recomendación
            if resultado['puntaje'] >= 70:
                st.error("🚨 **Recomendación:** No accedas a este enlace. Es altamente sospechoso.")
            elif resultado['puntaje'] >= 40:
                st.warning("⚠️ **Recomendación:** Ten precaución. El enlace presenta características sospechosas.")
            else:
                st.success("✅ El enlace parece seguro, pero siempre verifica antes de hacer clic.")

            # Guardar resultados
            resultados_pdf = {
                "URL": url_analizar,
                "Nivel de Riesgo": f"{nivel} ({resultado['puntaje']}%)",
                "Hallazgos": "\n".join(resultado['riesgos'])
            }

            pdf_data = generar_pdf("Análisis de Enlaces Sospechosos", resultados_pdf)
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_data,
                file_name="analisis_enlace.pdf",
                mime="application/pdf"
            )
        else:
            st.warning("Por favor, ingresa una URL para analizar")

# --- SECCIÓN: VERIFICADOR DE CORREOS ---
elif choice == "✉️ Verificador de Correos":
    st.subheader("📧 Verificador de Correos Electrónicos")
    st.write("""
    Analiza direcciones de correo electrónico en busca de características sospechosas
    (dominios temporales, caracteres extraños, etc.)
    """)

    email_analizar = st.text_input("Ingresa el correo electrónico a verificar:", placeholder="usuario@ejemplo.com")

    if st.button("Verificar Correo"):
        if email_analizar:
            resultado = verificar_correo_sospechoso(email_analizar)

            # Mostrar nivel de riesgo
            nivel = resultado['nivel']
            color = "risk-high" if nivel == "Alto" else "risk-medium" if nivel == "Medio" else "risk-low"
            st.markdown(f"### Nivel de Riesgo: <span class='{color}'>{nivel} ({resultado['puntaje']}%)</span>",
                        unsafe_allow_html=True)

            # Mostrar hallazgos
            st.markdown("### 📋 Hallazgos:")
            for sospecha in resultado['sospechas']:
                st.write(sospecha)

            # Recomendación
            if resultado['puntaje'] >= 70:
                st.error("🚨 **Recomendación:** Este correo es muy sospechoso. No confíes en él.")
            elif resultado['puntaje'] >= 40:
                st.warning("⚠️ **Recomendación:** Ten precaución con este correo. Podría ser sospechoso.")
            else:
                st.success("✅ El correo parece normal, pero siempre verifica la fuente.")

            resultados_pdf = {
                "Correo": email_analizar,
                "Nivel de Riesgo": f"{nivel} ({resultado['puntaje']}%)",
                "Hallazgos": "\n".join(resultado['sospechas'])
            }

            pdf_data = generar_pdf("Verificación de Correos Sospechosos", resultados_pdf)
            st.download_button(
                label="📥 Descargar Reporte PDF",
                data=pdf_data,
                file_name="verificacion_correo.pdf",
                mime="application/pdf"
            )
        else:
            st.warning("Por favor, ingresa un correo electrónico para verificar")

# --- SECCIÓN: DNS LOOKUP ---
elif choice == "🌐 DNS Lookup":
    st.subheader("🌐 Consulta de Registros DNS")
    st.write("""
    Realiza consultas DNS para obtener información sobre un dominio.
    Útil para verificar la configuración de servidores y detectar posibles problemas.
    """)

    dominio_dns = st.text_input("Ingresa el dominio a consultar:", placeholder="ejemplo.com")

    if st.button("Consultar DNS"):
        if dominio_dns:
            try:
                resultados = verificar_dns(dominio_dns)

                for tipo, valor in resultados.items():
                    if tipo != 'error':
                        st.markdown(f"### 📍 Registros {tipo}:")
                        if isinstance(valor, list):
                            for v in valor:
                                st.code(v)
                        else:
                            st.code(valor)
                    else:
                        st.error(f"Error en DNS: {valor}")

                resultados_pdf = {
                    "Dominio": dominio_dns,
                    "Registros DNS": json.dumps(resultados, indent=2)
                }

                pdf_data = generar_pdf("Consulta DNS", resultados_pdf)
                st.download_button(
                    label="📥 Descargar Reporte PDF",
                    data=pdf_data,
                    file_name=f"dns_{dominio_dns}.pdf",
                    mime="application/pdf"
                )

            except Exception as e:
                st.error(f"Error al consultar DNS: {e}")
        else:
            st.warning("Por favor, ingresa un dominio para consultar")

# --- SECCIÓN: SCANNER DE VULNERABILIDADES WEB ---
elif choice == "🌍 Scanner de Vulnerabilidades Web":
    st.subheader("🛡️ Escáner de Vulnerabilidades Web")
    st.write("""
    Realiza un escaneo básico de vulnerabilidades comunes en sitios web:
    - Cabeceras de seguridad
    - Protocolos SSL/TLS
    - Información del servidor expuesta
    - Métodos HTTP permitidos
    """)

    url_scan = st.text_input("URL a escanear:", placeholder="https://ejemplo.com")

    if st.button("Iniciar Escaneo de Vulnerabilidades"):
        if url_scan:
            vulnerabilidades_encontradas = []
            resultados_pdf = {"URL": url_scan, "Análisis": []}

            with st.spinner("Escaneando vulnerabilidades..."):
                try:
                    # 1. Verificar cabeceras de seguridad
                    st.markdown("### 🔍 Analizando Cabeceras de Seguridad")
                    response = requests.get(url_scan, timeout=10)
                    headers = response.headers

                    cabeceras_importantes = {
                        "Content-Security-Policy": "CSP implementado",
                        "Strict-Transport-Security": "HSTS implementado",
                        "X-Frame-Options": "Protección contra clickjacking",
                        "X-Content-Type-Options": "Prevención de MIME sniffing",
                        "Referrer-Policy": "Política de referer"
                    }

                    for header, descripcion in cabeceras_importantes.items():
                        if header in headers:
                            st.success(f"✅ {header}: {headers[header]}")
                        else:
                            st.error(f"❌ {header} - {descripcion}")
                            vulnerabilidades_encontradas.append(f"{header} no configurado")

                    # 2. Verificar información del servidor
                    st.markdown("### 🖥️ Información del Servidor")
                    if 'Server' in headers:
                        st.info(f"Servidor: {headers['Server']}")
                        if "Apache" in headers['Server'] or "nginx" in headers['Server']:
                            st.warning(f"⚠️ Servidor {headers['Server']} expuesto. Considera ocultar esta información.")
                            vulnerabilidades_encontradas.append("Información del servidor expuesta")
                    else:
                        st.success("✅ Información del servidor oculta")

                    # 3. Verificar HTTPS
                    st.markdown("### 🔒 Seguridad SSL/TLS")
                    if url_scan.startswith("https://"):
                        st.success("✅ Conexión HTTPS segura")
                    else:
                        st.error("❌ No utiliza HTTPS. Conexión insegura.")
                        vulnerabilidades_encontradas.append("No utiliza HTTPS")

                    # 4. Verificar métodos HTTP permitidos
                    st.markdown("### 🔧 Métodos HTTP")
                    metodos_peligrosos = ["TRACE", "TRACK", "DELETE", "PUT"]
                    for metodo in metodos_peligrosos:
                        try:
                            req = requests.options(url_scan, timeout=5)
                            if metodo in req.headers.get('Allow', ''):
                                st.error(f"⚠️ Método {metodo} permitido")
                                vulnerabilidades_encontradas.append(f"Método {metodo} permitido")
                        except:
                            pass

                    # 5. Verificar cookies
                    st.markdown("### 🍪 Cookies")
                    if 'Set-Cookie' in headers:
                        cookies = headers['Set-Cookie']
                        if 'Secure' not in cookies:
                            st.warning("⚠️ Cookie no tiene flag 'Secure'")
                            vulnerabilidades_encontradas.append("Cookie sin flag Secure")
                        if 'HttpOnly' not in cookies:
                            st.warning("⚠️ Cookie no tiene flag 'HttpOnly'")
                            vulnerabilidades_encontradas.append("Cookie sin flag HttpOnly")
                    else:
                        st.info("ℹ️ No se encontraron cookies")

                    # Resumen
                    st.markdown("---")
                    st.markdown("### 📊 Resumen del Escaneo")

                    if vulnerabilidades_encontradas:
                        st.error(
                            f"🚨 Se encontraron {len(vulnerabilidades_encontradas)} vulnerabilidades/puntos de mejora:")
                        for vuln in vulnerabilidades_encontradas:
                            st.write(f"- {vuln}")
                    else:
                        st.success("🎉 No se encontraron vulnerabilidades críticas")

                    resultados_pdf["Análisis"] = "\n".join(
                        vulnerabilidades_encontradas) if vulnerabilidades_encontradas else "Sin vulnerabilidades críticas"

                    # Botón de reporte
                    pdf_data = generar_pdf("Reporte de Escaneo de Vulnerabilidades", resultados_pdf)
                    st.download_button(
                        label="📥 Descargar Reporte de Vulnerabilidades",
                        data=pdf_data,
                        file_name="escaneo_vulnerabilidades.pdf",
                        mime="application/pdf"
                    )

                except Exception as e:
                    st.error(f"Error al escanear: {e}")
        else:
            st.warning("Por favor, ingresa una URL para escanear")

# --- SECCIÓN: ANÁLISIS DE QR CODES ---
elif choice == "📁 Analizador de código QR":
    st.subheader("📱 Escáner y Analizador de Códigos QR")
    st.write("""
    Sube una imagen con un código QR para:
    - Decodificar su contenido
    - Verificar si enlaza a sitios maliciosos
    - Analizar la seguridad del enlace
    """)

    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        import io

        uploaded_qr = st.file_uploader("Sube imagen del QR Code", type=['png', 'jpg', 'jpeg', 'webp', 'bmp'])

        if uploaded_qr is not None:
            try:
                image = Image.open(io.BytesIO(uploaded_qr.getvalue()))
                decoded_objects = decode(image)

                if decoded_objects:
                    st.success(f"✅ Se encontraron {len(decoded_objects)} códigos QR")

                    for idx, obj in enumerate(decoded_objects, 1):
                        data = obj.data.decode('utf-8')
                        st.markdown(f"**QR #{idx}**")
                        st.code(data, language="text")

                        if data.startswith(('http://', 'https://')):
                            st.markdown("---")
                            st.markdown("### 🔗 Análisis del enlace")
                            resultado = analizar_enlace(data)

                            nivel = resultado['nivel']
                            color = "risk-high" if nivel == "Alto" else "risk-medium" if nivel == "Medio" else "risk-low"
                            st.markdown(
                                f"**Nivel de Riesgo:** <span class='{color}'>{nivel} ({resultado['puntaje']}%)</span>",
                                unsafe_allow_html=True)

                            for riesgo in resultado['riesgos']:
                                st.write(riesgo)

                            if resultado['puntaje'] >= 40:
                                st.warning(
                                    "⚠️ El QR Code enlaza a un sitio sospechoso. ¡No escanees códigos QR desconocidos!")
                            else:
                                st.success("✅ El enlace parece seguro")

                            resultados_pdf = {
                                "Contenido QR": data,
                                "Nivel de Riesgo": f"{nivel} ({resultado['puntaje']}%)",
                                "Hallazgos": "\n".join(resultado['riesgos'])
                            }

                            pdf_data = generar_pdf("Análisis de QR Code", resultados_pdf)
                            st.download_button(
                                label="📥 Descargar Reporte PDF",
                                data=pdf_data,
                                file_name="analisis_qr.pdf",
                                mime="application/pdf"
                            )
                        else:
                            st.info(f"ℹ️ El QR contiene texto plano (no es una URL): {data}")

                else:
                    st.error(
                        "❌ No se pudo decodificar el código QR. Asegúrate de que la imagen sea clara y contenga un QR válido.")

            except Exception as e:
                st.error(f"Error al procesar el QR: {e}")
                st.info("💡 Asegúrate de que el archivo sea una imagen válida con un código QR legible.")

    except ImportError as e:
        st.error("❌ Dependencias no instaladas")
        st.markdown("""
        Para usar esta función, necesitas instalar las siguientes librerías:

        ```bash
        pip install pillow pyzbar
        """)

# --- SECCIÓN: VERIFICADOR DE CONTRASEÑAS ROBADAS ---
elif choice == "🛡️ Verificador de Contraseñas":
    st.subheader("🔐 ¿Tu contraseña ha sido comprometida?")
    st.write("""
    Esta herramienta verifica si tu contraseña ha aparecido en filtraciones de datos
    usando el servicio Have I Been Pwned (API de k-anonimidad).
    **Nota:** Tu contraseña nunca se envía completa, solo los primeros 5 caracteres del hash.
    """)

    password = st.text_input("Ingresa la contraseña a verificar:", type="password")

    if st.button("Verificar si ha sido comprometida"):
        if password:
            try:
                sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
                prefix = sha1_hash[:5]
                suffix = sha1_hash[5:]

                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                response = requests.get(url)

                if response.status_code == 200:
                    hashes = response.text.split('\n')
                    encontrado = False

                    for h in hashes:
                        if h.startswith(suffix):
                            count = int(h.split(':')[1])
                            encontrado = True
                            st.error(f"🚨 ¡ALERTA! Esta contraseña ha sido filtrada {count} veces!")
                            st.info("💡 **Recomendación:** Cambia esta contraseña inmediatamente y no la uses en otros sitios.")
                            break

                    if not encontrado:
                        st.success("✅ ¡Buena noticia! Esta contraseña no ha sido encontrada en filtraciones conocidas.")
                else:
                    st.error("Error al consultar la API")

            except Exception as e:
                st.error(f"Error: {e}")
# --- SECCIÓN: GEOLOCALIZACIÓN DE IPS ---
elif choice == "🌐 Geolocalización de IPs":
    st.subheader("🌍 Geolocalización y Análisis de IP")
    st.write("""
    Obtén información detallada sobre una dirección IP:
    - Ubicación geográfica
    - ISP/Proveedor
    - Coordenadas
    - Mapa interactivo
    """)

    ip_geo = st.text_input("Ingresa la IP a geolocalizar:", placeholder="8.8.8.8")

    if st.button("Geolocalizar IP"):
        if ip_geo:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip_geo}")
                data = response.json()

                if data.get('status') == 'success':
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("### 📍 Información de Ubicación")
                        st.write(f"**País:** {data.get('country', 'N/A')}")
                        st.write(f"**Región:** {data.get('regionName', 'N/A')}")
                        st.write(f"**Ciudad:** {data.get('city', 'N/A')}")
                        st.write(f"**Código Postal:** {data.get('zip', 'N/A')}")
                        st.write(f"**Coordenadas:** {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")

                    with col2:
                        st.markdown("### 🌐 Información de Red")
                        st.write(f"**ISP:** {data.get('isp', 'N/A')}")
                        st.write(f"**Organización:** {data.get('org', 'N/A')}")
                        st.write(f"**AS:** {data.get('as', 'N/A')}")
                        st.write(f"**Zona Horaria:** {data.get('timezone', 'N/A')}")
                        st.write(f"**Código País:** {data.get('countryCode', 'N/A')}")

                    if data.get('lat') and data.get('lon'):
                        st.markdown("### 🗺️ Ubicación en el Mapa")
                        st.map({
                            "lat": [data['lat']],
                            "lon": [data['lon']]
                        })

                    st.markdown("### 🔍 Análisis adicional")
                    col3, col4 = st.columns(2)
                    with col3:
                        st.info(f"🔍 [VirusTotal IP](https://www.virustotal.com/gui/ip-address/{ip_geo})")
                    with col4:
                        st.info(f"🌎 [IP Info](https://ipinfo.io/{ip_geo})")

                else:
                    st.error("No se pudo geolocalizar la IP")

            except Exception as e:
                st.error(f"Error: {e}")
# --- SECCIÓN: ANÁLISIS DE METADATOS ---
elif choice == "📁 Análisis de Metadatos":
    st.subheader("📊 Análisis Forense de Metadatos")
    st.write("""
    Extrae y analiza metadatos ocultos de archivos:
    - Fotos (EXIF)
    - Documentos PDF
    - Imágenes (GPS, fecha, modelo de cámara)
    """)

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        uploaded_meta = st.file_uploader("Sube un archivo para analizar",
                                         type=['jpg', 'jpeg', 'png', 'pdf', 'docx'])

        if uploaded_meta is not None:
            try:
                # --- ANÁLISIS DE IMÁGENES ---
                if uploaded_meta.type in ['image/jpeg', 'image/png']:
                    image = Image.open(uploaded_meta)
                    exifdata = image.getexif()

                    st.markdown("### 🖼️ Metadatos de la Imagen")

                    if exifdata:
                        for tag_id, value in exifdata.items():
                            tag = TAGS.get(tag_id, tag_id)

                            # --- CORRECCIÓN PARA DATOS BINARIOS ---
                            # Si es GPS o MakerNote (que suelen ser binarios complejos)
                            if tag in ['GPSInfo', 'MakerNote']:
                                st.info(f"**{tag}:** [Datos binarios complejos. Requiere decodificación externa]")

                            # Si el valor es un objeto 'bytes' (como el 59932 que te salió)
                            elif isinstance(value, bytes):
                                # Muestra solo los primeros 20 bytes para no saturar la pantalla
                                st.write(f"**{tag}:** [Datos binarios (primeros 20 bytes): {value[:20]}]")
                                # Si prefieres ocultarlo del todo, usa esta línea en vez de la de arriba:
                                # st.write(f"**{tag}:** [Dato binario no legible]")

                            # Si el valor es texto o números, lo mostramos normal
                            else:
                                st.write(f"**{tag}:** {value}")
                    else:
                        st.info("No se encontraron metadatos EXIF")

                # --- ANÁLISIS DE PDF ---
                elif uploaded_meta.type == 'application/pdf':
                    try:
                        import PyPDF2

                        pdf_reader = PyPDF2.PdfReader(uploaded_meta)

                        st.markdown("### 📄 Metadatos del PDF")
                        info = pdf_reader.metadata
                        if info:
                            for key, value in info.items():
                                st.write(f"**{key}:** {value}")
                        else:
                            st.info("No se encontraron metadatos")
                    except ImportError:
                        st.warning("Instala PyPDF2: pip install PyPDF2")

                # --- OTROS ARCHIVOS ---
                else:
                    st.markdown("### 📦 Metadatos del Archivo")
                    st.info(f"**Nombre:** {uploaded_meta.name}")
                    st.info(f"**Tamaño:** {len(uploaded_meta.getvalue())} bytes")
                    st.info(f"**Tipo:** {uploaded_meta.type}")

            except Exception as e:
                st.error(f"Error al analizar metadatos: {e}")

    except ImportError:
        st.warning("Instala Pillow: pip install pillow")
# --- SECCIÓN: VERIFICADOR SSL ---
elif choice == "🌍 Verificador SSL":
    st.subheader("🔒 Verificador de Certificados SSL/TLS")
    st.write("""
    Analiza la seguridad y validez de certificados SSL de sitios web.
    """)

    dominio_ssl = st.text_input("Ingresa el dominio a verificar SIN HTTPS:", placeholder="ejemplo.com")

    if st.button("Verificar Certificado SSL"):
        if dominio_ssl:
            try:
                import ssl
                import socket
                from datetime import datetime

                context = ssl.create_default_context()
                with socket.create_connection((dominio_ssl, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=dominio_ssl) as ssock:
                        cert = ssock.getpeercert()

                st.markdown("### 📋 Información del Certificado")

                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Emisor:**")
                    st.code(str(cert.get('issuer', 'N/A')))
                    st.write("**Sujeto:**")
                    st.code(str(cert.get('subject', 'N/A')))

                with col2:
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                    st.write("**Válido desde:**")
                    st.write(not_before.strftime('%d/%m/%Y %H:%M:%S'))
                    st.write("**Válido hasta:**")
                    st.write(not_after.strftime('%d/%m/%Y %H:%M:%S'))

                    hoy = datetime.now()
                    if hoy > not_after:
                        st.error("❌ ¡CERTIFICADO EXPIRADO!")
                    elif (not_after - hoy).days < 30:
                        st.warning(f"⚠️ El certificado expira en {(not_after - hoy).days} días")
                    else:
                        st.success(f"✅ Certificado válido por {(not_after - hoy).days} días")

                st.markdown("### 🔍 Detalles Técnicos")
                st.write(f"**Versión:** {cert.get('version', 'N/A')}")
                st.write(f"**Número de Serie:** {cert.get('serialNumber', 'N/A')}")

                st.info(f"🔍 [Verificar en SSL Labs](https://www.ssllabs.com/ssltest/analyze.html?d={dominio_ssl})")

            except Exception as e:
                st.error(f"Error al verificar certificado: {e}")
# --- SECCIÓN: GENERADOR DE REPORTES ---
elif choice == "📁 Generador de Reportes":
    st.subheader("📊 Generador de Reportes de Seguridad")
    st.write("""
    Genera un reporte completo de seguridad combinando múltiples análisis:
    - Escaneo de puertos
    - Análisis de cabeceras
    - Verificación SSL
    - Análisis de DNS
    """)

    target_report = st.text_input("URL o dominio para análisis completo:", placeholder="ejemplo.com")

    if st.button("Generar Reporte Completo"):
        if target_report:
            with st.spinner("Generando reporte completo de seguridad..."):
                resultados = {
                    "Target": target_report,
                    "Fecha": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    "Análisis": {}
                }

                clean_target = target_report.replace('https://', '').replace('http://', '').split('/')[0]

                try:
                    if not target_report.startswith('http'):
                        target_report = 'https://' + target_report
                    response = requests.get(target_report, timeout=10)
                    resultados["Análisis"]["Cabeceras"] = dict(response.headers)
                    resultados["Análisis"]["Estado"] = response.status_code
                except:
                    resultados["Análisis"]["Cabeceras"] = "Error al obtener cabeceras"

                try:
                    import ssl, socket
                    context = ssl.create_default_context()
                    with socket.create_connection((clean_target, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=clean_target) as ssock:
                            cert = ssock.getpeercert()
                            resultados["Análisis"]["SSL"] = "Certificado válido"
                except:
                    resultados["Análisis"]["SSL"] = "Error al verificar SSL o no usa HTTPS"

                try:
                    puertos_comunes = [80, 443, 21, 22, 25, 3306]
                    puertos_abiertos = []
                    ip = socket.gethostbyname(clean_target)

                    for port in puertos_comunes:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        socket.setdefaulttimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            puertos_abiertos.append(port)
                        sock.close()

                    resultados["Análisis"]["Puertos_Abiertos"] = puertos_abiertos
                except:
                    resultados["Análisis"]["Puertos_Abiertos"] = "Error en escaneo de puertos"

                st.success("✅ Reporte generado correctamente")
                st.json(resultados)

                pdf_data = generar_pdf("Reporte Completo de Seguridad", resultados)
                st.download_button(
                    label="📥 Descargar Reporte Completo PDF",
                    data=pdf_data,
                    file_name=f"reporte_seguridad_{clean_target}.pdf",
                    mime="application/pdf"
                )
# --- SECCIÓN: DETECTOR DE ARCHIVOS MALICIOSOS ---
elif choice == "🛡️ Detector de Malware":
    st.subheader("🛡️ Detección de Archivos Maliciosos")
    st.write("""
    Analiza archivos sospechosos utilizando:
    - Firmas YARA (básico)
    - Análisis de extensión
    - Verificación de hash en bases de datos
    """)

    file_malware = st.file_uploader("Sube archivo para análisis", type=None)

    if file_malware is not None:
        firmas_malware = {
            b'<?php eval': "PHP Shell",
            b'<?php system': "PHP Backdoor",
            b'<script>alert': "XSS Payload",
            b'eval(base64_decode': "PHP Encoded Malware",
            b'powershell -e': "PowerShell Encoded",
            b'cmd.exe /c': "Windows Command",
            b'<?= eval': "PHP Short Tag Malware",
            b'exec(': "PHP Exec Function",
            b'shell_exec(': "PHP Shell Exec"
        }

        file_content = file_malware.getvalue()
        extension = file_malware.name.split('.')[-1].lower()

        st.markdown("### 🔍 Análisis del Archivo")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Nombre", file_malware.name)
        with col2:
            st.metric("Tamaño", f"{len(file_content)} bytes")

        ext_peligrosas = ['exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js', 'jar', 'apk']

        if extension in ext_peligrosas:
            st.warning(f"⚠️ Extensión '{extension}' potencialmente peligrosa")

        st.markdown("### 🦠 Análisis de Firmas")
        encontrado = False
        for firma, nombre in firmas_malware.items():
            if firma in file_content[:1000]:
                st.error(f"🚨 **¡ALERTA!** Firmas de {nombre} detectadas")
                encontrado = True

        if not encontrado:
            st.success("✅ No se detectaron firmas maliciosas comunes")

        sha256 = hashlib.sha256(file_content).hexdigest()
        st.markdown("### 🔑 Hash del Archivo")
        st.code(sha256)
        st.markdown(f"[🔍 Verificar en VirusTotal](https://www.virustotal.com/gui/file/{sha256})")

