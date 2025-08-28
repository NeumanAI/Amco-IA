import streamlit as st
import re
from typing import Optional

# Importaciones necesarias para la función del sidebar
from datetime import datetime
import pytz
from .config import get_configuration
from .cookies import get_session_cookie
from auth.auth import show_login_page, logout # Importar función logout
from auth.auth import check_authentication
from auth.auth import logout
import logging

log = logging.getLogger(__name__)

# --- Mapeo de Permisos a Archivos de Página ---
# Clave: Nombre exacto del permiso (como en la BD/Roles)
# Valor: Ruta relativa del archivo .py en la carpeta pages/
PAGE_PERMISSION_MAP = {
    "Agentes IA": "pages/01_Agentes_IA.py",
    "Gestión de agentes IA": "pages/02_Gestion_Agentes_IA.py",
    "Historial de Conversaciones": "pages/03_Historial_Conversaciones.py",
    "Análisis de Consultas": "pages/04_Analisis_Consultas.py",
    "Monitoreo": "pages/05_Monitoreo.py",
    "Gestión de Usuarios": "pages/06_Gestion_Usuarios.py",
    "Roles": "pages/07_Roles.py",
    "Configuración": "pages/08_Configuracion.py",
    "Mi Perfil": "pages/09_Mi_Perfil.py",
    "Control de Acceso": "pages/10_Control_Acceso_Agentes.py",
}

# --- NUEVA FUNCIÓN VITAL PARA RESTAURAR LA SESIÓN ---
def restore_session_from_cookie():
    """
    Comprueba si existe una cookie de sesión y restaura el estado de la sesión si existe
    y el usuario no está ya autenticado en la ejecución actual.
    Debe llamarse al principio de CADA script de página.
    """
    # Si la sesión ya está autenticada en esta ejecución, no hagas nada.
    if st.session_state.get('authenticated', False):
        return

    cookie_data = get_session_cookie()
    if cookie_data:
        log.info("Intentando restaurar la sesión desde la cookie.")
        try:
            # Restaurar los datos del usuario desde la cookie
            st.session_state['authenticated'] = cookie_data.get('authenticated', False)
            st.session_state['username'] = cookie_data.get('username')
            st.session_state['user_id'] = cookie_data.get('user_id')
            st.session_state['role_name'] = cookie_data.get('role_name')
            # Asegurarse de que los permisos se restauren como un conjunto (set)
            st.session_state['permissions'] = set(cookie_data.get('permissions', []))
            
            # Actualizar la última actividad para prevenir un timeout inmediato
            try:
                tz_str = get_configuration('timezone', 'general', 'America/Bogota')
                colombia_tz = pytz.timezone(tz_str)
            except Exception:
                colombia_tz = pytz.timezone('America/Bogota')
            st.session_state['last_activity_time'] = datetime.now(colombia_tz)

            log.info(f"Sesión para el usuario '{st.session_state.get('username')}' restaurada correctamente.")
        except Exception as e:
            log.error(f"Fallo al restaurar la sesión desde la cookie: {e}", exc_info=True)
            # Limpiar el estado de sesión si la restauración falla para forzar un nuevo login
            st.session_state.clear()

# --- Funciones existentes ---
def is_valid_email(email: Optional[str]) -> bool:
    if not email:
        return False
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.fullmatch(pattern, email) is not None

def show_dev_placeholder(page_title: str):
    st.warning(f"🚧 La sección **'{page_title}'** aún está en desarrollo.", icon="🛠️")
    st.markdown("Las funcionalidades principales para esta área se implementarán próximamente.")
    st.info("Si tienes ideas o requisitos específicos para esta sección, por favor comunícalos.")

# --- NUEVA FUNCIÓN PARA RENDERIZAR SIDEBAR ---
def render_sidebar():
    """
    Renderiza el contenido completo del sidebar, incluyendo logo,
    enlaces de página filtrados por permisos, información de usuario
    y botón de logout.
    """
    with st.sidebar:
        # 1. Mostrar logo si está configurado (CON PARÁMETRO CORREGIDO)
        logo_sidebar_url = get_configuration('logo_url', 'general', None)
        if logo_sidebar_url:
            st.image(logo_sidebar_url, width='stretch') # <-- CORRECCIÓN 3
            st.divider()

        # 2. Definir la estructura del menú (secciones y páginas)
        SECTIONS = {
            "AGENTES": [
                "Agentes IA",
                "Gestión de agentes IA",
                "Historial de Conversaciones",
                "Análisis de Consultas",
            ],
            "HERRAMIENTAS": [
                "Monitoreo",
                "Gestión de Usuarios",
                "Roles",
                "Configuración",
                "Mi Perfil",
            ]
        }

        # 3. Generar enlaces de página filtrados por permisos
        user_permissions = st.session_state.get('permissions', set())
        log.debug(f"Rendering sidebar for user '{st.session_state.get('username')}' with permissions: {user_permissions}")

        for section_title, page_names in SECTIONS.items():
            st.markdown(f"**{section_title}**")
            for page_name in page_names:
                if page_name in PAGE_PERMISSION_MAP:
                    page_path = PAGE_PERMISSION_MAP[page_name]
                    if page_name in user_permissions:
                        st.page_link(page_path, label=page_name, icon=None)
                        log.debug(f"  - Allowed: {page_name} (Path: {page_path}) under {section_title}")
                    else:
                        log.debug(f"  - Denied: {page_name} (Path: {page_path}) under {section_title} due to missing permission")
                else:
                    log.warning(f"  - Config Error: Page '{page_name}' in SECTIONS but not in PAGE_PERMISSION_MAP.")

        st.markdown("---")

        # 4. Mostrar información del usuario logueado
        st.markdown(f"👤 **Usuario:** {st.session_state.get('username', 'N/A')}")
        st.markdown(f"🎭 **Rol:** {st.session_state.get('role_name', 'N/A')}")

        st.markdown("---")

        # 6. Botón de Cerrar Sesión (usando la función logout importada)
        if st.button("🚪 Cerrar Sesión", key="logout_sidebar_button", width='stretch', type="primary"):
            logout()