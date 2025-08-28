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

# --- Enhanced Session Restoration with Security Middleware ---
def restore_session_from_cookie():
    """
    Enhanced session restoration using the new security middleware.
    This function now uses the enhanced SessionManager for secure session handling.
    """
    try:
        # Import here to avoid circular imports
        from auth.security_middleware import initialize_security_system
        
        # Initialize the enhanced security system
        initialize_security_system()
        
        log.info("Enhanced session restoration completed")
        
    except Exception as e:
        log.error(f"Error during enhanced session restoration: {e}", exc_info=True)
        # Clear session state if restoration fails
        st.session_state.clear()
        st.session_state.update({
            'authenticated': False,
            'username': None,
            'user_id': None,
            'role_name': None,
            'permissions': set()
        })

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

# --- Enhanced Sidebar with Security Features ---
def render_sidebar():
    """
    Enhanced sidebar with security monitoring and session management
    """
    try:
        with st.sidebar:
            # 1. Show logo if configured
            logo_sidebar_url = get_configuration('logo_url', 'general', None)
            if logo_sidebar_url:
                st.image(logo_sidebar_url, width='stretch')
                st.divider()

            # 2. Security Status (NEW)
            if st.session_state.get('authenticated', False):
                username = st.session_state.get('username', 'N/A')
                role_name = st.session_state.get('role_name', 'N/A')
                
                # Security indicator
                st.success("🔐 **Sesión Segura**")
                st.caption(f"👤 {username} | 🎭 {role_name}")
                
                # Session timeout warning (NEW)
                try:
                    from utils.session_ui import SessionUI
                    SessionUI.show_session_timeout_warning()
                except ImportError:
                    pass  # Fallback if session_ui is not available
                
                st.divider()

            # 3. Menu structure
            SECTIONS = {
                "AGENTES": [
                    "Agentes IA",
                    "Gestión de agentes IA", 
                    "Historial de Conversaciones",
                ],
                "ADMINISTRACIÓN": [
                    "Gestión de Usuarios",
                    "Roles",
                    "Control de Acceso",
                    "Configuración",
                ],
                "USUARIO": [
                    "Mi Perfil",
                ]
            }

            # 4. Generate filtered page links
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

            # 5. User information (session details removed as auto-refresh is handled automatically)
            # The session is automatically managed and refreshed in the background

            st.markdown("---")

            # 6. Enhanced logout button
            if st.button("🚪 Cerrar Sesión", key="logout_sidebar_button", width='stretch', type="primary"):
                logout()
                
    except Exception as e:
        log.error(f"Error rendering enhanced sidebar: {e}", exc_info=True)
        # Fallback to basic sidebar
        with st.sidebar:
            st.error("Error en el sidebar. Usando versión básica.")
            if st.button("🚪 Cerrar Sesión", key="fallback_logout"):
                logout()