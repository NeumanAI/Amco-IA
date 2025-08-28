# --- auth/auth.py (ENHANCED - Integrated with Security Middleware) ---

import streamlit as st
import hashlib
import bcrypt
from datetime import datetime, timedelta
import re
import pytz
import uuid
import time
from sqlalchemy.orm import joinedload
from typing import Optional, Dict, Any, Tuple, Set, List
import logging

# Enhanced security imports
from auth.security_middleware import (
    SessionManager, TokenManager, SecureStorage, SecurityConfig,
    requires_authentication, requires_permission, requires_role,
    initialize_security_system, get_session_timeout_info
)

# Importar desde los nuevos módulos
from database.database import (
    get_db_session, get_user_accessible_agents, check_user_agent_access
)
from database.models import User, Role
from utils.config import get_configuration
from utils.styles import get_login_page_style

log = logging.getLogger(__name__)

# --- Constantes y Configuración (Sin cambios) ---
try:
    DEFAULT_TIMEZONE = get_configuration('timezone', 'general', 'America/Bogota')
    colombia_tz = pytz.timezone(DEFAULT_TIMEZONE if DEFAULT_TIMEZONE else 'America/Bogota')
except Exception as e:
    log.warning(f"Failed getting/setting timezone config: {e}. Using America/Bogota")
    colombia_tz = pytz.timezone('America/Bogota')

# --- Enhanced Password Functions with bcrypt ---
def hash_password(password: str) -> str:
    """Hash password using bcrypt for enhanced security"""
    try:
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        log.error(f"Error hashing password: {e}")
        # Fallback to SHA256 for compatibility
        return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against hash using bcrypt"""
    try:
        # Try bcrypt first
        if hashed_password.startswith('$2b$'):
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        else:
            # Fallback to SHA256 for legacy passwords
            return hashlib.sha256(password.encode()).hexdigest() == hashed_password
    except Exception as e:
        log.error(f"Error verifying password: {e}")
        return False

def get_security_config_values():
    """Get security configuration values - now uses SecurityConfig class"""
    try:
        password_reqs = SecurityConfig.get_password_requirements()
        session_timeout = SecurityConfig.get_session_timeout()
        
        return {
            'password_min_length': password_reqs['min_length'],
            'password_require_special': password_reqs['require_special'],
            'password_require_numbers': password_reqs['require_numbers'],
            'password_require_uppercase': password_reqs['require_uppercase'],
            'session_timeout': session_timeout
        }
    except Exception as e:
        log.error(f"Error getting security config: {e}")
        return {
            'password_min_length': 8,
            'password_require_special': True,
            'password_require_numbers': True,
            'password_require_uppercase': True,
            'session_timeout': 30
        }

def validate_password(password, security_config=None):
    if not password: return False, "Contraseña vacía."
    if security_config is None: security_config = get_security_config_values()
    min_length = security_config['password_min_length']; req_spec = security_config['password_require_special']; req_num = security_config['password_require_numbers']; req_upper = security_config['password_require_uppercase']
    if len(password) < min_length: return False, f"Mín {min_length} chars."
    if req_spec and not re.search(r"\W", password): return False, "Requiere especial."
    if req_num and not any(c.isdigit() for c in password): return False, "Requiere número."
    if req_upper and not any(c.isupper() for c in password): return False, "Requiere mayúscula."
    return True, "Válida."

# --- Enhanced Session State Management ---
def init_session_state():
    """Initialize session state with enhanced security"""
    try:
        # Initialize the enhanced security system
        initialize_security_system()
        
        now_with_tz = datetime.now(colombia_tz)
        defaults = {
            'authenticated': False, 'username': None, 'user_id': None, 'role_name': None, 
            'permissions': set(), 'last_activity_time': now_with_tz, 'user_action': None, 
            'editing_user_id': None, 'deleting_user_id': None, 'role_action': None, 
            'editing_role_name': None, 'deleting_role_name': None, 'agent_action': None, 
            'editing_agent_id': None, 'deleting_agent_id': None, 'selected_agent_id': None, 
            'selected_agent_name': None, 'chat_messages': [], 'current_chat_agent_id': None, 
            'chat_session_id': None, 'chat_selected_agent_chat_url': None, 
            'selected_agent_id_for_crud': None, 'selected_role_id_for_crud': None
        }
        
        # Initialize defaults if not already set
        for key, default_value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = default_value
            elif key == 'last_activity_time':
                current_time_val = st.session_state.get(key)
                if not isinstance(current_time_val, datetime) or current_time_val.tzinfo is None:
                    st.session_state[key] = now_with_tz
                    
        log.info("Session state initialized with enhanced security")
        
    except Exception as e:
        log.error(f"Error initializing session state: {e}", exc_info=True)

def update_last_activity():
    """Update last activity timestamp - now uses SessionManager"""
    try:
        SessionManager.update_activity()
    except Exception as e:
        log.error(f"Error updating activity: {e}")
        st.session_state['last_activity_time'] = datetime.now(colombia_tz)

def check_session_timeout():
    """Check session timeout - now uses enhanced SessionManager"""
    try:
        return not SessionManager.validate_session()
    except Exception as e:
        log.error(f"Error checking session timeout: {e}")
        return True

def check_authentication():
    """Enhanced authentication check using SessionManager"""
    try:
        return SessionManager.validate_session()
    except Exception as e:
        log.error(f"Error checking authentication: {e}")
        return False

# --- Enhanced Authentication with bcrypt ---
def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Enhanced user authentication with bcrypt password verification"""
    try:
        with get_db_session() as db:
            user = db.query(User).options(joinedload(User.role)).filter(User.username == username).first()
            
            if not user:
                log.warning(f"Authentication attempt for non-existent user: {username}")
                return False, None, "Usuario o contraseña incorrectos."
            
            # Enhanced password verification
            if not verify_password(password, user.password):
                log.warning(f"Failed password verification for user: {username}")
                return False, None, "Usuario o contraseña incorrectos."
            
            if user.status != 'active':
                log.warning(f"Authentication attempt for inactive user: {username}")
                return False, None, "Cuenta inactiva."
            
            # Update last access
            user.last_access = datetime.now(colombia_tz)
            
            # Get user permissions
            perms = set()
            role_name = "N/A"
            if user.role:
                role_name = user.role.name
                perms = set(p.strip() for p in (user.role.permissions or '').split(',') if p.strip())
            
            user_info = {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "role_name": role_name,
                "permissions": perms
            }
            
            log.info(f"User '{username}' authenticated successfully")
            return True, user_info, None
            
    except Exception as e:
        log.error(f"Database error during authentication for user {username}: {e}", exc_info=True)
        return False, None, "Error interno del servidor."

# --- Función de Login Page (MODIFICADA para usar st.switch_page) ---
def show_login_page():
    st.markdown(get_login_page_style(), unsafe_allow_html=True)
    _, col_login, _ = st.columns([1, 1.5, 1])
    with col_login:
        logo_url = get_configuration('logo_url', 'general', '')
        if logo_url: st.markdown(f'<div style="text-align:center;"><img src="{logo_url}" style="max-width:350px;height:auto;margin-bottom:1rem;"></div>', unsafe_allow_html=True)

        # Obtener el nombre del dashboard dinámicamente
        APP_TITLE_DEFAULT = "IA-AMCO Dashboard" # Default en caso de que no se encuentre en la config
        try:
            # Intentar obtener el nombre del dashboard desde la configuración
            # Nota: get_db_session() podría ser necesario si get_configuration no maneja su propia sesión
            # y estamos fuera de un contexto de sesión activa (lo cual es probable en show_login_page si aún no hay sesión de BD).
            # Por ahora, asumimos que get_configuration puede manejar esto o que la conexión es implícita.
            dynamic_dashboard_name = get_configuration('dashboard_name', 'general', APP_TITLE_DEFAULT)
            if not dynamic_dashboard_name: # Asegurarse de que no sea None o vacío
                dynamic_dashboard_name = APP_TITLE_DEFAULT
        except Exception as e:
            log.error(f"Error getting dashboard name for login page: {e}. Using default.")
            dynamic_dashboard_name = APP_TITLE_DEFAULT

        st.markdown(f"<h2 class='login-header-title'>{dynamic_dashboard_name}</h2>", unsafe_allow_html=True)
        st.markdown("<p class='login-header-subtitle'>Administración de agentes IA</p>", unsafe_allow_html=True)
        st.markdown('<div style="height:1.5rem;"></div>', unsafe_allow_html=True)
        with st.container(): # Caja login
            st.markdown("<h3 class='login-box-title'>Acceso</h3>", unsafe_allow_html=True)
            st.markdown("<p class='login-box-subtitle'>Ingrese sus credenciales</p>", unsafe_allow_html=True)
            with st.form("login_form"):
                username = st.text_input("Usuario", key="login_username", placeholder="Usuario", label_visibility="collapsed")
                password = st.text_input("Contraseña", type="password", key="login_password", placeholder="Contraseña", label_visibility="collapsed")
                st.markdown('<div style="height: 0.5rem;"></div>', unsafe_allow_html=True)
                submitted = st.form_submit_button("Iniciar Sesión", width='stretch')
                if submitted:
                    if not username or not password: st.error("Ingrese usuario y contraseña.")
                    else:
                        with st.spinner("Autenticando..."):
                            authenticated, user_info, error_msg = authenticate_user(username, password)
                        if authenticated:
                            # Create secure session using SessionManager
                            if SessionManager.create_session(user_info):
                                # Clear any temporary state
                                for key in ['user_action','role_action','agent_action']: 
                                    st.session_state.pop(key, None)
                                
                                st.success("🔐 Inicio de sesión exitoso...")
                                time.sleep(0.5)
                                
                                try:
                                    st.switch_page("pages/01_Agentes_IA.py")
                                except Exception as e_switch:
                                    log.error(f"Failed to switch page after login: {e_switch}")
                                    st.rerun()
                            else:
                                st.error("Error al crear la sesión segura. Intente nuevamente.")
                        else: 
                            st.error(error_msg or "Usuario o contraseña incorrectos.")

# --- Enhanced Logout with SessionManager ---
def logout(silent: bool = False, message: str = "Sesión cerrada correctamente."):
    """Enhanced logout using SessionManager"""
    try:
        username = st.session_state.get('username', 'N/A')
        log.info(f"Logging out user '{username}'...")
        
        # Use SessionManager to securely destroy session
        SessionManager.destroy_session(message if not silent else None)
        
        # Force page reload after logout
        if not silent:
            time.sleep(0.5)
        st.rerun()
        
    except Exception as e:
        log.error(f"Error during logout: {e}", exc_info=True)
        # Fallback cleanup
        st.session_state.clear()
        st.session_state.update({
            'authenticated': False,
            'username': None,
            'user_id': None,
            'role_name': None,
            'permissions': set()
        })
        if not silent:
            st.success("Sesión cerrada.")
        st.rerun()

# --- Decoradores ---
def requires_permission(permission_name):
    """
    Decorador refactorizado para verificar permisos.
    Confía en que `restore_session_from_cookie()` ya se ha ejecutado
    al inicio de cada script de página.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # 1. Chequeo de autenticación directo sobre el session_state.
            # Se asume que restore_session_from_cookie() ya fue llamado.
            if not st.session_state.get('authenticated', False):
                log.info(f"Permission Check ({permission_name}): User not authenticated. Showing login page.")
                show_login_page()
                st.stop()

            # 2. Chequeo de timeout de sesión
            if check_session_timeout():
                log.info(f"Permission Check ({permission_name}): Session timeout detected.")
                st.stop()

            # 3. Chequeo de permisos
            user_permissions = st.session_state.get('permissions', set())
            if permission_name not in user_permissions:
                log.warning(f"Access Denied for user '{st.session_state.get('username')}' trying to access '{permission_name}'.")
                st.title("🚫 Acceso Denegado")
                st.warning(f"No tienes el permiso necesario para acceder a esta página ('{permission_name}').")
                st.info("Si crees que esto es un error, por favor contacta a un administrador.")
                st.stop()

            # 4. Si todo está en orden, ejecutar la función de la página
            try:
                update_last_activity()
                # Session is automatically managed by SessionManager
                # No need for manual cookie management
                
                return func(*args, **kwargs)
            except Exception as e:
                log.error(f"Error executing decorated function '{func.__name__}': {e}", exc_info=True)
                st.error("Ocurrió un error inesperado al cargar la página.")
                st.stop()
        return wrapper
    return decorator

def requires_role(allowed_roles):
     if isinstance(allowed_roles, str): allowed_roles = [allowed_roles]
     allowed_roles_lower = set(role.lower() for role in allowed_roles)
     def decorator(func):
         def wrapper(*args, **kwargs):
            # Lógica de este decorador se mantiene, pero podemos simplificarla
            # asumiendo que el chequeo principal de autenticación ya pasó si
            # se usa junto a @requires_permission, o basándonos en el mismo
            # principio de que restore_session_from_cookie ya se ejecutó.

             if not check_authentication():
                 show_login_page() # Mostrar login si no está autenticado
                 st.stop()

             current_role = (st.session_state.get('role_name') or '').lower()
             if current_role not in allowed_roles_lower:
                  st.title("🚫 Acceso Restringido"); st.warning(f"Para acceder a esta página, se requiere uno de los siguientes roles: {', '.join(allowed_roles)}."); st.stop()

             try:
                 update_last_activity()
                 # Session management is handled by SessionManager
                 return func(*args, **kwargs)
             except Exception as e:
                 log.error(f"Error in @requires_role({allowed_roles}) for {func.__name__}: {e}", exc_info=True)
                 st.error("Error inesperado.")
                 st.stop()
         return wrapper
     return decorator

# --- FUNCIONES PARA CONTROL DE ACCESO A AGENTES ---

def get_current_user_accessible_agents(access_level: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Obtiene los agentes accesibles para el usuario actual.
    
    Args:
        access_level: Nivel de acceso específico ('read_only', 'full_access')
    
    Returns:
        List[Dict]: Lista de agentes accesibles con información de permisos
    """
    user_id = st.session_state.get('user_id')
    if not user_id:
        log.warning("No user_id in session for agent access check")
        return []
    
    try:
        accessible_agents = get_user_accessible_agents(user_id, access_level)
        log.info(f"User {user_id} has access to {len(accessible_agents)} agents")
        return accessible_agents
    except Exception as e:
        log.error(f"Error getting accessible agents for user {user_id}: {e}", exc_info=True)
        return []

def check_current_user_agent_access(agent_id: int) -> Dict[str, Any]:
    """
    Verifica si el usuario actual puede acceder a un agente específico.
    
    Args:
        agent_id: ID del agente a verificar
    
    Returns:
        Dict: Información de acceso {'can_view': bool, 'can_interact': bool, 'access_level': str}
    """
    user_id = st.session_state.get('user_id')
    if not user_id:
        log.warning("No user_id in session for agent access check")
        return {'can_view': False, 'can_interact': False, 'access_level': 'no_access'}
    
    try:
        access_info = check_user_agent_access(user_id, agent_id)
        log.debug(f"User {user_id} access to agent {agent_id}: {access_info}")
        return access_info
    except Exception as e:
        log.error(f"Error checking agent access for user {user_id}, agent {agent_id}: {e}", exc_info=True)
        return {'can_view': False, 'can_interact': False, 'access_level': 'no_access'}

def requires_agent_access(agent_id: int, required_access: str = 'read_only'):
    """
    Decorador que verifica si el usuario tiene acceso a un agente específico.
    
    Args:
        agent_id: ID del agente requerido
        required_access: Tipo de acceso requerido ('read_only' o 'full_access')
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Verificar autenticación primero
            if not check_authentication():
                show_login_page()
                st.stop()
            
            # Verificar acceso al agente
            access_info = check_current_user_agent_access(agent_id)
            
            if required_access == 'full_access' and not access_info['can_interact']:
                st.title("🚫 Acceso Denegado al Agente")
                st.error("No tienes permisos para interactuar con este agente.")
                st.info("Contacta a un administrador si necesitas acceso.")
                st.stop()
            elif required_access == 'read_only' and not access_info['can_view']:
                st.title("🚫 Agente No Accesible")
                st.error("Este agente no está disponible para tu rol.")
                st.info("Contacta a un administrador si necesitas acceso.")
                st.stop()
            
            # Si el acceso es válido, ejecutar la función
            try:
                update_last_activity()
                return func(*args, **kwargs)
            except Exception as e:
                log.error(f"Error in @requires_agent_access for agent {agent_id}: {e}", exc_info=True)
                st.error("Error inesperado al acceder al agente.")
                st.stop()
        return wrapper
    return decorator

def filter_agents_by_user_access(agents: List[Dict[str, Any]], access_level: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Filtra una lista de agentes según el acceso del usuario actual.
    
    Args:
        agents: Lista de agentes a filtrar
        access_level: Nivel de acceso requerido (None para cualquier acceso)
    
    Returns:
        List[Dict]: Lista filtrada de agentes accesibles
    """
    user_id = st.session_state.get('user_id')
    if not user_id:
        return []
    
    accessible_agents = []
    
    for agent in agents:
        agent_id = agent.get('id')
        if not agent_id:
            continue
        
        access_info = check_current_user_agent_access(agent_id)
        
        # Verificar si cumple con el nivel de acceso requerido
        if access_level == 'full_access' and not access_info['can_interact']:
            continue
        elif access_level == 'read_only' and not access_info['can_view']:
            continue
        elif not access_level and not access_info['can_view']:
            continue
        
        # Añadir información de acceso al agente
        agent_with_access = agent.copy()
        agent_with_access.update(access_info)
        accessible_agents.append(agent_with_access)
    
    log.info(f"Filtered {len(agents)} agents to {len(accessible_agents)} accessible agents for user {user_id}")
    return accessible_agents