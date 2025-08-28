# --- pages/10_Control_Acceso_Agentes.py ---
# Página para gestionar el control de acceso granular de roles a agentes

import streamlit as st
import pandas as pd
import time
from typing import Dict, List, Optional, Tuple
from sqlalchemy.exc import OperationalError

# Importaciones locales
from auth.auth import requires_permission
from database.database import (
    get_db_session, get_role_agent_access_matrix, set_role_agent_access,
    get_agents_for_role
)
from database.models import Role, Agent, RoleAgentAccess
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
import logging

log = logging.getLogger(__name__)

# --- PASO 1: RESTAURAR SESIÓN AL INICIO ---
restore_session_from_cookie()

PAGE_PERMISSION = "Roles"

def load_roles_and_agents() -> Tuple[List[Dict], List[Dict], Optional[str]]:
    """
    Carga roles y agentes disponibles para la matriz de acceso.
    
    Returns:
        Tuple[List[Dict], List[Dict], Optional[str]]: (roles, agents, error_message)
    """
    roles = []
    agents = []
    error_message = None
    
    try:
        with get_db_session() as db:
            # Cargar roles
            roles_query = db.query(Role).order_by(Role.name).all()
            for role in roles_query:
                roles.append({
                    'id': role.id,
                    'name': role.name,
                    'description': role.description
                })
            
            # Cargar agentes
            agents_query = db.query(Agent).filter(Agent.status == 'active').order_by(Agent.name).all()
            for agent in agents_query:
                agents.append({
                    'id': agent.id,
                    'name': agent.name,
                    'description': agent.description,
                    'status': agent.status
                })
                
        log.info(f"Loaded {len(roles)} roles and {len(agents)} agents")
        
    except Exception as e:
        log.error(f"Error loading roles and agents: {e}", exc_info=True)
        error_message = f"Error cargando datos: {e}"
        
    return roles, agents, error_message

def get_current_access_matrix(roles: List[Dict], agents: List[Dict]) -> Dict:
    """
    Obtiene la matriz actual de acceso rol-agente.
    
    Args:
        roles: Lista de roles
        agents: Lista de agentes
    
    Returns:
        Dict: Matriz de acceso {role_id: {agent_id: access_level}}
    """
    matrix = {}
    
    try:
        with get_db_session() as db:
            access_records = db.query(RoleAgentAccess).all()
            
            # Inicializar matriz con 'no_access' por defecto
            for role in roles:
                matrix[role['id']] = {}
                for agent in agents:
                    matrix[role['id']][agent['id']] = 'no_access'
            
            # Llenar con los accesos actuales
            for access in access_records:
                if access.role_id in matrix and access.agent_id in matrix[access.role_id]:
                    matrix[access.role_id][access.agent_id] = access.access_level
                    
    except Exception as e:
        log.error(f"Error getting access matrix: {e}", exc_info=True)
        
    return matrix

def render_access_matrix_table(roles: List[Dict], agents: List[Dict], access_matrix: Dict):
    """
    Renderiza la tabla de matriz de acceso con controles interactivos.
    
    Args:
        roles: Lista de roles
        agents: Lista de agentes
        access_matrix: Matriz actual de acceso
    """
    if not roles or not agents:
        st.warning("No hay roles o agentes disponibles para configurar accesos.")
        return
    
    st.subheader("🔐 Matriz de Control de Acceso")
    st.caption("Configura qué roles pueden acceder a cada agente y con qué nivel de permisos.")
    
    # Opciones de acceso
    ACCESS_LEVELS = {
        'no_access': {'label': '🚫 Sin Acceso', 'color': '#ff4444'},
        'read_only': {'label': '👁️ Solo Vista', 'color': '#ffaa00'},
        'full_access': {'label': '✅ Acceso Completo', 'color': '#00aa44'}
    }
    
    # Crear tabla interactiva
    with st.container():
        # Encabezados
        cols = st.columns([2] + [1.5] * len(agents))
        cols[0].markdown("**Rol / Agente**")
        for i, agent in enumerate(agents):
            cols[i + 1].markdown(f"**{agent['name'][:15]}{'...' if len(agent['name']) > 15 else ''}**")
        
        st.divider()
        
        # Filas de roles
        changes_made = False
        for role in roles:
            role_id = role['id']
            role_name = role['name']
            
            # Verificar si es superadministrador (acceso completo siempre)
            is_super = role_name.lower() == 'superadministrador'
            
            cols = st.columns([2] + [1.5] * len(agents))
            
            # Nombre del rol
            role_color = "#e1f5fe" if is_super else "#f5f5f5"
            cols[0].markdown(f"""
                <div style="background-color: {role_color}; padding: 8px; border-radius: 4px; margin: 2px 0;">
                    <strong>{role_name}</strong>
                    {'<br><small>🔒 Super Admin</small>' if is_super else ''}
                </div>
            """, unsafe_allow_html=True)
            
            # Controles de acceso por agente
            for i, agent in enumerate(agents):
                agent_id = agent['id']
                current_access = access_matrix.get(role_id, {}).get(agent_id, 'no_access')
                
                # Para superadministrador, siempre full_access y deshabilitado
                if is_super:
                    access_level = 'full_access'
                    disabled = True
                else:
                    access_level = current_access
                    disabled = False
                
                # Selectbox para nivel de acceso
                new_access = cols[i + 1].selectbox(
                    label="",
                    options=list(ACCESS_LEVELS.keys()),
                    index=list(ACCESS_LEVELS.keys()).index(access_level),
                    format_func=lambda x: ACCESS_LEVELS[x]['label'],
                    key=f"access_{role_id}_{agent_id}",
                    disabled=disabled,
                    label_visibility="collapsed"
                )
                
                # Detectar cambios
                if not is_super and new_access != current_access:
                    changes_made = True
                    # Actualizar matriz en session_state
                    if 'access_matrix_changes' not in st.session_state:
                        st.session_state.access_matrix_changes = {}
                    st.session_state.access_matrix_changes[f"{role_id}_{agent_id}"] = new_access
        
        # Botones de acción
        if changes_made or st.session_state.get('access_matrix_changes'):
            st.divider()
            col1, col2, col3 = st.columns([1, 1, 2])
            
            with col1:
                if st.button("💾 Guardar Cambios", type="primary"):
                    save_access_changes()
            
            with col2:
                if st.button("❌ Cancelar"):
                    st.session_state.pop('access_matrix_changes', None)
                    st.rerun()
            
            with col3:
                st.caption(f"⚠️ Hay cambios pendientes por guardar")

def save_access_changes():
    """Guarda los cambios en la matriz de acceso."""
    changes = st.session_state.get('access_matrix_changes', {})
    
    if not changes:
        st.warning("No hay cambios para guardar.")
        return
    
    success_count = 0
    error_count = 0
    
    try:
        for change_key, new_access in changes.items():
            role_id, agent_id = map(int, change_key.split('_'))
            
            if set_role_agent_access(role_id, agent_id, new_access):
                success_count += 1
            else:
                error_count += 1
        
        if success_count > 0:
            st.success(f"✅ Se guardaron {success_count} cambios exitosamente.")
        
        if error_count > 0:
            st.error(f"❌ {error_count} cambios fallaron al guardarse.")
        
        # Limpiar cambios pendientes
        st.session_state.pop('access_matrix_changes', None)
        time.sleep(1)
        st.rerun()
        
    except Exception as e:
        log.error(f"Error saving access changes: {e}", exc_info=True)
        st.error(f"Error guardando cambios: {e}")

def render_role_summary_section(roles: List[Dict]):
    """
    Renderiza una sección de resumen por rol.
    
    Args:
        roles: Lista de roles disponibles
    """
    st.subheader("📊 Resumen por Rol")
    
    if not roles:
        st.info("No hay roles disponibles.")
        return
    
    # Selector de rol
    role_options = {f"{role['name']} (ID: {role['id']})": role['id'] for role in roles}
    selected_role_label = st.selectbox(
        "Seleccionar rol para ver resumen:",
        options=list(role_options.keys()),
        key="role_summary_select"
    )
    
    if selected_role_label:
        selected_role_id = role_options[selected_role_label]
        selected_role = next(role for role in roles if role['id'] == selected_role_id)
        
        # Obtener agentes accesibles para este rol
        accessible_agents = get_agents_for_role(selected_role_id)
        
        if accessible_agents:
            # Agrupar por nivel de acceso
            access_summary = {}
            for agent in accessible_agents:
                level = agent['access_level']
                if level not in access_summary:
                    access_summary[level] = []
                access_summary[level].append(agent)
            
            # Mostrar resumen
            col1, col2, col3 = st.columns(3)
            
            with col1:
                full_access_count = len(access_summary.get('full_access', []))
                st.metric("🟢 Acceso Completo", full_access_count)
            
            with col2:
                read_only_count = len(access_summary.get('read_only', []))
                st.metric("🟡 Solo Lectura", read_only_count)
            
            with col3:
                total_agents = full_access_count + read_only_count
                st.metric("📊 Total Accesibles", total_agents)
            
            # Detalles por nivel
            for access_level, agents in access_summary.items():
                if agents:
                    level_info = {
                        'full_access': {'emoji': '🟢', 'title': 'Acceso Completo'},
                        'read_only': {'emoji': '🟡', 'title': 'Solo Lectura'}
                    }
                    
                    if access_level in level_info:
                        with st.expander(f"{level_info[access_level]['emoji']} {level_info[access_level]['title']} ({len(agents)} agentes)"):
                            for agent in agents:
                                st.write(f"• **{agent['name']}** - {agent['description'] or 'Sin descripción'}")
        else:
            st.info(f"El rol '{selected_role['name']}' no tiene acceso a ningún agente.")

@requires_permission(PAGE_PERMISSION)
def show_agent_access_control_page():
    """Página principal de control de acceso a agentes."""
    st.title("🔐 Control de Acceso a Agentes")
    st.caption("Gestiona qué roles pueden acceder a cada agente y con qué permisos.")
    
    try:
        # Botón de actualizar
        if st.button("🔄 Actualizar", help="Recargar datos"):
            st.session_state.pop('access_matrix_changes', None)
            st.rerun()
        
        # Cargar datos
        roles, agents, error_message = load_roles_and_agents()
        
        if error_message:
            st.error(error_message)
            st.stop()
        
        if not roles:
            st.warning("No hay roles configurados. Ve a la página de Roles para crear algunos.")
            st.stop()
        
        if not agents:
            st.warning("No hay agentes activos. Ve a la página de Gestión de Agentes para crear algunos.")
            st.stop()
        
        # Obtener matriz actual
        access_matrix = get_current_access_matrix(roles, agents)
        
        # Tabs para diferentes vistas
        tab1, tab2 = st.tabs(["🔐 Matriz de Acceso", "📊 Resumen por Rol"])
        
        with tab1:
            render_access_matrix_table(roles, agents, access_matrix)
        
        with tab2:
            render_role_summary_section(roles)
        
        # Información adicional
        st.divider()
        st.markdown("""
        ### ℹ️ Información sobre Niveles de Acceso
        
        - **🚫 Sin Acceso**: El rol no puede ver ni interactuar con el agente
        - **👁️ Solo Vista**: El rol puede ver el agente en la lista pero no puede chatear con él
        - **✅ Acceso Completo**: El rol puede ver e interactuar completamente con el agente
        
        > **Nota**: Los usuarios con rol 'SuperAdministrador' siempre tienen acceso completo a todos los agentes.
        """)
        
    except Exception as e:
        log.error(f"Error in agent access control page: {e}", exc_info=True)
        st.error(f"Error en la página: {e}")

# --- EJECUCIÓN PRINCIPAL ---
apply_global_styles()
render_sidebar()
show_agent_access_control_page()
