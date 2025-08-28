
# --- pages/03_Historial_Conversaciones.py (REDISEÑADO - Interfaz similar a OpenAI) ---

import streamlit as st
from datetime import datetime
import pytz
import time

from auth.security_middleware import requires_permission
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
from utils.session_ui import render_session_monitor
from database.database import (
    get_conversations_for_user, 
    get_conversation_messages, 
    update_conversation_title, 
    delete_conversation
)
import logging

log = logging.getLogger(__name__)

# --- Restaurar sesión al inicio ---
restore_session_from_cookie()

# Permiso requerido para acceder a esta página
PAGE_PERMISSION = "Historial de Conversaciones"

def format_datetime(dt):
    """Formatea fecha y hora para mostrar en la UI"""
    if not dt:
        return "Fecha desconocida"
    
    try:
        # Asegurar que tenemos timezone info
        if dt.tzinfo is None:
            colombia_tz = pytz.timezone('America/Bogota')
            dt = colombia_tz.localize(dt)
        
        now = datetime.now(pytz.timezone('America/Bogota'))
        diff = now - dt
        
        if diff.days == 0:
            return dt.strftime("Hoy %H:%M")
        elif diff.days == 1:
            return dt.strftime("Ayer %H:%M")
        elif diff.days < 7:
            return dt.strftime("%A %H:%M")
        else:
            return dt.strftime("%d/%m/%Y %H:%M")
    except Exception as e:
        log.error(f"Error formatting datetime {dt}: {e}")
        return str(dt)

def continue_conversation(session_id: str, agent_id: int, agent_name: str, conversation_title: str):
    """
    Carga una conversación existente en el chat activo para continuar la conversación.
    
    Args:
        session_id: ID de la sesión de conversación
        agent_id: ID del agente
        agent_name: Nombre del agente
        conversation_title: Título de la conversación
    """
    log.info(f"Loading conversation {session_id} to continue chat with agent {agent_name}")
    
    try:
        # Cargar mensajes de la conversación
        messages = get_conversation_messages(session_id)
        
        # Convertir mensajes al formato esperado por el chat
        chat_messages = []
        for msg in messages:
            # Agregar mensaje del usuario
            chat_messages.append({
                "role": "user",
                "content": msg['user_message']
            })
            
            # Agregar respuesta del agente si existe
            if msg['agent_response']:
                chat_messages.append({
                    "role": "assistant", 
                    "content": msg['agent_response']
                })
        
        # Obtener información del agente para el chat_url
        from database.database import get_db_session
        from database.models import Agent
        
        with get_db_session() as db:
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            agent_chat_url = agent.n8n_chat_url if agent else None
        
        # Configurar el estado del chat para continuar la conversación
        st.session_state.update({
            'chat_selected_agent_id': agent_id,
            'chat_selected_agent_name': agent_name,
            'chat_selected_agent_chat_url': agent_chat_url,
            'chat_messages': chat_messages,
            'chat_session_id': session_id,  # Usar el mismo session_id para continuar
            'continuing_conversation': True,  # Flag para indicar que es una conversación continuada
            'continued_conversation_title': conversation_title
        })
        
        log.info(f"Successfully loaded {len(chat_messages)} messages for conversation continuation")
        
    except Exception as e:
        log.error(f"Error loading conversation {session_id} for continuation: {e}", exc_info=True)
        st.error("Error al cargar la conversación")

def render_mobile_conversation_list(conversations):
    """Renderiza la lista de conversaciones optimizada para móvil"""
    selected_session = st.session_state.get('selected_conversation_session')
    
    # Lista compacta para móvil
    with st.container(height=500):
        for i, conv in enumerate(conversations):
            # Card compacta para móvil
            with st.container():
                col_main, col_action = st.columns([4, 1])
                
                with col_main:
                    # Título más corto para móvil
                    title_display = conv['title'][:40] + ("..." if len(conv['title']) > 40 else "")
                    
                    if st.button(
                        f"{'✅ ' if conv['session_id'] == selected_session else '💬 '}{title_display}",
                        key=f"mobile_conv_{conv['session_id']}",
                        type="primary" if conv['session_id'] == selected_session else "secondary",
                        use_container_width=True
                    ):
                        st.session_state['selected_conversation_session'] = conv['session_id']
                        st.session_state['selected_conversation_title'] = conv['title']
                        st.rerun()
                    
                    # Metadata compacta
                    st.caption(f"🤖 {conv['agent_name']} • {conv['message_count']} mensajes • {format_datetime(conv['last_activity'])}")
                
                with col_action:
                    # Menú de acciones móvil
                    with st.popover("⋮", use_container_width=True):
                        if st.button("💬 Continuar", key=f"mobile_continue_{conv['session_id']}", use_container_width=True):
                            continue_conversation(conv['session_id'], conv['agent_id'], conv['agent_name'], conv['title'])
                            st.switch_page("pages/01_Agentes_IA.py")
                        
                        if st.button("✏️ Renombrar", key=f"mobile_rename_{conv['session_id']}", use_container_width=True):
                            st.session_state[f'editing_title_{conv["session_id"]}'] = True
                            st.rerun()
                        
                        if st.button("🗑️ Eliminar", key=f"mobile_delete_{conv['session_id']}", use_container_width=True):
                            if delete_conversation(conv['session_id']):
                                st.success("Eliminada")
                                st.rerun()
                
                if i < len(conversations) - 1:
                    st.divider()

def display_conversation_messages(session_id: str, conversation_title: str):
    """Muestra los mensajes de una conversación específica"""
    messages = get_conversation_messages(session_id)
    
    if not messages:
        st.info("No hay mensajes en esta conversación")
        return
    
    # Header con botón para continuar conversación
    col_title, col_continue = st.columns([3, 1])
    with col_title:
        st.subheader(f"💬 {conversation_title}")
        st.caption(f"Sesión: `{session_id}` | {len(messages)} mensajes")
    
    with col_continue:
        # Obtener info del agente de la conversación
        if messages:
            # Buscar agent_id en los mensajes o usar el primer mensaje para obtener info
            conversations = get_conversations_for_user(st.session_state.get('user_id'), limit=50)
            current_conv = next((c for c in conversations if c['session_id'] == session_id), None)
            
            if current_conv and st.button("💬 Continuar", key=f"continue_from_view_{session_id}", type="primary", use_container_width=True):
                continue_conversation(session_id, current_conv['agent_id'], current_conv['agent_name'], conversation_title)
                st.success("🔄 Cargando...")
                time.sleep(0.5)
                st.switch_page("pages/01_Agentes_IA.py")
    
    # Contenedor con scroll para mensajes - altura adaptativa
    container_height = 450 if st.session_state.get('is_mobile', False) else 550
    
    with st.container(height=container_height, border=True):
        for msg in messages:
            # Mensaje del usuario
            with st.chat_message("user", avatar="🧑‍💻"):
                st.write(msg['user_message'])
                st.caption(f"📅 {format_datetime(msg['created_at'])}")
            
            # Respuesta del agente
            if msg['agent_response']:
                with st.chat_message("assistant", avatar="🤖"):
                    st.write(msg['agent_response'])
                    # Indicador de éxito/error
                    status_icon = "✅" if msg['success'] else "❌"
                    status_text = "Respuesta exitosa" if msg['success'] else "Error en respuesta"
                    st.caption(f"{status_icon} {status_text}")
            else:
                with st.chat_message("assistant", avatar="🤖"):
                    st.write("*Sin respuesta*")
                    st.caption("❌ Sin respuesta del agente")

@requires_permission(PAGE_PERMISSION)
def show_conversation_history_page() -> None:
    """Página principal del historial de conversaciones - Diseño responsivo optimizado"""
    
    # Header mejorado con botón de actualización
    col_title, col_refresh = st.columns([4, 1])
    with col_title:
        st.title("💬 Historial de Conversaciones")
        st.caption("Explora y gestiona tus conversaciones con los agentes IA")
    
    with col_refresh:
        if st.button("🔄", help="Actualizar historial", key="refresh_history", type="secondary"):
            st.rerun()
    
    # Instrucciones colapsables en la parte superior para optimizar espacio
    with st.expander("ℹ️ Cómo usar el Historial de Conversaciones", expanded=False):
        col_info1, col_info2 = st.columns(2)
        with col_info1:
            st.markdown("""
            **📖 Ver y Gestionar:**
            - Haz clic en cualquier conversación para ver todos los mensajes
            - Usa el menú (⋮) para renombrar conversaciones
            - Elimina conversaciones que ya no necesites
            """)
        with col_info2:
            st.markdown("""
            **💬 Continuar Chats:**
            - Botón rápido (💬) para continuar chateando
            - Se cargan automáticamente todos los mensajes anteriores
            - Mantiene el contexto completo de la conversación
            """)
        
        st.info("💡 **Tip:** Las conversaciones se guardan automáticamente cuando chateas con los agentes.")
    
    # Obtener conversaciones del usuario actual
    user_id = st.session_state.get('user_id')
    conversations = get_conversations_for_user(user_id, limit=50)
    
    if not conversations:
        st.warning("🔍 No hay conversaciones guardadas")
        st.info("Comienza a chatear con los agentes para ver tus conversaciones aquí.")
        return
    
    # Layout responsivo optimizado
    # Usar layout móvil (con tabs) como predeterminado - se ve mejor
    is_mobile = st.session_state.get('is_mobile', True)
    
    if is_mobile:
        # Layout móvil: Stack vertical con tabs para mejor UX
        tab_list, tab_chat = st.tabs(["📋 Conversaciones", "💬 Chat"])
        
        with tab_list:
            render_mobile_conversation_list(conversations)
        
        with tab_chat:
            selected_session = st.session_state.get('selected_conversation_session')
            if selected_session:
                selected_title = st.session_state.get('selected_conversation_title', 'Conversación')
                display_conversation_messages(selected_session, selected_title)
            else:
                st.info("👆 Selecciona una conversación en la pestaña 'Conversaciones' para ver los mensajes")
    else:
        # Layout desktop: Sidebar optimizado + área de chat (más espacio para conversaciones)
        col_sidebar, col_chat = st.columns([1.3, 2.7], gap="medium")
        
        with col_sidebar:
            render_desktop_conversation_list(conversations)
        
        with col_chat:
            selected_session = st.session_state.get('selected_conversation_session')
            selected_title = st.session_state.get('selected_conversation_title', 'Conversación')
            
            if selected_session:
                # Mostrar conversación seleccionada
                display_conversation_messages(selected_session, selected_title)
            else:
                # Estado vacío - interfaz limpia y funcional
                st.info("👈 Selecciona una conversación para ver los mensajes")
                
                # Botón para alternar vista (móvil es por defecto)
                st.markdown("---")
                col_mobile_toggle, col_space = st.columns([1, 2])
                with col_mobile_toggle:
                    current_mobile = st.session_state.get('is_mobile', True)
                    if st.button(f"📱 {'Vista Clásica' if current_mobile else 'Vista con Tabs'}", help="Alternar entre vista con tabs y vista clásica"):
                        st.session_state['is_mobile'] = not current_mobile
                        st.rerun()

def render_desktop_conversation_list(conversations):
    """Renderiza la lista de conversaciones optimizada para desktop"""
    st.subheader("📋 Conversaciones Recientes")
    
    selected_session = st.session_state.get('selected_conversation_session')
    
    # Lista de conversaciones con altura optimizada para desktop
    with st.container(height=650):  # Más altura para desktop
        for i, conv in enumerate(conversations):
            # Crear contenedor con clase CSS personalizada para cada conversación
            conversation_class = "conversation-item active" if conv['session_id'] == selected_session else "conversation-item"
            
            st.markdown(f'<div class="{conversation_class}">', unsafe_allow_html=True)
            
            # Layout optimizado para desktop
            col_main, col_actions = st.columns([3.5, 1])
            
            with col_main:
                # Título clickeable con más espacio
                title_display = conv['title'][:60] + ("..." if len(conv['title']) > 60 else "")
                
                if st.button(
                    title_display,
                    key=f"desktop_conv_select_{conv['session_id']}",
                    type="primary" if conv['session_id'] == selected_session else "secondary",
                    help=f"Ver conversación con {conv['agent_name']}",
                    use_container_width=True
                ):
                    st.session_state['selected_conversation_session'] = conv['session_id']
                    st.session_state['selected_conversation_title'] = conv['title']
                    if f'editing_title_{conv["session_id"]}' in st.session_state:
                        del st.session_state[f'editing_title_{conv["session_id"]}']
                    st.rerun()
                
                # Metadata más detallada para desktop
                st.caption(f"🤖 **{conv['agent_name']}** • 💬 {conv['message_count']} mensajes • 🕒 {format_datetime(conv['last_activity'])}")
            
            with col_actions:
                # Acciones compactas para desktop
                col_continue, col_menu = st.columns(2)
                
                with col_continue:
                    if st.button("💬", key=f"desktop_continue_{conv['session_id']}", help="Continuar conversación", use_container_width=True):
                        continue_conversation(conv['session_id'], conv['agent_id'], conv['agent_name'], conv['title'])
                        st.success("🔄 Cargando...")
                        time.sleep(0.5)
                        st.switch_page("pages/01_Agentes_IA.py")
                
                with col_menu:
                    # Menú de opciones con popover
                    with st.popover("⋮", use_container_width=True):
                        st.caption(f"**{conv['agent_name']}**")
                        st.caption(f"📅 {format_datetime(conv['last_activity'])}")
                        st.caption(f"💬 {conv['message_count']} mensajes")
                        
                        st.divider()
                        
                        # Opción renombrar
                        if st.button("✏️ Renombrar", key=f"desktop_rename_{conv['session_id']}", use_container_width=True):
                            st.session_state[f'editing_title_{conv["session_id"]}'] = True
                            st.rerun()
                        
                        # Opción eliminar con confirmación simplificada
                        if st.button("🗑️ Eliminar", key=f"desktop_delete_{conv['session_id']}", use_container_width=True, type="secondary"):
                            if delete_conversation(conv['session_id']):
                                st.success("Conversación eliminada")
                                # Limpiar selección si era la conversación actual
                                if selected_session == conv['session_id']:
                                    if 'selected_conversation_session' in st.session_state:
                                        del st.session_state['selected_conversation_session']
                                    if 'selected_conversation_title' in st.session_state:
                                        del st.session_state['selected_conversation_title']
                                st.rerun()
                            else:
                                st.error("Error al eliminar")
            
            # Campo de edición de título (si está en modo edición)
            if st.session_state.get(f'editing_title_{conv["session_id"]}'):
                new_title = st.text_input(
                    "Nuevo título:",
                    value=conv['title'],
                    key=f"desktop_title_input_{conv['session_id']}",
                    placeholder="Ingresa el nuevo título..."
                )
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.button("💾 Guardar", key=f"desktop_save_{conv['session_id']}", type="primary"):
                        if new_title.strip():
                            if update_conversation_title(conv['session_id'], new_title.strip()):
                                st.success("Título actualizado")
                                del st.session_state[f'editing_title_{conv["session_id"]}']
                                # Actualizar título en session state si es la conversación actual
                                if selected_session == conv['session_id']:
                                    st.session_state['selected_conversation_title'] = new_title.strip()
                                st.rerun()
                            else:
                                st.error("Error al actualizar título")
                        else:
                            st.warning("El título no puede estar vacío")
                
                with col_cancel:
                    if st.button("❌ Cancelar", key=f"desktop_cancel_{conv['session_id']}"):
                        del st.session_state[f'editing_title_{conv["session_id"]}']
                        st.rerun()
            
            # Cerrar div de conversación
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Separador entre conversaciones
            if i < len(conversations) - 1:
                st.markdown("<br>", unsafe_allow_html=True)

# Enhanced rendering with security monitoring
apply_global_styles()
render_sidebar()
render_session_monitor()  # Add session monitoring
show_conversation_history_page()