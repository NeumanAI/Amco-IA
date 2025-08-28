# --- pages/03_Historial_Conversaciones.py (REDISEÑADO - Interfaz similar a OpenAI) ---

import streamlit as st
from datetime import datetime
import pytz

from auth.auth import requires_permission
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
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

def display_conversation_messages(session_id: str, conversation_title: str):
    """Muestra los mensajes de una conversación específica"""
    messages = get_conversation_messages(session_id)
    
    if not messages:
        st.info("No hay mensajes en esta conversación")
        return
    
    st.subheader(f"💬 {conversation_title}")
    st.caption(f"Sesión: `{session_id}` | {len(messages)} mensajes")
    
    # Contenedor con scroll para mensajes
    with st.container(height=500, border=True):
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
    """Página principal del historial de conversaciones - Interfaz estilo OpenAI"""
    
    st.title("💬 Historial de Conversaciones")
    st.caption("Explora tus conversaciones recientes con los agentes IA")
    
    # Layout principal: sidebar de conversaciones + área de chat
    col_sidebar, col_chat = st.columns([1, 2.5], gap="medium")
    
    with col_sidebar:
        st.subheader("📋 Conversaciones Recientes")
        
        # Obtener conversaciones del usuario actual
        user_id = st.session_state.get('user_id')
        conversations = get_conversations_for_user(user_id, limit=50)
        
        if not conversations:
            st.info("🔍 No hay conversaciones guardadas")
            st.markdown("---")
            st.caption("💡 **Tip:** Las conversaciones se guardan automáticamente cuando chateas con los agentes.")
            return
        
        # Estado para conversación seleccionada
        selected_session = st.session_state.get('selected_conversation_session')
        
        # Lista de conversaciones estilo OpenAI
        for i, conv in enumerate(conversations):
            # Crear contenedor para cada conversación
            with st.container():
                # Verificar si está seleccionada
                is_selected = conv['session_id'] == selected_session
                
                # Botón principal de conversación
                button_label = f"🤖 {conv['title']}"
                if len(button_label) > 45:
                    button_label = button_label[:42] + "..."
                
                button_type = "primary" if is_selected else "secondary"
                
                # Layout: botón + menú de opciones
                col_btn, col_menu = st.columns([4, 1])
                
                with col_btn:
                    if st.button(
                        button_label,
                        key=f"conv_btn_{conv['session_id']}",
                        type=button_type,
                        width='stretch',
                        help=f"Agente: {conv['agent_name']} | {conv['message_count']} mensajes"
                    ):
                        st.session_state['selected_conversation_session'] = conv['session_id']
                        st.session_state['selected_conversation_title'] = conv['title']
                        # Limpiar estado de edición si existe
                        if f'editing_title_{conv["session_id"]}' in st.session_state:
                            del st.session_state[f'editing_title_{conv["session_id"]}']
                        st.rerun()
                
                with col_menu:
                    # Menú de opciones con popover
                    with st.popover("⋮", width='stretch'):
                        st.caption(f"**{conv['agent_name']}**")
                        st.caption(f"📅 {format_datetime(conv['last_activity'])}")
                        st.caption(f"💬 {conv['message_count']} mensajes")
                        
                        st.divider()
                        
                        # Opción renombrar
                        if st.button("✏️ Renombrar", key=f"rename_btn_{conv['session_id']}", width='stretch'):
                            st.session_state[f'editing_title_{conv["session_id"]}'] = True
                            st.rerun()
                        
                        # Opción eliminar
                        if st.button("🗑️ Eliminar", key=f"delete_btn_{conv['session_id']}", width='stretch', type="secondary"):
                            if st.session_state.get(f'confirm_delete_{conv["session_id"]}'):
                                # Confirmar eliminación
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
                                    st.error("Error al eliminar conversación")
                            else:
                                # Pedir confirmación
                                st.session_state[f'confirm_delete_{conv["session_id"]}'] = True
                                st.rerun()
                        
                        # Mostrar confirmación de eliminación
                        if st.session_state.get(f'confirm_delete_{conv["session_id"]}'):
                            st.warning("⚠️ ¿Confirmar eliminación?")
                            col_yes, col_no = st.columns(2)
                            with col_yes:
                                if st.button("✅ Sí", key=f"confirm_yes_{conv['session_id']}"):
                                    # La lógica de eliminación se ejecuta arriba
                                    pass
                            with col_no:
                                if st.button("❌ No", key=f"confirm_no_{conv['session_id']}"):
                                    del st.session_state[f'confirm_delete_{conv["session_id"]}']
                                    st.rerun()
                
                # Campo de edición de título (si está en modo edición)
                if st.session_state.get(f'editing_title_{conv["session_id"]}'):
                    new_title = st.text_input(
                        "Nuevo título:",
                        value=conv['title'],
                        key=f"new_title_input_{conv['session_id']}",
                        placeholder="Ingresa el nuevo título..."
                    )
                    
                    col_save, col_cancel = st.columns(2)
                    with col_save:
                        if st.button("💾 Guardar", key=f"save_title_{conv['session_id']}", type="primary"):
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
                        if st.button("❌ Cancelar", key=f"cancel_title_{conv['session_id']}"):
                            del st.session_state[f'editing_title_{conv["session_id"]}']
                            st.rerun()
                
                # Separador entre conversaciones
                if i < len(conversations) - 1:
                    st.divider()
    
    # Área de chat
    with col_chat:
        selected_session = st.session_state.get('selected_conversation_session')
        selected_title = st.session_state.get('selected_conversation_title', 'Conversación')
        
        if selected_session:
            # Mostrar conversación seleccionada
            display_conversation_messages(selected_session, selected_title)
        else:
            # Estado vacío - invitar a seleccionar conversación
            st.info("👈 Selecciona una conversación para ver los mensajes")
            
            # Mostrar estadísticas generales
            if conversations:
                st.subheader("📊 Estadísticas Generales")
                
                total_conversations = len(conversations)
                total_messages = sum(conv['message_count'] for conv in conversations)
                agents_used = len(set(conv['agent_name'] for conv in conversations))
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Conversaciones", total_conversations)
                
                with col2:
                    st.metric("Mensajes Totales", total_messages)
                
                with col3:
                    st.metric("Agentes Usados", agents_used)
                
                st.subheader("🤖 Agentes Más Utilizados")
                agent_usage = {}
                for conv in conversations:
                    agent_name = conv['agent_name']
                    if agent_name in agent_usage:
                        agent_usage[agent_name] += conv['message_count']
                    else:
                        agent_usage[agent_name] = conv['message_count']
                
                # Ordenar por uso
                sorted_agents = sorted(agent_usage.items(), key=lambda x: x[1], reverse=True)
                
                for agent_name, message_count in sorted_agents[:5]:  # Top 5
                    st.write(f"🤖 **{agent_name}**: {message_count} mensajes")

# Aplicar estilos y renderizar
apply_global_styles()
render_sidebar()
show_conversation_history_page()