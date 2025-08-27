import streamlit as st

from auth.auth import requires_permission
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
from database.database import get_db_session, fetch_recent_conversations
from database.models import Query


# --- Restaurar sesión al inicio ---
restore_session_from_cookie()

# Permiso requerido para acceder a esta página
PAGE_PERMISSION = "Historial de Conversaciones"


@requires_permission(PAGE_PERMISSION)
def show_conversation_history_page() -> None:
    """Muestra las conversaciones recientes y el detalle de la seleccionada."""

    st.title("📜 Historial de Conversaciones")
    st.caption("Revisa y accede a tus conversaciones recientes con los agentes IA.")

    col_list, col_chat = st.columns([1, 3], gap="small")

    with col_list:
        conversations = fetch_recent_conversations()
        if not conversations:
            st.info("No hay conversaciones registradas.")
            st.session_state.pop("conv_id", None)
        else:
            options = []
            for conv in conversations:
                title = conv["title"] or "Sin título"
                short_title = title[:40] + ("..." if len(title) > 40 else "")
                options.append((short_title, conv["session_id"]))

            titles = [opt[0] for opt in options]
            selected = st.radio(
                "Conversaciones",
                titles,
                key="selected_conv",
            )
            st.session_state["conv_id"] = dict(options)[selected]

    with col_chat:
        conv_id = st.session_state.get("conv_id")
        if conv_id:
            with get_db_session() as db:
                msgs = (
                    db.query(Query)
                    .filter(Query.session_id == conv_id)
                    .order_by(Query.created_at.asc())
                    .all()
                )
            for m in msgs:
                st.chat_message("user").write(m.query_text)
                if m.response_text:
                    st.chat_message("assistant").write(m.response_text)
        else:
            st.info("Selecciona una conversación para ver sus mensajes.")


apply_global_styles()
render_sidebar()
show_conversation_history_page()

