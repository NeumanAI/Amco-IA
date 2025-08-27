# --- database/database.py (Corregido Nombre DB y Verificación Esquema) ---

from sqlalchemy import create_engine, text, inspect, func
from sqlalchemy.orm import sessionmaker, Session as SQLAlchemySession
from sqlalchemy.exc import OperationalError
from contextlib import contextmanager
import os
import logging
import pytz
from typing import Optional

# Importar modelos para que Base los conozca si apply_migrations se usa
from .models import Base, Query, Conversation, Agent, User

log = logging.getLogger(__name__)
# logging.basicConfig(level=logging.INFO)

# --- Configuración de la Base de Datos (NOMBRE CORREGIDO) ---
try:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # >>>>>>>>> NOMBRE CORREGIDO AQUÍ <<<<<<<<<<
    DB_NAME = "amco.bybinary_dashboard.db"
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    DATABASE_FILE_PATH = os.path.join(BASE_DIR, DB_NAME)
    DATABASE_URL = f"sqlite:///{DATABASE_FILE_PATH}" # Ruta absoluta Unix

    log.info(f"Attempting connect: {DATABASE_FILE_PATH}")
    log.info(f"SQLAlchemy URL: {DATABASE_URL}")

    if not os.path.exists(DATABASE_FILE_PATH):
        log.error(f"Database file NOT FOUND at specified path: {DATABASE_FILE_PATH}")
        # Considerar crear el archivo/directorio o lanzar un error más informativo
        # os.makedirs(os.path.dirname(DATABASE_FILE_PATH), exist_ok=True) # Solo si se quiere crear directorio
        raise FileNotFoundError(f"DB file not found: {DATABASE_FILE_PATH}")

    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, echo=False)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    log.info("SQLAlchemy engine/SessionLocal created.")

    # --- VERIFICACIÓN DE ESQUEMA (Mejorada) ---
    try:
        log.info("Inspecting DB schema via SQLAlchemy inspector...")
        inspector = inspect(engine)
        tables_found = inspector.get_table_names()
        log.info(f"Tables found by inspector: {tables_found}")

        required_tables = ["agents", "agent_options_language_models", "agent_options_skills", "agent_options_personalities", "agent_options_goals", "users", "roles", "configurations", "queries"]
        missing_tables = []
        for table in required_tables:
            if table not in tables_found:
                log.error(f"CRITICAL: Required table '{table}' NOT FOUND via inspector!")
                missing_tables.append(table)

        if not missing_tables:
            log.info("All required tables seem to exist.")
            # Verificar columnas clave si las tablas existen
            if "agents" in tables_found:
                cols = inspector.get_columns('agents'); names = [c['name'] for c in cols]
                if 'model_name' not in names: log.error("CRITICAL: 'model_name' column NOT FOUND in 'agents'!")
                else: log.info("'model_name' column verified in 'agents'.")
            # Añadir más verificaciones de columnas si es necesario
        else:
            log.error(f"Missing critical tables: {', '.join(missing_tables)}. Ensure ALL migrations (001-012) were applied correctly to '{DATABASE_FILE_PATH}'.")

    except Exception as inspect_e:
        log.error(f"Failed to inspect database schema (DB might be locked, corrupted, or path wrong?): {inspect_e}", exc_info=True)
    # --- FIN VERIFICACIÓN ---

except Exception as e_init:
    log.error(f"CRITICAL ERROR DB init: {e_init}", exc_info=True)
    raise RuntimeError(f"Failed DB init: {e_init}") from e_init

# --- Context Manager (Sin cambios) ---
@contextmanager
def get_db_session() -> SQLAlchemySession:
    db: Optional[SQLAlchemySession] = None
    try: db = SessionLocal(); yield db; db.commit()
    except Exception as e: log.error(f"DB transaction rollback: {e}", exc_info=True); db.rollback(); raise
    finally:
        if db: db.close()

# --- Aplicación de Migraciones (Sin cambios en la firma, implementación robusta necesaria) ---
def apply_sqlite_migrations(db_engine, sql_base, migrations_dir="database/migrations"):
     # ... (Usar versión robusta con historial si se activa en app.py) ...
     print(f"INFO: apply_sqlite_migrations called for dir '{migrations_dir}' (ensure implementation is robust).")
     pass


def fetch_recent_conversations(limit: int = 20):
    """Return recent conversation sessions ordered by last activity. (LEGACY - usar get_conversations_for_user)"""
    results = []
    with get_db_session() as db:
        sessions = (
            db.query(
                Query.session_id,
                func.min(Query.id).label("first_id"),
                func.max(Query.created_at).label("last_ts"),
            )
            .group_by(Query.session_id)
            .order_by(func.max(Query.created_at).desc())
            .limit(limit)
            .all()
        )
        for s in sessions:
            first_q = (
                db.query(Query.query_text).filter(Query.id == s.first_id).first()
            )
            title = first_q.query_text if first_q and first_q.query_text else "Sin título"
            results.append(
                {"session_id": s.session_id, "title": title, "last_ts": s.last_ts}
            )
    return results

# --- NUEVAS FUNCIONES PARA HISTORIAL DINÁMICO DE CONVERSACIONES ---

def save_conversation_message(session_id: str, agent_id: int, user_message: str, 
                            agent_response: str, user_id: Optional[int] = None) -> bool:
    """
    Guarda un intercambio de mensajes y actualiza/crea la conversación automáticamente.
    
    Args:
        session_id: ID único de la sesión de conversación
        agent_id: ID del agente que responde
        user_message: Mensaje del usuario
        agent_response: Respuesta del agente
        user_id: ID del usuario (opcional)
    
    Returns:
        bool: True si se guardó exitosamente, False en caso de error
    """
    try:
        from datetime import datetime
        current_time = datetime.now(pytz.timezone('America/Bogota'))
        
        with get_db_session() as db:
            # 1. Buscar o crear conversación
            conversation = db.query(Conversation).filter(
                Conversation.session_id == session_id
            ).first()
            
            if not conversation:
                # Crear nueva conversación con título del primer mensaje
                title = user_message[:50] + "..." if len(user_message) > 50 else user_message
                conversation = Conversation(
                    session_id=session_id,
                    title=title,
                    agent_id=agent_id,
                    user_id=user_id,
                    message_count=0,
                    created_at=current_time,
                    updated_at=current_time
                )
                db.add(conversation)
                log.info(f"Created new conversation: {session_id} with title: {title[:30]}...")
            
            # 2. Guardar mensaje en la tabla queries
            query_record = Query(
                agent_id=agent_id,
                session_id=session_id,
                query_text=user_message,
                response_text=agent_response,
                success=True if agent_response else False,
                created_at=current_time
            )
            db.add(query_record)
            
            # 3. Actualizar contador y timestamp de conversación
            conversation.message_count += 1
            conversation.updated_at = current_time
            
            db.commit()
            log.info(f"Saved conversation message for session {session_id}, total messages: {conversation.message_count}")
            return True
            
    except Exception as e:
        log.error(f"Error saving conversation message for session {session_id}: {e}", exc_info=True)
        return False

def get_conversations_for_user(user_id: Optional[int] = None, limit: int = 50) -> list[dict]:
    """
    Obtiene conversaciones ordenadas por actividad reciente, similar a OpenAI.
    
    Args:
        user_id: ID del usuario (None para obtener todas las conversaciones)
        limit: Límite de conversaciones a retornar
    
    Returns:
        List[Dict]: Lista de conversaciones con metadatos
    """
    try:
        with get_db_session() as db:
            query = db.query(Conversation).join(Agent, Conversation.agent_id == Agent.id)
            
            if user_id:
                query = query.filter(Conversation.user_id == user_id)
                
            conversations = query.order_by(
                Conversation.updated_at.desc()
            ).limit(limit).all()
            
            result = []
            for conv in conversations:
                result.append({
                    'id': conv.id,
                    'session_id': conv.session_id,
                    'title': conv.title,
                    'agent_name': conv.agent.name if conv.agent else 'Agente Desconocido',
                    'agent_id': conv.agent_id,
                    'message_count': conv.message_count,
                    'last_activity': conv.updated_at,
                    'created_at': conv.created_at
                })
            
            log.info(f"Retrieved {len(result)} conversations for user {user_id}")
            return result
            
    except Exception as e:
        log.error(f"Error fetching conversations for user {user_id}: {e}", exc_info=True)
        return []

def get_conversation_messages(session_id: str) -> list[dict]:
    """
    Obtiene todos los mensajes de una conversación ordenados cronológicamente.
    
    Args:
        session_id: ID de la sesión de conversación
    
    Returns:
        List[Dict]: Lista de mensajes con metadatos
    """
    try:
        with get_db_session() as db:
            messages = db.query(Query).filter(
                Query.session_id == session_id
            ).order_by(Query.created_at.asc()).all()
            
            result = []
            for msg in messages:
                result.append({
                    'id': msg.id,
                    'user_message': msg.query_text,
                    'agent_response': msg.response_text,
                    'created_at': msg.created_at,
                    'success': msg.success,
                    'agent_id': msg.agent_id
                })
            
            log.info(f"Retrieved {len(result)} messages for session {session_id}")
            return result
            
    except Exception as e:
        log.error(f"Error fetching messages for session {session_id}: {e}", exc_info=True)
        return []

def update_conversation_title(session_id: str, new_title: str) -> bool:
    """
    Actualiza el título de una conversación.
    
    Args:
        session_id: ID de la sesión de conversación
        new_title: Nuevo título para la conversación
    
    Returns:
        bool: True si se actualizó exitosamente, False en caso de error
    """
    try:
        from datetime import datetime
        current_time = datetime.now(pytz.timezone('America/Bogota'))
        
        with get_db_session() as db:
            conversation = db.query(Conversation).filter(
                Conversation.session_id == session_id
            ).first()
            
            if conversation:
                conversation.title = new_title.strip()
                conversation.updated_at = current_time
                db.commit()
                log.info(f"Updated conversation title for {session_id}: {new_title[:30]}...")
                return True
            else:
                log.warning(f"Conversation not found for session {session_id}")
                return False
                
    except Exception as e:
        log.error(f"Error updating conversation title for {session_id}: {e}", exc_info=True)
        return False

def delete_conversation(session_id: str) -> bool:
    """
    Elimina una conversación y todos sus mensajes asociados.
    
    Args:
        session_id: ID de la sesión de conversación
    
    Returns:
        bool: True si se eliminó exitosamente, False en caso de error
    """
    try:
        with get_db_session() as db:
            # Eliminar mensajes primero
            deleted_messages = db.query(Query).filter(Query.session_id == session_id).delete()
            
            # Eliminar conversación
            deleted_conversation = db.query(Conversation).filter(
                Conversation.session_id == session_id
            ).delete()
            
            db.commit()
            
            if deleted_conversation > 0:
                log.info(f"Deleted conversation {session_id} with {deleted_messages} messages")
                return True
            else:
                log.warning(f"No conversation found to delete for session {session_id}")
                return False
                
    except Exception as e:
        log.error(f"Error deleting conversation {session_id}: {e}", exc_info=True)
        return False
