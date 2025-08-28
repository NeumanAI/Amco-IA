# --- database/models.py (Añadir Modelos para Opciones) ---

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, ForeignKey, Text, Index, Boolean
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func
from datetime import datetime
import pytz

# Configuración Timezone (con fallback)
try:
    # from utils.config import get_configuration # Evitar import circular aquí
    # TZ_CONFIG = get_configuration('timezone', 'general', 'America/Bogota') or 'America/Bogota'
    colombia_tz = pytz.timezone('America/Bogota') # Usar default seguro
except Exception:
     colombia_tz = pytz.timezone('America/Bogota')

def get_current_time_colombia():
    return datetime.now(colombia_tz)

class Base(DeclarativeBase): pass

class Configuration(Base):
    __tablename__ = 'configurations'; id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False, index=True); value = Column(Text)
    category = Column(String, nullable=False, index=True); description = Column(String)
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    updated_at = Column(DateTime(timezone=True), default=get_current_time_colombia, onupdate=get_current_time_colombia)
    def __repr__(self): return f"<Configuration(key='{self.key}')>"

class Role(Base):
    __tablename__ = 'roles'; id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False); description = Column(String(255))
    permissions = Column(Text); users = relationship('User', back_populates='role')
    def get_permissions_set(self): return set(p.strip() for p in (self.permissions or '').split(',') if p.strip())
    def __repr__(self): return f"<Role(name='{self.name}')>"

class User(Base):
    __tablename__ = 'users'; id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True); password = Column(String(64), nullable=False)
    email = Column(String(120), unique=True, nullable=True, index=True); role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    role = relationship('Role', back_populates='users'); description = Column(String(255))
    status = Column(String(10), default='active', nullable=False); created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    last_access = Column(DateTime(timezone=True)); __table_args__ = (Index('ix_user_status', 'status'),)
    def __repr__(self): return f"<User(username='{self.username}')>"

# --- Modelo Agent (Sin cambios estructurales necesarios, usará TEXT para almacenar selecciones) ---
class Agent(Base):
    __tablename__ = 'agents'; id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text)
    model_name = Column(Text) # Almacena el nombre del modelo seleccionado
    skills = Column(Text) # Almacena JSON string de nombres de skills seleccionadas
    goals = Column(Text) # Almacena JSON string de nombres de objetivos seleccionados
    personality = Column(Text) # Almacena JSON string de nombres de personalidades seleccionadas
    status = Column(String(20), nullable=False, default='active', index=True)
    n8n_details_url = Column(String(512)); n8n_chat_url = Column(String(512))
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    updated_at = Column(DateTime(timezone=True), default=get_current_time_colombia, onupdate=get_current_time_colombia)
    queries = relationship('Query', back_populates='agent', cascade="all, delete-orphan", passive_deletes=True)
    def __repr__(self): return f"<Agent(id={self.id}, name='{self.name}')>"

class Query(Base):
    __tablename__ = 'queries'; id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey('agents.id', ondelete='CASCADE'), nullable=False, index=True)
    session_id = Column(String(36), index=True); query_text = Column(Text, nullable=False); response_text = Column(Text)
    response_time_ms = Column(Integer); success = Column(Boolean, nullable=False, default=True); feedback_score = Column(Integer); error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    agent = relationship('Agent', back_populates='queries')
    def __repr__(self): return f"<Query(id={self.id}, agent_id={self.agent_id})>"

# --- MODELO CONVERSATION PARA HISTORIAL DINÁMICO ---
class Conversation(Base):
    """Modelo para gestionar conversaciones con historial dinámico similar a OpenAI."""
    __tablename__ = 'conversations'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    agent_id = Column(Integer, ForeignKey('agents.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    updated_at = Column(DateTime(timezone=True), default=get_current_time_colombia, onupdate=get_current_time_colombia)
    message_count = Column(Integer, default=0, nullable=False)
    
    # Relationships
    agent = relationship('Agent', foreign_keys=[agent_id])
    user = relationship('User', foreign_keys=[user_id])
    
    # Índices adicionales
    __table_args__ = (
        Index('ix_conversation_updated_at', 'updated_at'),
        Index('ix_conversation_user_agent', 'user_id', 'agent_id'),
    )
    
    def __repr__(self): 
        return f"<Conversation(id={self.id}, session_id='{self.session_id}', title='{self.title[:30]}...')>"
    
    def get_messages(self):
        """Obtiene los mensajes de esta conversación ordenados por fecha."""
        from database.database import get_db_session
        try:
            with get_db_session() as db:
                return db.query(Query).filter(
                    Query.session_id == self.session_id
                ).order_by(Query.created_at.asc()).all()
        except Exception:
            return []

# --- NUEVOS MODELOS PARA OPCIONES DE AGENTE ---

class AgentOptionBase(Base):
    """Clase base abstracta para opciones con ID y Nombre únicos."""
    __abstract__ = True # No crear tabla para esta clase base
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True) # Descripción opcional
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)

    def __repr__(self): return f"<{self.__class__.__name__}(name='{self.name}')>"

class LanguageModelOption(AgentOptionBase):
    """Opciones para Modelos de Lenguaje."""
    __tablename__ = 'agent_options_language_models'

class SkillOption(AgentOptionBase):
    """Opciones para Habilidades."""
    __tablename__ = 'agent_options_skills'

class PersonalityOption(AgentOptionBase):
    """Opciones para Personalidades."""
    __tablename__ = 'agent_options_personalities'

class GoalOption(AgentOptionBase):
    """Opciones para Objetivos."""
    __tablename__ = 'agent_options_goals'

# --- NUEVOS MODELOS PARA CONTROL DE ACCESO AVANZADO ---

class RoleAgentAccess(Base):
    """Modelo para controlar qué roles pueden acceder a qué agentes."""
    __tablename__ = 'role_agent_access'
    
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey('agents.id', ondelete='CASCADE'), nullable=False, index=True)
    access_level = Column(String(20), nullable=False, default='read_only', index=True)
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    updated_at = Column(DateTime(timezone=True), default=get_current_time_colombia, onupdate=get_current_time_colombia)
    
    # Relationships
    role = relationship('Role', foreign_keys=[role_id])
    agent = relationship('Agent', foreign_keys=[agent_id])
    
    # Índices adicionales
    __table_args__ = (
        Index('ix_role_agent_unique', 'role_id', 'agent_id', unique=True),
    )
    
    def __repr__(self):
        return f"<RoleAgentAccess(role_id={self.role_id}, agent_id={self.agent_id}, access={self.access_level})>"
    
    def can_interact(self) -> bool:
        """Verifica si el nivel de acceso permite interacción con el agente."""
        return self.access_level in ['full_access']
    
    def can_view(self) -> bool:
        """Verifica si el nivel de acceso permite ver el agente."""
        return self.access_level in ['read_only', 'full_access']

class UserPreferences(Base):
    """Modelo para preferencias y configuraciones de usuario."""
    __tablename__ = 'user_preferences'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    preference_key = Column(String(100), nullable=False, index=True)
    preference_value = Column(Text)
    category = Column(String(50), default='general', index=True)
    created_at = Column(DateTime(timezone=True), default=get_current_time_colombia)
    updated_at = Column(DateTime(timezone=True), default=get_current_time_colombia, onupdate=get_current_time_colombia)
    
    # Relationships
    user = relationship('User', foreign_keys=[user_id])
    
    # Índices adicionales
    __table_args__ = (
        Index('ix_user_pref_unique', 'user_id', 'preference_key', unique=True),
    )
    
    def __repr__(self):
        return f"<UserPreferences(user_id={self.user_id}, key='{self.preference_key}')>"
