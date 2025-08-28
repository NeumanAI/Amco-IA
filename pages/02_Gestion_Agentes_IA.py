# --- pages/02_Gestion_Agentes_IA.py (CORREGIDO - AttributeError en form submit) ---

import streamlit as st
import pandas as pd
import time
import json
from sqlalchemy.exc import IntegrityError, OperationalError
from typing import Optional, List, Tuple, Dict, Any

# Importar dependencias locales
from auth.auth import requires_permission
from database.database import (
    get_db_session, get_role_agent_access_matrix, set_role_agent_access,
    get_agents_for_role
)
from database.models import (
    Agent, LanguageModelOption, SkillOption, PersonalityOption, GoalOption,
    Role, RoleAgentAccess
)
from utils.config import get_configuration
import pytz
import logging
from datetime import datetime
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
# from utils.cookies import get_session_cookie

# --- LLAMAR A RENDER_SIDEBAR TEMPRANO ---
# render_sidebar()
# --- FIN LLAMADA ---

log = logging.getLogger(__name__)
# logging.basicConfig(level=logging.INFO)

# --- PASO 1: RESTAURAR SESIÓN AL INICIO ---
restore_session_from_cookie()

PAGE_PERMISSION = "Gestión de agentes IA"
try: colombia_tz = pytz.timezone(get_configuration('timezone', 'general', 'America/Bogota'))
except: colombia_tz = pytz.timezone('America/Bogota')

# --- Funciones Auxiliares ---
def format_json_list(json_string: Optional[str]) -> str:
    if not json_string: return ""
    try: data = json.loads(json_string); return ", ".join(str(item).strip() for item in data if item and str(item).strip()) if isinstance(data, list) else "[No Lista JSON]"
    except: return "[JSON Inválido]"

def get_agent_role_access(agent_id: int) -> Dict[str, str]:
    """
    Obtiene los roles que tienen acceso a un agente específico.
    
    Args:
        agent_id: ID del agente
    
    Returns:
        Dict: Mapeo de role_name -> access_level
    """
    role_access = {}
    try:
        with get_db_session() as db:
            # Obtener todos los roles y sus accesos a este agente
            query = db.query(
                Role.name,
                RoleAgentAccess.access_level
            ).outerjoin(
                RoleAgentAccess, 
                (Role.id == RoleAgentAccess.role_id) & (RoleAgentAccess.agent_id == agent_id)
            ).order_by(Role.name).all()
            
            for role_name, access_level in query:
                # Si es SuperAdministrador, siempre tiene acceso completo
                if role_name and role_name.lower() == 'superadministrador':
                    role_access[role_name] = 'full_access'
                else:
                    role_access[role_name] = access_level or 'no_access'
    
    except Exception as e:
        log.error(f"Error getting agent role access for agent {agent_id}: {e}", exc_info=True)
    
    return role_access

def format_agent_roles_display(role_access: Dict[str, str]) -> str:
    """
    Formatea la información de roles para mostrar en la interfaz.
    
    Args:
        role_access: Mapeo de role_name -> access_level
    
    Returns:
        str: Texto formateado para mostrar
    """
    if not role_access:
        return "Sin accesos configurados"
    
    access_icons = {
        'full_access': '🟢',
        'read_only': '🟡', 
        'no_access': '🔴'
    }
    
    formatted_roles = []
    for role_name, access_level in role_access.items():
        if access_level and access_level != 'no_access':
            icon = access_icons.get(access_level, '❓')
            access_text = {
                'full_access': 'Completo',
                'read_only': 'Solo Vista'
            }.get(access_level, access_level)
            formatted_roles.append(f"{icon} {role_name} ({access_text})")
    
    return "; ".join(formatted_roles) if formatted_roles else "Sin accesos activos"

def load_local_agents_data() -> Tuple[List[Dict[str, Any]], List[Tuple[str, int]], Optional[Exception], Optional[str]]:
    agents_data: List[Dict[str, Any]] = []; agent_options: List[Tuple[str, int]] = []
    error: Optional[Exception] = None; error_message: Optional[str] = None
    log.info("[Gestión Agentes] Loading agents...")
    try:
        with get_db_session() as db:
            agents_objects = db.query(Agent).order_by(Agent.name).all()
            log.info(f"[Gestión Agentes] Query OK. Found {len(agents_objects)} agents.")
            for agent in agents_objects:
                created = agent.created_at.astimezone(colombia_tz).strftime('%Y-%m-%d %H:%M') if agent.created_at else 'N/A'
                updated = agent.updated_at.astimezone(colombia_tz).strftime('%Y-%m-%d %H:%M') if agent.updated_at else 'N/A'
                icon = "🟢" if agent.status == "active" else "🔴"
                
                # Obtener información de roles para este agente
                role_access = get_agent_role_access(agent.id)
                roles_display = format_agent_roles_display(role_access)
                
                agents_data.append({
                    "ID": agent.id, "Nombre": agent.name, "Descripción": agent.description or "",
                    "Modelo": agent.model_name or "N/A", "Habilidades": format_json_list(agent.skills),
                    "Objetivos": format_json_list(agent.goals), "Personalidad": format_json_list(agent.personality),
                    "URL Chat N8N": agent.n8n_chat_url or "No", "URL Detalles N8N": agent.n8n_details_url or "No",
                    "Estado": f"{icon} {agent.status.capitalize()}", "Roles con Acceso": roles_display,
                    "Creado": created, "Actualizado": updated,})
                agent_options.append((f"{agent.name} (ID: {agent.id})", agent.id))
    except OperationalError as oe: log.error(f"[GA] OpError: {oe}",exc_info=True); error=oe; error_message=f"Error DB: {oe}"
    except Exception as e: log.error(f"[GA] Generic error: {e}",exc_info=True); error=e; error_message=f"Error: {e}"
    log.info(f"[GA] Load finished. Rows: {len(agents_data)}, Error: {error is not None}")
    return agents_data, agent_options, error, error_message

# --- Funciones Dialog ---
@st.dialog("Crear Nuevo Agente Local", width="large")
def create_agent_dialog(): log.info("Render create dialog..."); render_agent_form_content(mode='create')

@st.dialog("Editar Agente", width="large")
def edit_agent_dialog(agent_id: int):
    log.info(f"Render edit dialog ID: {agent_id}"); data={}; name=f"(ID: {agent_id})"
    try:
        with get_db_session() as db:
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent: st.error(f"Agente ID {agent_id} no."); time.sleep(2); st.session_state.agent_action=None; st.session_state.editing_agent_id=None; st.rerun(); return
            name=agent.name; data={k: getattr(agent, k) for k in Agent.__table__.columns.keys()}; log.info(f"Agent data load OK {agent_id}")
        st.subheader(f"Editando: {name} (ID: {agent_id})"); render_agent_form_content(mode='edit', agent_data=data, agent_id_to_edit=agent_id)
    except Exception as e:
         st.error(f"Error cargando: {e}"); log.error(f"Fail load agent {agent_id}", exc_info=True)
         if st.button("Cerrar"): st.session_state.agent_action=None; st.session_state.editing_agent_id=None; st.rerun()

@st.dialog("Gestionar Roles del Agente", width="large")
def manage_agent_roles_dialog(agent_id: int):
    """Diálogo para gestionar qué roles tienen acceso a un agente específico."""
    log.info(f"Render manage roles dialog for agent ID: {agent_id}")
    
    # Variables para almacenar datos fuera de la sesión DB
    agent_name = None
    all_roles_data = []
    
    try:
        with get_db_session() as db:
            # Obtener información del agente y extraer datos primitivos
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                st.error(f"Agente ID {agent_id} no encontrado.")
                time.sleep(2)
                st.session_state.agent_action = None
                st.session_state.managing_roles_agent_id = None
                st.rerun()
                return
            
            # Extraer datos primitivos del agente
            agent_name = agent.name
            
            # Obtener todos los roles disponibles y extraer datos primitivos
            all_roles = db.query(Role).order_by(Role.name).all()
            if not all_roles:
                st.warning("No hay roles configurados en el sistema.")
                return
            
            # Convertir roles a datos primitivos
            for role in all_roles:
                all_roles_data.append({
                    'id': role.id,
                    'name': role.name
                })
        
        # Mostrar información del agente usando datos primitivos
        st.subheader(f"🔐 Gestionar Accesos: {agent_name}")
        st.caption(f"Configura qué roles pueden acceder al agente ID: {agent_id}")
        
        # Obtener configuración actual de accesos
        current_access = get_agent_role_access(agent_id)
        
        st.markdown("### Configuración de Accesos por Rol")
        
        # Crear formulario para cada rol
        with st.form(key=f"agent_roles_form_{agent_id}"):
            changes_made = {}
            
            for role_data in all_roles_data:
                role_id = role_data['id']
                role_name = role_data['name']
                current_level = current_access.get(role_name, 'no_access')
                
                # Para SuperAdministrador, siempre acceso completo y deshabilitado
                is_super = role_name.lower() == 'superadministrador'
                if is_super:
                    st.markdown(f"**🔒 {role_name}**: Acceso Completo (No modificable)")
                    continue
                
                # Selector de nivel de acceso para otros roles
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    st.markdown(f"**{role_name}:**")
                
                with col2:
                    access_options = ['no_access', 'read_only', 'full_access']
                    access_labels = {
                        'no_access': '🚫 Sin Acceso',
                        'read_only': '👁️ Solo Vista', 
                        'full_access': '✅ Acceso Completo'
                    }
                    
                    current_index = access_options.index(current_level) if current_level in access_options else 0
                    
                    new_access = st.selectbox(
                        label="",
                        options=access_options,
                        index=current_index,
                        format_func=lambda x: access_labels[x],
                        key=f"role_access_{role_id}_{agent_id}",
                        label_visibility="collapsed"
                    )
                    
                    if new_access != current_level:
                        changes_made[role_id] = new_access
            
            st.markdown("---")
            
            # Botones de acción
            col1, col2, col3 = st.columns([1, 1, 2])
            
            with col1:
                submitted = st.form_submit_button("💾 Guardar Cambios", type="primary")
            
            with col2:
                if st.form_submit_button("❌ Cancelar"):
                    st.session_state.agent_action = None
                    st.session_state.managing_roles_agent_id = None
                    st.rerun()
            
            with col3:
                if changes_made:
                    st.caption(f"⚠️ {len(changes_made)} cambio(s) pendiente(s)")
            
            if submitted:
                if changes_made:
                    success_count = 0
                    error_count = 0
                    
                    for role_id, new_access_level in changes_made.items():
                        if set_role_agent_access(role_id, agent_id, new_access_level):
                            success_count += 1
                        else:
                            error_count += 1
                    
                    if success_count > 0:
                        st.success(f"✅ Se guardaron {success_count} cambios exitosamente.")
                    
                    if error_count > 0:
                        st.error(f"❌ {error_count} cambios fallaron al guardarse.")
                    
                    time.sleep(1.5)
                    st.session_state.agent_action = None
                    st.session_state.managing_roles_agent_id = None
                    st.rerun()
                else:
                    st.info("No hay cambios para guardar.")
        
        # Mostrar resumen actual
        st.markdown("### 📊 Resumen Actual de Accesos")
        if current_access:
            access_summary = []
            for role_name, access_level in current_access.items():
                if access_level and access_level != 'no_access':
                    icon = {'full_access': '🟢', 'read_only': '🟡'}.get(access_level, '❓')
                    text = {'full_access': 'Completo', 'read_only': 'Solo Vista'}.get(access_level, access_level)
                    access_summary.append(f"{icon} **{role_name}**: {text}")
            
            if access_summary:
                for item in access_summary:
                    st.markdown(f"- {item}")
            else:
                st.info("Este agente no tiene accesos configurados (excepto SuperAdministrador).")
        else:
            st.info("No se pudo cargar la información de accesos.")
            
    except Exception as e:
        st.error(f"Error gestionando roles del agente: {e}")
        log.error(f"Error in manage_agent_roles_dialog for agent {agent_id}: {e}", exc_info=True)
        if st.button("Cerrar"):
            st.session_state.agent_action = None
            st.session_state.managing_roles_agent_id = None
            st.rerun()

@st.dialog("Confirmar Eliminación")
def delete_agent_dialog(agent_id: int):
     log.info(f"Render delete dialog ID: {agent_id}")
     try:
        with get_db_session() as db:
             agent_info = db.query(Agent.id, Agent.name).filter(Agent.id == agent_id).first()
             if not agent_info: st.error(f"Agente ID {agent_id} no."); time.sleep(2); st.session_state.agent_action=None; st.session_state.deleting_agent_id=None; st.rerun(); return
             name=agent_info.name; st.warning(f"❓ Eliminar '{name}' (ID: {agent_id})?"); st.markdown("**Eliminará definición y TODO historial.**")
             c1, c2 = st.columns(2)
             with c1:
                  if st.button("🗑️ Sí", type="primary", key="confirm_del_btn"):
                       log.warning(f"Attempt delete {agent_id}")
                       try:
                           with get_db_session() as db_del:
                               agent_db = db_del.query(Agent).filter(Agent.id == agent_id).first()
                               if agent_db: db_del.delete(agent_db); db_del.commit(); st.success(f"✅ '{name}' eliminado."); log.info(f"Agent {agent_id} deleted.")
                               else: st.warning("Ya no existía.")
                           st.session_state.agent_action=None; st.session_state.deleting_agent_id=None; time.sleep(1); st.rerun()
                       except Exception as del_e: log.error(f"Error deleting {agent_id}", exc_info=True); st.error(f"❌ Error: {del_e}")
             with c2:
                  if st.button("❌ Cancelar", key="cancel_del_btn"): st.session_state.agent_action=None; st.session_state.deleting_agent_id=None; st.rerun()
     except Exception as e:
         st.error(f"❌ Error preparando: {e}"); log.error(f"Error render delete {agent_id}", exc_info=True)
         if st.button("Cerrar"): st.session_state.agent_action=None; st.session_state.deleting_agent_id=None; st.rerun()

# --- Contenido del Formulario (CORREGIDO AttributeError) ---
def render_agent_form_content(mode: str, agent_data: Optional[Dict[str, Any]] = None, agent_id_to_edit: Optional[int] = None):
    is_edit = mode == 'edit'; submit_label = "💾 Guardar" if is_edit else "✅ Crear"
    m_opts, s_opts, p_opts, g_opts = [],[],[],[]
    try: # Cargar Opciones
        with get_db_session() as db:
            m_opts = [n for n, in db.query(LanguageModelOption.name).order_by(LanguageModelOption.name).all()]
            s_opts = [n for n, in db.query(SkillOption.name).order_by(SkillOption.name).all()]
            p_opts = [n for n, in db.query(PersonalityOption.name).order_by(PersonalityOption.name).all()]
            g_opts = [n for n, in db.query(GoalOption.name).order_by(GoalOption.name).all()]
        log.info("Agent options loaded.")
    except OperationalError as oe: log.error(f"OpError opts: {oe}", exc_info=True); st.error(f"Error DB: Tablas opciones no encontradas ({oe}). Aplica migración '012'."); return
    except Exception as e: st.error(f"Error cargando opciones: {e}"); log.error("Fail load opts", exc_info=True); return

    # Defaults para Edit
    d_name=agent_data.get('name','') if is_edit else ''; d_desc=agent_data.get('description','') if is_edit else ''; d_stat=agent_data.get('status','active') if is_edit else 'active'
    d_chat=agent_data.get('n8n_chat_url','') if is_edit else ''; d_dets=agent_data.get('n8n_details_url','') if is_edit else ''; s_idx=0 if d_stat=='active' else 1
    d_model=agent_data.get('model_name') if is_edit else None; m_idx=0; m_opts_ph=["-- Modelo --"]+m_opts
    if d_model and d_model in m_opts: m_idx=m_opts.index(d_model)+1
    d_skills=[]; d_goals=[]; d_pers=[]
    if is_edit: # Parsear JSON
        try: d_skills=json.loads(agent_data.get('skills','[]') or '[]') if agent_data.get('skills') else []
        except: log.warning(f"Bad JSON skills {agent_id_to_edit}")
        try: d_goals=json.loads(agent_data.get('goals','[]') or '[]') if agent_data.get('goals') else []
        except: log.warning(f"Bad JSON goals {agent_id_to_edit}")
        try: d_pers=json.loads(agent_data.get('personality','[]') or '[]') if agent_data.get('personality') else []
        except: log.warning(f"Bad JSON pers {agent_id_to_edit}")
        d_skills=[s for s in d_skills if s in s_opts]; d_goals=[g for g in d_goals if g in g_opts]; d_pers=[p for p in d_pers if p in p_opts]

    # Renderizar Formulario
    with st.form(key=f"{mode}_agent_form_in_dialog"):
        name=st.text_input("Nombre *", value=d_name, disabled=is_edit); description=st.text_area("Descripción", value=d_desc, height=80)
        st.selectbox("Modelo *", options=m_opts_ph, index=m_idx, key="form_model_name") # Widget key
        st.multiselect("Habilidades", options=s_opts, default=d_skills, key="form_skills") # Widget key
        st.multiselect("Objetivos", options=g_opts, default=d_goals, key="form_goals") # Widget key
        st.multiselect("Personalidades", options=p_opts, default=d_pers, key="form_personality") # Widget key
        status=st.selectbox("Estado *", ["active", "inactive"], index=s_idx, key="form_status") # Widget key
        st.markdown("---"); st.subheader("N8N URLs"); n8n_chat_url=st.text_input("URL Chat", value=d_chat, key="form_n8n_chat_url"); n8n_details_url=st.text_input("URL Detalles (Opc)", value=d_dets, key="form_n8n_details_url")
        st.markdown("---"); submitted=st.form_submit_button(submit_label, type="primary")

        if submitted:
            errs=[]; final_model=st.session_state.form_model_name # Leer por key
            if not is_edit and not name.strip(): errs.append("Nombre.")
            if not final_model or final_model=="-- Modelo --": errs.append("Modelo.")
            skills_j=None; goals_j=None; pers_j=None
            try: # --- CORREGIR KEYS AQUÍ ---
                skills_j=json.dumps(st.session_state.form_skills) if st.session_state.form_skills else None
            except Exception as e: errs.append(f"Skills:{e}")
            try: # --- CORREGIR KEYS AQUÍ ---
                goals_j=json.dumps(st.session_state.form_goals) if st.session_state.form_goals else None
            except Exception as e: errs.append(f"Objetivos:{e}")
            try: # --- CORREGIR KEYS AQUÍ ---
                pers_j=json.dumps(st.session_state.form_personality) if st.session_state.form_personality else None
            except Exception as e: errs.append(f"Personalidades:{e}")

            # --- CORREGIR AttributeError ---
            chat_url_val = st.session_state.form_n8n_chat_url
            details_url_val = st.session_state.form_n8n_details_url
            n8n_chat_url_save = chat_url_val.strip() if chat_url_val else None
            n8n_details_url_save = details_url_val.strip() if details_url_val else None
            # --- FIN CORRECCIÓN AttributeError ---

            if errs:
                for e in errs: st.error(f"⚠️ {e}"); return

            data_save={"name": name.strip() if not is_edit else agent_data.get('name'), "description": description.strip(), "model_name": final_model,
                         "skills": skills_j, "goals": goals_j, "personality": pers_j, "status": st.session_state.form_status,
                         "n8n_chat_url": n8n_chat_url_save, "n8n_details_url": n8n_details_url_save }
            try: # Guardar
                with get_db_session() as db:
                    if is_edit:
                        log.info(f"Updating agent {agent_id_to_edit}"); agent_upd=db.query(Agent).filter(Agent.id==agent_id_to_edit).first()
                        if not agent_upd: raise ValueError("Agente no encontrado.")
                        for k,v in data_save.items():
                             if k!="name": setattr(agent_upd,k,v)
                        agent_upd.updated_at=datetime.now(colombia_tz); db.flush(); st.success(f"✅ '{agent_upd.name}' actualizado.")
                    else: log.info(f"Creating agent: {data_save['name']}"); new_agent=Agent(**data_save); db.add(new_agent); db.flush(); st.success(f"✅ '{data_save['name']}' creado.")
                st.session_state.agent_action=None; st.session_state.editing_agent_id=None; time.sleep(1); st.rerun()
            except IntegrityError: st.error(f"⚠️ Error: Ya existe '{data_save['name']}'.")
            except Exception as e: st.error(f"❌ Error guardando: {e}"); log.error("Error saving agent", exc_info=True)

    if st.button("Cancelar", key=f"cancel_{mode}_btn"): st.session_state.agent_action=None; st.session_state.editing_agent_id=None; st.rerun()

# --- Página Principal ---
@requires_permission(PAGE_PERMISSION)
def show_agent_management_page():
    st.title("🛠️ Gestión Agentes (Local)")
    st.caption("Crear, editar, eliminar y gestionar accesos por roles.")
    
    # Información sobre la nueva funcionalidad
    with st.expander("ℹ️ Información sobre Control de Acceso", expanded=False):
        st.markdown("""
        ### 🔐 Control de Acceso por Roles
        
        Cada agente puede tener diferentes niveles de acceso según el rol del usuario:
        
        - **🟢 Acceso Completo**: Puede ver e interactuar con el agente
        - **🟡 Solo Vista**: Puede ver el agente pero no chatear con él  
        - **🔴 Sin Acceso**: El agente no es visible para este rol
        
        **Nota**: Los usuarios con rol 'SuperAdministrador' siempre tienen acceso completo a todos los agentes.
        
        ### 🎯 Cómo Gestionar Accesos
        
        1. Selecciona un agente de la tabla
        2. Haz clic en el botón **🔐** para gestionar roles
        3. Configura el nivel de acceso para cada rol
        4. Guarda los cambios
        
        Los cambios se aplicarán inmediatamente para todos los usuarios.
        """)
    
    st.divider()
    try:
        agents_data, agent_options, error_load, error_message = load_local_agents_data()
        if st.button("🔄 Refrescar"): st.rerun()
        if error_load: st.error(error_message or "Error."); st.warning("Verifica BD/migraciones."); st.stop()
        if agents_data: st.dataframe(pd.DataFrame(agents_data), key='agent_df', width='stretch', hide_index=True, column_config={ "ID": st.column_config.NumberColumn(width="small"), "Estado": st.column_config.TextColumn(width="small"), "Habilidades": st.column_config.TextColumn("Habilidades"), "Roles con Acceso": st.column_config.TextColumn("Roles con Acceso", width="large"), "Creado": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm"), "Actualizado": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm"),})
        else: st.info("No hay agentes.")
        st.divider(); st.subheader("Acciones"); c1,c2,c3=st.columns([1.5,2.5,2])
        with c1:
            if st.button("➕ Crear", width='stretch'): st.session_state.agent_action='create'; st.session_state.editing_agent_id=None; st.session_state.deleting_agent_id=None; st.session_state.managing_roles_agent_id=None
        with c2:
            opts_map={l:i for l,i in agent_options}; opts_disp={"":"Seleccione..."}; opts_disp.update(opts_map)
            sel_lbl=st.selectbox("Sel:", options=list(opts_disp.keys()), index=0, label_visibility="collapsed", key="agent_select_crud")
            st.session_state.selected_agent_id_for_crud = opts_disp.get(sel_lbl)
        with c3:
             ce,cr,cd=st.columns(3); cur_sel=st.session_state.get("selected_agent_id_for_crud")
             with ce:
                  if st.button("✏️", key="edit_btn", help="Editar", width='stretch', disabled=not cur_sel): st.session_state.agent_action='edit'; st.session_state.editing_agent_id=cur_sel; st.session_state.deleting_agent_id=None; st.session_state.managing_roles_agent_id=None
             with cr:
                  if st.button("🔐", key="roles_btn", help="Gestionar Roles", width='stretch', disabled=not cur_sel): st.session_state.agent_action='manage_roles'; st.session_state.managing_roles_agent_id=cur_sel; st.session_state.editing_agent_id=None; st.session_state.deleting_agent_id=None
             with cd:
                  if st.button("🗑️", key="del_btn", help="Eliminar", width='stretch', disabled=not cur_sel): st.session_state.agent_action='delete'; st.session_state.deleting_agent_id=cur_sel; st.session_state.editing_agent_id=None; st.session_state.managing_roles_agent_id=None
        action=st.session_state.get('agent_action'); edit_id=st.session_state.get('editing_agent_id'); del_id=st.session_state.get('deleting_agent_id'); roles_id=st.session_state.get('managing_roles_agent_id')
        log.debug(f"Dialog check: act={action}, ed={edit_id}, del={del_id}, roles={roles_id}")
        if action=='create': create_agent_dialog()
        elif action=='edit' and edit_id is not None: edit_agent_dialog(agent_id=edit_id) # Check ID
        elif action=='delete' and del_id is not None: delete_agent_dialog(agent_id=del_id) # Check ID
        elif action=='manage_roles' and roles_id is not None: manage_agent_roles_dialog(agent_id=roles_id) # Check ID
    except Exception as page_e: log.error(f"Error page: {page_e}", exc_info=True); st.error(f"Error: {page_e}")

# --- PASO 2: SIMPLIFICAR EL BLOQUE DE EJECUCIÓN ---
# El decorador ya se encarga de la seguridad. Si la sesión no se restaura,
# el decorador mostrará el login y detendrá la ejecución.
apply_global_styles()
render_sidebar()
show_agent_management_page()