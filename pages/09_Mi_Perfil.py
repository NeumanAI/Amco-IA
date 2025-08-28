# Archivo: pages/09_Mi_Perfil.py

import streamlit as st
import time
from sqlalchemy.orm import joinedload
from auth.auth import requires_permission # <-- CAMBIO: Importar requires_permission
from auth.auth import hash_password, validate_password, get_security_config_values
from database.database import get_db_session
from database.models import User, Role
from utils.helpers import is_valid_email
import logging
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
# from utils.cookies import get_session_cookie

log = logging.getLogger(__name__)

# --- PASO 1: RESTAURAR SESIÓN AL INICIO ---
restore_session_from_cookie()

@requires_permission("Mi Perfil") # <-- CAMBIO: Añadido decorador para proteger y gestionar la sesión
def show_profile_page():
    st.title("👤 Mi Perfil"); st.caption("Actualiza tu información personal y contraseña.")
    user_id = st.session_state.get('user_id')
    if not user_id:
        st.error("Error: Sesión no identificada. Por favor, inicie sesión.")
        log.warning("User ID not found in session for Mi Perfil page.")
        st.stop()

    try:
        with get_db_session() as db:
            user = db.query(User).options(
                joinedload(User.role)
            ).filter(User.id == user_id).first()
            if not user:
                st.error("Error: Usuario no encontrado.")
                st.session_state['authenticated']=False;
                log.error(f"User with ID {user_id} not found in DB for Mi Perfil page.")
                time.sleep(1); st.rerun(); st.stop()

            sec_conf=get_security_config_values(); pw_hint=f"Min {sec_conf['password_min_length']}c."
            if sec_conf['password_require_uppercase']: pw_hint += " M."
            if sec_conf['password_require_numbers']: pw_hint += " N."
            if sec_conf['password_require_special']: pw_hint += " E."

            with st.form("profile_form"):
                st.subheader("Información"); c1, c2 = st.columns(2)
                with c1: st.text_input("Usuario", value=user.username, disabled=True)
                with c2: st.text_input("Rol", value=user.role.name if user.role else "N/A", disabled=True)
                email = st.text_input("Email *", value=user.email or "", key="profile_email")
                st.markdown("---"); st.subheader("Cambiar Contraseña (Opcional)")
                chg_pwd = st.checkbox("Cambiar", key="profile_chg_pwd")
                pwd_curr, pwd_new1, pwd_new2 = None, None, None
                if chg_pwd:
                    pwd_curr=st.text_input("Actual *", type="password", key="profile_curr_pwd")
                    c_pwd1, c_pwd2 = st.columns(2)
                    with c_pwd1: pwd_new1=st.text_input("Nueva *", type="password", key="profile_new_pwd1", help=pw_hint)
                    with c_pwd2: pwd_new2=st.text_input("Confirmar Nueva *", type="password", key="profile_new_pwd2")
                st.markdown("---"); submitted = st.form_submit_button("💾 Guardar Cambios", type="primary", width='stretch')

                if submitted:
                    errors = []; email_changed = (st.session_state.profile_email != user.email); pwd_req = chg_pwd; valid_new_pwd = False
                    if email_changed:
                        new_email = st.session_state.profile_email
                        if not is_valid_email(new_email): errors.append("Email inválido.")
                        else:
                             with get_db_session() as db_check:
                                 if db_check.query(User).filter(User.email==new_email, User.id!=user_id).first(): errors.append(f"Email '{new_email}' ya en uso.")
                    if pwd_req:
                        if not pwd_curr or not pwd_new1 or not pwd_new2: errors.append("Complete campos contraseña.")
                        elif hash_password(pwd_curr) != user.password: errors.append("Contraseña actual incorrecta.")
                        elif pwd_new1 != pwd_new2: errors.append("Nuevas contraseñas no coinciden.")
                        else: valid_new_pwd, pwd_msg = validate_password(pwd_new1, sec_conf); errors.append(pwd_msg) if not valid_new_pwd else None
                    if errors:
                        for e in errors: st.error(f"⚠️ {e}")
                    else:
                        changed = False
                        try:
                            with get_db_session() as db_save:
                                user_upd = db_save.query(User).filter(User.id == user_id).first()
                                if not user_upd:
                                    st.error("Error crítico: Usuario no encontrado durante el guardado.")
                                    log.error(f"User {user_id} disappeared before saving profile changes.")
                                    st.stop()
                                if email_changed: user_upd.email = st.session_state.profile_email; changed = True; log.info(f"User '{user.username}' updated email.")
                                if pwd_req and valid_new_pwd: user_upd.password = hash_password(pwd_new1); changed = True; log.info(f"User '{user.username}' updated password.")
                                if changed:
                                    db_save.commit()
                                    st.success("✅ ¡Perfil actualizado!")
                                    for k in ['profile_curr_pwd','profile_new_pwd1','profile_new_pwd2']: st.session_state.pop(k, None)
                                    st.session_state.profile_chg_pwd = False
                                    time.sleep(0.5)
                                    st.rerun()
                                else: st.info("ℹ️ No se detectaron cambios.")
                        except Exception as e: st.error(f"❌ Error guardando perfil: {e}"); log.error("Error saving profile", exc_info=True)
    except Exception as e: st.error(f"Error cargando datos perfil: {e}"); log.error("Error loading profile page", exc_info=True)


# --- PASO 2: SIMPLIFICAR EL BLOQUE DE EJECUCIÓN ---
# El decorador ya se encarga de la seguridad. Si la sesión no se restaura,
# el decorador mostrará el login y detendrá la ejecución.
apply_global_styles()
render_sidebar()
show_profile_page()