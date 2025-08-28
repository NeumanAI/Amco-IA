# --- utils/session_ui.py ---
"""
Session UI Components for displaying session status and timeout warnings
"""

import streamlit as st
from datetime import datetime, timedelta
import time
import logging
from typing import Dict, Any, Optional

from auth.security_middleware import get_session_timeout_info, SessionManager

log = logging.getLogger(__name__)

class SessionUI:
    """UI components for session management"""
    
    @staticmethod
    def show_session_timeout_warning() -> None:
        """Show minimal session timeout warning only when critically close to expiration"""
        try:
            timeout_info = get_session_timeout_info()
            if not timeout_info:
                return
            
            remaining_seconds = timeout_info.get('remaining_seconds', 0)
            
            # Only show warning in the last 2 minutes (120 seconds)
            if remaining_seconds > 0 and remaining_seconds <= 120:
                minutes_remaining = max(1, remaining_seconds // 60)
                
                # Show subtle warning only
                with st.sidebar:
                    st.caption(f"⏰ Sesión expira en {minutes_remaining} min")
            
        except Exception as e:
            log.error(f"Error showing session timeout warning: {e}")
    
    @staticmethod
    def show_session_info() -> None:
        """Show detailed session information in an expander"""
        try:
            timeout_info = get_session_timeout_info()
            if not timeout_info:
                return
            
            with st.expander("🔒 Información de Sesión", expanded=False):
                remaining_seconds = timeout_info.get('remaining_seconds', 0)
                timeout_minutes = timeout_info.get('timeout_minutes', 30)
                expires_at = timeout_info.get('expires_at')
                
                if remaining_seconds > 0:
                    minutes = remaining_seconds // 60
                    seconds = remaining_seconds % 60
                    
                    st.info(f"⏱️ **Tiempo restante:** {minutes}m {seconds}s")
                    st.info(f"⏰ **Expira a las:** {expires_at.strftime('%H:%M:%S') if expires_at else 'N/A'}")
                    st.info(f"🕐 **Duración total:** {timeout_minutes} minutos")
                    
                    # Progress bar for visual indication
                    progress = max(0, remaining_seconds / (timeout_minutes * 60))
                    st.progress(progress, text="Tiempo de sesión restante")
                    
                    if st.button("🔄 Renovar Sesión", key="manual_refresh"):
                        SessionManager.update_activity()
                        st.success("Sesión renovada exitosamente")
                        st.rerun()
                else:
                    st.error("❌ Sesión expirada")
                    if st.button("🔄 Recargar", key="reload_expired"):
                        st.rerun()
                        
        except Exception as e:
            log.error(f"Error showing session info: {e}")
    
    @staticmethod
    def auto_refresh_session() -> None:
        """Automatically refresh session when user is active"""
        try:
            # Add JavaScript for detecting user activity
            st.markdown("""
            <script>
            let lastActivity = Date.now();
            let activityTimeout;
            
            function updateActivity() {
                lastActivity = Date.now();
                clearTimeout(activityTimeout);
                activityTimeout = setTimeout(function() {
                    // Send activity update to Streamlit
                    window.parent.postMessage({
                        type: 'streamlit:userActivity',
                        timestamp: lastActivity
                    }, '*');
                }, 1000); // Debounce for 1 second
            }
            
            // Listen for user activity
            ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(function(event) {
                document.addEventListener(event, updateActivity, true);
            });
            
            // Initial activity update
            updateActivity();
            </script>
            """, unsafe_allow_html=True)
            
        except Exception as e:
            log.error(f"Error setting up auto-refresh: {e}")
    
    @staticmethod
    def show_security_status() -> None:
        """Show overall security status indicator"""
        try:
            if st.session_state.get('authenticated', False):
                username = st.session_state.get('username', 'N/A')
                role_name = st.session_state.get('role_name', 'N/A')
                
                with st.sidebar:
                    st.success("🔐 **Sesión Segura Activa**")
                    st.caption(f"👤 {username} | 🎭 {role_name}")
                    
                    # Show session timeout warning
                    SessionUI.show_session_timeout_warning()
                    
        except Exception as e:
            log.error(f"Error showing security status: {e}")

def render_session_monitor() -> None:
    """Render session monitoring components"""
    try:
        # Only show for authenticated users
        if not st.session_state.get('authenticated', False):
            return
        
        # Auto-refresh functionality
        SessionUI.auto_refresh_session()
        
        # Security status in sidebar
        SessionUI.show_security_status()
        
        # Detailed session info (optional)
        if st.session_state.get('show_session_details', False):
            SessionUI.show_session_info()
            
    except Exception as e:
        log.error(f"Error rendering session monitor: {e}")

def add_session_timeout_countdown() -> None:
    """Add a countdown timer for session timeout"""
    try:
        timeout_info = get_session_timeout_info()
        if not timeout_info:
            return
        
        remaining_seconds = timeout_info.get('remaining_seconds', 0)
        will_expire_soon = timeout_info.get('will_expire_soon', False)
        
        if will_expire_soon and remaining_seconds > 0:
            # Add countdown timer in a container
            placeholder = st.empty()
            
            # JavaScript countdown
            countdown_script = f"""
            <div id="session-countdown" style="
                position: fixed;
                top: 10px;
                right: 10px;
                background: linear-gradient(45deg, #ff6b6b, #ee5a24);
                color: white;
                padding: 10px 15px;
                border-radius: 25px;
                font-weight: bold;
                z-index: 1000;
                box-shadow: 0 4px 15px rgba(255, 107, 107, 0.4);
                animation: pulse 2s infinite;
            ">
                ⏰ Sesión expira en: <span id="countdown-timer">{remaining_seconds}</span>s
            </div>
            
            <style>
            @keyframes pulse {{
                0% {{ transform: scale(1); }}
                50% {{ transform: scale(1.05); }}
                100% {{ transform: scale(1); }}
            }}
            </style>
            
            <script>
            let timeLeft = {remaining_seconds};
            const countdownElement = document.getElementById('countdown-timer');
            
            const countdown = setInterval(function() {{
                timeLeft--;
                if (countdownElement) {{
                    countdownElement.textContent = timeLeft;
                }}
                
                if (timeLeft <= 0) {{
                    clearInterval(countdown);
                    // Redirect to login or refresh page
                    window.location.reload();
                }}
            }}, 1000);
            </script>
            """
            
            placeholder.markdown(countdown_script, unsafe_allow_html=True)
            
    except Exception as e:
        log.error(f"Error adding countdown timer: {e}")

# Export main functions
__all__ = [
    'SessionUI',
    'render_session_monitor',
    'add_session_timeout_countdown'
]
