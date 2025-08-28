# --- utils/security_logger.py ---
"""
Enhanced Security Logging and Error Handling System
Provides comprehensive logging for security events and error tracking
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
import streamlit as st
from pathlib import Path

# Create logs directory if it doesn't exist
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

class SecurityLogger:
    """Enhanced security logger with structured logging"""
    
    def __init__(self, name: str = "security"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup logging handlers"""
        try:
            # File handler for security events
            security_file = LOGS_DIR / "security.log"
            file_handler = logging.handlers.RotatingFileHandler(
                security_file, 
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            
            # Console handler
            console_handler = logging.StreamHandler()
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            
        except Exception as e:
            print(f"Error setting up security logger: {e}")
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], level: str = "INFO"):
        """Log security events with structured data"""
        try:
            # Get user context
            username = st.session_state.get('username', 'Anonymous')
            user_id = st.session_state.get('user_id', 'Unknown')
            
            # Create structured log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'username': username,
                'user_id': user_id,
                'details': details,
                'session_id': st.session_state.get('chat_session_id', 'N/A')
            }
            
            # Log based on level
            message = f"SECURITY_EVENT: {json.dumps(log_entry)}"
            
            if level.upper() == "ERROR":
                self.logger.error(message)
            elif level.upper() == "WARNING":
                self.logger.warning(message)
            elif level.upper() == "CRITICAL":
                self.logger.critical(message)
            else:
                self.logger.info(message)
                
        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
    
    def log_authentication_attempt(self, username: str, success: bool, ip_address: str = None):
        """Log authentication attempts"""
        details = {
            'success': success,
            'ip_address': ip_address or 'Unknown',
            'user_agent': st.session_state.get('user_agent', 'Unknown')
        }
        
        event_type = "AUTH_SUCCESS" if success else "AUTH_FAILURE"
        level = "INFO" if success else "WARNING"
        
        # Add username to details for failed attempts
        if not success:
            details['attempted_username'] = username
        
        self.log_security_event(event_type, details, level)
    
    def log_session_event(self, event_type: str, details: Dict[str, Any] = None):
        """Log session-related events"""
        if details is None:
            details = {}
        
        self.log_security_event(f"SESSION_{event_type}", details)
    
    def log_permission_violation(self, required_permission: str, attempted_action: str):
        """Log permission violations"""
        details = {
            'required_permission': required_permission,
            'attempted_action': attempted_action,
            'user_permissions': list(st.session_state.get('permissions', set()))
        }
        
        self.log_security_event("PERMISSION_VIOLATION", details, "WARNING")
    
    def log_error(self, error: Exception, context: str = None):
        """Log errors with context"""
        details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context or 'Unknown'
        }
        
        self.log_security_event("APPLICATION_ERROR", details, "ERROR")

class SecurityErrorHandler:
    """Centralized error handling for security-related errors"""
    
    def __init__(self):
        self.logger = SecurityLogger("error_handler")
    
    def handle_authentication_error(self, error: Exception, username: str = None):
        """Handle authentication-related errors"""
        try:
            self.logger.log_error(error, f"Authentication error for user: {username}")
            
            # Show user-friendly error
            st.error("🔒 Error de autenticación. Por favor, intente nuevamente.")
            
            # Clear potentially corrupted session
            self._clear_session_safely()
            
        except Exception as e:
            st.error("Error crítico de seguridad. Contacte al administrador.")
            print(f"Critical security error: {e}")
    
    def handle_session_error(self, error: Exception, context: str = None):
        """Handle session-related errors"""
        try:
            self.logger.log_error(error, f"Session error: {context}")
            
            # Show user-friendly error
            st.warning("⚠️ Error de sesión. Será redirigido al login.")
            
            # Clear session and redirect
            self._clear_session_safely()
            st.rerun()
            
        except Exception as e:
            st.error("Error crítico de sesión. Recargue la página.")
            print(f"Critical session error: {e}")
    
    def handle_permission_error(self, required_permission: str, context: str = None):
        """Handle permission-related errors"""
        try:
            username = st.session_state.get('username', 'Unknown')
            self.logger.log_permission_violation(required_permission, context or 'Unknown action')
            
            # Show access denied message
            st.title("🚫 Acceso Denegado")
            st.error(f"No tienes permisos para realizar esta acción.")
            st.info(f"Permiso requerido: **{required_permission}**")
            st.info("Contacta al administrador si necesitas acceso.")
            
        except Exception as e:
            st.error("Error en la validación de permisos.")
            print(f"Permission error handling failed: {e}")
    
    def handle_general_error(self, error: Exception, context: str = None, show_user_message: bool = True):
        """Handle general application errors"""
        try:
            self.logger.log_error(error, context)
            
            if show_user_message:
                st.error("❌ Ha ocurrido un error inesperado.")
                
                # Show error details in debug mode
                if st.session_state.get('debug_mode', False):
                    st.exception(error)
            
        except Exception as e:
            st.error("Error crítico en el manejo de errores.")
            print(f"Critical error handling failure: {e}")
    
    def _clear_session_safely(self):
        """Safely clear session state"""
        try:
            # Import here to avoid circular imports
            from auth.security_middleware import SessionManager
            SessionManager.destroy_session()
        except Exception as e:
            # Fallback session clearing
            st.session_state.clear()
            st.session_state.update({
                'authenticated': False,
                'username': None,
                'user_id': None,
                'role_name': None,
                'permissions': set()
            })

class SecurityAuditLogger:
    """Audit logger for tracking security-sensitive operations"""
    
    def __init__(self):
        self.logger = SecurityLogger("audit")
    
    def log_user_action(self, action: str, target: str = None, details: Dict[str, Any] = None):
        """Log user actions for audit trail"""
        audit_details = {
            'action': action,
            'target': target,
            'timestamp': datetime.now().isoformat()
        }
        
        if details:
            audit_details.update(details)
        
        self.logger.log_security_event("USER_ACTION", audit_details)
    
    def log_admin_action(self, action: str, target_user: str = None, details: Dict[str, Any] = None):
        """Log administrative actions"""
        audit_details = {
            'action': action,
            'target_user': target_user,
            'admin_user': st.session_state.get('username', 'Unknown'),
            'timestamp': datetime.now().isoformat()
        }
        
        if details:
            audit_details.update(details)
        
        self.logger.log_security_event("ADMIN_ACTION", audit_details, "WARNING")
    
    def log_data_access(self, data_type: str, operation: str, record_count: int = None):
        """Log data access operations"""
        details = {
            'data_type': data_type,
            'operation': operation,
            'record_count': record_count,
            'timestamp': datetime.now().isoformat()
        }
        
        self.logger.log_security_event("DATA_ACCESS", details)

# Global instances
security_logger = SecurityLogger()
error_handler = SecurityErrorHandler()
audit_logger = SecurityAuditLogger()

# Decorator for automatic error handling
def handle_security_errors(func):
    """Decorator to automatically handle security-related errors"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_handler.handle_general_error(e, f"Error in {func.__name__}")
            st.stop()
    return wrapper

# Context manager for audit logging
class AuditContext:
    """Context manager for audit logging"""
    
    def __init__(self, action: str, target: str = None):
        self.action = action
        self.target = target
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        details = {
            'duration_seconds': duration,
            'success': exc_type is None
        }
        
        if exc_type:
            details['error'] = str(exc_val)
        
        audit_logger.log_user_action(self.action, self.target, details)

# Export main components
__all__ = [
    'SecurityLogger',
    'SecurityErrorHandler', 
    'SecurityAuditLogger',
    'security_logger',
    'error_handler',
    'audit_logger',
    'handle_security_errors',
    'AuditContext'
]
