# --- auth/security_middleware.py ---
"""
Enhanced Security Middleware for Streamlit Authentication
Implements JWT tokens, secure session management, and comprehensive route protection
"""

import streamlit as st
import jwt
import hashlib
import secrets
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable, Set
import pytz
import logging
from functools import wraps
from cryptography.fernet import Fernet
import os

# Local imports
from database.database import get_db_session
from database.models import User, Role
from utils.config import get_configuration

log = logging.getLogger(__name__)

# Security Configuration Constants
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_urlsafe(32))
JWT_ALGORITHM = 'HS256'
SESSION_TIMEOUT_MINUTES = 30  # Default session timeout
REFRESH_TOKEN_MINUTES = 60 * 24 * 7  # 7 days for refresh tokens
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())

# Initialize encryption
try:
    cipher_suite = Fernet(ENCRYPTION_KEY)
except Exception as e:
    log.error(f"Failed to initialize encryption: {e}")
    cipher_suite = Fernet(Fernet.generate_key())

# Timezone configuration
try:
    DEFAULT_TIMEZONE = get_configuration('timezone', 'general', 'America/Bogota')
    colombia_tz = pytz.timezone(DEFAULT_TIMEZONE if DEFAULT_TIMEZONE else 'America/Bogota')
except Exception as e:
    log.warning(f"Failed getting timezone config: {e}. Using America/Bogota")
    colombia_tz = pytz.timezone('America/Bogota')

class SecurityConfig:
    """Centralized security configuration management"""
    
    @staticmethod
    def get_session_timeout() -> int:
        """Get session timeout in minutes from configuration"""
        try:
            timeout = get_configuration('session_timeout', 'security', str(SESSION_TIMEOUT_MINUTES))
            return max(5, int(timeout))  # Minimum 5 minutes
        except Exception as e:
            log.error(f"Error getting session timeout: {e}")
            return SESSION_TIMEOUT_MINUTES
    
    @staticmethod
    def get_password_requirements() -> Dict[str, Any]:
        """Get password requirements from configuration"""
        defaults = {
            'min_length': 8,
            'require_special': True,
            'require_numbers': True,
            'require_uppercase': True
        }
        
        try:
            with get_db_session() as db:
                config = {}
                config['min_length'] = max(4, int(get_configuration('password_min_length', 'security', '8', db)))
                config['require_special'] = get_configuration('password_require_special', 'security', 'True', db).lower() == 'true'
                config['require_numbers'] = get_configuration('password_require_numbers', 'security', 'True', db).lower() == 'true'
                config['require_uppercase'] = get_configuration('password_require_uppercase', 'security', 'True', db).lower() == 'true'
                return config
        except Exception as e:
            log.error(f"Error reading password requirements: {e}")
            return defaults

class TokenManager:
    """Secure JWT token management with encryption"""
    
    @staticmethod
    def generate_access_token(user_info: Dict[str, Any]) -> str:
        """Generate secure JWT access token"""
        try:
            now = datetime.now(colombia_tz)
            timeout_minutes = SecurityConfig.get_session_timeout()
            
            payload = {
                'user_id': user_info['user_id'],
                'username': user_info['username'],
                'role_name': user_info['role_name'],
                'permissions': list(user_info['permissions']),
                'iat': now.timestamp(),
                'exp': (now + timedelta(minutes=timeout_minutes)).timestamp(),
                'type': 'access'
            }
            
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            log.info(f"Generated access token for user {user_info['username']}")
            return token
            
        except Exception as e:
            log.error(f"Error generating access token: {e}")
            raise SecurityException("Failed to generate access token")
    
    @staticmethod
    def generate_refresh_token(user_info: Dict[str, Any]) -> str:
        """Generate secure refresh token"""
        try:
            now = datetime.now(colombia_tz)
            
            payload = {
                'user_id': user_info['user_id'],
                'username': user_info['username'],
                'iat': now.timestamp(),
                'exp': (now + timedelta(minutes=REFRESH_TOKEN_MINUTES)).timestamp(),
                'type': 'refresh'
            }
            
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            log.info(f"Generated refresh token for user {user_info['username']}")
            return token
            
        except Exception as e:
            log.error(f"Error generating refresh token: {e}")
            raise SecurityException("Failed to generate refresh token")
    
    @staticmethod
    def validate_token(token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
        """Validate and decode JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get('type') != token_type:
                log.warning(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
                return None
            
            # Check if token is expired
            if datetime.now(colombia_tz).timestamp() > payload.get('exp', 0):
                log.info(f"Token expired for user {payload.get('username')}")
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            log.info("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            log.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            log.error(f"Error validating token: {e}")
            return None
    
    @staticmethod
    def refresh_access_token(refresh_token: str) -> Optional[str]:
        """Generate new access token using refresh token"""
        try:
            payload = TokenManager.validate_token(refresh_token, 'refresh')
            if not payload:
                return None
            
            # Get fresh user info from database
            with get_db_session() as db:
                user = db.query(User).filter(User.id == payload['user_id']).first()
                if not user or user.status != 'active':
                    log.warning(f"User {payload['username']} not found or inactive during token refresh")
                    return None
                
                # Get updated permissions
                permissions = set()
                if user.role:
                    permissions = set(p.strip() for p in (user.role.permissions or '').split(',') if p.strip())
                
                user_info = {
                    'user_id': user.id,
                    'username': user.username,
                    'role_name': user.role.name if user.role else 'N/A',
                    'permissions': permissions
                }
                
                return TokenManager.generate_access_token(user_info)
                
        except Exception as e:
            log.error(f"Error refreshing token: {e}")
            return None

class SecureStorage:
    """Encrypted local storage management"""
    
    @staticmethod
    def encrypt_data(data: Dict[str, Any]) -> str:
        """Encrypt data for secure storage"""
        try:
            json_data = json.dumps(data)
            encrypted = cipher_suite.encrypt(json_data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            log.error(f"Error encrypting data: {e}")
            raise SecurityException("Failed to encrypt data")
    
    @staticmethod
    def decrypt_data(encrypted_data: str) -> Optional[Dict[str, Any]]:
        """Decrypt data from secure storage"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = cipher_suite.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
        except Exception as e:
            log.error(f"Error decrypting data: {e}")
            return None
    
    @staticmethod
    def store_session_data(session_data: Dict[str, Any]) -> None:
        """Store encrypted session data in browser storage"""
        try:
            # Add timestamp for validation
            session_data['stored_at'] = datetime.now(colombia_tz).timestamp()
            encrypted = SecureStorage.encrypt_data(session_data)
            
            # Store in Streamlit session state with encryption
            st.session_state['_encrypted_session'] = encrypted
            
            # Also store in query params as backup (for page refreshes)
            st.query_params['session_token'] = encrypted[:100]  # Truncated for URL safety
            
        except Exception as e:
            log.error(f"Error storing session data: {e}")
    
    @staticmethod
    def retrieve_session_data() -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt session data"""
        try:
            # Try to get from session state first
            encrypted = st.session_state.get('_encrypted_session')
            
            # Fallback to query params if not in session state
            if not encrypted and 'session_token' in st.query_params:
                # This is a truncated version, so we can't decrypt it
                # This is just for session detection
                return None
            
            if encrypted:
                data = SecureStorage.decrypt_data(encrypted)
                if data:
                    # Validate storage time (prevent old session reuse)
                    stored_at = data.get('stored_at', 0)
                    if datetime.now(colombia_tz).timestamp() - stored_at > REFRESH_TOKEN_MINUTES * 60:
                        log.info("Stored session data too old, clearing")
                        SecureStorage.clear_session_data()
                        return None
                    return data
            
            return None
            
        except Exception as e:
            log.error(f"Error retrieving session data: {e}")
            return None
    
    @staticmethod
    def clear_session_data() -> None:
        """Clear all session data"""
        try:
            if '_encrypted_session' in st.session_state:
                del st.session_state['_encrypted_session']
            st.query_params.clear()
        except Exception as e:
            log.error(f"Error clearing session data: {e}")

class SessionManager:
    """Enhanced session management with automatic refresh"""
    
    @staticmethod
    def create_session(user_info: Dict[str, Any]) -> bool:
        """Create new secure session"""
        try:
            # Generate tokens
            access_token = TokenManager.generate_access_token(user_info)
            refresh_token = TokenManager.generate_refresh_token(user_info)
            
            # Prepare session data (convert set to list for JSON serialization)
            user_info_serializable = user_info.copy()
            user_info_serializable['permissions'] = list(user_info['permissions'])
            
            session_data = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user_info': user_info_serializable,
                'created_at': datetime.now(colombia_tz).timestamp(),
                'last_activity': datetime.now(colombia_tz).timestamp()
            }
            
            # Store encrypted session data
            SecureStorage.store_session_data(session_data)
            
            # Update Streamlit session state
            st.session_state.update({
                'authenticated': True,
                'username': user_info['username'],
                'user_id': user_info['user_id'],
                'role_name': user_info['role_name'],
                'permissions': user_info['permissions'],
                'last_activity_time': datetime.now(colombia_tz),
                'session_created_at': datetime.now(colombia_tz)
            })
            
            log.info(f"Session created for user {user_info['username']}")
            return True
            
        except Exception as e:
            log.error(f"Error creating session: {e}")
            return False
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session and refresh if needed"""
        try:
            # First check if user is already authenticated in current session
            if st.session_state.get('authenticated', False):
                # Check if session is still within timeout
                last_activity = st.session_state.get('last_activity_time')
                if last_activity:
                    timeout_minutes = SecurityConfig.get_session_timeout()
                    if datetime.now(colombia_tz) - last_activity <= timedelta(minutes=timeout_minutes):
                        return True
            
            # Try to restore from encrypted storage
            session_data = SecureStorage.retrieve_session_data()
            if not session_data:
                return False
            
            access_token = session_data.get('access_token')
            refresh_token = session_data.get('refresh_token')
            
            if not access_token or not refresh_token:
                return False
            
            # Try to validate access token
            payload = TokenManager.validate_token(access_token, 'access')
            
            if payload:
                # Token is valid, restore session state
                user_info = session_data.get('user_info', {})
                permissions = user_info.get('permissions', [])
                if isinstance(permissions, list):
                    permissions = set(permissions)
                
                st.session_state.update({
                    'authenticated': True,
                    'username': user_info.get('username'),
                    'user_id': user_info.get('user_id'),
                    'role_name': user_info.get('role_name'),
                    'permissions': permissions,
                    'last_activity_time': datetime.now(colombia_tz)
                })
                
                SessionManager.update_activity()
                return True
            
            # Access token expired, try to refresh
            log.info("Access token expired, attempting refresh")
            new_access_token = TokenManager.refresh_access_token(refresh_token)
            
            if new_access_token:
                # Update session with new token
                session_data['access_token'] = new_access_token
                session_data['last_activity'] = datetime.now(colombia_tz).timestamp()
                SecureStorage.store_session_data(session_data)
                
                # Restore session state
                user_info = session_data.get('user_info', {})
                permissions = user_info.get('permissions', [])
                if isinstance(permissions, list):
                    permissions = set(permissions)
                
                st.session_state.update({
                    'authenticated': True,
                    'username': user_info.get('username'),
                    'user_id': user_info.get('user_id'),
                    'role_name': user_info.get('role_name'),
                    'permissions': permissions,
                    'last_activity_time': datetime.now(colombia_tz)
                })
                
                log.info(f"Session refreshed for user {user_info.get('username')}")
                return True
            
            # Both tokens invalid
            log.info("Both access and refresh tokens invalid, clearing session")
            SessionManager.destroy_session()
            return False
            
        except Exception as e:
            log.error(f"Error validating session: {e}")
            return False
    
    @staticmethod
    def update_activity() -> None:
        """Update last activity timestamp"""
        try:
            st.session_state['last_activity_time'] = datetime.now(colombia_tz)
            
            # Update stored session data
            session_data = SecureStorage.retrieve_session_data()
            if session_data:
                session_data['last_activity'] = datetime.now(colombia_tz).timestamp()
                SecureStorage.store_session_data(session_data)
                
        except Exception as e:
            log.error(f"Error updating activity: {e}")
    
    @staticmethod
    def destroy_session(message: str = "Sesión cerrada correctamente") -> None:
        """Destroy current session"""
        try:
            username = st.session_state.get('username', 'Unknown')
            log.info(f"Destroying session for user {username}")
            
            # Clear encrypted storage
            SecureStorage.clear_session_data()
            
            # Clear all session state
            keys_to_clear = list(st.session_state.keys())
            for key in keys_to_clear:
                try:
                    del st.session_state[key]
                except KeyError:
                    pass
            
            # Reset to default state
            st.session_state.update({
                'authenticated': False,
                'username': None,
                'user_id': None,
                'role_name': None,
                'permissions': set()
            })
            
            if message:
                st.success(message)
                
        except Exception as e:
            log.error(f"Error destroying session: {e}")
    
    @staticmethod
    def get_session_info() -> Dict[str, Any]:
        """Get current session information"""
        try:
            session_data = SecureStorage.retrieve_session_data()
            if not session_data:
                return {}
            
            user_info = session_data.get('user_info', {})
            created_at = session_data.get('created_at', 0)
            last_activity = session_data.get('last_activity', 0)
            
            return {
                'username': user_info.get('username'),
                'role_name': user_info.get('role_name'),
                'permissions': user_info.get('permissions', set()),
                'created_at': datetime.fromtimestamp(created_at, colombia_tz) if created_at else None,
                'last_activity': datetime.fromtimestamp(last_activity, colombia_tz) if last_activity else None,
                'timeout_minutes': SecurityConfig.get_session_timeout()
            }
            
        except Exception as e:
            log.error(f"Error getting session info: {e}")
            return {}

class SecurityException(Exception):
    """Custom exception for security-related errors"""
    pass

def requires_authentication(func: Callable) -> Callable:
    """
    Enhanced authentication decorator with automatic session refresh
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            # Initialize session if needed
            if not hasattr(st.session_state, 'authenticated'):
                st.session_state.authenticated = False
            
            # Try to validate/refresh session
            if not SessionManager.validate_session():
                log.info("Authentication required - showing login page")
                from auth.auth import show_login_page
                show_login_page()
                st.stop()
            
            # Update activity timestamp
            SessionManager.update_activity()
            
            # Execute the protected function
            return func(*args, **kwargs)
            
        except SecurityException as e:
            log.error(f"Security error in {func.__name__}: {e}")
            st.error("Error de seguridad. Por favor, inicie sesión nuevamente.")
            SessionManager.destroy_session("Sesión terminada por razones de seguridad")
            st.rerun()
            
        except Exception as e:
            log.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
            st.error("Error inesperado. Por favor, intente nuevamente.")
            st.stop()
    
    return wrapper

def requires_permission(permission_name: str) -> Callable:
    """
    Enhanced permission decorator with session validation
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # First check authentication
                if not SessionManager.validate_session():
                    log.info(f"Permission check failed - not authenticated for {permission_name}")
                    from auth.auth import show_login_page
                    show_login_page()
                    st.stop()
                
                # Check permissions
                user_permissions = st.session_state.get('permissions', set())
                if permission_name not in user_permissions:
                    username = st.session_state.get('username', 'Unknown')
                    log.warning(f"Access denied for user {username} trying to access {permission_name}")
                    
                    st.title("🚫 Acceso Denegado")
                    st.error(f"No tienes permisos para acceder a esta funcionalidad.")
                    st.info(f"Permiso requerido: **{permission_name}**")
                    st.info("Contacta al administrador si necesitas acceso.")
                    st.stop()
                
                # Update activity and execute function
                SessionManager.update_activity()
                return func(*args, **kwargs)
                
            except SecurityException as e:
                log.error(f"Security error in permission check for {permission_name}: {e}")
                st.error("Error de seguridad en la validación de permisos.")
                SessionManager.destroy_session("Sesión terminada por error de seguridad")
                st.rerun()
                
            except Exception as e:
                log.error(f"Unexpected error in permission check for {permission_name}: {e}", exc_info=True)
                st.error("Error inesperado en la validación de permisos.")
                st.stop()
        
        return wrapper
    return decorator

def requires_role(allowed_roles: list) -> Callable:
    """
    Enhanced role decorator with session validation
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    
    allowed_roles_lower = set(role.lower() for role in allowed_roles)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Check authentication first
                if not SessionManager.validate_session():
                    log.info(f"Role check failed - not authenticated for roles {allowed_roles}")
                    from auth.auth import show_login_page
                    show_login_page()
                    st.stop()
                
                # Check role
                current_role = (st.session_state.get('role_name', '') or '').lower()
                if current_role not in allowed_roles_lower:
                    username = st.session_state.get('username', 'Unknown')
                    log.warning(f"Access denied for user {username} with role {current_role}, required: {allowed_roles}")
                    
                    st.title("🚫 Acceso Restringido")
                    st.error("Tu rol no tiene permisos para acceder a esta funcionalidad.")
                    st.info(f"Roles permitidos: **{', '.join(allowed_roles)}**")
                    st.info(f"Tu rol actual: **{st.session_state.get('role_name', 'N/A')}**")
                    st.stop()
                
                # Update activity and execute function
                SessionManager.update_activity()
                return func(*args, **kwargs)
                
            except SecurityException as e:
                log.error(f"Security error in role check for {allowed_roles}: {e}")
                st.error("Error de seguridad en la validación de roles.")
                SessionManager.destroy_session("Sesión terminada por error de seguridad")
                st.rerun()
                
            except Exception as e:
                log.error(f"Unexpected error in role check for {allowed_roles}: {e}", exc_info=True)
                st.error("Error inesperado en la validación de roles.")
                st.stop()
        
        return wrapper
    return decorator

def initialize_security_system() -> None:
    """Initialize the security system"""
    try:
        log.info("Initializing enhanced security system")
        
        # Ensure session state is properly initialized
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        
        # Try to restore session from encrypted storage
        if not st.session_state.get('authenticated', False):
            # The session validation will handle restoration automatically
            SessionManager.validate_session()
        
    except Exception as e:
        log.error(f"Error initializing security system: {e}", exc_info=True)

# Session timeout monitoring (for UI display)
def get_session_timeout_info() -> Dict[str, Any]:
    """Get session timeout information for UI display"""
    try:
        session_info = SessionManager.get_session_info()
        if not session_info.get('last_activity'):
            return {}
        
        timeout_minutes = session_info.get('timeout_minutes', SESSION_TIMEOUT_MINUTES)
        last_activity = session_info['last_activity']
        expires_at = last_activity + timedelta(minutes=timeout_minutes)
        remaining = expires_at - datetime.now(colombia_tz)
        
        return {
            'expires_at': expires_at,
            'remaining_seconds': max(0, int(remaining.total_seconds())),
            'timeout_minutes': timeout_minutes,
            'will_expire_soon': remaining.total_seconds() < 300  # 5 minutes warning
        }
        
    except Exception as e:
        log.error(f"Error getting timeout info: {e}")
        return {}

# Export main functions
__all__ = [
    'requires_authentication',
    'requires_permission', 
    'requires_role',
    'SessionManager',
    'TokenManager',
    'SecureStorage',
    'SecurityConfig',
    'initialize_security_system',
    'get_session_timeout_info',
    'SecurityException'
]
