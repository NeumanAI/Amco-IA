# --- database/supabase_config.py ---
"""
Supabase Configuration and Integration
Provides enhanced database functionality with Supabase features
"""

import os
import logging
from typing import Optional, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

log = logging.getLogger(__name__)

class SupabaseConfig:
    """Supabase configuration and client management"""
    
    def __init__(self):
        self.supabase_url = os.getenv('SUPABASE_URL')
        self.supabase_anon_key = os.getenv('SUPABASE_ANON_KEY')
        self.supabase_service_key = os.getenv('SUPABASE_SERVICE_KEY')
        self.database_url = os.getenv('DATABASE_URL')
        
        # Validate configuration
        if not all([self.supabase_url, self.supabase_anon_key, self.database_url]):
            raise ValueError("Missing required Supabase configuration. Check your environment variables.")
        
        # Initialize clients
        self._supabase_client = None
        self._engine = None
        self._session_factory = None
    
    @property
    def supabase_client(self) -> Client:
        """Get Supabase client (lazy initialization)"""
        if self._supabase_client is None:
            self._supabase_client = create_client(
                self.supabase_url, 
                self.supabase_service_key  # Use service key for admin operations
            )
        return self._supabase_client
    
    @property
    def engine(self):
        """Get SQLAlchemy engine for Supabase PostgreSQL"""
        if self._engine is None:
            self._engine = create_engine(
                self.database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=300,
                echo=os.getenv('DEBUG', 'False').lower() == 'true'
            )
        return self._engine
    
    @property
    def session_factory(self):
        """Get SQLAlchemy session factory"""
        if self._session_factory is None:
            self._session_factory = sessionmaker(bind=self.engine)
        return self._session_factory
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                conn.commit()
            log.info("✅ Supabase database connection successful")
            return True
        except Exception as e:
            log.error(f"❌ Supabase database connection failed: {e}")
            return False
    
    def test_supabase_client(self) -> bool:
        """Test Supabase client connection"""
        try:
            # Test with a simple query
            result = self.supabase_client.table('users').select('id').limit(1).execute()
            log.info("✅ Supabase client connection successful")
            return True
        except Exception as e:
            log.error(f"❌ Supabase client connection failed: {e}")
            return False

class SupabaseManager:
    """Enhanced database operations with Supabase features"""
    
    def __init__(self, config: SupabaseConfig):
        self.config = config
        self.client = config.supabase_client
    
    def create_user_with_auth(self, email: str, password: str, user_data: Dict[str, Any]) -> Optional[Dict]:
        """Create user with Supabase Auth (optional enhancement)"""
        try:
            # Create auth user
            auth_response = self.client.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": user_data
                }
            })
            
            if auth_response.user:
                log.info(f"Created Supabase auth user: {email}")
                return auth_response.user
            
        except Exception as e:
            log.error(f"Error creating Supabase auth user: {e}")
            return None
    
    def enable_rls_policies(self) -> bool:
        """Enable Row Level Security policies (security enhancement)"""
        try:
            policies = [
                # Users can only see their own data
                """
                CREATE POLICY "Users can view own data" ON users
                FOR SELECT USING (auth.uid()::text = id::text);
                """,
                
                # Users can only see their own conversations
                """
                CREATE POLICY "Users can view own conversations" ON conversations
                FOR SELECT USING (auth.uid()::text = user_id::text);
                """,
                
                # Users can only see their own queries
                """
                CREATE POLICY "Users can view own queries" ON queries
                FOR SELECT USING (
                    EXISTS (
                        SELECT 1 FROM conversations 
                        WHERE conversations.session_id = queries.session_id 
                        AND conversations.user_id::text = auth.uid()::text
                    )
                );
                """
            ]
            
            with self.config.engine.connect() as conn:
                for policy in policies:
                    try:
                        conn.execute(text(policy))
                        conn.commit()
                    except Exception as e:
                        # Policy might already exist
                        log.debug(f"Policy creation note: {e}")
            
            log.info("✅ RLS policies configured")
            return True
            
        except Exception as e:
            log.error(f"Error setting up RLS policies: {e}")
            return False
    
    def setup_realtime_subscriptions(self) -> bool:
        """Setup real-time subscriptions for live updates"""
        try:
            # Enable realtime for conversations
            self.client.postgrest.rpc('enable_realtime_for_table', {
                'table_name': 'conversations'
            })
            
            log.info("✅ Realtime subscriptions configured")
            return True
            
        except Exception as e:
            log.error(f"Error setting up realtime: {e}")
            return False
    
    def backup_to_storage(self, table_name: str) -> bool:
        """Backup table data to Supabase Storage"""
        try:
            # Export table data
            with self.config.engine.connect() as conn:
                result = conn.execute(text(f"SELECT * FROM {table_name}"))
                data = [dict(row._mapping) for row in result]
            
            # Upload to Supabase Storage
            import json
            from datetime import datetime
            
            backup_data = json.dumps(data, default=str)
            filename = f"{table_name}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            self.client.storage.from_('backups').upload(
                filename, 
                backup_data.encode('utf-8')
            )
            
            log.info(f"✅ Backup created: {filename}")
            return True
            
        except Exception as e:
            log.error(f"Error creating backup: {e}")
            return False

# Global instance
_supabase_config = None

def get_supabase_config() -> SupabaseConfig:
    """Get global Supabase configuration instance"""
    global _supabase_config
    if _supabase_config is None:
        _supabase_config = SupabaseConfig()
    return _supabase_config

def get_supabase_manager() -> SupabaseManager:
    """Get Supabase manager instance"""
    config = get_supabase_config()
    return SupabaseManager(config)

# Export main components
__all__ = [
    'SupabaseConfig',
    'SupabaseManager', 
    'get_supabase_config',
    'get_supabase_manager'
]
