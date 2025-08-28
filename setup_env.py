# --- setup_env.py ---
"""
Script para configurar el archivo .env con tus credenciales de Supabase
Ejecuta este script y sigue las instrucciones
"""

import os
from cryptography.fernet import Fernet
import secrets

def generate_keys():
    """Generate secure keys for the application"""
    jwt_key = secrets.token_urlsafe(32)
    fernet_key = Fernet.generate_key().decode()
    
    return jwt_key, fernet_key

def create_env_file():
    """Interactive setup for .env file"""
    print("🔧 Configuración de Supabase para IA-TEK Dashboard")
    print("=" * 60)
    
    # Get Supabase credentials
    print("\n📝 Ingresa tus credenciales de Supabase:")
    print("(Puedes encontrarlas en Settings > Database de tu proyecto)")
    
    supabase_url = input("SUPABASE_URL: https://")
    if not supabase_url.startswith('http'):
        supabase_url = f"https://{supabase_url}"
    
    supabase_anon_key = input("SUPABASE_ANON_KEY: ")
    supabase_service_key = input("SUPABASE_SERVICE_KEY: ")
    
    # Extract project reference from URL
    project_ref = supabase_url.replace('https://', '').replace('.supabase.co', '')
    
    db_password = input("Database Password: ")
    database_url = f"postgresql://postgres:{db_password}@db.{project_ref}.supabase.co:5432/postgres"
    
    # Generate security keys
    print("\n🔐 Generando claves de seguridad...")
    jwt_key, fernet_key = generate_keys()
    
    # Create .env content
    env_content = f"""# Supabase Configuration
SUPABASE_URL={supabase_url}
SUPABASE_ANON_KEY={supabase_anon_key}
SUPABASE_SERVICE_KEY={supabase_service_key}
DATABASE_URL={database_url}

# Security Configuration
JWT_SECRET_KEY={jwt_key}
ENCRYPTION_KEY={fernet_key}
SESSION_TIMEOUT_MINUTES=30

# Application Configuration
ENVIRONMENT=development
DEBUG=True
LOG_LEVEL=INFO
"""
    
    # Write to .env file
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("\n✅ Archivo .env creado exitosamente!")
    print("\n⚠️  IMPORTANTE:")
    print("- Nunca compartas tu archivo .env")
    print("- Agrega .env a tu .gitignore")
    print("- Para producción, usa variables de entorno del servidor")
    
    return True

def test_connection():
    """Test the database connection"""
    try:
        from database.supabase_config import get_supabase_config
        
        config = get_supabase_config()
        if config.test_connection():
            print("\n✅ ¡Conexión a Supabase exitosa!")
            return True
        else:
            print("\n❌ Error en la conexión. Verifica tus credenciales.")
            return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

if __name__ == "__main__":
    try:
        if create_env_file():
            print("\n🧪 Probando conexión...")
            test_connection()
            
            print("\n🚀 Siguiente paso:")
            print("Ejecuta: python migrate_to_supabase.py")
            
    except KeyboardInterrupt:
        print("\n\n❌ Configuración cancelada.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
