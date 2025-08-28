#!/usr/bin/env python3
"""
Script para aplicar las migraciones RBAC manualmente
"""

import os
import sys
import sqlite3
from pathlib import Path

def apply_migration_file(db_path: str, migration_file: str):
    """
    Aplica un archivo de migración específico a la base de datos.
    
    Args:
        db_path: Ruta a la base de datos SQLite
        migration_file: Ruta al archivo de migración SQL
    """
    print(f"Aplicando migración: {migration_file}")
    
    try:
        # Leer el contenido del archivo de migración
        with open(migration_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Conectar a la base de datos
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ejecutar las sentencias SQL
        cursor.executescript(sql_content)
        conn.commit()
        conn.close()
        
        print(f"✅ Migración aplicada exitosamente: {os.path.basename(migration_file)}")
        
    except Exception as e:
        print(f"❌ Error aplicando migración {migration_file}: {e}")
        sys.exit(1)

def main():
    """Función principal para aplicar migraciones RBAC."""
    
    # Rutas
    project_root = Path(__file__).parent
    db_path = project_root / "amco.bybinary_dashboard.db"
    migrations_dir = project_root / "database" / "migrations"
    
    # Verificar que la base de datos existe
    if not db_path.exists():
        print(f"❌ Base de datos no encontrada: {db_path}")
        sys.exit(1)
    
    # Migraciones RBAC a aplicar
    rbac_migrations = [
        "015_create_role_agent_access_table.sql",
        "016_add_user_preferences_table.sql"
    ]
    
    print("🚀 Aplicando migraciones RBAC...")
    print(f"Base de datos: {db_path}")
    print(f"Directorio de migraciones: {migrations_dir}")
    print()
    
    for migration_name in rbac_migrations:
        migration_path = migrations_dir / migration_name
        
        if not migration_path.exists():
            print(f"⚠️ Archivo de migración no encontrado: {migration_path}")
            continue
        
        apply_migration_file(str(db_path), str(migration_path))
    
    print()
    print("✅ Todas las migraciones RBAC han sido aplicadas exitosamente!")
    print()
    print("🔧 Próximos pasos:")
    print("1. Reinicia la aplicación Streamlit")
    print("2. Ve a la página 'Control de Acceso a Agentes' para configurar permisos")
    print("3. Asigna accesos específicos a los roles según sea necesario")
    
if __name__ == "__main__":
    main()
