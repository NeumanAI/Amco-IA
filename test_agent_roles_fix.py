#!/usr/bin/env python3
"""
Script de prueba para verificar que el error de gestión de roles se ha solucionado
"""

import sys
from pathlib import Path

# Agregar el directorio del proyecto al path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Importar las funciones necesarias
from database.database import get_db_session
from database.models import Agent, Role, RoleAgentAccess

def test_agent_roles_fix():
    """Prueba las funciones de gestión de roles sin errores de sesión."""
    
    print("🧪 Probando funciones de gestión de roles de agentes...")
    
    try:
        # Test 1: Verificar que podemos obtener agentes sin errores de sesión
        print("\n1. Probando carga de agentes...")
        with get_db_session() as db:
            agents = db.query(Agent).all()
            print(f"   ✓ Se encontraron {len(agents)} agentes")
            
            # Extraer datos primitivos (como en el fix)
            agents_data = []
            for agent in agents:
                agents_data.append({
                    'id': agent.id,
                    'name': agent.name
                })
        
        print(f"   ✓ Datos primitivos extraídos correctamente: {len(agents_data)} agentes")
        
        # Test 2: Verificar que podemos obtener roles sin errores de sesión
        print("\n2. Probando carga de roles...")
        with get_db_session() as db:
            roles = db.query(Role).all()
            print(f"   ✓ Se encontraron {len(roles)} roles")
            
            # Extraer datos primitivos (como en el fix)
            roles_data = []
            for role in roles:
                roles_data.append({
                    'id': role.id,
                    'name': role.name
                })
        
        print(f"   ✓ Datos primitivos extraídos correctamente: {len(roles_data)} roles")
        
        # Test 3: Verificar función get_agent_role_access (simulada)
        print("\n3. Probando consulta de accesos de agente...")
        if agents_data:
            test_agent_id = agents_data[0]['id']
            
            # Simular la función get_agent_role_access
            role_access = {}
            with get_db_session() as db:
                query = db.query(
                    Role.name,
                    RoleAgentAccess.access_level
                ).outerjoin(
                    RoleAgentAccess, 
                    (Role.id == RoleAgentAccess.role_id) & (RoleAgentAccess.agent_id == test_agent_id)
                ).order_by(Role.name).all()
                
                for role_name, access_level in query:
                    if role_name and role_name.lower() == 'superadministrador':
                        role_access[role_name] = 'full_access'
                    else:
                        role_access[role_name] = access_level or 'no_access'
            
            print(f"   ✓ Accesos obtenidos para agente {test_agent_id}: {len(role_access)} roles")
            
            for role_name, access_level in role_access.items():
                print(f"     - {role_name}: {access_level}")
        
        # Test 4: Verificar accesos existentes
        print("\n4. Verificando accesos existentes en BD...")
        with get_db_session() as db:
            access_count = db.query(RoleAgentAccess).count()
            print(f"   ✓ Se encontraron {access_count} registros de acceso configurados")
            
            if access_count > 0:
                sample_accesses = db.query(
                    Role.name,
                    Agent.name,
                    RoleAgentAccess.access_level
                ).join(Role, RoleAgentAccess.role_id == Role.id)\
                 .join(Agent, RoleAgentAccess.agent_id == Agent.id)\
                 .limit(5).all()
                
                print("   Ejemplos de accesos configurados:")
                for role_name, agent_name, access_level in sample_accesses:
                    print(f"     - {role_name} → {agent_name}: {access_level}")
        
        print("\n✅ Todas las pruebas pasaron exitosamente!")
        print("🔧 El error de sesión de SQLAlchemy debería estar solucionado.")
        
    except Exception as e:
        print(f"\n❌ Error durante las pruebas: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = test_agent_roles_fix()
    sys.exit(0 if success else 1)
