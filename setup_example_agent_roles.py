#!/usr/bin/env python3
"""
Script para configurar accesos de ejemplo para los agentes
"""

import os
import sys
import sqlite3
from pathlib import Path

def setup_example_agent_roles():
    """Configura accesos de ejemplo para demostrar el sistema RBAC."""
    
    # Rutas
    project_root = Path(__file__).parent
    db_path = project_root / "amco.bybinary_dashboard.db"
    
    # Verificar que la base de datos existe
    if not db_path.exists():
        print(f"❌ Base de datos no encontrada: {db_path}")
        sys.exit(1)
    
    print("🚀 Configurando accesos de ejemplo para agentes...")
    print(f"Base de datos: {db_path}")
    print()
    
    try:
        # Conectar a la base de datos
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Obtener roles disponibles
        cursor.execute("SELECT id, name FROM roles ORDER BY name")
        roles = cursor.fetchall()
        
        if not roles:
            print("❌ No se encontraron roles en la base de datos.")
            print("   Asegúrate de que existan roles antes de ejecutar este script.")
            return
        
        print("📋 Roles disponibles:")
        for role_id, role_name in roles:
            print(f"   - {role_name} (ID: {role_id})")
        print()
        
        # Obtener agentes disponibles
        cursor.execute("SELECT id, name FROM agents ORDER BY name")
        agents = cursor.fetchall()
        
        if not agents:
            print("❌ No se encontraron agentes en la base de datos.")
            print("   Crea algunos agentes antes de ejecutar este script.")
            return
        
        print("🤖 Agentes disponibles:")
        for agent_id, agent_name in agents:
            print(f"   - {agent_name} (ID: {agent_id})")
        print()
        
        # Configuraciones de ejemplo
        print("⚙️ Configurando accesos de ejemplo...")
        
        # Buscar roles específicos por nombre
        role_map = {name.lower(): role_id for role_id, name in roles}
        print(f"🔍 Mapa de roles: {role_map}")
        
        # Configurar accesos según el ejemplo del usuario
        configurations = []
        
        # Si existe el Agente 1 y roles Usuario/SuperAdministrador
        if len(agents) >= 1:
            agent_1_id = agents[0][0]  # Primer agente
            agent_1_name = agents[0][1]
            
            # Usuario - Solo vista al Agente 1
            if 'usuario' in role_map:
                configurations.append((role_map['usuario'], agent_1_id, 'read_only'))
                print(f"   ✓ Usuario → {agent_1_name}: Solo Vista")
            
            # Administrador - Acceso completo al Agente 1
            if 'administrador' in role_map:
                configurations.append((role_map['administrador'], agent_1_id, 'full_access'))
                print(f"   ✓ Administrador → {agent_1_name}: Acceso Completo")
        
        # Si existe el Agente 2 - acceso para todos los roles
        if len(agents) >= 2:
            agent_2_id = agents[1][0]  # Segundo agente
            agent_2_name = agents[1][1]
            
            for role_id, role_name in roles:
                if role_name.lower() != 'superadministrador':  # SuperAdmin siempre tiene acceso
                    access_level = 'full_access' if role_name.lower() == 'administrador' else 'read_only'
                    configurations.append((role_id, agent_2_id, access_level))
                    access_text = "Acceso Completo" if access_level == 'full_access' else "Solo Vista"
                    print(f"   ✓ {role_name} → {agent_2_name}: {access_text}")
        
        # Si hay más agentes, configurar acceso variado
        if len(agents) >= 3:
            for i, (agent_id, agent_name) in enumerate(agents[2:], start=3):
                # Alternar accesos para demostrar variedad
                for role_id, role_name in roles:
                    if role_name.lower() != 'superadministrador':
                        if i % 2 == 0:  # Agentes pares - más acceso
                            access_level = 'full_access' if role_name.lower() in ['administrador'] else 'read_only'
                        else:  # Agentes impares - menos acceso
                            access_level = 'read_only' if role_name.lower() in ['administrador', 'usuario'] else 'no_access'
                        
                        if access_level != 'no_access':
                            configurations.append((role_id, agent_id, access_level))
                            access_text = "Acceso Completo" if access_level == 'full_access' else "Solo Vista"
                            print(f"   ✓ {role_name} → {agent_name}: {access_text}")
        
        # Aplicar configuraciones
        print()
        print("💾 Aplicando configuraciones...")
        
        for role_id, agent_id, access_level in configurations:
            # Verificar si ya existe un registro
            cursor.execute("""
                SELECT id FROM role_agent_access 
                WHERE role_id = ? AND agent_id = ?
            """, (role_id, agent_id))
            
            existing = cursor.fetchone()
            
            if existing:
                # Actualizar registro existente
                cursor.execute("""
                    UPDATE role_agent_access 
                    SET access_level = ?, updated_at = datetime('now', 'localtime')
                    WHERE role_id = ? AND agent_id = ?
                """, (access_level, role_id, agent_id))
            else:
                # Crear nuevo registro
                cursor.execute("""
                    INSERT INTO role_agent_access (role_id, agent_id, access_level)
                    VALUES (?, ?, ?)
                """, (role_id, agent_id, access_level))
        
        # Confirmar cambios
        conn.commit()
        conn.close()
        
        print(f"✅ Se configuraron {len(configurations)} accesos exitosamente!")
        print()
        print("🔧 Próximos pasos:")
        print("1. Reinicia la aplicación Streamlit")
        print("2. Ve a 'Gestión de Agentes IA' para ver la columna 'Roles con Acceso'")
        print("3. Usa el botón 🔐 para gestionar roles de agentes específicos")
        print("4. Ve a 'Agentes IA' con diferentes usuarios para ver el filtrado")
        
    except Exception as e:
        print(f"❌ Error configurando accesos de ejemplo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    setup_example_agent_roles()
