# Sistema de Control de Acceso Basado en Roles (RBAC) - Guía de Implementación

## 📋 Resumen

Se ha implementado un sistema avanzado de control de acceso basado en roles (RBAC) que proporciona control granular sobre qué usuarios pueden acceder a qué agentes de IA y con qué nivel de permisos.

## 🏗️ Arquitectura del Sistema

### Componentes Principales

1. **Base de Datos**
   - `role_agent_access`: Tabla que mapea roles a agentes con niveles de acceso específicos
   - `user_preferences`: Tabla para preferencias personalizadas de usuario

2. **Niveles de Acceso**
   - `no_access`: Sin acceso al agente
   - `read_only`: Puede ver el agente pero no interactuar
   - `full_access`: Acceso completo para ver e interactuar

3. **Funcionalidades**
   - Control granular de acceso por rol y agente
   - Interfaz administrativa para gestionar permisos
   - Sistema de herencia de permisos
   - Filtrado automático de agentes según el rol del usuario

## 🚀 Instalación y Configuración

### Paso 1: Aplicar Migraciones

```bash
# Ejecutar el script de migraciones RBAC
python apply_rbac_migrations.py
```

### Paso 2: Configurar Roles Base

1. **SuperAdministrador**: Acceso completo automático a todos los agentes
2. **Administrador**: Acceso configurable según necesidades
3. **Usuario**: Acceso limitado según asignación

### Paso 3: Configurar Accesos Iniciales

1. Ir a la página **"Control de Acceso a Agentes"**
2. Configurar los niveles de acceso para cada rol
3. Asignar permisos específicos según las necesidades organizacionales

## 📊 Nuevas Páginas y Funcionalidades

### 1. Control de Acceso a Agentes (`pages/10_Control_Acceso_Agentes.py`)

**Funcionalidades:**
- Matriz interactiva de control de acceso
- Vista por rol con resumen de permisos
- Configuración granular de niveles de acceso
- Validación automática de cambios

**Acceso:** Solo usuarios con permiso "Roles"

### 2. Agentes IA Mejorados (`pages/01_Agentes_IA.py`)

**Mejoras:**
- Filtrado automático de agentes según el rol del usuario
- Indicadores visuales de nivel de acceso
- Botones deshabilitados para agentes sin permisos de interacción
- Mensajes informativos sobre restricciones de acceso

### 3. Sistema de Autenticación Mejorado (`auth/auth.py`)

**Nuevas Funciones:**
- `get_current_user_accessible_agents()`: Obtiene agentes accesibles para el usuario actual
- `check_current_user_agent_access()`: Verifica acceso a un agente específico
- `requires_agent_access()`: Decorador para proteger páginas específicas de agentes
- `filter_agents_by_user_access()`: Filtra listas de agentes según permisos

## 🔧 Funciones de Base de Datos

### Control de Acceso Rol-Agente

```python
# Obtener agentes accesibles para un rol
get_agents_for_role(role_id, access_level=None)

# Verificar acceso específico usuario-agente
check_user_agent_access(user_id, agent_id)

# Establecer nivel de acceso rol-agente
set_role_agent_access(role_id, agent_id, access_level)

# Obtener matriz completa de acceso
get_role_agent_access_matrix(role_id=None)
```

### Preferencias de Usuario

```python
# Obtener preferencia de usuario
get_user_preference(user_id, preference_key, default_value=None)

# Establecer preferencia de usuario
set_user_preference(user_id, preference_key, preference_value, category='general')
```

## 🛡️ Seguridad y Validaciones

### Protecciones Implementadas

1. **Validación de Roles**: Solo SuperAdministradores pueden gestionar accesos
2. **Herencia de Permisos**: SuperAdministrador siempre tiene acceso completo
3. **Validación de Entrada**: Verificación de niveles de acceso válidos
4. **Auditoría**: Logging detallado de cambios de permisos
5. **Protección de Sesión**: Validación continua de autenticación

### Casos de Uso Protegidos

- Usuarios sin permisos no ven agentes restringidos
- Botones de interacción deshabilitados para acceso de solo lectura
- Redirección automática para usuarios no autorizados
- Mensajes informativos sobre restricciones de acceso

## 📱 Experiencia de Usuario

### Para Administradores

1. **Gestión Centralizada**: Interfaz única para todos los permisos
2. **Vista de Matriz**: Visualización clara de todos los accesos
3. **Resumen por Rol**: Información detallada de permisos por rol
4. **Cambios en Tiempo Real**: Aplicación inmediata de modificaciones

### Para Usuarios Finales

1. **Vista Filtrada**: Solo ven agentes a los que tienen acceso
2. **Indicadores Claros**: Iconos que muestran el nivel de acceso
3. **Experiencia Intuitiva**: Botones deshabilitados con explicaciones
4. **Mensajes Informativos**: Guías sobre cómo obtener más permisos

## 🔄 Flujo de Trabajo Típico

### Configuración Inicial

1. **Administrador** accede a "Control de Acceso a Agentes"
2. Revisa la matriz de acceso actual
3. Configura permisos según políticas organizacionales
4. Guarda los cambios

### Uso Diario

1. **Usuario** accede a "Agentes IA"
2. Ve solo los agentes permitidos para su rol
3. Puede interactuar según su nivel de acceso
4. Recibe mensajes claros sobre limitaciones

### Mantenimiento

1. **Administrador** revisa periódicamente los accesos
2. Ajusta permisos según cambios organizacionales
3. Monitorea el uso a través de logs
4. Actualiza roles según necesidades

## 🚨 Solución de Problemas

### Problemas Comunes

1. **Usuario no ve agentes**
   - Verificar que el rol tenga permisos asignados
   - Revisar la configuración en "Control de Acceso"

2. **Botón de chat deshabilitado**
   - Verificar que el usuario tenga acceso "full_access"
   - Confirmar que el agente tenga URL configurada

3. **Error de permisos**
   - Verificar que el usuario tenga sesión activa
   - Confirmar que el rol tenga los permisos necesarios

### Logs y Monitoreo

```python
# Los logs se encuentran en el logger principal
log.info(f"User {user_id} has access to {len(accessible_agents)} agents")
log.warning(f"Access denied for user {user_id} to agent {agent_id}")
```

## 📈 Métricas y Monitoreo

### Métricas Disponibles

- Número de agentes accesibles por rol
- Frecuencia de uso por nivel de acceso
- Intentos de acceso denegado
- Cambios en configuración de permisos

### Herramientas de Monitoreo

- Logs detallados en todas las operaciones RBAC
- Auditoría de cambios de permisos
- Métricas de uso por usuario y rol
- Alertas de seguridad para accesos denegados

## 🔮 Funcionalidades Futuras

### Extensiones Planificadas

1. **Permisos Temporales**: Accesos con fecha de expiración
2. **Grupos de Agentes**: Asignación masiva de permisos
3. **Aprobaciones**: Flujo de trabajo para solicitar accesos
4. **Auditoría Avanzada**: Dashboard de uso y seguridad
5. **API de Permisos**: Integración con sistemas externos

## 📝 Notas de Desarrollo

### Estructura de Código

- **Modelos**: `database/models.py` - Definiciones de tablas RBAC
- **Funciones DB**: `database/database.py` - Lógica de acceso a datos
- **Autenticación**: `auth/auth.py` - Funciones de control de acceso
- **UI**: `pages/10_Control_Acceso_Agentes.py` - Interfaz de gestión
- **Migraciones**: `database/migrations/015_*.sql` - Scripts de BD

### Consideraciones de Rendimiento

- Índices optimizados en tablas RBAC
- Caché de permisos en sesión de usuario
- Consultas eficientes con JOINs apropiados
- Lazy loading de datos de agentes

---

## 🎯 Conclusión

El sistema RBAC implementado proporciona un control granular y seguro sobre el acceso a los agentes de IA, mejorando significativamente la seguridad y organización del sistema. La interfaz intuitiva facilita la gestión de permisos mientras mantiene la experiencia de usuario fluida y comprensible.

Para soporte técnico o consultas sobre implementación, consultar los logs del sistema o contactar al equipo de desarrollo.
