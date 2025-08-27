import streamlit as st

# Importar dependencias locales
from auth.auth import requires_permission # Decorador para proteger página
from utils.helpers import show_dev_placeholder # Helper para mensaje "en desarrollo"
# from utils.api_client import get_agentops_data # Se importaría cuando se implemente
from utils.helpers import render_sidebar, restore_session_from_cookie
from utils.styles import apply_global_styles
# from utils.cookies import get_session_cookie

# --- LLAMAR A RENDER_SIDEBAR TEMPRANO ---
# render_sidebar()
# --- FIN LLAMADA ---

# --- PASO 1: RESTAURAR SESIÓN AL INICIO ---
restore_session_from_cookie()

# Permiso requerido para acceder a esta página (ajustar si es necesario)
PAGE_PERMISSION = "Monitoreo"

@requires_permission(PAGE_PERMISSION)
def show_monitoring_page():
    """
    Muestra la página de Monitoreo de Agentes (actualmente en desarrollo).
    """
    st.title("📡 Monitoreo de Agentes y Sistema")
    st.caption("Visualización del rendimiento, estado y costos operativos en tiempo real.")

    # Mostrar el mensaje estándar de "en desarrollo"
    show_dev_placeholder("Monitoreo")

    # --- Notas para Futura Implementación ---
    st.markdown("---")
    st.markdown("""
    **Funcionalidades Futuras Posibles:**

    * **Integración con AgentOps (u similar):**
        * Conectar con la API de AgentOps usando la clave configurada.
        * Obtener métricas por agente: número de ejecuciones, tokens usados, costos estimados, latencia, tasa de error.
        * Visualizar estas métricas en gráficos de series de tiempo o tablas resumen.
    * **Estado de Agentes:**
        * Mostrar el estado actual de cada agente (activo, inactivo, entrenando) obtenido de N8N o la plataforma de agentes.
        * Indicadores visuales (🟢, 🔴) para rápida identificación.
    * **Métricas del Sistema (Opcional):**
        * Si la aplicación se despliega en un entorno controlable, mostrar uso de CPU/RAM del contenedor/VM.
        * Estado de la conexión a la base de datos.
        * Latencia promedio de las respuestas de la API N8N.
    * **Alertas:**
        * Mostrar alertas importantes (ej. agente inactivo, alta tasa de errores, costo excedido).
    * **Logs Recientes:**
        * Mostrar un extracto de los logs de errores recientes de los agentes o del sistema.
    """)

# --- PASO 2: SIMPLIFICAR EL BLOQUE DE EJECUCIÓN ---
# El decorador ya se encarga de la seguridad. Si la sesión no se restaura,
# el decorador mostrará el login y detendrá la ejecución.
apply_global_styles()
render_sidebar()
show_monitoring_page()