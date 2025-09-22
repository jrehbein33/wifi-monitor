# Monitor de Red WiFi

Una aplicación completa para monitorear tu red WiFi, detectar dispositivos conectados y recibir alertas sobre problemas de conectividad.

## Características

- **Monitoreo en tiempo real** de la conexión WiFi
- **Detección de dispositivos** conectados a la red
- **Medición de velocidad** de internet y latencia
- **Sistema de alertas** para problemas de conectividad
- **Interfaz gráfica intuitiva** con múltiples pestañas
- **Notificaciones del sistema** en macOS
- **Historial de alertas** con filtrado por fecha
- **Configuración personalizable** de umbrales de alerta

## Requisitos del Sistema

- macOS (la aplicación está optimizada para macOS)
- Python 3.7 o superior
- Conexión a internet
- Permisos de administrador para algunos comandos de red

## Instalación

1. **Clonar o descargar** el proyecto:
   ```bash
   cd ~/Downloads
   # Si tienes el código, copiarlo a una carpeta
   ```

2. **Navegar al directorio** del proyecto:
   ```bash
   cd wifi-monitor
   ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

## Uso

### Ejecución Básica

Para iniciar la aplicación:

```bash
python main.py
```

### Funcionalidades Principales

#### 1. Monitor Principal
- **Estado de Conexión**: Muestra si estás conectado, la red WiFi actual y la intensidad de la señal
- **Métricas de Red**: Velocidad de internet y latencia en tiempo real
- **Lista de Dispositivos**: Todos los dispositivos conectados a tu red con información detallada

#### 2. Controles de Monitoreo
- **Iniciar Monitoreo**: Comienza el monitoreo automático cada 5 segundos
- **Detener Monitoreo**: Pausa el monitoreo automático
- **Escanear Red**: Realiza un escaneo completo de todos los dispositivos (puede tomar 1-2 minutos)
- **Escaneo Rápido**: Escaneo rápido basado en la tabla ARP del sistema

#### 3. Sistema de Alertas
- **Alertas automáticas** para:
  - Pérdida de conexión WiFi
  - Latencia alta (configurable, por defecto >100ms)
  - Velocidad baja (configurable, por defecto <10Mbps)
  - Nuevos dispositivos conectados
  - Dispositivos desconectados

#### 4. Configuración
- **Umbrales personalizables** para alertas
- **Activar/desactivar** tipos específicos de notificaciones
- **Configuración persistente** que se guarda automáticamente

## Arquitectura del Proyecto

```
wifi-monitor/
├── main.py                 # Interfaz principal de la aplicación
├── wifi_monitor.py         # Módulo de monitoreo de WiFi
├── network_scanner.py      # Escáner de dispositivos de red
├── alert_manager.py        # Sistema de gestión de alertas
├── requirements.txt        # Dependencias de Python
├── README.md              # Documentación
└── alert_history.json     # Historial de alertas (se crea automáticamente)
```

### Módulos Principales

#### `wifi_monitor.py`
- Monitoreo del estado de conexión WiFi
- Medición de velocidad de internet
- Cálculo de latencia
- Información de la red (SSID, intensidad de señal)

#### `network_scanner.py`
- Escaneo de dispositivos en la red local
- Identificación de fabricantes por dirección MAC
- Resolución de nombres de host
- Escaneo paralelo para mayor velocidad

#### `alert_manager.py`
- Sistema de alertas configurable
- Notificaciones del sistema
- Historial persistente de alertas
- Configuración de umbrales

#### `main.py`
- Interfaz gráfica con tkinter
- Coordinación entre módulos
- Manejo de hilos para operaciones no bloqueantes

## Comandos del Sistema Utilizados

La aplicación utiliza varios comandos del sistema de macOS:

- `networksetup -getairportnetwork en0`: Obtener red WiFi actual
- `airport -I`: Información detallada de WiFi (requiere herramientas adicionales)
- `ping`: Medición de latencia
- `arp`: Tabla de direcciones MAC
- `route`: Información de rutas de red
- `ifconfig`: Configuración de interfaces de red

## Solución de Problemas

### Problemas Comunes

1. **Error "Airport command not found"**
   - La aplicación funcionará sin la información de intensidad de señal
   - Alternativa: Instalar herramientas de desarrollador de Xcode

2. **Permisos denegados**
   - Algunos comandos pueden requerir permisos de administrador
   - Ejecutar con `sudo python main.py` si es necesario

3. **Velocidad de escaneo lenta**
   - Usar "Escaneo Rápido" en lugar de "Escanear Red"
   - El escaneo completo puede tomar 1-2 minutos dependiendo del tamaño de la red

4. **Alertas de velocidad inexactas**
   - Las mediciones de velocidad son aproximadas
   - Se realizan cada 5 minutos para evitar uso excesivo de ancho de banda

### Configuración Avanzada

#### Modificar Intervalos de Monitoreo
En `wifi_monitor.py`, cambiar:
```python
self.speed_test_interval = 300  # Segundos entre tests de velocidad
```

En `main.py`, cambiar:
```python
time.sleep(5)  # Intervalo de monitoreo principal
```

#### Personalizar Base de Datos de Fabricantes
En `network_scanner.py`, agregar entradas al diccionario `vendors`:
```python
vendors = {
    "XX:XX:XX": "Nombre del Fabricante",
    # ... más entradas
}
```

## Limitaciones

- **Optimizado para macOS**: Comandos específicos de macOS
- **Redes IPv4**: No compatible con IPv6
- **Redes /24**: Asume máscaras de subred estándar
- **Velocidad aproximada**: Mediciones de velocidad son estimativas

## Seguridad y Privacidad

- **Escaneo local únicamente**: Solo escanea la red local
- **Sin datos externos**: No envía información a servidores remotos
- **Historial local**: Las alertas se almacenan localmente
- **Sin credenciales**: No requiere contraseñas de red

## Contribuciones

Para mejorar la aplicación:

1. Agregar soporte para otros sistemas operativos
2. Implementar escaneo IPv6
3. Mejorar la precisión de medición de velocidad
4. Agregar más fabricantes a la base de datos MAC
5. Implementar exportación de datos
6. Agregar gráficos de tendencias

## Licencia

Este proyecto es de código abierto y está disponible bajo los términos que prefieras establecer.

## Contacto

Para reportar problemas o sugerir mejoras, puedes crear un issue en el repositorio del proyecto.