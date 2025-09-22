#!/usr/bin/env python3
"""
Módulo de AlertManager con correcciones de seguridad aplicadas
"""

import time
import json
import os
import logging
import subprocess
import shlex
from typing import List, Dict, Optional, Callable
from tkinter import messagebox

class SecureAlertManager:
    def __init__(self):
        self.alert_history_file = "alert_history.json"
        self.alert_history = self.load_alert_history()
        self.alert_callbacks = []
        self.last_device_scan = []
        self.connection_down_start = None
        self.notification_enabled = True
        
        # Configurar logging seguro
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('wifi_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Configuración de alertas con validación
        self.config = {
            'ping_threshold': 100,  # ms
            'speed_threshold': 10,  # Mbps
            'connection_timeout': 30,  # segundos
            'notify_new_devices': True,
            'notify_connection_issues': True,
            'notify_speed_issues': True
        }
        
        # Rate limiting para notificaciones
        self.notification_rate_limit = {
            'max_notifications': 10,
            'time_window': 300,  # 5 minutos
            'notifications': []
        }
    
    def load_alert_history(self) -> List[Dict]:
        """Cargar historial de alertas desde archivo con validación de seguridad"""
        try:
            if os.path.exists(self.alert_history_file):
                # Verificar permisos del archivo
                file_stat = os.stat(self.alert_history_file)
                if file_stat.st_mode & 0o077:  # Verificar que no sea legible por otros
                    self.logger.warning("Archivo de historial tiene permisos inseguros")
                
                with open(self.alert_history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Validar estructura de datos
                if isinstance(data, list):
                    return [alert for alert in data if self._validate_alert_structure(alert)]
                    
        except json.JSONDecodeError:
            self.logger.error("Error de formato en archivo de historial")
        except PermissionError:
            self.logger.error("Sin permisos para leer archivo de historial")
        except Exception as e:
            self.logger.error(f"Error inesperado cargando historial: {type(e).__name__}")
            
        return []
    
    def _validate_alert_structure(self, alert: Dict) -> bool:
        """Validar estructura de alerta"""
        required_fields = ['timestamp', 'type', 'message', 'severity', 'time_str']
        return (isinstance(alert, dict) and 
                all(field in alert for field in required_fields) and
                isinstance(alert['timestamp'], (int, float)) and
                alert['severity'] in ['info', 'warning', 'error'])
    
    def save_alert_history(self):
        """Guardar historial de alertas con permisos seguros"""
        try:
            # Crear archivo temporal primero
            temp_file = f"{self.alert_history_file}.tmp"
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.alert_history[-100:], f, indent=2, ensure_ascii=False)
            
            # Establecer permisos restrictivos (solo propietario puede leer/escribir)
            os.chmod(temp_file, 0o600)
            
            # Reemplazar archivo original atómicamente
            os.replace(temp_file, self.alert_history_file)
            
        except PermissionError:
            self.logger.error("Sin permisos para guardar historial de alertas")
        except OSError as e:
            self.logger.error(f"Error del sistema guardando historial: {e}")
        except Exception as e:
            self.logger.error(f"Error inesperado guardando historial: {type(e).__name__}")
    
    def add_alert_callback(self, callback: Callable):
        """Agregar callback para recibir alertas con validación"""
        if callable(callback):
            self.alert_callbacks.append(callback)
        else:
            self.logger.error("Callback no es función válida")
    
    def _sanitize_string(self, text: str, max_length: int = 200) -> str:
        """Sanitizar strings para prevenir injection attacks"""
        if not isinstance(text, str):
            return str(text)[:max_length]
        
        # Remover caracteres peligrosos para shell injection
        dangerous_chars = ['`', '$', '(', ')', ';', '&', '|', '<', '>', '"', "'"]
        sanitized = text
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Truncar a longitud máxima
        return sanitized[:max_length]
    
    def _check_rate_limit(self) -> bool:
        """Verificar rate limit para notificaciones"""
        current_time = time.time()
        time_window = self.notification_rate_limit['time_window']
        
        # Limpiar notificaciones antiguas
        self.notification_rate_limit['notifications'] = [
            timestamp for timestamp in self.notification_rate_limit['notifications']
            if current_time - timestamp < time_window
        ]
        
        # Verificar límite
        if len(self.notification_rate_limit['notifications']) >= self.notification_rate_limit['max_notifications']:
            return False
        
        self.notification_rate_limit['notifications'].append(current_time)
        return True
    
    def create_alert(self, alert_type: str, message: str, severity: str = "info"):
        """Crear una nueva alerta con validaciones de seguridad"""
        
        # Validar parámetros de entrada
        if not isinstance(alert_type, str) or not alert_type.strip():
            self.logger.error("Tipo de alerta inválido")
            return
        
        if not isinstance(message, str) or not message.strip():
            self.logger.error("Mensaje de alerta inválido")
            return
        
        if severity not in ['info', 'warning', 'error']:
            severity = 'info'
        
        # Sanitizar entrada
        alert_type = self._sanitize_string(alert_type, 50)
        message = self._sanitize_string(message, 500)
        
        alert = {
            'timestamp': time.time(),
            'type': alert_type,
            'message': message,
            'severity': severity,
            'time_str': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.alert_history.append(alert)
        self.save_alert_history()
        
        # Notificar a callbacks de forma segura
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error en callback de alerta: {type(e).__name__}")
        
        # Mostrar notificación del sistema con rate limiting
        if self.notification_enabled and self._check_rate_limit():
            self.show_system_notification(alert)
        
        # Log seguro (sin información sensible)
        log_message = f"ALERTA [{severity.upper()}] {alert_type}: {len(message)} caracteres"
        if severity == 'error':
            self.logger.error(log_message)
        elif severity == 'warning':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def show_system_notification(self, alert: Dict):
        """Mostrar notificación del sistema de forma segura"""
        try:
            # Sanitizar y limitar longitud de strings
            title = self._sanitize_string(f"WiFi Monitor - {alert['type']}", 50)
            message = self._sanitize_string(alert['message'], 200)
            
            # Usar shlex.quote para escapar argumentos de forma segura
            script = f'display notification {shlex.quote(message)} with title {shlex.quote(title)}'
            
            # Ejecutar con timeout y captura de errores
            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Error en notificación del sistema: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout en notificación del sistema")
        except FileNotFoundError:
            self.logger.warning("osascript no encontrado - notificaciones del sistema no disponibles")
        except Exception as e:
            self.logger.error(f"Error inesperado en notificación: {type(e).__name__}")
    
    def check_connection_status(self, connection_info: Dict):
        """Verificar estado de conexión con validaciones mejoradas"""
        if not isinstance(connection_info, dict):
            self.logger.error("Información de conexión inválida")
            return
        
        current_time = time.time()
        
        # Verificar conexión
        status = connection_info.get('status', '')
        if status == 'Desconectado':
            if self.connection_down_start is None:
                self.connection_down_start = current_time
            elif current_time - self.connection_down_start > self.config['connection_timeout']:
                if self.config['notify_connection_issues']:
                    downtime = int(current_time - self.connection_down_start)
                    self.create_alert(
                        "Conexión",
                        f"Conexión WiFi perdida por más de {downtime} segundos",
                        "warning"
                    )
        else:
            if self.connection_down_start is not None:
                downtime = current_time - self.connection_down_start
                if downtime > 10:  # Solo notificar si estuvo caído más de 10 segundos
                    self.create_alert(
                        "Conexión",
                        f"Conexión WiFi restaurada después de {int(downtime)} segundos",
                        "info"
                    )
            self.connection_down_start = None
        
        # Verificar latencia con validación
        ping_str = connection_info.get('ping', '')
        if ping_str and ping_str not in ['N/A', '--']:
            try:
                ping_value = float(ping_str)
                if 0 < ping_value <= 10000:  # Validar rango razonable
                    threshold = self.config.get('ping_threshold', 100)
                    if ping_value > threshold and self.config.get('notify_connection_issues', True):
                        self.create_alert(
                            "Latencia",
                            f"Latencia alta detectada: {ping_value:.1f}ms (límite: {threshold}ms)",
                            "warning"
                        )
            except (ValueError, TypeError):
                self.logger.warning("Valor de ping inválido recibido")
        
        # Verificar velocidad con validación
        speed_str = connection_info.get('speed', '')
        if speed_str and speed_str != '--':
            try:
                speed_value = float(speed_str)
                if 0 < speed_value <= 10000:  # Validar rango razonable
                    threshold = self.config.get('speed_threshold', 10)
                    if speed_value < threshold and self.config.get('notify_speed_issues', True):
                        self.create_alert(
                            "Velocidad",
                            f"Velocidad de internet baja: {speed_value:.1f}Mbps (límite: {threshold}Mbps)",
                            "warning"
                        )
            except (ValueError, TypeError):
                self.logger.warning("Valor de velocidad inválido recibido")
    
    def update_config(self, new_config: Dict):
        """Actualizar configuración con validación"""
        if not isinstance(new_config, dict):
            self.logger.error("Configuración inválida proporcionada")
            return False
        
        # Validar valores numéricos
        numeric_configs = ['ping_threshold', 'speed_threshold', 'connection_timeout']
        for key in numeric_configs:
            if key in new_config:
                try:
                    value = float(new_config[key])
                    if key == 'ping_threshold' and not (1 <= value <= 5000):
                        raise ValueError(f"Ping threshold debe estar entre 1-5000ms")
                    elif key == 'speed_threshold' and not (0.1 <= value <= 1000):
                        raise ValueError(f"Speed threshold debe estar entre 0.1-1000Mbps")
                    elif key == 'connection_timeout' and not (5 <= value <= 300):
                        raise ValueError(f"Connection timeout debe estar entre 5-300s")
                except (ValueError, TypeError) as e:
                    self.logger.error(f"Valor inválido para {key}: {e}")
                    return False
        
        # Validar valores booleanos
        boolean_configs = ['notify_new_devices', 'notify_connection_issues', 'notify_speed_issues']
        for key in boolean_configs:
            if key in new_config and not isinstance(new_config[key], bool):
                self.logger.error(f"Valor booleano esperado para {key}")
                return False
        
        # Actualizar configuración válida
        self.config.update(new_config)
        self.logger.info("Configuración actualizada exitosamente")
        return True
    
    def get_config(self) -> Dict:
        """Obtener configuración actual (copia para evitar modificaciones)"""
        return self.config.copy()
    
    def set_notifications_enabled(self, enabled: bool):
        """Habilitar/deshabilitar notificaciones del sistema"""
        if isinstance(enabled, bool):
            self.notification_enabled = enabled
            self.logger.info(f"Notificaciones {'habilitadas' if enabled else 'deshabilitadas'}")
        else:
            self.logger.error("Valor booleano esperado para notifications_enabled")
    
    def clear_alert_history(self):
        """Limpiar historial de alertas de forma segura"""
        try:
            self.alert_history = []
            self.save_alert_history()
            self.logger.info("Historial de alertas limpiado")
        except Exception as e:
            self.logger.error(f"Error limpiando historial: {type(e).__name__}")
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Obtener alertas recientes con validación"""
        if not isinstance(hours, (int, float)) or hours <= 0:
            hours = 24
        
        cutoff_time = time.time() - (hours * 3600)
        recent_alerts = [
            alert for alert in self.alert_history 
            if alert.get('timestamp', 0) > cutoff_time
        ]
        
        # Retornar copia para evitar modificaciones
        return [alert.copy() for alert in recent_alerts]
    
    def get_alert_summary(self) -> Dict:
        """Obtener resumen de alertas con métricas de seguridad"""
        recent_alerts = self.get_recent_alerts(24)
        
        summary = {
            'total_alerts_24h': len(recent_alerts),
            'alerts_by_type': {},
            'alerts_by_severity': {'info': 0, 'warning': 0, 'error': 0},
            'last_alert': None,
            'security_metrics': {
                'rate_limit_active': len(self.notification_rate_limit['notifications']) > 0,
                'file_permissions_secure': self._check_file_permissions(),
                'total_alerts': len(self.alert_history)
            }
        }
        
        for alert in recent_alerts:
            alert_type = alert.get('type', 'unknown')
            severity = alert.get('severity', 'info')
            
            summary['alerts_by_type'][alert_type] = summary['alerts_by_type'].get(alert_type, 0) + 1
            if severity in summary['alerts_by_severity']:
                summary['alerts_by_severity'][severity] += 1
        
        if recent_alerts:
            summary['last_alert'] = recent_alerts[-1].copy()
        
        return summary
    
    def _check_file_permissions(self) -> bool:
        """Verificar permisos seguros del archivo de historial"""
        try:
            if os.path.exists(self.alert_history_file):
                file_stat = os.stat(self.alert_history_file)
                # Verificar que solo el propietario pueda leer/escribir
                return (file_stat.st_mode & 0o077) == 0
            return True  # No existe archivo aún
        except Exception:
            return False