#!/usr/bin/env python3
"""
Módulo para manejar alertas y notificaciones del monitor WiFi
"""

import time
import json
import os
from typing import List, Dict, Optional, Callable
from tkinter import messagebox
import subprocess

class AlertManager:
    def __init__(self):
        self.alert_history_file = "alert_history.json"
        self.alert_history = self.load_alert_history()
        self.alert_callbacks = []
        self.last_device_scan = []
        self.connection_down_start = None
        self.notification_enabled = True
        
        # Configuración de alertas
        self.config = {
            'ping_threshold': 100,  # ms
            'speed_threshold': 10,  # Mbps
            'connection_timeout': 30,  # segundos
            'notify_new_devices': True,
            'notify_connection_issues': True,
            'notify_speed_issues': True
        }
    
    def load_alert_history(self) -> List[Dict]:
        """Cargar historial de alertas desde archivo"""
        try:
            if os.path.exists(self.alert_history_file):
                with open(self.alert_history_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_alert_history(self):
        """Guardar historial de alertas"""
        try:
            with open(self.alert_history_file, 'w') as f:
                json.dump(self.alert_history[-100:], f, indent=2)  # Mantener solo últimas 100
        except Exception as e:
            print(f"Error guardando historial de alertas: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Agregar callback para recibir alertas"""
        self.alert_callbacks.append(callback)
    
    def create_alert(self, alert_type: str, message: str, severity: str = "info"):
        """Crear una nueva alerta"""
        alert = {
            'timestamp': time.time(),
            'type': alert_type,
            'message': message,
            'severity': severity,
            'time_str': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.alert_history.append(alert)
        self.save_alert_history()
        
        # Notificar a callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except:
                pass
        
        # Mostrar notificación del sistema si está habilitada
        if self.notification_enabled:
            self.show_system_notification(alert)
        
        print(f"ALERTA [{severity.upper()}]: {message}")
    
    def show_system_notification(self, alert: Dict):
        """Mostrar notificación del sistema en macOS de forma segura"""
        try:
            # Sanitizar strings para prevenir command injection
            title = f"WiFi Monitor - {alert['type']}"
            message = alert['message']
            
            # Remover caracteres peligrosos
            title_safe = title.replace('"', '\\"').replace("'", "\\'").replace('`', '').replace('$', '')
            message_safe = message.replace('"', '\\"').replace("'", "\\'").replace('`', '').replace('$', '')
            
            # Limitar longitud para prevenir ataques de buffer
            title_safe = title_safe[:50]
            message_safe = message_safe[:200]
            
            # Usar argumentos separados en lugar de script interpolado
            subprocess.run([
                'osascript', '-e', 
                f'display notification "{message_safe}" with title "{title_safe}"'
            ], capture_output=True, timeout=5, check=False)
            
        except subprocess.TimeoutExpired:
            print("Timeout en notificación del sistema")
        except Exception as e:
            print(f"Error en notificación: {type(e).__name__}")
            pass
    
    def check_connection_status(self, connection_info: Dict):
        """Verificar estado de conexión y generar alertas si es necesario"""
        current_time = time.time()
        
        # Verificar conexión
        if connection_info.get('status') == 'Desconectado':
            if self.connection_down_start is None:
                self.connection_down_start = current_time
            elif current_time - self.connection_down_start > self.config['connection_timeout']:
                if self.config['notify_connection_issues']:
                    self.create_alert(
                        "Conexión",
                        f"Conexión WiFi perdida por más de {self.config['connection_timeout']} segundos",
                        "warning"
                    )
        else:
            if self.connection_down_start is not None:
                downtime = current_time - self.connection_down_start
                if downtime > 10:  # Solo notificar si estuvo caído más de 10 segundos
                    self.create_alert(
                        "Conexión",
                        f"Conexión WiFi restaurada después de {downtime:.0f} segundos",
                        "info"
                    )
            self.connection_down_start = None
        
        # Verificar latencia
        ping_str = connection_info.get('ping', '')
        if ping_str and ping_str != 'N/A' and ping_str != '--':
            try:
                ping_value = float(ping_str)
                if ping_value > self.config['ping_threshold']:
                    if self.config['notify_connection_issues']:
                        self.create_alert(
                            "Latencia",
                            f"Latencia alta detectada: {ping_value}ms (límite: {self.config['ping_threshold']}ms)",
                            "warning"
                        )
            except:
                pass
        
        # Verificar velocidad
        speed_str = connection_info.get('speed', '')
        if speed_str and speed_str != '--':
            try:
                speed_value = float(speed_str)
                if speed_value < self.config['speed_threshold']:
                    if self.config['notify_speed_issues']:
                        self.create_alert(
                            "Velocidad",
                            f"Velocidad de internet baja: {speed_value:.1f}Mbps (límite: {self.config['speed_threshold']}Mbps)",
                            "warning"
                        )
            except:
                pass
    
    def check_device_changes(self, current_devices: List[Dict]):
        """Verificar cambios en dispositivos conectados"""
        if not self.config['notify_new_devices']:
            return
        
        if self.last_device_scan:
            # Comparar con escaneo anterior
            old_ips = {device['ip'] for device in self.last_device_scan}
            new_ips = {device['ip'] for device in current_devices}
            
            # Dispositivos nuevos
            added_ips = new_ips - old_ips
            for ip in added_ips:
                device = next((d for d in current_devices if d['ip'] == ip), None)
                if device:
                    self.create_alert(
                        "Nuevo Dispositivo",
                        f"Nuevo dispositivo conectado: {ip} ({device.get('vendor', 'Desconocido')})",
                        "info"
                    )
            
            # Dispositivos desconectados
            removed_ips = old_ips - new_ips
            for ip in removed_ips:
                device = next((d for d in self.last_device_scan if d['ip'] == ip), None)
                if device:
                    self.create_alert(
                        "Dispositivo Desconectado",
                        f"Dispositivo desconectado: {ip} ({device.get('vendor', 'Desconocido')})",
                        "info"
                    )
        
        self.last_device_scan = current_devices.copy()
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Obtener alertas recientes"""
        cutoff_time = time.time() - (hours * 3600)
        return [alert for alert in self.alert_history if alert['timestamp'] > cutoff_time]
    
    def clear_alert_history(self):
        """Limpiar historial de alertas"""
        self.alert_history = []
        self.save_alert_history()
    
    def update_config(self, new_config: Dict):
        """Actualizar configuración de alertas"""
        self.config.update(new_config)
    
    def get_config(self) -> Dict:
        """Obtener configuración actual"""
        return self.config.copy()
    
    def set_notifications_enabled(self, enabled: bool):
        """Habilitar/deshabilitar notificaciones del sistema"""
        self.notification_enabled = enabled
    
    def get_alert_summary(self) -> Dict:
        """Obtener resumen de alertas"""
        recent_alerts = self.get_recent_alerts(24)
        
        summary = {
            'total_alerts_24h': len(recent_alerts),
            'alerts_by_type': {},
            'alerts_by_severity': {'info': 0, 'warning': 0, 'error': 0},
            'last_alert': None
        }
        
        for alert in recent_alerts:
            alert_type = alert['type']
            severity = alert['severity']
            
            summary['alerts_by_type'][alert_type] = summary['alerts_by_type'].get(alert_type, 0) + 1
            summary['alerts_by_severity'][severity] += 1
        
        if recent_alerts:
            summary['last_alert'] = recent_alerts[-1]
        
        return summary