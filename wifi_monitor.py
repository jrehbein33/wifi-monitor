#!/usr/bin/env python3
"""
Módulo para monitorear el estado de la conexión WiFi
"""

import subprocess
import re
import time
import requests
import socket
from typing import Dict, Optional

class WiFiMonitor:
    def __init__(self):
        self.last_speed_test = 0
        self.speed_cache = None
        self.speed_test_interval = 300  # 5 minutos
        
    def get_connection_status(self) -> Dict[str, str]:
        """
        Obtener el estado completo de la conexión WiFi
        """
        status_info = {
            'status': 'Desconectado',
            'speed': '--',
            'ping': '--',
            'ssid': '--',
            'signal_strength': '--'
        }
        
        # Verificar si hay conexión WiFi
        if self.is_wifi_connected():
            status_info['status'] = 'Conectado'
            status_info['ssid'] = self.get_wifi_ssid()
            status_info['signal_strength'] = self.get_signal_strength()
            status_info['ping'] = self.get_ping_latency()
            
            # Test de velocidad (limitado por tiempo)
            current_time = time.time()
            if current_time - self.last_speed_test > self.speed_test_interval:
                speed = self.measure_internet_speed()
                if speed:
                    self.speed_cache = speed
                    self.last_speed_test = current_time
            
            if self.speed_cache:
                status_info['speed'] = f"{self.speed_cache:.1f}"
        
        return status_info
    
    def is_wifi_connected(self) -> bool:
        """Verificar si hay conexión WiFi activa"""
        try:
            # Primero verificar si en0 tiene una IP asignada
            result = subprocess.run(['ifconfig', 'en0'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and 'inet ' in result.stdout and 'status: active' in result.stdout:
                return True
            
            # Verificar otras interfaces WiFi posibles
            for interface in ['en1', 'en2']:
                result = subprocess.run(['ifconfig', interface], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'inet ' in result.stdout and 'status: active' in result.stdout:
                    return True
                    
        except:
            pass
            
        # Fallback: intentar conectar a Google DNS
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False
    
    def get_wifi_ssid(self) -> str:
        """Obtener el nombre de la red WiFi actual"""
        try:
            # Intentar con networksetup primero
            result = subprocess.run(['networksetup', '-getairportnetwork', 'en0'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and "You are not associated" not in result.stdout:
                # Extraer SSID del resultado
                match = re.search(r'Current Wi-Fi Network: (.+)', result.stdout)
                if match:
                    return match.group(1).strip()
            
            # Intentar con system_profiler como alternativa
            result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                # Buscar la red actual en el output
                lines = result.stdout.split('\n')
                current_network = None
                for i, line in enumerate(lines):
                    if 'Current Network Information:' in line and i + 1 < len(lines):
                        # La siguiente línea contiene el SSID
                        next_line = lines[i + 1].strip()
                        if ':' in next_line:
                            current_network = next_line.split(':')[0].strip()
                            break
                if current_network:
                    return current_network
                    
        except:
            pass
        
        # Si tenemos conexión a internet, asumir que hay una red activa
        if self.is_wifi_connected():
            return "Red Conectada"
        
        return "Sin Red"
    
    def get_signal_strength(self) -> str:
        """Obtener la intensidad de la señal WiFi"""
        try:
            # Intentar con airport utility en macOS
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', 
                                   '-I'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Buscar agrCtlRSSI (señal)
                for line in result.stdout.split('\n'):
                    if 'agrCtlRSSI' in line:
                        rssi = re.search(r'-?\d+', line)
                        if rssi:
                            signal_value = int(rssi.group())
                            # Convertir RSSI a porcentaje aproximado
                            if signal_value >= -50:
                                return "Excelente (100%)"
                            elif signal_value >= -60:
                                return "Buena (75%)"
                            elif signal_value >= -70:
                                return "Regular (50%)"
                            else:
                                return "Débil (25%)"
        except:
            pass
        
        # Intentar con system_profiler como alternativa
        try:
            result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                # Buscar información de señal
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Signal / Noise:' in line or 'RSSI:' in line:
                        # Extraer valor numérico
                        numbers = re.findall(r'-?\d+', line)
                        if numbers:
                            signal_value = int(numbers[0])
                            if signal_value >= -50:
                                return "Excelente"
                            elif signal_value >= -60:
                                return "Buena"
                            elif signal_value >= -70:
                                return "Regular"
                            else:
                                return "Débil"
        except:
            pass
        
        # Si estamos conectados pero no podemos medir la señal
        if self.is_wifi_connected():
            return "Conectado (señal no disponible)"
        
        return "Desconocida"
    
    def get_ping_latency(self) -> str:
        """Medir la latencia de ping a Google DNS"""
        try:
            result = subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                # Extraer tiempo promedio de ping
                match = re.search(r'avg = ([\d.]+)', result.stdout)
                if match:
                    return f"{float(match.group(1)):.1f}"
        except:
            pass
        return "N/A"
    
    def measure_internet_speed(self) -> Optional[float]:
        """
        Medir velocidad de descarga de internet de forma simple
        (usando descarga de un archivo pequeño)
        """
        try:
            print("Midiendo velocidad de internet...")
            start_time = time.time()
            
            # Descargar un archivo de 1MB para test
            response = requests.get('https://www.google.com/favicon.ico', timeout=30)
            
            if response.status_code == 200:
                end_time = time.time()
                duration = end_time - start_time
                # Calcular velocidad en Mbps
                bytes_downloaded = len(response.content)
                speed_mbps = (bytes_downloaded * 8) / (duration * 1_000_000)
                return speed_mbps
        except Exception as e:
            print(f"Error midiendo velocidad: {e}")
        
        return None
    
    def get_network_info(self) -> Dict[str, str]:
        """Obtener información adicional de la red"""
        info = {}
        
        try:
            # Obtener dirección IP local
            result = subprocess.run(['ifconfig', 'en0'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    info['local_ip'] = ip_match.group(1)
                    
                # Obtener gateway (router)
                result = subprocess.run(['route', 'get', 'default'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    gateway_match = re.search(r'gateway: (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if gateway_match:
                        info['gateway'] = gateway_match.group(1)
        except:
            pass
            
        return info