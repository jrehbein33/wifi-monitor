#!/usr/bin/env python3
"""
Módulo para escanear la red y detectar dispositivos conectados
"""

import subprocess
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import json

class NetworkScanner:
    def __init__(self):
        self.known_vendors = self.load_vendor_database()
        
    def load_vendor_database(self) -> Dict[str, str]:
        """Cargar base de datos básica de fabricantes por MAC"""
        # Base de datos simplificada de prefijos MAC conocidos
        vendors = {
            "00:1B:63": "Apple",
            "00:23:DF": "Apple", 
            "00:25:00": "Apple",
            "04:0C:CE": "Apple",
            "28:C2:DD": "Apple",
            "3C:07:54": "Apple",
            "40:6C:8F": "Apple",
            "64:20:0C": "Apple",
            "80:E6:50": "Apple",
            "A4:5E:60": "Apple",
            "BC:52:B7": "Apple",
            "DC:A9:04": "Apple",
            "F0:B4:79": "Apple",
            "F4:7B:09": "Apple",
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1C:42": "VMware",
            "00:15:5D": "Microsoft",
            "00:03:FF": "Microsoft",
            "AC:1F:6B": "Amazon",
            "02:42:AC": "Docker",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:16:3E": "Xen",
            "00:1A:4A": "Cisco",
            "00:23:04": "Cisco",
            "00:D0:58": "Cisco",
            "B4:99:BA": "TP-Link",
            "EC:08:6B": "TP-Link",
            "F4:F2:6D": "TP-Link",
            "30:B5:C2": "Netgear",
            "A0:40:A0": "Netgear",
            "20:4E:7F": "Netgear",
            "00:1F:33": "Belkin",
            "00:17:3F": "Belkin",
            "94:44:52": "Belkin",
        }
        return vendors
    
    def get_network_range(self) -> Optional[str]:
        """Obtener el rango de la red local"""
        try:
            # Obtener la IP del gateway (router)
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                gateway_match = re.search(r'gateway: (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    gateway_ip = gateway_match.group(1)
                    # Asumir red /24 (255.255.255.0)
                    network_base = '.'.join(gateway_ip.split('.')[:-1])
                    return f"{network_base}.0/24"
        except:
            pass
        
        # Fallback: obtener IP local y asumir red /24
        try:
            result = subprocess.run(['ifconfig', 'en0'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    local_ip = ip_match.group(1)
                    network_base = '.'.join(local_ip.split('.')[:-1])
                    return f"{network_base}.0/24"
        except:
            pass
            
        return "192.168.1.0/24"  # Fallback común
    
    def ping_host(self, ip: str) -> bool:
        """Hacer ping a una IP específica para verificar si está activa"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1000', ip], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Obtener la dirección MAC de una IP usando ARP"""
        try:
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Buscar MAC en el formato xx:xx:xx:xx:xx:xx
                mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', result.stdout)
                if mac_match:
                    return mac_match.group(1).upper()
        except:
            pass
        return None
    
    def get_vendor_from_mac(self, mac: str) -> str:
        """Identificar el fabricante basado en la dirección MAC"""
        if not mac:
            return "Desconocido"
            
        # Obtener los primeros 3 octetos (OUI - Organizationally Unique Identifier)
        oui = ':'.join(mac.split(':')[:3])
        
        # Buscar en la base de datos
        vendor = self.known_vendors.get(oui, "Desconocido")
        
        # Intentar identificar algunos patrones comunes adicionales
        if vendor == "Desconocido":
            if mac.startswith("02:42:"):
                return "Docker"
            elif mac.startswith("52:54:"):
                return "QEMU/KVM"
            elif "FF:FF:FF" in mac:
                return "Broadcast"
        
        return vendor
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Intentar obtener el nombre del host"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def scan_single_ip(self, ip: str) -> Optional[Dict[str, str]]:
        """Escanear una IP individual"""
        if self.ping_host(ip):
            mac = self.get_mac_address(ip)
            vendor = self.get_vendor_from_mac(mac) if mac else "Desconocido"
            hostname = self.get_hostname(ip)
            
            device_info = {
                'ip': ip,
                'mac': mac or "N/A",
                'vendor': vendor,
                'hostname': hostname or "Desconocido",
                'status': 'Activo'
            }
            return device_info
        return None
    
    def scan_network(self) -> List[Dict[str, str]]:
        """Escanear toda la red para encontrar dispositivos activos"""
        print("Iniciando escaneo de red...")
        
        # Obtener rango de red
        network_range = self.get_network_range()
        print(f"Escaneando rango: {network_range}")
        
        # Extraer base de IP del rango
        if '/' in network_range:
            network_base = network_range.split('/')[0].rsplit('.', 1)[0]
        else:
            network_base = "192.168.1"
        
        devices = []
        
        # Escanear IPs en paralelo para mayor velocidad
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Crear lista de IPs a escanear (1-254)
            future_to_ip = {
                executor.submit(self.scan_single_ip, f"{network_base}.{i}"): f"{network_base}.{i}"
                for i in range(1, 255)
            }
            
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    devices.append(result)
                    print(f"Dispositivo encontrado: {result['ip']} - {result['vendor']}")
        
        # Ordenar por IP
        devices.sort(key=lambda x: int(x['ip'].split('.')[-1]))
        
        print(f"Escaneo completado. {len(devices)} dispositivos encontrados.")
        return devices
    
    def scan_arp_table(self) -> List[Dict[str, str]]:
        """Escanear la tabla ARP para dispositivos conocidos (más rápido)"""
        devices = []
        
        try:
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Parsear líneas del tipo: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
                        match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
                        if match:
                            hostname = match.group(1)
                            ip = match.group(2)
                            mac = match.group(3).upper()
                            vendor = self.get_vendor_from_mac(mac)
                            
                            device_info = {
                                'ip': ip,
                                'mac': mac,
                                'vendor': vendor,
                                'hostname': hostname if hostname != '?' else 'Desconocido',
                                'status': 'En cache ARP'
                            }
                            devices.append(device_info)
        except:
            pass
        
        return devices
    
    def quick_scan(self) -> List[Dict[str, str]]:
        """Escaneo rápido usando tabla ARP y ping al gateway"""
        print("Realizando escaneo rápido...")
        
        devices = self.scan_arp_table()
        
        # Agregar gateway si no está en la lista
        try:
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                gateway_match = re.search(r'gateway: (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    gateway_ip = gateway_match.group(1)
                    
                    # Verificar si el gateway ya está en la lista
                    if not any(device['ip'] == gateway_ip for device in devices):
                        gateway_device = self.scan_single_ip(gateway_ip)
                        if gateway_device:
                            gateway_device['vendor'] = "Router/Gateway"
                            devices.append(gateway_device)
        except:
            pass
        
        print(f"Escaneo rápido completado. {len(devices)} dispositivos encontrados.")
        return devices