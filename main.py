#!/usr/bin/env python3
"""
WiFi Monitor - Aplicación para monitorear tu red WiFi
Autor: WiFi Monitor Tool
Fecha: 2025

Esta aplicación permite monitorear el estado de tu red WiFi incluyendo:
- Estado de la conexión
- Velocidad de internet
- Dispositivos conectados
- Latencia y rendimiento
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from wifi_monitor import WiFiMonitor
from network_scanner import NetworkScanner
from alert_manager import AlertManager
from vulnerability_analyzer import VulnerabilityAnalyzer

class WiFiMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Red WiFi")
        self.root.geometry("1000x700")
        
        # Inicializar componentes
        self.wifi_monitor = WiFiMonitor()
        self.network_scanner = NetworkScanner()
        self.alert_manager = AlertManager()
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        
        # Variables para control de monitoreo
        self.monitoring = False
        self.monitor_thread = None
        
        # Configurar callback de alertas
        self.alert_manager.add_alert_callback(self.on_alert_received)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configurar la interfaz de usuario"""
        # Crear notebook para pestañas
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Pestaña principal - Monitor
        main_frame = ttk.Frame(notebook, padding="10")
        notebook.add(main_frame, text="Monitor Principal")
        
        # Título
        title_label = ttk.Label(main_frame, text="Monitor de Red WiFi", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Frame de estado de conexión
        connection_frame = ttk.LabelFrame(main_frame, text="Estado de Conexión", padding="10")
        connection_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.status_label = ttk.Label(connection_frame, text="Estado: No conectado")
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        self.ssid_label = ttk.Label(connection_frame, text="Red: --")
        self.ssid_label.grid(row=1, column=0, sticky=tk.W)
        
        self.signal_label = ttk.Label(connection_frame, text="Señal: --")
        self.signal_label.grid(row=2, column=0, sticky=tk.W)
        
        self.speed_label = ttk.Label(connection_frame, text="Velocidad: -- Mbps")
        self.speed_label.grid(row=0, column=1, sticky=tk.W, padx=(50, 0))
        
        self.ping_label = ttk.Label(connection_frame, text="Latencia: -- ms")
        self.ping_label.grid(row=1, column=1, sticky=tk.W, padx=(50, 0))
        
        # Frame de dispositivos
        devices_frame = ttk.LabelFrame(main_frame, text="Dispositivos Conectados", padding="10")
        devices_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Lista de dispositivos
        columns = ("IP", "MAC", "Fabricante", "Hostname")
        self.devices_tree = ttk.Treeview(devices_frame, columns=columns, show="headings", height=8)
        self.devices_tree.heading("IP", text="Dirección IP")
        self.devices_tree.heading("MAC", text="Dirección MAC")
        self.devices_tree.heading("Fabricante", text="Fabricante")
        self.devices_tree.heading("Hostname", text="Nombre del Host")
        
        # Configurar anchos de columna
        self.devices_tree.column("IP", width=120)
        self.devices_tree.column("MAC", width=150)
        self.devices_tree.column("Fabricante", width=150)
        self.devices_tree.column("Hostname", width=200)
        
        scrollbar_devices = ttk.Scrollbar(devices_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar_devices.set)
        
        self.devices_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_devices.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Botones de control
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        self.start_button = ttk.Button(buttons_frame, text="Iniciar Monitoreo", 
                                      command=self.start_monitoring)
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        self.stop_button = ttk.Button(buttons_frame, text="Detener Monitoreo", 
                                     command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=(0, 10))
        
        self.scan_button = ttk.Button(buttons_frame, text="Escanear Red", 
                                     command=self.scan_network)
        self.scan_button.grid(row=0, column=2, padx=(0, 10))
        
        self.quick_scan_button = ttk.Button(buttons_frame, text="Escaneo Rápido", 
                                           command=self.quick_scan)
        self.quick_scan_button.grid(row=0, column=3)
        
        # Pestaña de alertas
        alerts_frame = ttk.Frame(notebook, padding="10")
        notebook.add(alerts_frame, text="Alertas")
        
        # Lista de alertas
        self.setup_alerts_tab(alerts_frame)
        
        # Pestaña de configuración
        config_frame = ttk.Frame(notebook, padding="10")
        notebook.add(config_frame, text="Configuración")
        
        self.setup_config_tab(config_frame)
        
        # Pestaña de vulnerabilidades  
        vuln_frame = ttk.Frame(notebook, padding="10")
        notebook.add(vuln_frame, text="Vulnerabilidades")
        
        self.setup_vulnerability_tab(vuln_frame)
        
        # Configurar redimensionamiento
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        devices_frame.columnconfigure(0, weight=1)
        devices_frame.rowconfigure(0, weight=1)
        
    def setup_alerts_tab(self, parent):
        """Configurar la pestaña de alertas"""
        # Título
        title_label = ttk.Label(parent, text="Historial de Alertas", 
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Lista de alertas
        columns = ("Hora", "Tipo", "Mensaje", "Severidad")
        self.alerts_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)
        self.alerts_tree.heading("Hora", text="Fecha/Hora")
        self.alerts_tree.heading("Tipo", text="Tipo")
        self.alerts_tree.heading("Mensaje", text="Mensaje")
        self.alerts_tree.heading("Severidad", text="Severidad")
        
        # Configurar anchos de columna
        self.alerts_tree.column("Hora", width=150)
        self.alerts_tree.column("Tipo", width=120)
        self.alerts_tree.column("Mensaje", width=400)
        self.alerts_tree.column("Severidad", width=100)
        
        scrollbar_alerts = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar_alerts.set)
        
        self.alerts_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        scrollbar_alerts.grid(row=1, column=1, sticky=(tk.N, tk.S), pady=(0, 10))
        
        # Botones de alertas
        alert_buttons_frame = ttk.Frame(parent)
        alert_buttons_frame.grid(row=2, column=0, pady=(10, 0))
        
        refresh_alerts_btn = ttk.Button(alert_buttons_frame, text="Actualizar", 
                                       command=self.refresh_alerts)
        refresh_alerts_btn.grid(row=0, column=0, padx=(0, 10))
        
        clear_alerts_btn = ttk.Button(alert_buttons_frame, text="Limpiar Historial", 
                                     command=self.clear_alerts)
        clear_alerts_btn.grid(row=0, column=1)
        
        # Configurar redimensionamiento para alertas
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        
    def setup_config_tab(self, parent):
        """Configurar la pestaña de configuración"""
        # Título
        title_label = ttk.Label(parent, text="Configuración de Alertas", 
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Frame de configuración
        config_frame = ttk.LabelFrame(parent, text="Umbrales de Alerta", padding="10")
        config_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Configuraciones
        ttk.Label(config_frame, text="Latencia máxima (ms):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ping_threshold_var = tk.StringVar(value="100")
        ping_entry = ttk.Entry(config_frame, textvariable=self.ping_threshold_var, width=10)
        ping_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Label(config_frame, text="Velocidad mínima (Mbps):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.speed_threshold_var = tk.StringVar(value="10")
        speed_entry = ttk.Entry(config_frame, textvariable=self.speed_threshold_var, width=10)
        speed_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        # Checkboxes para tipos de notificaciones
        notify_frame = ttk.LabelFrame(parent, text="Tipos de Notificaciones", padding="10")
        notify_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.notify_devices_var = tk.BooleanVar(value=True)
        devices_check = ttk.Checkbutton(notify_frame, text="Notificar nuevos dispositivos", 
                                       variable=self.notify_devices_var)
        devices_check.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.notify_connection_var = tk.BooleanVar(value=True)
        connection_check = ttk.Checkbutton(notify_frame, text="Notificar problemas de conexión", 
                                          variable=self.notify_connection_var)
        connection_check.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.notify_speed_var = tk.BooleanVar(value=True)
        speed_check = ttk.Checkbutton(notify_frame, text="Notificar problemas de velocidad", 
                                     variable=self.notify_speed_var)
        speed_check.grid(row=2, column=0, sticky=tk.W, pady=5)
        
        # Botón para guardar configuración
        save_config_btn = ttk.Button(parent, text="Guardar Configuración", 
                                    command=self.save_config)
        save_config_btn.grid(row=3, column=0, pady=(20, 0))
        
        # Cargar configuración actual
        self.load_config()
        
    def start_monitoring(self):
        """Iniciar el monitoreo de la red"""
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Iniciar hilo de monitoreo
        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Detener el monitoreo de la red"""
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
    def monitoring_loop(self):
        """Bucle principal de monitoreo"""
        while self.monitoring:
            try:
                # Actualizar estado de conexión
                connection_info = self.wifi_monitor.get_connection_status()
                
                # Verificar alertas de conexión
                self.alert_manager.check_connection_status(connection_info)
                
                # Actualizar UI en el hilo principal
                self.root.after(0, self.update_connection_info, connection_info)
                
                # Esperar antes de la siguiente actualización
                time.sleep(5)
                
            except Exception as e:
                print(f"Error en el monitoreo: {e}")
                time.sleep(10)
                
    def update_connection_info(self, info):
        """Actualizar la información de conexión en la UI"""
        self.status_label.config(text=f"Estado: {info.get('status', 'Desconocido')}")
        self.ssid_label.config(text=f"Red: {info.get('ssid', '--')}")
        self.signal_label.config(text=f"Señal: {info.get('signal_strength', '--')}")
        self.speed_label.config(text=f"Velocidad: {info.get('speed', '--')} Mbps")
        self.ping_label.config(text=f"Latencia: {info.get('ping', '--')} ms")
        
    def scan_network(self):
        """Escanear la red para encontrar dispositivos"""
        def scan_thread():
            try:
                devices = self.network_scanner.scan_network()
                self.alert_manager.check_device_changes(devices)
                self.root.after(0, self.update_devices_list, devices)
            except Exception as e:
                messagebox.showerror("Error", f"Error al escanear la red: {e}")
                
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def quick_scan(self):
        """Escaneo rápido de la red"""
        def scan_thread():
            try:
                devices = self.network_scanner.quick_scan()
                self.alert_manager.check_device_changes(devices)
                self.root.after(0, self.update_devices_list, devices)
            except Exception as e:
                messagebox.showerror("Error", f"Error en el escaneo rápido: {e}")
                
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def update_devices_list(self, devices):
        """Actualizar la lista de dispositivos"""
        # Limpiar lista actual
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
            
        # Agregar dispositivos encontrados
        for device in devices:
            self.devices_tree.insert("", tk.END, values=(
                device.get('ip', ''),
                device.get('mac', ''),
                device.get('vendor', 'Desconocido'),
                device.get('hostname', 'Desconocido')
            ))
    
    def on_alert_received(self, alert):
        """Callback para cuando se recibe una alerta"""
        # Actualizar lista de alertas en UI
        self.root.after(0, self.refresh_alerts)
        
        # Mostrar popup para alertas importantes
        if alert['severity'] in ['warning', 'error']:
            self.root.after(0, lambda: messagebox.showwarning(
                f"Alerta - {alert['type']}", 
                alert['message']
            ))
    
    def refresh_alerts(self):
        """Actualizar la lista de alertas"""
        # Limpiar lista actual
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
            
        # Obtener alertas recientes
        recent_alerts = self.alert_manager.get_recent_alerts(24)
        
        # Agregar alertas a la lista (más recientes primero)
        for alert in reversed(recent_alerts):
            self.alerts_tree.insert("", tk.END, values=(
                alert['time_str'],
                alert['type'],
                alert['message'],
                alert['severity'].upper()
            ))
    
    def clear_alerts(self):
        """Limpiar historial de alertas"""
        result = messagebox.askyesno("Confirmar", 
                                   "¿Estás seguro de que quieres limpiar todo el historial de alertas?")
        if result:
            self.alert_manager.clear_alert_history()
            self.refresh_alerts()
    
    def load_config(self):
        """Cargar configuración actual"""
        config = self.alert_manager.get_config()
        self.ping_threshold_var.set(str(config['ping_threshold']))
        self.speed_threshold_var.set(str(config['speed_threshold']))
        self.notify_devices_var.set(config['notify_new_devices'])
        self.notify_connection_var.set(config['notify_connection_issues'])
        self.notify_speed_var.set(config['notify_speed_issues'])
    
    def save_config(self):
        """Guardar configuración"""
        try:
            new_config = {
                'ping_threshold': float(self.ping_threshold_var.get()),
                'speed_threshold': float(self.speed_threshold_var.get()),
                'notify_new_devices': self.notify_devices_var.get(),
                'notify_connection_issues': self.notify_connection_var.get(),
                'notify_speed_issues': self.notify_speed_var.get()
            }
            self.alert_manager.update_config(new_config)
            messagebox.showinfo("Configuración", "Configuración guardada exitosamente")
        except ValueError:
            messagebox.showerror("Error", "Por favor, ingresa valores numéricos válidos")
    
    def setup_vulnerability_tab(self, parent):
        """Configurar la pestaña de vulnerabilidades"""
        # Título
        title_label = ttk.Label(parent, text="Análisis de Vulnerabilidades de Red", 
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Frame de resumen de seguridad
        summary_frame = ttk.LabelFrame(parent, text="Resumen de Seguridad", padding="10")
        summary_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.security_score_label = ttk.Label(summary_frame, text="Puntuación de Seguridad: -- / 100", 
                                             font=("Arial", 12, "bold"))
        self.security_score_label.grid(row=0, column=0, sticky=tk.W)
        
        self.total_vulnerabilities_label = ttk.Label(summary_frame, text="Total de Vulnerabilidades: --")
        self.total_vulnerabilities_label.grid(row=1, column=0, sticky=tk.W)
        
        self.last_scan_label = ttk.Label(summary_frame, text="Último Escaneo: --")
        self.last_scan_label.grid(row=2, column=0, sticky=tk.W)
        
        # Frame de severidad
        severity_frame = ttk.LabelFrame(summary_frame, text="Por Severidad", padding="5")
        severity_frame.grid(row=0, column=1, rowspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(20, 0))
        
        self.critical_label = ttk.Label(severity_frame, text="Críticas: --", foreground="red")
        self.critical_label.grid(row=0, column=0, sticky=tk.W)
        
        self.high_label = ttk.Label(severity_frame, text="Altas: --", foreground="orange")
        self.high_label.grid(row=1, column=0, sticky=tk.W)
        
        self.medium_label = ttk.Label(severity_frame, text="Medias: --", foreground="yellow")
        self.medium_label.grid(row=2, column=0, sticky=tk.W)
        
        self.low_label = ttk.Label(severity_frame, text="Bajas: --", foreground="green")
        self.low_label.grid(row=3, column=0, sticky=tk.W)
        
        # Lista de vulnerabilidades
        vuln_list_frame = ttk.LabelFrame(parent, text="Vulnerabilidades Detectadas", padding="10")
        vuln_list_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        columns = ("Dispositivo", "Puerto", "Servicio", "Severidad", "Descripción")
        self.vulnerabilities_tree = ttk.Treeview(vuln_list_frame, columns=columns, show="headings", height=12)
        self.vulnerabilities_tree.heading("Dispositivo", text="IP Dispositivo")
        self.vulnerabilities_tree.heading("Puerto", text="Puerto")
        self.vulnerabilities_tree.heading("Servicio", text="Servicio")
        self.vulnerabilities_tree.heading("Severidad", text="Severidad")
        self.vulnerabilities_tree.heading("Descripción", text="Descripción")
        
        # Configurar anchos de columna
        self.vulnerabilities_tree.column("Dispositivo", width=120)
        self.vulnerabilities_tree.column("Puerto", width=80)
        self.vulnerabilities_tree.column("Servicio", width=100)
        self.vulnerabilities_tree.column("Severidad", width=100)
        self.vulnerabilities_tree.column("Descripción", width=400)
        
        scrollbar_vuln = ttk.Scrollbar(vuln_list_frame, orient=tk.VERTICAL, command=self.vulnerabilities_tree.yview)
        self.vulnerabilities_tree.configure(yscrollcommand=scrollbar_vuln.set)
        
        self.vulnerabilities_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_vuln.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Frame de recomendaciones
        recommendations_frame = ttk.LabelFrame(parent, text="Recomendaciones de Seguridad", padding="10")
        recommendations_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.recommendations_text = tk.Text(recommendations_frame, height=6, wrap=tk.WORD)
        scrollbar_rec = ttk.Scrollbar(recommendations_frame, orient=tk.VERTICAL, command=self.recommendations_text.yview)
        self.recommendations_text.configure(yscrollcommand=scrollbar_rec.set)
        
        self.recommendations_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar_rec.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Botones de control de vulnerabilidades
        vuln_buttons_frame = ttk.Frame(parent)
        vuln_buttons_frame.grid(row=4, column=0, columnspan=3, pady=(10, 0))
        
        self.scan_vulnerabilities_btn = ttk.Button(vuln_buttons_frame, text="Escanear Vulnerabilidades", 
                                                  command=self.scan_vulnerabilities)
        self.scan_vulnerabilities_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.export_report_btn = ttk.Button(vuln_buttons_frame, text="Exportar Reporte", 
                                           command=self.export_vulnerability_report)
        self.export_report_btn.grid(row=0, column=1, padx=(0, 10))
        
        self.refresh_vuln_btn = ttk.Button(vuln_buttons_frame, text="Actualizar", 
                                          command=self.refresh_vulnerabilities)
        self.refresh_vuln_btn.grid(row=0, column=2)
        
        # Configurar redimensionamiento para vulnerabilidades
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        vuln_list_frame.columnconfigure(0, weight=1)
        vuln_list_frame.rowconfigure(0, weight=1)
        recommendations_frame.columnconfigure(0, weight=1)
        recommendations_frame.rowconfigure(0, weight=1)
    
    def scan_vulnerabilities(self):
        """Escanear vulnerabilidades en la red"""
        self.scan_vulnerabilities_btn.config(state=tk.DISABLED, text="Escaneando...")
        
        # Ejecutar escaneo en hilo separado
        threading.Thread(target=self._vulnerability_scan_thread, daemon=True).start()
    
    def _vulnerability_scan_thread(self):
        """Hilo para escaneo de vulnerabilidades"""
        try:
            # Obtener dispositivos de la red
            devices = self.network_scanner.scan_network()
            device_ips = [device['ip'] for device in devices if device['ip'] != 'N/A']
            
            # Realizar análisis de vulnerabilidades
            self.vulnerability_report = self.vulnerability_analyzer.scan_network_devices(device_ips)
            
            # Actualizar interfaz en hilo principal
            self.root.after(0, self._update_vulnerability_display)
            
        except Exception as e:
            print(f"Error durante el escaneo de vulnerabilidades: {e}")
            self.root.after(0, lambda: self.scan_vulnerabilities_btn.config(
                state=tk.NORMAL, text="Escanear Vulnerabilidades"))
    
    def _update_vulnerability_display(self):
        """Actualizar la visualización de vulnerabilidades"""
        try:
            if not hasattr(self, 'vulnerability_report') or not self.vulnerability_report:
                return
            
            report = self.vulnerability_report
            
            # Actualizar resumen
            total_devices = report.get('total_devices', 0)
            total_vulns = report.get('total_vulnerabilities', 0)
            severity_summary = report.get('severity_summary', {})
            
            # Calcular puntuación promedio de seguridad
            device_summaries = report.get('device_summaries', {})
            if device_summaries:
                avg_score = sum(summary.get('risk_score', 0) for summary in device_summaries.values()) / len(device_summaries)
                security_score = max(0, 100 - avg_score)
            else:
                security_score = 100
            
            self.security_score_label.config(text=f"Puntuación de Seguridad: {security_score:.0f} / 100")
            self.total_vulnerabilities_label.config(text=f"Total de Vulnerabilidades: {total_vulns}")
            self.last_scan_label.config(text=f"Último Escaneo: {report.get('scan_timestamp', 'N/A')[:19].replace('T', ' ')}")
            
            # Actualizar contadores por severidad
            self.critical_label.config(text=f"Críticas: {severity_summary.get('Critical', 0)}")
            self.high_label.config(text=f"Altas: {severity_summary.get('High', 0)}")
            self.medium_label.config(text=f"Medias: {severity_summary.get('Medium', 0)}")
            self.low_label.config(text=f"Bajas: {severity_summary.get('Low', 0)}")
            
            # Limpiar y actualizar lista de vulnerabilidades
            for item in self.vulnerabilities_tree.get_children():
                self.vulnerabilities_tree.delete(item)
            
            # Añadir vulnerabilidades de dispositivos
            for device_ip, device_data in device_summaries.items():
                for vuln in device_data.get('vulnerabilities', []):
                    self.vulnerabilities_tree.insert("", tk.END, values=(
                        vuln.get('device_ip', device_ip),
                        vuln.get('port', 'N/A'),
                        vuln.get('service', 'N/A'),
                        vuln.get('severity', 'Low'),
                        vuln.get('description', '')[:80] + "..." if len(vuln.get('description', '')) > 80 else vuln.get('description', '')
                    ))
            
            # Añadir vulnerabilidades de red
            for vuln in report.get('network_vulnerabilities', []):
                self.vulnerabilities_tree.insert("", tk.END, values=(
                    'Red General',
                    'N/A',
                    'Configuración',
                    vuln.get('severity', 'Low'),
                    vuln.get('description', '')[:80] + "..." if len(vuln.get('description', '')) > 80 else vuln.get('description', '')
                ))
            
            # Actualizar recomendaciones
            recommendations = self.vulnerability_analyzer.get_top_recommendations()
            self.recommendations_text.delete(1.0, tk.END)
            if recommendations:
                recommendation_text = "📋 RECOMENDACIONES PRINCIPALES:\n\n"
                for i, rec in enumerate(recommendations, 1):
                    recommendation_text += f"{i}. {rec}\n\n"
            else:
                recommendation_text = "✅ No se encontraron vulnerabilidades críticas.\n\nTu red parece estar bien configurada desde el punto de vista de seguridad básica."
            
            self.recommendations_text.insert(1.0, recommendation_text)
            
        except Exception as e:
            print(f"Error actualizando vulnerabilidades: {e}")
        finally:
            self.scan_vulnerabilities_btn.config(state=tk.NORMAL, text="Escanear Vulnerabilidades")
    
    def refresh_vulnerabilities(self):
        """Actualizar visualización de vulnerabilidades"""
        if hasattr(self, 'vulnerability_report') and self.vulnerability_report:
            self._update_vulnerability_display()
    
    def export_vulnerability_report(self):
        """Exportar reporte de vulnerabilidades"""
        if not hasattr(self, 'vulnerability_report') or not self.vulnerability_report:
            messagebox.showwarning("Advertencia", "No hay datos de vulnerabilidades para exportar. Ejecuta un escaneo primero.")
            return
        
        try:
            import json
            from datetime import datetime
            
            filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.vulnerability_report, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Éxito", f"Reporte exportado como {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar reporte: {e}")


def main():
    root = tk.Tk()
    app = WiFiMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()