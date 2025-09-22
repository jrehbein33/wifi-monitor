#!/usr/bin/env python3
"""
Configuración de seguridad para WiFi Monitor
"""

# Configuración de comandos permitidos con rutas completas
ALLOWED_COMMANDS = {
    'networksetup': '/usr/sbin/networksetup',
    'system_profiler': '/usr/sbin/system_profiler',
    'route': '/sbin/route',
    'ifconfig': '/sbin/ifconfig',
    'ping': '/sbin/ping',
    'arp': '/usr/sbin/arp',
    'osascript': '/usr/bin/osascript'
}

# Límites de seguridad
SECURITY_LIMITS = {
    'max_string_length': 200,
    'max_timeout': 10,
    'max_notifications_per_minute': 5,
    'allowed_file_permissions': 0o600
}

# URLs seguras para tests
SECURE_URLS = {
    'speed_test': 'https://www.google.com/favicon.ico',
    'connectivity_test': 'https://8.8.8.8'
}

def sanitize_string(text, max_length=200):
    """Sanitizar strings para prevenir injection"""
    if not isinstance(text, str):
        return str(text)[:max_length]
    
    # Remover caracteres peligrosos
    dangerous_chars = ['`', '$', '(', ')', ';', '&', '|', '<', '>', '"', "'", '\\']
    sanitized = text
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized[:max_length]

def validate_command(command_name):
    """Validar que un comando esté en la lista permitida"""
    return command_name in ALLOWED_COMMANDS

def get_secure_command_path(command_name):
    """Obtener ruta segura de un comando"""
    if command_name in ALLOWED_COMMANDS:
        return ALLOWED_COMMANDS[command_name]
    raise ValueError(f"Comando no permitido: {command_name}")
