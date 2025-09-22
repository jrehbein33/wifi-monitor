#!/usr/bin/env python3
"""
Wrapper seguro para ejecutar comandos del sistema
"""

import subprocess
import os
import time
from security_config import ALLOWED_COMMANDS, SECURITY_LIMITS

class SecureSubprocess:
    def __init__(self):
        self.last_calls = []
        
    def _check_rate_limit(self):
        """Verificar rate limiting"""
        current_time = time.time()
        self.last_calls = [t for t in self.last_calls if current_time - t < 60]
        
        if len(self.last_calls) >= SECURITY_LIMITS['max_notifications_per_minute']:
            return False
        
        self.last_calls.append(current_time)
        return True
    
    def run_secure(self, command_name, args=None, timeout=None):
        """Ejecutar comando de forma segura"""
        if not self._check_rate_limit():
            raise Exception("Rate limit excedido")
        
        if command_name not in ALLOWED_COMMANDS:
            raise ValueError(f"Comando no permitido: {command_name}")
        
        full_path = ALLOWED_COMMANDS[command_name]
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Comando no encontrado: {full_path}")
        
        # Aplicar timeout por defecto
        if timeout is None:
            timeout = SECURITY_LIMITS['max_timeout']
        elif timeout > SECURITY_LIMITS['max_timeout']:
            timeout = SECURITY_LIMITS['max_timeout']
        
        cmd = [full_path]
        if args:
            cmd.extend(args)
        
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

# Instancia global
secure_runner = SecureSubprocess()
