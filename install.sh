#!/bin/bash

# Script de instalación para Monitor de Red WiFi
# Para macOS

echo "🔌 Instalando Monitor de Red WiFi..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado. Por favor, instala Python 3 primero."
    exit 1
fi

echo "✅ Python 3 encontrado"

# Verificar pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 no está instalado. Instalando..."
    python3 -m ensurepip --upgrade
fi

echo "✅ pip3 está disponible"

# Instalar dependencias
echo "📦 Instalando dependencias..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencias instaladas correctamente"
else
    echo "❌ Error instalando dependencias"
    exit 1
fi

# Verificar permisos
echo "🔐 Verificando permisos..."

# Crear script de lanzamiento
cat > launch_wifi_monitor.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
python3 main.py
EOF

chmod +x launch_wifi_monitor.sh

echo "🚀 Instalación completada!"
echo ""
echo "Para ejecutar la aplicación:"
echo "  ./launch_wifi_monitor.sh"
echo "  o"
echo "  python3 main.py"
echo ""
echo "📖 Lee el README.md para más información sobre el uso."