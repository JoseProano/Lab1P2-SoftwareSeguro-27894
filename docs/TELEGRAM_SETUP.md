# Configuración de Telegram Bot para CI/CD

## 📱 Crear Bot de Telegram

### 1. Crear el Bot

1. Abre Telegram y busca **@BotFather**
2. Envía `/newbot`
3. Sigue las instrucciones:
   - Nombre del bot: `Lab1P2 Security Bot`
   - Username: `lab1p2_security_bot` (debe terminar en `_bot`)
4. **GUARDA EL TOKEN** que te da BotFather (ejemplo: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 2. Obtener Chat ID

1. Busca tu bot en Telegram por el username
2. Envía `/start` al bot
3. Abre en navegador: `https://api.telegram.org/bot<TU_TOKEN>/getUpdates`
4. Busca el campo `"chat":{"id": 123456789}` → **ese es tu CHAT_ID**

## 🔐 Configurar Secrets en GitHub

### En tu repositorio GitHub:

1. Ve a **Settings** → **Secrets and variables** → **Actions**
2. Click en **New repository secret**
3. Agrega estos 2 secrets:

**Secret 1:**
- Name: `TELEGRAM_BOT_TOKEN`
- Value: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz` (el token de BotFather)

**Secret 2:**
- Name: `TELEGRAM_CHAT_ID`
- Value: `123456789` (tu chat ID)

## 📋 Secrets Opcionales para Deploy

### Para Render:

1. Ve a Render Dashboard → Settings
2. Copia el **Deploy Hook URL**
3. En GitHub Secrets, agrega:
   - Name: `RENDER_DEPLOY_HOOK`
   - Value: `https://api.render.com/deploy/srv-xxx`

### Para Railway:

1. Railway Dashboard → Project Settings → Tokens
2. Crea un token de deploy
3. En GitHub Secrets, agrega:
   - Name: `RAILWAY_TOKEN`
   - Value: `tu-railway-token`
   - Name: `RAILWAY_SERVICE_ID`
   - Value: `tu-service-id`

## ✅ Verificar Configuración

Ejecuta este script para probar el bot:

```bash
python scripts/test_telegram_bot.py
```

## 📨 Tipos de Notificaciones

El bot enviará mensajes en estos momentos:

1. **🔍 Analysis Started** - Cuando inicia el análisis de seguridad
2. **🚨 Vulnerability Detected** - Si encuentra código vulnerable
3. **✅ Code is Safe** - Si el código pasa el análisis
4. **🧪 Tests Started** - Al iniciar pruebas unitarias
5. **✅ Tests Passed** - Si las pruebas pasan
6. **❌ Tests Failed** - Si alguna prueba falla
7. **🔀 Merged to Test** - Al hacer merge automático a test
8. **🚀 Deployment Started** - Al iniciar despliegue
9. **🎉 Deployment Success** - Cuando se despliega a producción

## 🔧 Formato de Mensajes

Los mensajes usan Markdown de Telegram:

```
🚨 *VULNERABILITY DETECTED*

PR: #42
Author: @username
Branch: dev → test

📄 `src/vulnerable.c`
Confidence: 87.32%
Possible: CWE-787 (Buffer Overflow)

Action Required: Fix vulnerabilities before merging.
```

## 🧪 Test Manual del Bot

```python
import requests

def send_test_message():
    bot_token = "TU_BOT_TOKEN"
    chat_id = "TU_CHAT_ID"
    
    message = "🧪 *Test Message*\n\nBot configurado correctamente!"
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    response = requests.post(url, data=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

send_test_message()
```

## 📱 Canales Adicionales (Opcional)

Para notificar a un grupo o canal:

1. Crea un grupo/canal en Telegram
2. Agrega el bot como administrador
3. Envía un mensaje en el grupo/canal
4. Obtén el chat_id con `getUpdates` (será negativo, ejemplo: `-1001234567890`)
5. Usa ese chat_id en los secrets
