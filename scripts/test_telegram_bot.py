#!/usr/bin/env python3
"""
Script para probar Telegram Bot
"""

import requests
import sys
from pathlib import Path

def test_telegram_bot(bot_token: str, chat_id: str):
    """
    Envía mensaje de prueba al bot de Telegram
    """
    print("=" * 60)
    print("TESTING TELEGRAM BOT")
    print("=" * 60)
    
    # Mensaje de prueba
    message = """🧪 *Telegram Bot Test*

✅ Bot configurado correctamente
🤖 Sistema CI/CD listo
🔒 Notificaciones de seguridad activas

Este mensaje confirma que:
- Bot token válido
- Chat ID correcto
- Conexión establecida"""
    
    # Enviar mensaje
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        print(f"\nEnviando mensaje a chat_id: {chat_id}...")
        response = requests.post(url, data=data, timeout=10)
        
        if response.status_code == 200:
            print("✅ Mensaje enviado exitosamente!")
            print(f"\nRespuesta: {response.json()}")
            return True
        else:
            print(f"❌ Error al enviar mensaje")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    if len(sys.argv) != 3:
        print("Uso: python test_telegram_bot.py <BOT_TOKEN> <CHAT_ID>")
        print("\nEjemplo:")
        print("  python test_telegram_bot.py 1234567890:ABCdef... 123456789")
        print("\nO configura variables de entorno:")
        print("  export TELEGRAM_BOT_TOKEN='tu-token'")
        print("  export TELEGRAM_CHAT_ID='tu-chat-id'")
        print("  python test_telegram_bot.py")
        sys.exit(1)
    
    bot_token = sys.argv[1]
    chat_id = sys.argv[2]
    
    success = test_telegram_bot(bot_token, chat_id)
    
    if success:
        print("\n✅ Bot configurado correctamente!")
        print("Puedes proceder con el setup de CI/CD")
    else:
        print("\n❌ Hay problemas con la configuración")
        print("Verifica el token y chat_id")
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
