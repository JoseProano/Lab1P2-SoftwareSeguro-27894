# 🚀 Guía de Configuración de Render

## Paso 1: Crear Web Service en Render

1. Ve a https://render.com/
2. Click en **"New +"** → **"Web Service"**
3. Conecta tu repositorio: `JoseProano/Lab1P2-SoftwareSeguro-27894`
4. Configuración:
   - **Name:** `lab1p2-vulnerability-detector`
   - **Region:** Oregon (US West)
   - **Branch:** `main`
   - **Environment:** Docker
   - **Plan:** Free

5. Click **"Create Web Service"**

## Paso 2: Obtener Deploy Hook

1. En tu servicio de Render, ve a **Settings**
2. Scroll hasta **"Deploy Hook"**
3. Click en **"Create Deploy Hook"**
4. Copia la URL generada (algo como):
   ```
   https://api.render.com/deploy/srv-xxxxxxxxxxxxx?key=yyyyyyyyyyyy
   ```

## Paso 3: Agregar Deploy Hook a GitHub Secrets

1. Ve a tu repositorio en GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Click en **"New repository secret"**
4. Configura:
   - **Name:** `RENDER_DEPLOY_HOOK`
   - **Secret:** Pega la URL del Deploy Hook
5. Click **"Add secret"**

## Paso 4: Probar el Deploy

### Opción A: Deploy Manual desde Render
1. En Render dashboard → tu servicio
2. Click en **"Manual Deploy"** → **"Deploy latest commit"**
3. Espera ~2-3 minutos
4. Verifica que el servicio esté "Live"

### Opción B: Deploy Automático con PR
1. Asegúrate de que todos los cambios estén en `main`
2. Crea un PR de `dev` → `main`
3. GitHub Actions ejecutará:
   - Análisis ML de seguridad
   - Deploy automático a Render
   - Notificaciones Telegram

## Paso 5: Verificar Deployment

Una vez que Render muestre "Live", obtén tu URL:

```
https://lab1p2-vulnerability-detector.onrender.com
```

### Probar endpoints:

**Health Check:**
```bash
curl https://lab1p2-vulnerability-detector.onrender.com/health
```

**Análisis de Código:**
```bash
curl -X POST https://lab1p2-vulnerability-detector.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "void test() { char buf[10]; strcpy(buf, input); system(input); }"
  }'
```

Deberías recibir:
```json
{
  "status": "success",
  "classification": "VULNERABLE",
  "confidence": 99.87,
  "is_vulnerable": true,
  "vulnerabilities": [
    "CWE-787: Buffer Overflow (strcpy)",
    "CWE-78: Command Injection (system)"
  ]
}
```

## Notas Importantes

- **Primera vez:** El deploy puede tardar 5-10 minutos
- **Subsecuentes:** ~2-3 minutos
- **Free tier:** El servicio se duerme después de 15 min de inactividad
- **Cold start:** Primera petición después de dormir tarda ~30 segundos

## Actualizar README.md

Una vez tengas la URL, actualiza tu README con:

```markdown
## 🌐 Despliegue en Producción

**URL:** https://lab1p2-vulnerability-detector.onrender.com
**Health Check:** https://lab1p2-vulnerability-detector.onrender.com/health
**Estado:** ✅ Online

### Probar el modelo en producción:

\`\`\`bash
curl -X POST https://lab1p2-vulnerability-detector.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "tu código aquí"}'
\`\`\`
```

## Troubleshooting

### Error: "Model not loaded"
- Verifica que los archivos `.joblib` estén en la carpeta `models/`
- Revisa los logs en Render dashboard

### Error: "Health check failed"
- El servicio puede estar tardando en iniciar (cold start)
- Espera 2-3 minutos y vuelve a intentar

### Deploy no se activa automáticamente
- Verifica que `RENDER_DEPLOY_HOOK` esté configurado en GitHub Secrets
- Asegúrate de que el PR sea hacia la rama `main`
