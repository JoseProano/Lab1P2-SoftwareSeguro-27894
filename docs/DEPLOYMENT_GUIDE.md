# Deployment Guide - CI/CD Project

## 🚀 Opciones de Despliegue

### Opción 1: Render (Recomendada) ⭐

**Ventajas**: Gratis, simple, auto-deploy desde GitHub

#### Setup:

1. **Crear cuenta en Render**
   - Ve a https://render.com
   - Sign up con GitHub

2. **Crear Web Service**
   - Click en "New +" → "Web Service"
   - Conecta tu repositorio GitHub
   - Configuración:
     - **Name**: `vulnerability-detector-api`
     - **Environment**: `Docker`
     - **Branch**: `main`
     - **Plan**: `Free`

3. **Configurar Deploy Hook**
   - En Render Dashboard → Settings
   - Copia **Deploy Hook URL**
   - En GitHub: Settings → Secrets → Actions
   - Agrega secret:
     - Name: `RENDER_DEPLOY_HOOK`
     - Value: `https://api.render.com/deploy/srv-xxxxx`

4. **Verificar Deploy**
   - Render auto-deploya en cada push a `main`
   - URL: `https://vulnerability-detector-api.onrender.com`

---

### Opción 2: Railway

**Ventajas**: Gratis $5/mes crédito, rápido

#### Setup:

1. **Crear cuenta en Railway**
   - Ve a https://railway.app
   - Sign up con GitHub

2. **Crear proyecto**
   - Click en "New Project"
   - Select: "Deploy from GitHub repo"
   - Selecciona tu repositorio

3. **Configurar Variables**
   - En Railway Dashboard → Variables
   - Agrega:
     ```
     PYTHONUNBUFFERED=1
     PYTHONPATH=/app
     PORT=8000
     ```

4. **Deploy Token**
   - Railway → Settings → Tokens
   - Genera un token de deploy
   - En GitHub Secrets:
     - Name: `RAILWAY_TOKEN`
     - Value: `tu-token`
     - Name: `RAILWAY_SERVICE_ID`
     - Value: `srv-xxxxx`

5. **Descomenta sección en workflow**
   ```yaml
   # En .github/workflows/cicd-pipeline.yml
   # Descomentar líneas de Railway deploy
   ```

---

### Opción 3: Fly.io

**Ventajas**: Gratis tier generoso, rápido

#### Setup:

1. **Instalar CLI**
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```

2. **Login**
   ```bash
   fly auth login
   ```

3. **Launch app**
   ```bash
   fly launch
   ```
   - Nombre: `vulnerability-detector-api`
   - Region: us-west
   - No database

4. **Deploy**
   ```bash
   fly deploy
   ```

5. **Auto-deploy desde GitHub**
   ```bash
   fly tokens create deploy
   ```
   - Guarda token en GitHub Secret: `FLY_API_TOKEN`

---

### Opción 4: Vercel (Solo Frontend/API)

**Para proyectos con frontend**

```bash
npm install -g vercel
vercel login
vercel
```

---

### Opción 5: Docker Hub + Play with Docker

**Para demo temporal (4 horas)**

1. **Build y push a Docker Hub**
   ```bash
   docker login
   docker build -t tuusuario/vulnerability-detector:latest .
   docker push tuusuario/vulnerability-detector:latest
   ```

2. **Run en Play with Docker**
   - Ve a https://labs.play-with-docker.com/
   - Click "Start"
   - Run:
     ```bash
     docker run -p 8000:8000 tuusuario/vulnerability-detector:latest
     ```

---

## 🔧 Configuración Común

### Variables de Entorno Requeridas

```bash
PYTHONUNBUFFERED=1
PYTHONPATH=/app
MODEL_PATH=/app/models/cicd_vulnerability_detector.joblib
TELEGRAM_BOT_TOKEN=<tu-token>
TELEGRAM_CHAT_ID=<tu-chat-id>
```

### Health Check Endpoint

El deployment debe tener un health check en:

```
GET /health
Response: {"status": "ok", "model_loaded": true}
```

Crea este endpoint:

```python
# src/api/health.py
from fastapi import FastAPI
from pathlib import Path

app = FastAPI()

@app.get("/health")
def health_check():
    model_path = Path("/app/models/cicd_vulnerability_detector.joblib")
    return {
        "status": "ok",
        "model_loaded": model_path.exists()
    }
```

---

## 📊 Monitoreo

### Logs en Render

```bash
# Ver logs en tiempo real
render logs --service vulnerability-detector-api --tail
```

### Logs en Railway

```bash
railway logs
```

### Logs en Fly.io

```bash
fly logs
```

---

## 🧪 Testing del Deploy

```bash
# Test endpoint
curl https://tu-app.onrender.com/health

# Expected response:
# {"status":"ok","model_loaded":true}
```

---

## 🔄 Auto-Deploy Setup

### GitHub → Render (Automático)

Render auto-deploya cuando se hace push a `main`

### GitHub → Railway (Vía workflow)

El workflow hace:
```yaml
- name: Deploy to Railway
  run: |
    railway up --service=${{ secrets.RAILWAY_SERVICE_ID }}
```

### GitHub → Fly.io (Vía workflow)

```yaml
- name: Deploy to Fly.io
  uses: superfly/flyctl-actions@master
  with:
    args: "deploy"
  env:
    FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

---

## 📋 Checklist de Deploy

- [ ] Crear cuenta en plataforma elegida
- [ ] Conectar repositorio GitHub
- [ ] Configurar variables de entorno
- [ ] Obtener Deploy Hook URL (Render) o Token (Railway/Fly)
- [ ] Agregar secret en GitHub: `RENDER_DEPLOY_HOOK` o `RAILWAY_TOKEN`
- [ ] Hacer test push a `main`
- [ ] Verificar que el deploy funciona
- [ ] Probar endpoint `/health`
- [ ] Verificar notificación Telegram de deploy exitoso

---

## 🆘 Troubleshooting

### "Deploy failed: Build error"

```bash
# Probar build local
docker build -t test .
docker run -p 8000:8000 test
```

### "Health check failed"

Verifica que el endpoint `/health` responde:
```bash
docker exec -it container_id curl localhost:8000/health
```

### "Model not found"

Verifica que el modelo está en la imagen:
```bash
docker run -it imagen ls -la /app/models/
```

---

## 🎯 Resultado Final

Tu aplicación debe estar accesible en:

- **Render**: `https://vulnerability-detector-api.onrender.com`
- **Railway**: `https://vulnerability-detector-production.up.railway.app`
- **Fly.io**: `https://vulnerability-detector-api.fly.dev`

Incluye esta URL en el README y en la presentación.
