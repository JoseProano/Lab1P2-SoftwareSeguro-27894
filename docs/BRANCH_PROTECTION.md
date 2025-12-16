# Branch Protection Rules - Configuración

## 🔒 Configurar Protección de Ramas en GitHub

### Para rama `test`

1. Ve a **Settings** → **Branches**
2. Click en **Add branch protection rule**
3. Branch name pattern: `test`
4. Activa estas opciones:

   ✅ **Require a pull request before merging**
   - Required approvals: 0 (auto-merge habilitado)
   
   ✅ **Require status checks to pass before merging**
   - Requiere: `🔒 ML Security Analysis`
   - Requiere: `🧪 Unit Tests`
   
   ✅ **Require branches to be up to date before merging**
   
   ✅ **Do not allow bypassing the above settings**

5. Click en **Create**

### Para rama `main`

1. Click en **Add branch protection rule**
2. Branch name pattern: `main`
3. Activa estas opciones:

   ✅ **Require a pull request before merging**
   - Required approvals: 1 (mínimo 1 aprobación manual)
   
   ✅ **Require status checks to pass before merging**
   - Requiere: `🔒 ML Security Analysis`
   - Requiere: `🧪 Unit Tests`
   - Requiere: `🚀 Build & Deploy`
   
   ✅ **Require branches to be up to date before merging**
   
   ✅ **Require conversation resolution before merging**
   
   ✅ **Do not allow bypassing the above settings**
   
   ✅ **Restrict pushes that create matching branches**

4. Click en **Create**

## 🌳 Estructura de Ramas

```
main (producción) ← protegida, requiere aprobación manual
  ↑
  | (PR automático si todo pasa)
  |
test (staging) ← protegida, merge automático desde dev
  ↑
  | (PR desde dev, trigger del pipeline)
  |
dev (desarrollo) ← rama de trabajo
```

## 📋 Flujo de Trabajo

### Desarrollador (en rama dev):

```bash
# 1. Crear rama dev si no existe
git checkout -b dev

# 2. Hacer cambios
git add .
git commit -m "feat: nueva funcionalidad"
git push origin dev

# 3. Crear PR: dev → test
# Esto AUTOMÁTICAMENTE activa el pipeline CI/CD
```

### Pipeline CI/CD (automático):

1. **Análisis ML**: ¿Es vulnerable?
   - ❌ SI → PR rechazado, notificación Telegram, issue creada
   - ✅ NO → Continúa

2. **Tests**: ¿Pasan todas las pruebas?
   - ❌ NO → Pipeline falla, notificación Telegram
   - ✅ SI → Continúa

3. **Auto-merge a test**: Si PR es dev→test
   - Merge automático
   - Notificación Telegram

4. **Deploy (solo si test→main)**:
   - Build Docker image
   - Push a registry
   - Deploy a producción (Render/Railway)
   - Merge automático a main
   - Notificación Telegram de éxito

## 🚀 Comandos Útiles

### Crear las 3 ramas:

```bash
# Crear dev
git checkout -b dev
git push origin dev

# Crear test
git checkout -b test
git push origin test

# Crear main (ya existe)
git checkout main
git push origin main
```

### Workflow normal de desarrollo:

```bash
# En rama dev
git checkout dev
git pull origin dev

# Hacer cambios
# ... editar archivos ...

git add .
git commit -m "feat: implementar nueva característica"
git push origin dev

# Crear PR en GitHub: dev → test
# El pipeline se activa automáticamente
```

### Sincronizar ramas:

```bash
# Actualizar dev desde test
git checkout dev
git pull origin test
git push origin dev

# Actualizar test desde main
git checkout test
git pull origin main
git push origin test
```

## ⚠️ Notas Importantes

1. **NUNCA hacer push directo a `test` o `main`** - Siempre vía PR
2. **El pipeline se activa SOLO en PRs** a `test` o `main`
3. **Merge automático** solo si el código es seguro Y los tests pasan
4. **Para producción (main)**: requiere aprobación manual adicional
5. **Todos los checks deben pasar** antes de merge

## 🔧 Troubleshooting

### "Status checks required but not found"

Si ves este error al crear PR:

1. Haz un push dummy para activar el workflow:
   ```bash
   git commit --allow-empty -m "trigger workflow"
   git push
   ```

2. Una vez que el workflow corre la primera vez, GitHub lo reconoce

### "Auto-merge no funciona"

Verifica:
- Branch protection tiene "Require a pull request" activado
- El bot tiene permisos de escritura en el repo
- Los status checks están configurados correctamente

### "Tests fallan en CI pero localmente pasan"

```bash
# Correr tests exactamente como CI
docker-compose exec ml_app pytest tests/ -v
```
