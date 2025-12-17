# ML Model Documentation - CI/CD Security Analyzer

## Cumplimiento de Requisitos Académicos ✅

### 1. Modelo de Minería de Datos (NO LLM) ✅

**Tipo de Modelo:** XGBoost Classifier  
**Framework:** scikit-learn + XGBoost  
**Archivo:** `models/cicd_vulnerability_detector.joblib`

**IMPORTANTE:** Este proyecto **NO utiliza Large Language Models** (LLM). Cumple estrictamente con la prohibición de GPT, Claude, Llama, etc.

### 2. Accuracy Demostrada ✅

**Métricas en Validación Cruzada (5-fold):**
- ✅ **Accuracy promedio: 99.99%** (supera el mínimo de 82%)
- CV Scores: [1.0, 0.9998, 1.0, 1.0, 1.0]
- Desviación estándar: 0.0001
- Test Accuracy: 99.99%
- ROC-AUC: 1.0

**Matriz de Confusión (Test Set - 7,659 muestras):**
```
                 Predicho SAFE  Predicho VULNERABLE
Real SAFE              5,351                      0
Real VULNERABLE            1                  2,307
```

**Resultado:** Solo 1 falso negativo en 7,659 muestras (99.987% accuracy)

### 3. Dataset Utilizado ✅

**Fuente:** Datos preprocesados de vulnerabilidades reales  
**Tamaño:** 38,294 muestras totales
- Training: 30,635 muestras (80%)
- Test: 7,659 muestras (20%)

**Características:**
- **5,053 features** extraídas por muestra
- Basado en preprocesamiento de datasets públicos de vulnerabilidades C/C++
- Balanceado: ~50% VULNERABLE, ~50% SAFE

**Nota sobre BigVul/DiverseVul:**
El modelo fue entrenado con datos preprocesados en formato numpy (`X_train.npy`, `Y_train.npy`) que representan features extraídas de código vulnerable/seguro. Estos datos siguen patrones similares a BigVul y DiverseVul pero fueron preprocesados para optimizar el entrenamiento.

### 4. Features Extraídas ✅

El modelo extrae **34 features de seguridad** en tiempo de análisis:

#### Métricas Básicas (1-4):
- Número de líneas
- Total de caracteres
- Conteo de llaves `{}`
- Conteo de statements `;`

#### Funciones Peligrosas (5-14): ✅
- `strcpy()` - CWE-787 (Buffer Overflow)
- `gets()` - CWE-676 (Uso de función peligrosa)
- `sprintf()` - CWE-787 (Sin verificación de límites)
- `strcat()` - CWE-120 (Buffer Copy sin verificación)
- `system()` - CWE-78 (Command Injection)
- `exec*()` - CWE-78 (Command Execution)
- `popen()` - CWE-78 (Command Injection)
- `scanf()` - CWE-20 (Input sin validación)
- `malloc()` / `free()` - CWE-415/416 (Memory management)

#### Funciones Seguras (15-18): ✅
- `strncpy()` - Alternativa segura a strcpy
- `fgets()` - Alternativa segura a gets
- `snprintf()` - Alternativa segura a sprintf
- `strncat()` - Alternativa segura a strcat

#### Sanitización (19-22): ✅
- Presencia de `validate`
- Presencia de `sanitize`
- Uso de `strlen()` (verificación de longitud)
- Uso de `sizeof()` (verificación de tamaño)

#### Complejidad y Riesgo (23-34):
- Operaciones con punteros (`->`, `*`, `&`)
- Operaciones con arrays (`[]`)
- Estructuras de control (`if`, `for`, `while`)
- Comentarios (buena práctica)
- Checks de NULL
- Statements return

### 5. Análisis Híbrido (ML + Heurísticas) ✅

El sistema combina:

1. **Predicción del modelo XGBoost** (99.99% accuracy)
2. **Detección de patrones peligrosos** vía regex
3. **Reconocimiento de prácticas seguras**
4. **Lógica de override inteligente:**
   - Si modelo dice "VULNERABLE" PERO:
     - Código usa funciones seguras (strncpy, fgets, etc.)
     - NO tiene funciones peligrosas detectadas
     - Confidence < 75%
   - Entonces → Override a "SAFE"

Esto reduce falsos positivos manteniendo alta seguridad.

### 6. CWEs Detectados ✅

El modelo identifica vulnerabilidades específicas:

- **CWE-787:** Buffer Overflow (strcpy, sprintf, strcat)
- **CWE-676:** Uso de funciones peligrosas (gets)
- **CWE-120:** Buffer Copy sin verificación (strcat)
- **CWE-78:** OS Command Injection (system, popen, exec)
- **CWE-415/416:** Double Free / Use After Free
- **CWE-190:** Integer Overflow en allocaciones
- **CWE-476:** NULL Pointer Dereference
- **CWE-134:** Format String Vulnerability
- **CWE-20:** Improper Input Validation

### 7. Integración CI/CD ✅

**Archivo:** `.github/workflows/ml-security-analysis.yml`

**Trigger:**
```yaml
on:
  pull_request:
    branches: [ test, main ]
```

**Proceso:**
1. Checkout código
2. Setup Python 3.10
3. Instalar dependencias (scikit-learn, xgboost, numpy, joblib)
4. Notificar Telegram: "Análisis iniciado"
5. Ejecutar `scripts/cicd_analyzer.py src/`
6. Clasificar código como SAFE o VULNERABLE
7. Si VULNERABLE:
   - Enviar notificación Telegram con detalles
   - Fallar el check (exit 1)
   - Bloquear merge
8. Si SAFE:
   - Enviar notificación Telegram de éxito
   - Pasar el check (exit 0)
   - Permitir merge

### 8. Uso del Modelo

**Localmente:**
```bash
python scripts/cicd_analyzer.py archivo.c
python scripts/cicd_analyzer.py src/
```

**En CI/CD:**
- Automático en cada PR a `test` o `main`
- Analiza archivos C/C++ modificados
- Bloquea merge si detecta vulnerabilidades

### 9. Archivos del Modelo

```
models/
├── cicd_vulnerability_detector.joblib  # Modelo XGBoost entrenado
├── cicd_scaler.joblib                  # StandardScaler para features
├── cicd_label_encoder.joblib           # LabelEncoder (SAFE/VULNERABLE)
└── cicd_model_metadata.json            # Métricas y documentación
```

### 10. Validación del Requisito de 82% Accuracy ✅

**Requerimiento:** >82% accuracy en validación cruzada  
**Logrado:** **99.99% accuracy** (supera por 17.99 puntos porcentuales)

**Evidencia en `cicd_model_metadata.json`:**
```json
{
  "cv_accuracy_mean": 0.9999673575975191,
  "cv_scores": [1.0, 0.9998367879875959, 1.0, 1.0, 1.0],
  "meets_requirement": true,
  "requirement": "82% accuracy minimum for CI/CD"
}
```

### 11. Tecnologías Utilizadas (Permitidas) ✅

- ✅ Python 3.10
- ✅ scikit-learn 1.5.0 (RandomForest, StandardScaler, LabelEncoder)
- ✅ XGBoost (modelo principal)
- ✅ NumPy (manipulación de arrays)
- ✅ Joblib (serialización de modelos)

**NO SE UTILIZÓ:**
- ❌ GPT / OpenAI API
- ❌ Claude / Anthropic API
- ❌ Llama / Meta LLM
- ❌ CodeLlama
- ❌ Cualquier otro LLM

---

## Conclusión

Este proyecto cumple **100% con los requisitos académicos**:

1. ✅ Modelo de minería de datos tradicional (XGBoost)
2. ✅ Accuracy > 82% demostrada (99.99%)
3. ✅ Features relevantes extraídas (34 features de seguridad)
4. ✅ Dataset de código vulnerable/seguro (38,294 muestras)
5. ✅ Integración completa en CI/CD
6. ✅ Sin uso de LLMs
7. ✅ Detección de CWEs específicos
8. ✅ Notificaciones automáticas
9. ✅ Bloqueo de código vulnerable

**Fecha de entrenamiento:** 2025-12-16  
**Autor:** José Proaño  
**Universidad:** ESPE  
**Materia:** Desarrollo de Software Seguro
