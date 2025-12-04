# Sistema de Detección de Vulnerabilidades con Minería de Datos

## 📚 Información Académica

**Universidad de las Fuerzas Armadas ESPE**  
**Carrera:** Ingeniería en Software  
**Materia:** Desarrollo de Software Seguro  
**Docente:** Ing. Geovanny Cudco  
**Laboratorio:** Nº 1 - Aplicación de Minería de Datos en Desarrollo de Software Seguro  
**Estudiantes:** José Proaño, Josúe Guallichico, Cristian Robalino  
**Fecha:** Diciembre 2025

---

## 🎯 Objetivo del Proyecto

Desarrollar un sistema inteligente de detección y predicción de vulnerabilidades en código fuente utilizando técnicas avanzadas de minería de datos, siguiendo la metodología **SEMMA** (Sample, Explore, Modify, Model, Assess) para identificar patrones de riesgo y automatizar la detección de vulnerabilidades en entornos DevSecOps.

## 📋 Contexto

Este proyecto investiga cómo la minería de datos puede mejorar la seguridad en el desarrollo de software mediante el análisis de:
- Código fuente de repositorios open-source
- Bases de datos de vulnerabilidades (CVE, NVD)
- Métricas de código estático
- Historiales de incidentes de seguridad

El objetivo es reducir el tiempo de exposición a amenazas y mejorar la calidad del software mediante la detección temprana de vulnerabilidades.

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                     FUENTES DE DATOS                            │
├─────────────────────────────────────────────────────────────────┤
│  • DiverseVul (330,492 funciones C/C++)                         │
│  • BigVul (4,432 CVEs)                                          │
│  • NVD Database                                                 │
│  • Repositorios GitHub                                          │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                  METODOLOGÍA SEMMA                              │
├─────────────────────────────────────────────────────────────────┤
│  1. SAMPLE   → Muestreo balanceado (45,830 muestras)           │
│  2. EXPLORE  → Análisis exploratorio y visualización           │
│  3. MODIFY   → Feature Engineering (34 características)        │
│  4. MODEL    → Entrenamiento de múltiples algoritmos           │
│  5. ASSESS   → Evaluación con métricas (F1, ROC-AUC)          │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                  MODELOS ENTRENADOS                             │
├─────────────────────────────────────────────────────────────────┤
│  • Random Forest     → 70.10% accuracy                          │
│  • Gradient Boosting → 66.03% accuracy                          │
│  • SVM              → 69.13% accuracy                           │
│  • Neural Network   → 70.35% accuracy ⭐ MEJOR                  │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              SCANNER DE VULNERABILIDADES                        │
├─────────────────────────────────────────────────────────────────┤
│  • Análisis de código C/C++                                     │
│  • Detección de 6 tipos de CWE                                  │
│  • Generación automática de reportes JSON + HTML               │
│  • Snippets de código vulnerable                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tecnologías Utilizadas

### Backend & ML
- **Python 3.12** - Lenguaje principal
- **scikit-learn** - Modelos de machine learning
- **TensorFlow/Keras** - Redes neuronales
- **pandas & numpy** - Manipulación de datos
- **joblib** - Serialización de modelos

### Procesamiento de Código
- **pygments** - Análisis sintáctico
- **textstat** - Métricas de complejidad
- **radon** - Métricas de código

### Visualización
- **matplotlib** - Gráficos estadísticos
- **seaborn** - Visualización avanzada

### Infraestructura
- **Docker** - Contenedorización
- **Docker Compose** - Orquestación de servicios
- **MongoDB** - Base de datos (opcional)

### Control de Versiones
- **Git & GitHub** - Versionamiento y colaboración

---

## 📊 Resultados Obtenidos

### 1. Dataset Profesional
Se construyó un dataset balanceado de **45,830 muestras**:
- **22,915 muestras vulnerables** (de DiverseVul + BigVul)
- **22,915 muestras seguras** (balanceo estratificado)
- **Lenguaje:** C/C++
- **CWEs cubiertos:** CWE-787, CWE-125, CWE-20, CWE-416, CWE-476, CWE-119, CWE-190

### 2. Modelos Entrenados (20,000 muestras)

| Modelo | Accuracy | F1-Score | ROC-AUC | Notas |
|--------|----------|----------|---------|-------|
| **Neural Network** | **70.35%** | **0.7034** | **0.7748** | ⭐ Mejor modelo |
| Random Forest | 70.10% | 0.6997 | 0.7751 | Buena interpretabilidad |
| SVM | 69.13% | 0.6856 | 0.7484 | Efectivo en patrones complejos |
| Gradient Boosting | 66.03% | 0.6602 | 0.7282 | Requiere optimización |

**Configuración del Mejor Modelo (Neural Network):**
```python
Arquitectura: [512, 256, 128, 64]
Activación: ReLU
Optimizador: Adam (learning_rate=0.001, decay adaptativo)
Regularización: Dropout 0.3
Batch Size: 32
Epochs: 50 (early stopping)
```

### 3. Scanner de Vulnerabilidades C/C++

**Características:**
- ✅ Detección automática de 6 tipos de CWE
- ✅ Análisis de 34 características de código
- ✅ Umbral de confianza: 65%
- ✅ Generación automática de reportes JSON + HTML
- ✅ Snippets de código vulnerable con contexto

**Resultados en Repositorios de Prueba:**

#### Damn_Vulnerable_C_Program
- **Archivos escaneados:** 14 de 16
- **Vulnerabilidades detectadas:** 24
- **CWE types:** 3 (alta precisión)
  - CWE-416 (Use After Free): 21 detecciones
  - CWE-476 (NULL Pointer): 5 detecciones
  - CWE-Unknown: 3 detecciones
- **Confianza:** 67-84%
- **Validación:** ✅ Confirmado con análisis manual del código fuente

#### how2heap (Técnicas de Explotación Heap)
- **Archivos escaneados:** 236 de 321
- **Vulnerabilidades detectadas:** 544
- **CWE types:** 6
  - CWE-476 (NULL Pointer): 239 detecciones
  - CWE-416 (Use After Free): 203 detecciones
  - CWE-787 (Buffer Overflow): 28 detecciones
  - CWE-190 (Integer Overflow): 29 detecciones
  - CWE-78 (Command Injection): 3 detecciones
  - CWE-Unknown: 214 detecciones

**Archivos más vulnerables detectados:**
- `house_of_roman.c`: 8 vulnerabilidades
- `house_of_water.c`: 6-7 vulnerabilidades
- `house_of_gods.c`: 6 vulnerabilidades

### 4. CWEs Detectados

El scanner identifica los siguientes tipos de vulnerabilidades:

| CWE | Descripción | Patrón de Detección |
|-----|-------------|---------------------|
| **CWE-787** | Buffer Overflow | `strcpy/strcat/gets` sin verificación de límites |
| **CWE-416** | Use After Free | Múltiples `free()` o uso de punteros post-liberación |
| **CWE-476** | NULL Pointer Dereference | Desreferencia sin verificación previa |
| **CWE-190** | Integer Overflow | Operaciones aritméticas en asignación de memoria |
| **CWE-78** | Command Injection | `system/exec/popen` con entrada no sanitizada |
| **CWE-Unknown** | Patrón no clasificado | Alta confianza sin patrón CWE específico |

---

## 📂 Estructura del Proyecto

```
Lab1P2-SoftwareSeguro/
│
├── 📁 src/                          # Código fuente
│   ├── models/
│   │   ├── process_professional_datasets.py    # Procesamiento DiverseVul + BigVul
│   │   └── train_professional_model.py         # Entrenamiento de modelos
│   ├── integration/
│   │   └── scanner_professional_cpp.py         # Scanner C/C++ con ML
│   ├── preprocessing/
│   │   └── feature_engineering.py              # Extracción de 34 features
│   └── exploration/
│       └── eda.py                              # Análisis exploratorio
│
├── 📁 data/                         # Datasets (no subidos a Git)
│   ├── professional_vulnerability_dataset.json  # 45,830 muestras
│   ├── Damn_Vulnerable_C_Program/              # Repositorio de prueba
│   └── how2heap/                               # Técnicas de explotación heap
│
├── 📁 models/                       # Modelos entrenados (no subidos a Git)
│   ├── professional_vulnerability_detector.joblib  # Neural Network (mejor)
│   ├── professional_scaler.joblib                  # StandardScaler
│   ├── professional_label_encoder.joblib           # LabelEncoder
│   └── professional_model_metadata.json            # Métricas y configuración
│
├── 📁 reports/                      # Reportes generados (no subidos a Git)
│   ├── scan_*.json                 # Reportes JSON
│   └── scan_*.html                 # Reportes HTML visuales
│
├── 📁 config/                       # Configuración
│   └── config.yaml                 # Configuración del sistema
│
├── 📁 scripts/                      # Scripts auxiliares
│   └── generate_html_report.py     # Generador de reportes HTML
│
├── 📄 docker-compose.yml            # Orquestación de servicios
├── 📄 Dockerfile                    # Imagen Docker
├── 📄 requirements.txt              # Dependencias Python
├── 📄 .gitignore                    # Archivos ignorados
├── 📄 .env.example                  # Variables de entorno (plantilla)
├── 📄 LICENSE                       # Licencia MIT
└── 📄 README.md                     # Este archivo
```

---

## 🚀 Instalación y Uso

### Prerequisitos
- Docker & Docker Compose
- Git
- 8GB RAM mínimo (recomendado 16GB)

### 1. Clonar el Repositorio
```bash
git clone https://github.com/JoseProano/Lab1P2-SoftwareSeguro-27894.git
cd Lab1P2-SoftwareSeguro-27894
```

### 2. Configurar Variables de Entorno
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

### 3. Construir y Levantar Contenedores
```bash
# Windows PowerShell
.\start.ps1

# Linux/Mac
./start.sh
```

### 4. Descargar y Procesar Datasets (Opcional)
```bash
# Entrar al contenedor
docker-compose exec ml_app bash

# Descargar DiverseVul + BigVul (703MB + 4,432 CVEs)
python src/models/process_professional_datasets.py
```

### 5. Entrenar Modelos
```bash
# Dentro del contenedor
python src/models/train_professional_model.py
```

### 6. Escanear Código
```bash
# Escanear un repositorio C/C++
python src/integration/scanner_professional_cpp.py /app/data/Damn_Vulnerable_C_Program

# Los reportes se generan automáticamente en /app/reports/
```

---

## 📖 Metodología SEMMA Aplicada

### 1️⃣ SAMPLE (Muestreo)
- **Dataset DiverseVul:** 330,492 funciones C/C++ → 18,913 vulnerables extraídas
- **Dataset BigVul:** 4,432 CVEs → 4,002 vulnerables extraídas
- **Balanceo:** 50/50 vulnerable/safe → **45,830 muestras totales**
- **Técnica:** Muestreo estratificado por CWE

### 2️⃣ EXPLORE (Exploración)
- **Análisis EDA:** Distribución de CWEs, longitud de código, complejidad
- **Visualizaciones:** Histogramas, matriz de correlación, gráficos de barras
- **Estadísticas:** 
  - CWE-787 (Buffer Overflow): 1,379 muestras (6.0%)
  - CWE-125 (Out-of-bounds Read): 1,134 muestras (4.9%)
  - CWE-20 (Improper Input Validation): 896 muestras (3.9%)

### 3️⃣ MODIFY (Modificación)
- **Limpieza:** Eliminación de duplicados, manejo de valores nulos
- **Feature Engineering:** Extracción de **34 características**:
  - Longitud de código
  - Conteo de palabras clave (malloc, free, strcpy, etc.)
  - Complejidad ciclomática
  - Profundidad de anidamiento
  - Métricas de Halstead
  - Índice de mantenibilidad
  - Vectorización TF-IDF

### 4️⃣ MODEL (Modelado)
- **Algoritmos probados:** Random Forest, Gradient Boosting, SVM, Neural Network
- **Validación:** 5-fold Cross-Validation
- **Selección:** Neural Network (70.35% accuracy, 0.7034 F1-score)
- **Optimización:** GridSearchCV para hiperparámetros

### 5️⃣ ASSESS (Evaluación)
- **Métricas:**
  - Accuracy: 70.35%
  - F1-Score: 0.7034
  - ROC-AUC: 0.7748
  - Precision: 73.09%
  - Recall: 67.72%
- **Matriz de Confusión:**
  ```
  [[1465  535]
   [646 1354]]
  ```
- **Validación en producción:** Confirmado con análisis manual de código real

---

## 🔍 Ejemplo de Detección

**Código Vulnerable Detectado (dvcp.c):**
```c
// CWE-416: Use After Free / Double Free
char *buff1 = malloc(size1);
free(buff1);
if (size1 % 2 == 0) {
    free(buff1);  // ← DOUBLE FREE detectado (77% confianza)
} else if(size1 % 3 == 0) {
    buff1[0] = 'a';  // ← USE AFTER FREE detectado (73% confianza)
}
```

**Reporte JSON Generado:**
```json
{
  "file": "/app/data/Damn_Vulnerable_C_Program/dvcp.c",
  "line_start": 62,
  "line_end": 68,
  "confidence": 77.42,
  "cwe": "CWE-416 (Use After Free / Double Free)",
  "snippet": "free(buff1);\nif (size1 % 2 == 0) free(buff1);"
}
```

---

## 📈 Algoritmos de Minería de Datos Utilizados

### Clasificación (Predicción de Vulnerabilidades)
1. **Random Forest** - Ensemble de árboles de decisión, alta interpretabilidad
2. **Gradient Boosting** - Boosting iterativo, mejora gradual
3. **SVM** - Separación no lineal con kernel RBF
4. **Neural Network** ⭐ - Capas densas con dropout, mejor rendimiento

### Feature Engineering
- **TF-IDF Vectorization** - Representación textual de código
- **Extracción de Métricas** - Complejidad, mantenibilidad, Halstead
- **Pattern Matching** - Detección de funciones inseguras

### Evaluación
- **Cross-Validation** - 5-fold para robustez
- **ROC-AUC** - Curva característica operativa
- **Confusion Matrix** - Análisis detallado de errores

---

## 🎓 Contribuciones Académicas

### Datasets Utilizados
1. **DiverseVul** ([Google Drive](https://drive.google.com/...))
   - 330,492 funciones C/C++
   - Formato JSONL
   - 18,913 vulnerables extraídas

2. **BigVul** ([MSR 2020](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset))
   - 4,432 CVEs
   - Formato CSV
   - 4,002 vulnerables extraídas

3. **CVEFixes** (Opcional)
   - Commits de fixes históricos
   - Pares vulnerable/fixed

### Publicaciones y Referencias
- **Metodología SEMMA** - SAS Institute
- **Common Weakness Enumeration (CWE)** - MITRE
- **National Vulnerability Database (NVD)** - NIST

---

## ⚠️ Limitaciones y Trabajo Futuro

### Limitaciones Actuales
- ✅ **Lenguaje:** Solo C/C++ (entrenado con DiverseVul)
- ✅ **Precisión:** 70.35% - Espacio para mejorar
- ✅ **CWE Coverage:** 6 tipos principales, faltan otros CWEs
- ✅ **Contexto:** Análisis estático, no dinámico

### Mejoras Propuestas
- 🔄 **Multi-lenguaje:** Entrenar con Java, Python, JavaScript
- 🔄 **Deep Learning:** Modelos basados en transformers (CodeBERT, GraphCodeBERT)
- 🔄 **Análisis Dinámico:** Integración con fuzzing y análisis de runtime
- 🔄 **Explicabilidad:** Implementar SHAP/LIME para interpretabilidad
- 🔄 **CI/CD Integration:** GitHub Actions completo (pendiente)

---

## 📞 Contacto

**Estudiante:** José Proaño  
**Universidad:** ESPE - Universidad de las Fuerzas Armadas  
**Repositorio:** [GitHub](https://github.com/JoseProano/Lab1P2-SoftwareSeguro-27894)

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- **Ing. Geovanny Cudco** - Docente y guía del proyecto
- **ESPE** - Universidad de las Fuerzas Armadas
- **DiverseVul Team** - Por el dataset académico
- **BigVul Team** - Por la base de datos de CVEs
- **Comunidad Open Source** - Por herramientas y repositorios de prueba

---

## 📝 Notas Finales

Este proyecto fue desarrollado con fines académicos como parte del Laboratorio 1 de la materia Desarrollo de Software Seguro. Los modelos entrenados y datasets utilizados son de naturaleza académica y **no deben usarse en entornos de producción sin validación adicional**.

**Última actualización:** Diciembre 2025  
**Versión:** 1.0.0
