# Email Header Analyzer

Analiza cabeceras de correo electrónico y detecta spoofing, fallos de autenticación y rutas sospechosas. Veredicto visual inmediato con desglose de SPF, DKIM, DMARC y hops.

---

## Funcionalidades

- Veredicto de seguridad automático: `LEGÍTIMO` / `SOSPECHOSO` / `PELIGROSO`
- Semáforo visual de autenticación: SPF, DKIM, DMARC
- Timeline de ruta de entrega con detección de servidores desconocidos e IPs privadas
- Puntuación de spam con barra de progreso
- Soporte de archivos `.eml`, `.msg`, `.txt`, `.mht` con drag & drop
- Cabecera raw colapsable para análisis manual

---

## Stack

| Capa | Tecnología |
|---|---|
| Backend | Python 3.12+ · FastAPI · Uvicorn |
| Parser | Módulo `email` de la stdlib de Python |
| Frontend | HTML · CSS · JavaScript vanilla |

---

## Estructura del proyecto

```
email-header-analyzer/
├── backend/
│   ├── main.py           # API FastAPI — endpoint /analyze
│   ├── parser.py         # Lógica de parseo de cabeceras
│   └── requirements.txt  # Dependencias Python
├── frontend/
│   └── index.html        # Interfaz web completa
├── .gitignore
└── README.md
```

---

## Inicio rápido

### Requisitos

- Python 3.12 o superior
- pip

### Backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

El servidor arranca en `http://localhost:8000`.
La documentación interactiva (Swagger) está en `http://localhost:8000/docs`.

### Frontend

Abre `frontend/index.html` directamente en el navegador, o sirve con:

```bash
python -m http.server 5500
# Abre: http://localhost:5500/frontend/index.html
```

---

## Despliegue en producción

### Railway (recomendado)

1. Crea una cuenta en [railway.app](https://railway.app)
2. Conecta el repositorio de GitHub
3. Railway detecta automáticamente FastAPI — configura el start command:
   ```
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
4. Establece el directorio raíz en `backend`
5. Despliega — Railway asigna una URL pública automáticamente
6. Actualiza `API_URL` en `frontend/index.html` con la URL de Railway

### Render

1. Crea un nuevo **Web Service** en [render.com](https://render.com)
2. Conecta el repositorio
3. Configura:
   - **Root directory:** `backend`
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Despliega y actualiza `API_URL` en el frontend

---

## Guía de contribución

### Ramas

| Rama | Propósito |
|---|---|
| `main` | Código estable, listo para producción |
| `develop` | Rama de integración, aquí se fusionan las features |
| `feat/<nombre>` | Nueva funcionalidad |
| `fix/<nombre>` | Corrección de bug |

**Flujo de trabajo:**

```bash
# Crear una nueva feature
git checkout develop
git checkout -b feat/nombre-de-la-feature

# Trabajar, commitear...
git add .
git commit -m "feat: descripción del cambio"

# Fusionar de vuelta a develop
git checkout develop
git merge feat/nombre-de-la-feature

# Cuando develop está estable, fusionar a main
git checkout main
git merge develop
git push origin main
```

### Convención de commits

Seguimos [Conventional Commits](https://www.conventionalcommits.org/):

| Prefijo | Cuándo usarlo |
|---|---|
| `feat:` | Nueva funcionalidad |
| `fix:` | Corrección de bug |
| `style:` | Cambios visuales sin lógica |
| `refactor:` | Reestructuración de código |
| `docs:` | Cambios en documentación |
| `chore:` | Configuración, dependencias |

**Ejemplos:**
```
feat: add delay calculation between hops
fix: correct DMARC regex for subdomain policies
docs: add deployment section to README
style: improve verdict card contrast on dark screens
```

### Pull Requests

- Toda feature debe ir en su propia rama
- El PR debe apuntar a `develop`, nunca directamente a `main`
- Incluye una descripción breve de qué cambia y por qué
- El título del PR sigue la misma convención de commits

---

## Roadmap

### v0.2.0
- [ ] Cálculo real de delays entre hops con alertas visuales
- [ ] Soporte completo de archivos `.msg` de Outlook con `extract-msg`
- [ ] Exportar el análisis como PDF

### v0.3.0
- [ ] Consulta de reputación de IP contra listas negras (Spamhaus, SORBS)
- [ ] Historial de análisis guardado en base de datos (SQLite)
- [ ] Modo oscuro / claro

### v1.0.0
- [ ] Autenticación de usuarios
- [ ] API pública documentada
- [ ] Despliegue con Docker

---

## Licencia

MIT © [astrosinfinitos](https://github.com/astrosinfinitos)
