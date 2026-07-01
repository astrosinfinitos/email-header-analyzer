# Email Header Analyzer

Analiza cabeceras de correo electrónico y detecta spoofing, fallos de autenticación, rutas sospechosas, reputación de IPs y URLs potencialmente peligrosas. Ofrece un veredicto visual inmediato con desglose de SPF, DKIM, DMARC, hops, reputación y reporte de seguridad.

**Versión actual:** `v0.0.1`

---

## Funcionalidades

- Veredicto de seguridad automático: `LEGÍTIMO` / `SOSPECHOSO` / `PELIGROSO`
- Semáforo visual de autenticación: SPF, DKIM, DMARC
- Timeline de ruta de entrega con detección de servidores desconocidos e IPs privadas
- Puntuación de spam con barra de progreso
- Consulta de reputación de IPs con AbuseIPDB y VirusTotal
- Extracción y análisis básico de URLs encontradas en el cuerpo del correo
- Generación de reporte de seguridad
- Soporte de archivos `.eml`, `.msg`, `.txt`, `.mht` con drag & drop
- Cabecera raw colapsable para análisis manual
- Documentación Swagger disponible en desarrollo y deshabilitada en producción

---

## Stack

| Capa | Tecnología |
|---|---|
| Backend | Python 3.12+ · FastAPI · Uvicorn |
| Parser | Módulo `email` de la stdlib de Python |
| Reputación | AbuseIPDB · VirusTotal |
| Frontend | HTML · CSS · JavaScript vanilla |
| Despliegue | Render |

---

## Estructura del proyecto

```text
email-header-analyzer/
├── backend/
│   ├── main.py              # API FastAPI — endpoints /analyze y /report
│   ├── parser.py            # Parseo de cabeceras, cuerpo y URLs
│   ├── reputation.py        # Reputación de IPs con AbuseIPDB y VirusTotal
│   ├── report.py            # Generación de reporte de seguridad
│   ├── url_analyzer.py      # Análisis de URLs y consulta a VirusTotal
│   └── requirements.txt     # Dependencias Python
├── frontend/
│   ├── index.html           # Interfaz web
│   ├── css/
│   │   └── styles.css       # Estilos de la interfaz
│   └── js/
│       ├── api.js           # Comunicación con el backend
│       ├── main.js          # Lógica principal de la UI
│       ├── render.js        # Renderizado de resultados
│       └── upload.js        # Drag & drop y carga de archivos
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

El servidor arranca en:

```text
http://localhost:8000
```

En desarrollo, la documentación interactiva está disponible en:

```text
http://localhost:8000/docs
```

### Variables de entorno del backend

Para activar las consultas de reputación:

```text
ABUSEIPDB_KEY=<tu_api_key>
VIRUSTOTAL_KEY=<tu_api_key>
```

Para producción:

```text
ENV=production
```

Cuando `ENV=production`, FastAPI deshabilita:

```text
/docs
/redoc
/openapi.json
```

### Frontend

Abre `frontend/index.html` directamente en el navegador, o sirve el proyecto con:

```bash
python -m http.server 5500
```

Y abre:

```text
http://localhost:5500/frontend/index.html
```

---

## Despliegue en producción

El proyecto está desplegado en Render con dos servicios separados:

| Servicio | Tipo | URL |
|---|---|---|
| Frontend | Static Site | `https://email-header-analyzer-frontend.onrender.com/` |
| Backend | Web Service · Python 3 | `https://email-header-analyzer-j40x.onrender.com/` |

Ambos servicios despliegan desde la rama:

```text
main
```

### Backend en Render

Configuración recomendada:

```text
Root directory: backend
Build command: pip install -r requirements.txt
Start command: uvicorn main:app --host 0.0.0.0 --port $PORT
```

Variables de entorno necesarias:

```text
ABUSEIPDB_KEY=<api_key>
VIRUSTOTAL_KEY=<api_key>
ENV=production
```

### Frontend en Render

El frontend debe apuntar al backend de producción desde `frontend/js/api.js`:

```text
https://email-header-analyzer-j40x.onrender.com
```

---

## Seguridad

En producción, la documentación pública de FastAPI está deshabilitada para reducir exposición de endpoints y esquemas internos.

Comprobación esperada:

```text
GET https://email-header-analyzer-j40x.onrender.com/docs
→ 404 Not Found
```

Los endpoints funcionales siguen disponibles para el frontend:

```text
POST /analyze
POST /report
```

---

## Guía de contribución

### Ramas

| Rama | Propósito |
|---|---|
| `main` | Código estable, desplegado en producción |
| `feat/frontend-attachments` | Trabajo relacionado con análisis/visualización de adjuntos en frontend |
| `feat/backend-attachments` | Trabajo relacionado con análisis de adjuntos en backend |
| `feat/<nombre>` | Nueva funcionalidad |
| `fix/<nombre>` | Corrección de bug o hardening |
| `docs/<nombre>` | Cambios de documentación |

### Flujo de trabajo

```bash
git checkout main
git pull origin main

git checkout -b feat/nombre-de-la-feature

# Trabajar, probar y commitear
git add .
git commit -m "feat: descripción del cambio"

# Subir rama y abrir PR contra main
git push origin feat/nombre-de-la-feature
```

### Convención de commits

Seguimos [Conventional Commits](https://www.conventionalcommits.org/):

| Prefijo | Cuándo usarlo |
|---|---|
| `feat:` | Nueva funcionalidad |
| `fix:` | Corrección de bug o mejora de seguridad |
| `style:` | Cambios visuales sin lógica |
| `refactor:` | Reestructuración de código |
| `docs:` | Cambios en documentación |
| `chore:` | Configuración, dependencias o tareas auxiliares |

Ejemplos:

```text
feat: add attachment metadata analysis
fix: disable public API docs in production
docs: update Render deployment instructions
style: improve verdict card contrast
```

### Pull Requests

- Toda feature o fix debe ir en su propia rama.
- El PR debe apuntar a `main`.
- Antes de fusionar, comprobar que Render despliega desde `main`.
- Incluir una descripción breve de qué cambia y por qué.
- El título del PR debe seguir Conventional Commits.

---

## Historial de versiones

### v0.0.1

Primera versión funcional del analizador de cabeceras de correo.

- Backend FastAPI con endpoints `POST /analyze` y `POST /report`
- Parseo de cabeceras, cuerpo y URLs en correos `.eml`, `.msg`, `.txt` y `.mht`
- Veredicto de seguridad `LEGÍTIMO`, `SOSPECHOSO` o `PELIGROSO`
- Evaluación visual de SPF, DKIM y DMARC
- Timeline de ruta de entrega con detección de servidores desconocidos e IPs privadas
- Puntuación de spam con barra de progreso
- Consulta opcional de reputación de IPs con AbuseIPDB y VirusTotal
- Análisis básico de URLs con VirusTotal cuando hay API key configurada
- Generación de reporte de seguridad
- Frontend HTML, CSS y JavaScript vanilla con carga drag & drop
- Cabecera raw colapsable para análisis manual
- Configuración de producción con Swagger, Redoc y OpenAPI deshabilitados mediante `ENV=production`
- Despliegue documentado en Render para frontend y backend
- Licencia source-available de uso no comercial

---

## Roadmap

### v0.2.0

- [ ] Cálculo real de delays entre hops con alertas visuales
  ✅ Comprobador de enlaces dentro del correo
- [ ] Análisis básico de adjuntos en `.eml`
- [ ] Extracción de metadatos de adjuntos: nombre, tipo MIME, tamaño y hash SHA-256
- [ ] Detección de extensiones peligrosas y dobles extensiones
- [ ] Soporte completo de archivos `.msg` de Outlook con `extract-msg`
- [ ] Exportar el análisis como PDF

### v0.3.0

- [ ] Consulta de hashes de adjuntos en VirusTotal
- [ ] Consulta de reputación de IP contra listas negras adicionales
- [ ] Historial de análisis guardado en base de datos SQLite
- [ ] Modo oscuro / claro

### v1.0.0

- [ ] Autenticación de usuarios
- [ ] API pública documentada para entornos controlados
- [ ] Despliegue con Docker
- [ ] Separación formal de entornos: desarrollo, staging y producción

---

## Licencia

Este proyecto se publica bajo una licencia de uso no comercial.

Se permite usar, estudiar, modificar y ejecutar el software con fines personales, educativos, académicos, de investigación o evaluación interna, siempre que se mantenga el aviso de copyright y la atribución al autor original.

No se permite vender, sublicenciar, redistribuir con fines comerciales, integrar en productos o servicios comerciales, ofrecer como servicio a terceros ni utilizar este software para obtener beneficio económico directo o indirecto sin autorización previa y por escrito del titular del proyecto.

Para usos comerciales, integraciones empresariales, servicios gestionados, redistribución comercial o acuerdos de licencia específicos, contacta con el autor.

Copyright © 2026 [astrosinfinitos](https://github.com/astrosinfinitos). Todos los derechos reservados para usos comerciales.

El software se proporciona "tal cual", sin garantías de ningún tipo.
