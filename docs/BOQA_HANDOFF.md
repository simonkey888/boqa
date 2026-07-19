# BOQA — handoff operativo vivo

Última verificación: 2026-07-19, America/Argentina/Cordoba.

Este archivo acompaña al handoff canónico de Google Drive. Debe actualizarse después de cada deploy, rollback, incidente productivo, cambio material de arquitectura o pausa operativa.

## Fuentes de verdad

1. Producción verificada.
2. Cloudflare Worker y backend activos.
3. `main` remoto.
4. GitHub Actions y artifacts.
5. Código.
6. Este archivo y el Google Doc.

## Estado Git

- Repositorio: `simonkey888/boqa`.
- `main`: `ede06de817d607e6717f6ea71f2e40aac68ea7a2`.
- Último PR de producto mergeado: #15.
- Head fuente de PR #15: `18464a97b35917562a6b465f83258c9daa69d9c7`.
- PR #20: preview Cloudflare backend-aware, Draft.
- PR #19: preflight backend OCI, Draft.

## Cloudflare Worker

- Producción: `https://boqa.simondalmasso44.workers.dev/`.
- Preview: `https://boqa-next-boqa.simondalmasso44.workers.dev/`.
- Versión productiva registrada antes de promoción: `136e5689-91d3-4431-8af0-d8b3248c6e3c`.
- Deployment productivo registrado: `71016a2b-edc4-4786-8bf4-b56749507554`.
- Tráfico registrado: 100% sobre la versión anterior.
- Versión preview subida desde `main`: `35cb7522-829e-4013-80c4-cba6b59170a4`.
- La subida preview no modificó deployments ni tráfico productivo.

### Evidencia preview

- Run: `29693106813`.
- Artifact: `8444548858`.
- Digest: `sha256:cf688d539043cd70935b3c75b7eff6fd1c058c36b8d83452d445500ea59c0348`.
- Cloudflare auth: PASS.
- Secretos Worker requeridos verificados por nombre: `BOQA_API_KEY`, `BOQA_HMAC_SECRET`.
- Suite y dry-run: PASS.
- Upload de versión: PASS.
- Producción sin cambios: PASS.
- Desktop 1440, mobile 390 y 360: HTTP 200, overflow 0, pageerror 0.
- Bloqueo: backend productivo legacy no expone `/api/hunter/status`; preview muestra `DEGRADED` y `N/D` de forma honesta.

## Backend OCI

- Endpoint configurado actualmente en Worker: `http://136.248.117.15.nip.io`.
- Persistencia esperada: `/var/lib/boqa/output`.
- PR #19 agregó un preflight de sólo lectura.
- Run: `29694795017`.
- Artifact: `8444654274`.
- Digest: `sha256:4a4edb3095e6a39bef43a4c6a34abd220bce14b5196ec47ca16823e7bfcbff92`.
- Resultado: BLOCKED antes de conectar al host.
- Producción modificada: no.

### Acceso faltante

Configurar en GitHub Actions un conjunto completo, sin publicar valores:

- `BOQA_BACKEND_HOST`, `BOQA_BACKEND_USER`, `BOQA_BACKEND_SSH_KEY`; o
- `OCI_HOST`, `OCI_USER`, `OCI_SSH_PRIVATE_KEY`; o
- `SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY`.

Puerto opcional: `BOQA_BACKEND_SSH_PORT` o `OCI_SSH_PORT`; por defecto 22.

## Decisión de despliegue

- Adoptar Cloudflare-first mediante Workers Builds para el pipeline canónico del Worker.
- GitHub continúa como fuente de código.
- Las ramas no productivas usan `wrangler versions upload`.
- La promoción a tráfico es una operación separada y controlada.
- No usar edición manual de código en el dashboard como flujo normal.
- No promover el Worker nuevo contra el backend legacy.
- Rollback del Worker por version ID.
- Backend: despliegue side-by-side, health y hunter antes del cutover; preservar output y contenedor anterior.

## Restricciones

- Sólo activos propios o documentadamente autorizados.
- Sin pruebas sobre terceros.
- Sin valores secretos en código, logs o documentación.
- `BOQA_RELEASE_SHA` debe coincidir con el SHA realmente desplegado.
- Hunter fail-closed sin policy autorizada.
- No declarar deploy cerrado sin health, APIs, desktop/mobile, `/cobros`, version/deployment IDs y rollback state.

## Siguiente acción exacta

1. Completar los secretos SSH/OCI de GitHub Actions.
2. Reejecutar el preflight de PR #19.
3. Exigir Docker operativo, un único contenedor publicando puerto 80, persistencia existente y health 200.
4. Construir y desplegar backend candidate desde `ede06de817d607e6717f6ea71f2e40aac68ea7a2` con rollback verificable.
5. Revalidar la versión preview contra el backend compatible: `FRESH`, hunter `ACTIVE`, health `ok`, `/cobros`, 0 pageerror y 0 overflow.
6. Promover exactamente la versión validada al 100%, ejecutar smoke productivo y actualizar este archivo y Google Drive.
