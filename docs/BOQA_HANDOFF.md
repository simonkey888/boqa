# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T14:40:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=9570a9fdfb577c92c172f520cf2489d54fc4956b`
- `LAST_MERGED_PR=PR #22`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por PR #22.

## Frontera pública integrada

El Worker público oculta la superficie privada antes del proxy y de los assets. Páginas, archivos y rutas privadas responden `404` genérico con política de no almacenamiento, incluso con mayúsculas, separadores alternativos y codificación múltiple.

La API pública queda limitada a:

- `GET /api/health`
- `GET /api/hunter/status`

Cualquier otra API responde `404` genérico y no llega al backend.

### Evidencia final de PR #22

- `FINAL_HEAD=2b883c9981ad4b61c7db691d5f391a752ae4d61d`
- `BROWSER_RUN=29697179204` — SUCCESS
- `DOCKER_RUN=29697179195` — SUCCESS
- desktop 1440, mobile 390 y mobile 360: PASS;
- overflow horizontal: 0;
- errores de página: 0;
- errores críticos de consola: 0;
- rutas ocultas: 404 opaco;
- deploy realizado: false.

## Flujo activo — mobile clarity v2

- `BRANCH=fix/boqa-mobile-clarity-v2`
- `BASE_SHA=9570a9fdfb577c92c172f520cf2489d54fc4956b`
- `STATUS=IN_PROGRESS`

Alcance cerrado:

1. traducir códigos internos de estado y motivo a español legible;
2. abreviar el SHA visible conservando el valor completo en metadata accesible;
3. reducir densidad vertical en mobile sin alterar contratos, seguridad ni datos;
4. validar desktop 1440, mobile 390 y mobile 360.

## Cloudflare y backend

- Workers Builds permanece preview-only, sin trigger productivo.
- PR #20 debe reconstruirse sobre el `main` final posterior al pulido mobile.
- La versión exacta validada debe promoverse sin recompilar.
- PR #19 continúa bloqueado por falta de acceso remoto al host del backend.
- Cloudflare no sustituye el runtime que ejecuta Node, Playwright y Docker.

## Reglas permanentes

- No validar infraestructura de terceros.
- No trabajar directamente sobre `main`.
- No exponer información privada u operativa innecesaria en la URL pública.
- No confundir CI, preview, versión subida, deployment y producción activa.
- No declarar producción actualizada sin versión, deployment, tráfico, health, browser smoke y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Siguiente acción exacta

Implementar el alcance mobile cerrado en esta rama, abrir PR hacia `main` y exigir Browser Smoke más Docker Qualification sobre el head exacto antes de mergear.
