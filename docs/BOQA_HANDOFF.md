# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T14:35:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=ede06de817d607e6717f6ea71f2e40aac68ea7a2`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada durante PR #22.

## PR #22 — hardening del borde público

- `BRANCH=fix/boqa-public-private-boundary-v2`
- `BASE_SHA=ede06de817d607e6717f6ea71f2e40aac68ea7a2`
- `VALIDATED_CODE_SHA=a6cbe7fb44133a1340fc976fd257f1229c0bd699`
- Este documento es un descendiente documental del SHA validado; verificar el HEAD remoto antes del merge.

El Worker público oculta la superficie privada antes del proxy y de los assets. Páginas, archivos y rutas privadas responden `404` genérico con política de no almacenamiento, incluso con mayúsculas, separadores alternativos y codificación múltiple.

La superficie API pública queda limitada a:

- `GET /api/health`
- `GET /api/hunter/status`

Cualquier otra API responde `404` genérico y no llega al backend.

## Evidencia

- `BROWSER_RUN=29697008338` — SUCCESS
- `BROWSER_ARTIFACT_ID=8445303463`
- `BROWSER_DIGEST=sha256:187d4ca4724344270714cbee90d11bb15d705066a0ba100347073d3423fa8472`
- `DOCKER_RUN=29697008393` — SUCCESS
- `DOCKER_ARTIFACT_ID=8445311730`
- `DOCKER_DIGEST=sha256:457d9431d93115e2bc713db4bcf2d442945b6230bc7bf80d995c567c6f394dfe`

Browser smoke sobre el SHA validado:

- desktop 1440: PASS;
- mobile 390: PASS;
- mobile 360: PASS;
- estado FRESH;
- overflow horizontal: 0;
- errores de página: 0;
- errores críticos de consola: 0;
- rutas ocultas: 404 opaco;
- deploy realizado: false.

Docker qualification sobre el mismo SHA:

- instalación y sintaxis: PASS;
- suite completa: PASS;
- integridad del diff: PASS;
- identidad y arranque de imagen: PASS;
- ejecución aislada final: PASS.

## Revisión mobile

La interfaz es funcional y legible en 390 y 360 px. El pulido se hará en una rama separada para no mezclar UI con seguridad:

1. traducir códigos internos a texto humano;
2. abreviar el SHA visible conservando el valor completo de forma accesible;
3. reducir densidad vertical sin modificar contratos.

## Cloudflare y backend

- La configuración actual de Workers Builds es preview-only y no posee trigger productivo.
- PR #20 debe reconstruirse sobre el `main` final.
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

1. Exigir los dos gates verdes sobre este commit documental.
2. Verificar HEAD y mergeabilidad de PR #22.
3. Integrar PR #22 sólo con SHA esperado.
4. Ejecutar el pulido mobile en una rama separada y validarlo.
5. Reconstruir preview y preflight sobre el `main` final.
6. Promover sólo la versión exacta validada y verificar producción más rollback.
