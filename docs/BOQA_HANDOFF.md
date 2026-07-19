# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T14:49:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=9570a9fdfb577c92c172f520cf2489d54fc4956b`
- `LAST_MERGED_PR=PR #22`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por PR #22 ni PR #23.

## Frontera pública integrada

El Worker público oculta la superficie privada antes del proxy y de los assets. La API pública queda limitada a `GET /api/health` y `GET /api/hunter/status`; cualquier otra API responde `404` genérico y no llega al backend.

## PR #23 — mobile clarity v2

- `BRANCH=fix/boqa-mobile-clarity-v2`
- `BASE_SHA=9570a9fdfb577c92c172f520cf2489d54fc4956b`
- `VALIDATED_CODE_SHA=b9fde58a2cd0d2da18601476ef38364aaa5538cc`
- `STATE=OPEN_DRAFT`
- Este archivo es un descendiente documental del SHA validado; verificar el HEAD remoto antes del merge.

Cambios validados:

1. códigos internos traducidos a textos legibles;
2. timestamps compactos y deterministas en formato `es-AR`, con valor ISO accesible;
3. SHA visible abreviado, con valor completo en metadata accesible;
4. fuentes y paneles secundarios compactados en dos columnas para 360/390 px;
5. fallback de una columna para pantallas menores a 340 px;
6. copy de estados no disponibles simplificado sin inventar datos.

### Evidencia

- `BROWSER_RUN=29697489537` — SUCCESS
- `BROWSER_ARTIFACT_ID=8445437653`
- `BROWSER_DIGEST=sha256:2b5e266c2bea4c86300e7aefe8b39af726c088d8b0f0fbadc1e1cc0a2f0182ae`
- `DOCKER_RUN=29697489554` — SUCCESS
- `DOCKER_ARTIFACT_ID=8445444723`
- `DOCKER_DIGEST=sha256:aa053fefe767869d7c0063c401d9ce36da174d1a198a54640a9368f8f6068b51`

Browser smoke sobre el SHA validado:

- desktop 1440: PASS;
- mobile 390: PASS;
- mobile 360: PASS;
- texto humano y SHA accesible: PASS;
- compactación mobile: PASS;
- overflow horizontal: 0;
- errores de página: 0;
- errores críticos de consola: 0;
- rutas privadas y operativas ocultas: PASS;
- deploy realizado: false.

Docker qualification sobre el mismo SHA:

- instalación, sintaxis y suite completa: PASS;
- integridad del diff: PASS;
- identidad y arranque de imagen: PASS;
- ejecución aislada final: PASS.

## Cloudflare y backend

- Workers Builds permanece preview-only, sin trigger productivo.
- PR #20 debe reconstruirse sobre el `main` posterior a PR #23.
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

1. Exigir Browser Smoke y Docker Qualification verdes sobre este commit documental.
2. Verificar HEAD y mergeabilidad de PR #23.
3. Integrar PR #23 sólo con SHA esperado.
4. Reconstruir la preview Cloudflare y el preflight backend sobre el nuevo `main`.
5. Promover sólo la versión exacta validada y verificar producción más rollback.
