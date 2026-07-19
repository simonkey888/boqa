# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T14:58:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `LAST_MERGED_PR=PR #23`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por PR #22 ni PR #23.

## Producto integrado

- Frontera privada oculta en el Worker público.
- API pública limitada a `GET /api/health` y `GET /api/hunter/status`.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Browser y Docker finales de PR #23: SUCCESS.

## Flujo activo — Cloudflare preview v5

- `BRANCH=deploy/boqa-cloudflare-preview-v5`
- `BASE_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `STATUS=IN_PROGRESS`
- Workers Builds debe permanecer preview-only.
- Trigger productivo permitido: 0.
- El build de validación debe fijarse a rama y SHA exactos mediante Builds API.
- La nueva versión debe identificarse, obtener preview URL y probarse sin modificar el deployment activo.
- Deployment y distribución de tráfico antes/después deben coincidir exactamente.

## Arquitectura de entrega decidida

1. GitHub conserva código, PR, tests, Docker y browser smoke.
2. Cloudflare Workers Builds ejecuta un build API fijado al commit exacto.
3. `wrangler versions upload` crea una versión sin promover tráfico.
4. La preview versionada se valida en desktop, mobile, APIs y rutas ocultas.
5. La promoción final reutiliza la versión exacta validada; no recompila.
6. Rollback conserva la versión productiva anterior y se verifica antes de promover.

## Backend

- PR #19 histórico continúa basado en un `main` obsoleto.
- Debe reconstruirse sobre el `main` final.
- El complemento de Cloudflare no sustituye el acceso al runtime que ejecuta Node, Playwright y Docker.
- Sin acceso remoto efectivo, el deploy backend permanece bloqueado y no se puede declarar readiness productiva.

## Reglas permanentes

- No validar infraestructura de terceros.
- No trabajar directamente sobre `main`.
- No exponer información privada u operativa innecesaria.
- No imprimir valores sensibles.
- No confundir CI, preview, versión subida, deployment y producción activa.
- No declarar producción actualizada sin versión, deployment, tráfico, health, browser smoke y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Siguiente acción exacta

Agregar el workflow preview v5, abrir Draft PR contra `main`, disparar un build Cloudflare exacto para el head del PR, identificar su versión y preview URL, comprobar que producción no cambió y validar la preview completa.
