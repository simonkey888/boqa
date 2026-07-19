# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T15:20:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `LAST_MERGED_PR=PR #23`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por los builds preview.

## Producto integrado

- Frontera privada oculta en el Worker público.
- API pública limitada a `GET /api/health` y `GET /api/hunter/status`.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.

## PR #24 — Cloudflare preview v5

- `BRANCH=deploy/boqa-cloudflare-preview-v5`
- `BASE_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `STATUS=IN_PROGRESS`
- Workers Builds: preview-only.
- Trigger productivo: 0.
- Cada build está fijado a rama y SHA exactos mediante Builds API.
- Deployment activo antes/después: idéntico en todos los intentos.

### Evidencia acumulada

- Run `29697877432`: build exacto SUCCESS; smoke bloqueado por disponibilidad/validador inicial.
- Run `29698121180`: build exacto SUCCESS; smoke no iniciado por regex demasiado restrictiva para el hostname versionado.
- Run `29698272514`: build exacto SUCCESS; preview ready en el primer intento; `/api/health` 200; `/api/hunter/status` 404 desde el backend productivo legacy.
- Última versión del tercer intento: `36fed9c6-544f-4dc3-a3cd-38ba91f5f3ee`.
- Preview del tercer intento: `https://36fed9c6-boqa.simondalmasso44.workers.dev`.
- Deployment productivo conservado: `71016a2b-edc4-4786-8bf4-b56749507554`, 100% en la versión histórica `136e5689-91d3-4431-8af0-d8b3248c6e3c`.
- Producción cambiada: false.

### Compatibilidad backend legacy

El backend productivo activo responde `GET /api/health` pero todavía no registra `GET /api/hunter/status`. El Worker implementa una compatibilidad interna y acotada:

1. intenta el contrato moderno `/api/hunter/status`;
2. sólo ante 404 consulta internamente `/api/defensive/status` con autenticación y firma recalculadas;
3. valida `state` y `timestamp`;
4. recorta la respuesta al contrato mínimo del hunter;
5. elimina cualquier campo adicional, incluido inventario o evidencia;
6. devuelve 502/503 si el payload legacy no cumple.

La ruta `/api/defensive/status` continúa respondiendo 404 en el borde público y nunca aparece en el frontend.

## Arquitectura de entrega decidida

1. GitHub conserva código, PR, tests, Docker y browser smoke.
2. Cloudflare Workers Builds ejecuta un build API fijado al commit exacto.
3. `wrangler versions upload` crea una versión sin promover tráfico.
4. La preview versionada se valida en desktop, mobile, APIs y rutas ocultas.
5. La promoción final reutiliza la versión exacta validada; no recompila.
6. Rollback conserva la versión productiva anterior y se verifica antes de promover.

## Backend

- PR #25 es el único preflight backend vigente.
- PR #19 fue cerrado como supersedido.
- El deploy backend continúa bloqueado por falta de acceso remoto efectivo.
- Cloudflare no sustituye el runtime que ejecuta Node, Playwright y Docker.

## Reglas permanentes

- No validar infraestructura de terceros.
- No trabajar directamente sobre `main`.
- No exponer información privada u operativa innecesaria.
- No imprimir valores sensibles.
- No confundir CI, preview, versión subida, deployment y producción activa.
- No declarar producción actualizada sin versión, deployment, tráfico, health, browser smoke y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Siguiente acción exacta

Ejecutar Browser, Docker y Cloudflare Exact Preview sobre este head, exigir que la compatibilidad legacy entregue el contrato mínimo y que el deployment permanezca idéntico; luego registrar evidencia final antes del merge.
