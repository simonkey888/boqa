# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-21T00:31:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `LAST_MERGED_PR=PR #23`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por los flujos de preview ni preflight.

## Producto integrado en main

- Frontera privada oculta en el Worker público.
- API pública limitada a `GET /api/health` y `GET /api/hunter/status`.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Browser y Docker finales sobre `main`: PASS.

## Flujo activo — PR #26 Cloudflare preview v6

- `PR=26`
- `BRANCH=deploy/boqa-cloudflare-preview-v6`
- `BASE_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `VALIDATED_CODE_SHA=964784161ca06f591b6b4f9cff52f80f30969535`
- `LAST_CODE_FIX_SHA=bc3b34f9486362ace3bc47c11f910b5c289abeea`
- `CLASSIFICATION=BLOCKED_BACKEND_CONTRACT`
- `BLOCKER=BACKEND_HUNTER_CONTRACT_MISSING`
- `PROMOTION_READY=false`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`
- `ROLLBACK_EXECUTED=false`

Este archivo es un descendiente exclusivamente documental del SHA de código validado. Antes de integrar, verificar el HEAD remoto final y exigir los tres gates verdes sobre ese mismo HEAD; registrar esa identidad final en el body del PR.

### Gates sobre el SHA de código validado

- Browser Smoke run `29798562033`: SUCCESS.
- Browser artifact `8482903600`; digest `sha256:67dc65af3d968f09d4d0a60fd6e8189bb3bf0b8ab9cd2be139ed21f36881400c`.
- Real Docker Qualification run `29798562034`: SUCCESS.
- Docker artifact `8482917456`; digest `sha256:02349f34457d7815625a14241e9a1bc100989b7ac8fccf954053201a9b755ff0`.
- Cloudflare Preview V6 run `29798562036`: SUCCESS.
- Preview artifact `8482929433`; digest `sha256:a587b3ff50f0acae752c01e2d9c9a452f29c12dcc96e5431989078887cbd4427`.
- Preview artifact checksums: `16/16` válidos.

### Preview exacta auditada

- `BUILD_UUID=91e85df3-d30a-4ce8-ac64-5c6b4638d67f`
- `VERSION_ID=c14f70e3-d667-4f3c-9734-26b8689c81a9`
- `VERSION_NUMBER=70`
- `PREVIEW_URL=https://c14f70e3-boqa.simondalmasso44.workers.dev`
- `HEAD_SHA=964784161ca06f591b6b4f9cff52f80f30969535`

El deployment productivo fue idéntico antes y después:

- `ACTIVE_DEPLOYMENT_ID=71016a2b-edc4-4786-8bf4-b56749507554`
- `ACTIVE_VERSION_ID=136e5689-91d3-4431-8af0-d8b3248c6e3c`
- `ACTIVE_TRAFFIC=100%`

Estos IDs fueron revalidados mediante la evidencia de Preview V6. No se promovió la versión candidata.

### Contratos y browser smoke de preview

- Worker `/health`: 200, `status=ok`, backend configurado.
- Backend `/api/health`: 200, `status=ok`, versión `1.4.0`.
- Backend `/api/hunter/status`: 404 HTML.
- Dashboard: `DEGRADED` veraz; hunter `UNAVAILABLE`; health `FRESH` y `ok`.
- Motivo observado del hunter: `Respuesta JSON inválida`.
- Desktop 1440: PASS.
- Mobile 390: PASS.
- Mobile 360: PASS.
- Page errors: 0.
- Errores críticos inesperados de consola: 0.
- Requests fallidos inesperados: 0.
- Overflow horizontal: 0.
- Rutas privadas y operativas ocultas: PASS.
- Capturas inspeccionadas visualmente: PASS.

### Diagnóstico y corrección

El run anterior clasificó correctamente el backend como `BLOCKED_BACKEND_CONTRACT`, pero el smoke exigía sólo `Respuesta HTTP 404` mientras el transporte del dashboard representaba el 404 HTML como `Respuesta JSON inválida`.

La corrección conserva la clasificación directa del endpoint como 404 y acepta únicamente esas dos representaciones veraces del mismo bloqueo. El motivo observado se registra por viewport. No se modificó el dashboard, el Worker productivo, el backend ni el tráfico.

## Backend preflight

- `PR=25`
- `STATUS=BLOCKED_BY_EXTERNAL_ACCESS`
- SSH: faltan host remoto y clave bajo los nombres aceptados.
- OCI API: faltan identidad, firma, región, compartimento y resolución de instancia.
- Browser y Docker del preflight: SUCCESS.
- No hubo conexión remota, deploy, restart ni modificación productiva.

## Arquitectura de entrega decidida

1. GitHub conserva código, PR, tests, Docker y browser smoke.
2. Cloudflare Workers Builds crea una versión exacta sin tráfico.
3. El gate clasifica compatibilidad y promotion readiness.
4. Sólo una versión con `promotion_ready=true` puede promoverse.
5. La promoción reutiliza la versión validada; no recompila.
6. Rollback conserva y verifica la versión productiva anterior.

## Reglas permanentes

- No validar infraestructura de terceros.
- No trabajar directamente sobre `main`.
- No exponer información privada u operativa innecesaria.
- No imprimir valores sensibles.
- No inventar estado hunter desde health genérico.
- No confundir gate exitoso con candidato promocionable.
- No declarar producción actualizada sin versión, deployment, tráfico, health, browser smoke y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Siguiente acción exacta

Verificar los tres gates sobre el HEAD documental final de PR #26. Si quedan verdes y el diff respecto de `964784161ca06f591b6b4f9cff52f80f30969535` contiene únicamente este handoff, actualizar el body del PR y Drive. No mergear ni desplegar sin autorización explícita nueva.
