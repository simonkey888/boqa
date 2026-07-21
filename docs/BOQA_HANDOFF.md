# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-21T00:47:04-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c`
- `LAST_MERGED_PR=PR #26`
- `MERGE_METHOD=SQUASH`
- `MERGED_PR_HEAD=969ebdd3cc87e56d8407694c18dbd5a3df870e3d`
- `PRODUCTION_SHA=INDETERMINADO`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`
- `ROLLBACK_EXECUTED=false`

PR #26 fue integrado con protección sobre el HEAD exacto autorizado. El merge incorporó únicamente el mecanismo Cloudflare exact-preview y su clasificación fail-closed. No se promovió ninguna versión, no se modificó tráfico y no se desplegó backend.

## Producto integrado en main

- Frontera privada oculta en el Worker público.
- API pública limitada a `GET /api/health` y `GET /api/hunter/status`.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Workflow Cloudflare Preview V6 integrado con trigger exclusivo de `pull_request` hacia `main`.
- La preview crea una versión exacta sin tráfico y clasifica el candidato como `PROMOTION_READY` o `BLOCKED_BACKEND_CONTRACT`.
- Una clasificación exitosa con `promotion_ready=false` no autoriza deploy.

## PR #26 — resultado final

- `PR=26`
- `STATUS=MERGED`
- `FINAL_HEAD=969ebdd3cc87e56d8407694c18dbd5a3df870e3d`
- `MERGE_SHA=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c`
- `MERGED_AT=2026-07-21T03:44:27Z`

### Gates finales sobre el HEAD exacto

- Browser Smoke run `29798821600`: SUCCESS.
- Browser artifact `8482995057`; digest `sha256:eecb50a990274fb36e8db0469d31fea09e608f53b7def0d3f37e1d2265ee9bfa`.
- Real Docker Qualification run `29798821604`: SUCCESS.
- Docker artifact `8483005997`; digest `sha256:70dd4fbde05a7ef463e32c46f9c209d48e8a5878181fccdac4ecdc076e64a99e`.
- Cloudflare Preview V6 run `29798821613`: SUCCESS.
- Preview artifact `8483018787`; digest `sha256:9d54a830e1c1f6799e35af2cdb8af643fa857240284fbe23295cd71120f56d41`.
- Preview artifact checksums: `16/16` válidos.

### Preview exacta validada

- `BUILD_UUID=263e1f0c-da71-4175-8a7d-e8b5fe57846c`
- `VERSION_ID=4177d937-f2d0-4a5b-9e69-9bad46a95279`
- `VERSION_NUMBER=71`
- `PREVIEW_URL=https://4177d937-boqa.simondalmasso44.workers.dev`
- `CLASSIFICATION=BLOCKED_BACKEND_CONTRACT`
- `BLOCKER=BACKEND_HUNTER_CONTRACT_MISSING`
- `PROMOTION_READY=false`

### Contratos y browser smoke

- Worker `/health`: 200, `status=ok`, backend configurado.
- Backend `/api/health`: 200, `status=ok`, versión `1.4.0`.
- Backend `/api/hunter/status`: 404 HTML; contrato hunter ausente.
- Dashboard: `DEGRADED` veraz; hunter `UNAVAILABLE`; health `FRESH` y `ok`.
- Motivo visible observado: `Respuesta JSON inválida`.
- Desktop 1440: PASS.
- Mobile 390: PASS.
- Mobile 360: PASS.
- Page errors: 0.
- Errores críticos inesperados de consola: 0.
- Requests fallidos inesperados: 0.
- Overflow horizontal: 0.
- Rutas privadas y operativas ocultas: PASS.
- Capturas inspeccionadas: PASS.

### Producción preservada

Los snapshots productivos antes y después de la preview fueron idénticos:

- `ACTIVE_DEPLOYMENT_ID=71016a2b-edc4-4786-8bf4-b56749507554`
- `ACTIVE_VERSION_ID=136e5689-91d3-4431-8af0-d8b3248c6e3c`
- `ACTIVE_TRAFFIC=100%`

Estos IDs fueron revalidados por la evidencia de Preview V6 previa al merge. El merge Git no realizó una operación Cloudflare ni backend. No existe un run asociado al commit de merge dentro de los runs consultables por commit.

## Backend preflight

- `PR=25`
- `BRANCH=deploy/boqa-backend-preflight-v2`
- `HEAD=3925e8784f68c3a0084be161804b39a934512c1c`
- `STATUS=BLOCKED_BY_EXTERNAL_ACCESS`
- El PR quedó basado en el `main` anterior y actualmente no es mergeable.
- SSH: faltan host remoto y clave bajo los nombres aceptados.
- OCI API: faltan identidad, firma, región, compartimento y resolución de instancia.
- Browser y Docker del preflight: SUCCESS.
- No hubo conexión remota, deploy, restart ni modificación productiva.

## Arquitectura de entrega vigente

1. GitHub conserva código, PR, tests, Docker y browser smoke.
2. Cloudflare Workers Builds crea una versión exacta sin tráfico.
3. El gate clasifica compatibilidad y promotion readiness.
4. Sólo una versión con `promotion_ready=true` puede promoverse.
5. La promoción debe reutilizar la versión validada; no recompilar.
6. Backend y Worker se validan y despliegan como componentes separados.
7. Rollback conserva y verifica la versión productiva anterior.

## Riesgos abiertos

- Backend productivo inaccesible desde GitHub Actions por falta de ruta SSH u OCI API.
- `/api/hunter/status` no existe en el backend productivo activo.
- `BOQA_RELEASE_SHA` productivo continúa indeterminado.
- PR #25 necesita reconstruirse o rebasarse sobre `main=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c` antes de cualquier integración.
- La versión preview `4177d937-f2d0-4a5b-9e69-9bad46a95279` no es promocionable mientras falte el contrato backend.

## Reglas permanentes

- No validar infraestructura de terceros.
- No trabajar directamente sobre `main`.
- No exponer información privada u operativa innecesaria.
- No imprimir valores sensibles.
- No inventar estado hunter desde health genérico.
- No confundir gate exitoso con candidato promocionable.
- No declarar producción actualizada sin versión, deployment, tráfico, health, browser smoke y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Estado de esta actualización documental

- `HANDOFF_BRANCH=docs/boqa-handoff-post-pr26`
- Esta rama parte exactamente de `main=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c`.
- No se abrió PR automáticamente para evitar disparar Browser, Docker y otra preview Cloudflare sólo por un cambio documental.
- `main` todavía contiene el handoff pre-merge hasta que esta actualización documental sea integrada mediante un PR separado y autorizado.

## Siguiente acción exacta

Abrir un PR documental desde `docs/boqa-handoff-post-pr26` hacia `main`, revisar que el diff contenga únicamente `docs/BOQA_HANDOFF.md` y decidir si se permite omitir o aceptar los gates automáticos que se dispararán. No desplegar.
