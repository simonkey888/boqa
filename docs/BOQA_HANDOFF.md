# BOQA — Handoff operativo vivo

LAST_VERIFIED_DATE=2026-07-21  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `REMOTE_MAIN_HEAD=f33015c55fe84508377528c2ff718f9c5b28efe7`
- `LAST_MATERIAL_MAIN_SHA=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c`
- `MAIN_HEAD_POLICY=VERIFY_REMOTE_ON_READ`
- `LAST_MERGED_PR=PR #27`
- `PRODUCTION_SHA=INDETERMINADO`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`
- `ROLLBACK_EXECUTED=false`

`REMOTE_MAIN_HEAD` debe verificarse nuevamente antes de cualquier acción. `LAST_MATERIAL_MAIN_SHA` identifica el último commit de `main` que cambió código o workflows ya integrados; PR #27 fue exclusivamente documental.

## Producto integrado en main

- Frontera privada oculta en el Worker público.
- API pública del Worker limitada a contratos explícitos.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Cloudflare Preview V6 crea una versión exacta sin tráfico.
- El gate clasifica el candidato como `PROMOTION_READY` o `BLOCKED_BACKEND_CONTRACT`.
- Una clasificación exitosa con `promotion_ready=false` no autoriza deploy.

## PR #25 — backend preflight reconstruido

- `PR=25`
- `STATUS=OPEN_DRAFT`
- `BRANCH=deploy/boqa-backend-preflight-v2`
- `BASE_SHA=f33015c55fe84508377528c2ff718f9c5b28efe7`
- `HEAD_SHA=335a76afc303b7411737a729bdff2a761ce67d39`
- `COMMIT_COUNT=1`
- `CHANGED_FILES=2`
- `MERGEABLE=true`
- `OVERALL_STATUS=BLOCKED_BY_EXTERNAL_ACCESS`

La rama fue reconstruida atómicamente desde el `main` actual. El diff contiene únicamente:

- `.github/workflows/boqa-backend-ssh-preflight-v2.yml`
- `.github/workflows/boqa-backend-oci-api-preflight-v2.yml`

No se modificaron aplicación, dashboard, Worker, backend, almacenamiento ni workflows de despliegue.

### Gates de producto sobre el HEAD exacto

- Browser Smoke run `29800920838`: SUCCESS.
- Browser artifact `8483715389`; digest `sha256:5f75e5ef86efccb65ed49e0b077930bb4eae1e93efc22a79ed15de9cfe4c2897`.
- Real Docker Qualification run `29800920828`: SUCCESS.
- Docker artifact `8483724710`; digest `sha256:2d3cd118451acb4ae02748002f17e1a7a6ae9a4b69c3aaad22629a04fbe954ab`.
- Cloudflare Preview V6 run `29800920819`: SUCCESS.
- Preview artifact `8483741556`; digest `sha256:31e63c437f154aa4cb494165fa8c587683206c6cfffbf0ca297b4cfeb9c9ef22`.
- Preview artifact checksums: `16/16` válidos.

### Preview exacta

- `BUILD_UUID=92b42f46-badc-4654-9324-adb148089087`
- `VERSION_ID=c7d8d599-b809-4c0b-95ff-c95f759e41a4`
- `VERSION_NUMBER=74`
- `CLASSIFICATION=BLOCKED_BACKEND_CONTRACT`
- `BLOCKER=BACKEND_HUNTER_CONTRACT_MISSING`
- `PROMOTION_READY=false`

Validación browser de preview:

- Desktop 1440: PASS.
- Mobile 390: PASS.
- Mobile 360: PASS.
- Estado general: `DEGRADED`.
- Hunter: `UNAVAILABLE`.
- Health: `FRESH`, `ok`.
- Page errors: 0.
- Errores críticos inesperados de consola: 0.
- Requests fallidos inesperados: 0.
- Overflow horizontal: 0.
- Rutas privadas y operativas no utilizadas ocultas: PASS.

### SSH runtime preflight

- Run `29800920821`: FAILURE_AT_INPUT_GATE.
- Artifact `8483703913`; digest `sha256:bf4380f65665307f960121b5e32f129677c225e37a5446acf633cd82f8cad9d9`.
- Faltan las categorías: host backend y material SSH aceptado.
- Preparación del cliente, autenticación e inspección remota: SKIPPED.
- `production_changed=false`
- `deploy_performed=false`
- `restart_performed=false`

### OCI API control-plane preflight

- Run `29800920787`: FAILURE_AT_INPUT_GATE.
- Artifact `8483703227`; digest `sha256:3347cf96e10e7c403cb39ba31a24af9c6f400581ec44ee22edcf52626a40ef84`.
- Faltan las categorías: identidad de tenancy, identidad de usuario, fingerprint, material de firma, región, compartimento y resolución de instancia propia.
- Instalación/configuración OCI, consulta de identidad, resolución de instancia y consulta de Instance Agent: SKIPPED.
- `production_changed=false`
- `deploy_performed=false`
- `command_executed=false`

No se reintentó ninguno de los preflights fallidos.

## Producción preservada

Los snapshots Cloudflare antes y después de Preview V6 fueron idénticos:

- `ACTIVE_DEPLOYMENT_ID=71016a2b-edc4-4786-8bf4-b56749507554`
- `ACTIVE_VERSION_ID=136e5689-91d3-4431-8af0-d8b3248c6e3c`
- `ACTIVE_TRAFFIC=100%`

Estos IDs corresponden a la última evidencia auditada de Preview V6. Deben revalidarse en Cloudflare antes de cualquier promoción.

## Bloqueos actuales

- No existe una ruta autorizada y completa de acceso al backend desde GitHub Actions.
- El backend activo no ofrece `/api/hunter/status`.
- La preview exacta informa `promotion_ready=false`.
- `BOQA_RELEASE_SHA` productivo continúa indeterminado.
- Backend, persistencia y rollback no pueden validarse integralmente sin una ruta de acceso.

## Decisión operativa

- PR #25 permanece Draft.
- No mergear PR #25 todavía.
- No desplegar backend ni promover Worker.
- La ruta preferida para el próximo intento es OCI API control-plane.
- Los valores sensibles deben configurarse únicamente en GitHub Actions; nunca copiarlos al chat, PR, logs, dashboard, artifacts o handoffs.
- Después de completar una sola ruta, ejecutar únicamente su preflight. Detener ante el primer fallo y no reintentar automáticamente.

## Reglas permanentes

- No validar infraestructura de terceros.
- No ampliar scope automáticamente.
- No trabajar directamente sobre `main`.
- No imprimir valores sensibles.
- No inventar estado hunter desde health genérico.
- No confundir CI verde con candidato promocionable o producción activa.
- No declarar deploy sin versión, deployment, tráfico, contratos, browser smoke, backend, almacenamiento y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Estado de esta actualización documental

- `HANDOFF_BRANCH=docs/boqa-handoff-pr25-reconstructed`
- La rama parte exactamente de `main=f33015c55fe84508377528c2ff718f9c5b28efe7`.
- No se abrió PR documental para evitar disparar gates y una nueva preview sin autorización específica.

## Siguiente acción exacta

Simón configura en GitHub Actions las categorías completas de la ruta OCI API autorizada y avisa `OCI listo`. Reejecutar únicamente el preflight OCI de PR #25; no mergear ni desplegar.