# BOQA — Handoff operativo vivo

LAST_VERIFIED_DATE=2026-07-21
TIMEZONE=America/Argentina/Cordoba

## Estado canónico

- REPOSITORY=`simonkey888/boqa`
- MAIN=`f33015c55fe84508377528c2ff718f9c5b28efe7`
- LAST_MERGED_PR=`27`
- PRODUCTION_SHA=`INDETERMINADO`
- PRODUCTION_CHANGED=`false`
- DEPLOY_PERFORMED=`false`
- RESTART_PERFORMED=`false`
- ROLLBACK_EXECUTED=`false`

## Runtime controlado integrado

El runtime local aislado de OWASP Juice Shop y su negative control están integrados en `main`. La qualification histórica confirmó 12/12 rondas, cero falsos positivos, cero falsos negativos, cero conexiones no autorizadas y cleanup completo. El laboratorio permanece sintético, interno, read-only, sin host ports, Docker socket, privilegios ni egress público.

## Backend OCI y Oracle Cloud Agent

- PR #25: `OPEN_DRAFT`, HEAD `335a76afc303b7411737a729bdff2a761ce67d39`.
- OCI API preflight `29800920787` attempt 2: SUCCESS.
- Instancia: `RUNNING`.
- PR #28: `CLOSED_NOT_MERGED`; command creado una vez, sin reintento.
- PR #29 recovery run `29831821481`: command exacto identificado; `LIFECYCLE_STATE=ACCEPTED`, `DELIVERY_STATE=EXPIRED`, output `0` bytes.
- PR #30 run `29832880538`: `BLOCKED_PLUGIN_MISSING`; Run Command no aparece entre 11 plugins observados.
- PR #31 run `29833641694`: Canonical Ubuntu 22.04, imagen reciente, Run Command ausente del catálogo y de plugins observados; `BLOCKED_PLATFORM_PLUGIN_NOT_LISTED`.
- Ninguna de estas acciones modificó producción, backend, storage ni tráfico.

El backend productivo todavía no fue inspeccionado. Persistencia, imagen activa, release SHA y rollback permanecen indeterminados.

## PR #32 — OSMH registration diagnostic

- STATUS=`OPEN_DRAFT`
- HEAD=`90843043e7e84ecd88a65cf829d14a45d203679c`
- RUN=`29835495223`
- RESULT=`FAILURE_FAIL_CLOSED`
- ARTIFACT=`8497108587`
- DIGEST=`sha256:607678a5e48172ac9526f4458362debd1bed970cfe38e40d42f1d7c3f8c41964`
- CHECKSUMS=`3/3_VALID`
- OSMH result: no clasificable; el paso falló antes de registrar respuesta sanitizada.
- No hubo reintento automático ni escritura.

## PR #33 — safe lab dashboard preview v1

- STATUS=`OPEN_DRAFT`
- BASE=`main`
- BASE_SHA=`f33015c55fe84508377528c2ff718f9c5b28efe7`
- HEAD_BRANCH=`deploy/boqa-safe-lab-dashboard-preview-v1`
- HEAD_SHA=`3db1220f65ff089444ae781833356295f72bba9f`
- CHANGED_FILES=`1`
- APPLICATION_CODE_CHANGED=`false`

### Gates exactos

- Browser Smoke run `29854047640`: SUCCESS.
- Browser artifact `8504555821`.
- Browser digest `sha256:a7a0b760a3d7fce02fcff2b5c2da9648609f3a8e1126236c60a6eb1cd74f14cc`.
- Real Docker Qualification run `29854048094`: SUCCESS.
- Docker artifact `8504582965`.
- Docker digest `sha256:af395d7d678fdf8ac471a93a14d520fd8aa6872b72e2f5a996d75d17dfdb3d0e`.
- Cloudflare Exact Preview V6 run `29854047646`: SUCCESS.
- Preview artifact `8504597574`.
- Preview digest `sha256:fee42e045198e64b8308c7dc8d3334408c7fcd5869e68ac4b692bd9a0b675d94`.
- Preview artifact checksums: `16/16_VALID`.

### Candidate Cloudflare

- BUILD_UUID=`a29ef26e-f5d7-47b8-b2d0-f278cc0db79f`
- VERSION_ID=`0f896f48-b58c-41eb-8db7-2a092a8c1aa2`
- VERSION_NUMBER=`75`
- PREVIEW_URL=`https://0f896f48-boqa.simondalmasso44.workers.dev`
- CANDIDATE_TRAFFIC=`0%`
- PRODUCTION_CHANGED=`false`
- DEPLOY_PERFORMED=`false`

### Estado veraz del dashboard

- Preview readiness: PASS, HTTP 200.
- Worker health: `ok`, backend configurado.
- Backend health: `ok`, versión `1.4.0`.
- Backend release SHA: indeterminado.
- `/api/hunter/status`: `404 text/html`.
- CLASSIFICATION=`BLOCKED_BACKEND_CONTRACT`.
- BLOCKER=`BACKEND_HUNTER_CONTRACT_MISSING`.
- PROMOTION_READY=`false`.
- Dashboard overall: `DEGRADED`.
- Desktop 1440: PASS.
- Mobile 390: PASS.
- Mobile 360: PASS.
- Page errors: `0`.
- Unexpected critical console errors: `0`.
- Unexpected failed requests: `0`.
- Horizontal overflow: `0`.
- Private and unused operational paths concealed: PASS.
- Deployment snapshot before/after: identical.

## Producción preservada

Última identidad productiva observada:

- ACTIVE_DEPLOYMENT_ID=`71016a2b-edc4-4786-8bf4-b56749507554`
- ACTIVE_VERSION_ID=`136e5689-91d3-4431-8af0-d8b3248c6e3c`
- ACTIVE_TRAFFIC=`100%`

Revalidar antes de cualquier promoción.

## Bloqueos vigentes

- `BACKEND_HUNTER_CONTRACT_MISSING`.
- Oracle Cloud Agent no expone Run Command en la instancia observada.
- Backend release SHA indeterminado.
- Persistencia, container activo y rollback no inspeccionados.
- Preview no promocionable.

## Decisión operativa

- Mantener PR #33 Draft y candidata al 0%.
- No promover ni mergear.
- Usar la URL de preview para revisión visual inmediata.
- Continuar la ruta segura usando el laboratorio controlado ya validado.
- No afirmar `ACTIVE` hasta que exista contrato hunter real, ciclo fresco, scheduler, heartbeat y storage válido.

## Estado documental

- HANDOFF_BRANCH=`docs/boqa-handoff-pr25-reconstructed`
- VERSIONED_HANDOFF_RECONCILED=`true`
- CANONICAL_DRIVE_SYNC=`PENDING_PR33_UPDATE`
- DOCUMENTED_PR33_HEAD=`3db1220f65ff089444ae781833356295f72bba9f`

## Siguiente acción exacta

Revisar el dashboard en la preview `0f896f48...`; mientras tanto, construir una ruta segura de ciclos frescos desde el laboratorio controlado hacia un contrato hunter separado de producción, manteniendo el dashboard fail-closed y la candidata al 0%.
