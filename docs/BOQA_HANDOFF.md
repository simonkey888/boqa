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

## PR #25 — preflight de backend

- STATUS=`OPEN_DRAFT`
- HEAD_SHA=`335a76afc303b7411737a729bdff2a761ce67d39`
- OCI_PREFLIGHT_RUN=`29800920787`
- OCI_PREFLIGHT_RESULT=`SUCCESS`
- INSTANCE_LIFECYCLE=`RUNNING`
- INSTANCE_AGENT_VISIBILITY=`PASS`

La preview exacta continúa bloqueada por `BACKEND_HUNTER_CONTRACT_MISSING` y `promotion_ready=false`.

## PR #28 — inspección read-only original

- STATUS=`CLOSED_NOT_MERGED`
- HEAD_SHA=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- RUN_ID=`29824605280`
- JOB_ID=`88614940825`
- RESULT=`FAILURE_FAIL_CLOSED`
- ARTIFACT_ID=`8492864714`
- ARTIFACT_DIGEST=`sha256:6ffda86943624ddce8f8f3fca1e456fb8dfa4056a34a1203087f16e4f551b444`
- ARTIFACT_CHECKSUMS=`7/7_VALID`
- COMMAND_CREATED=`true`
- TERMINAL_STATE_OBSERVED=`false`
- SANITIZED_OUTPUT_RECORDED=`false`
- NEW_COMMAND_RETRY=`false`

PR #28 se cerró sin merge. La rama se conserva porque es la base exacta de PR #29.

## PR #29 — recuperación del resultado existente

- STATUS=`OPEN_DRAFT`
- BASE_SHA=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- HEAD_SHA=`a2a866d3d1d34bde20ab9e869c2aa380058cebab`
- CHANGED_FILES=`2`
- BEHIND_BASE=`0`
- MERGEABLE=`true`

Archivos finales:

- `.github/workflows/boqa-backend-execution-summary-recovery-v3.yml`
- `test/test-backend-execution-summary-recovery-v3.js`

### Diagnóstico de collectors anteriores

- Run variable-gated `29829310438`: SKIPPED antes de ejecutar pasos.
- Run autónomo `29829783699`: falló al autenticar el comando.
- Artifact `8494781041`; digest `sha256:d94750571850491e6aba69f689d72bea95c18ac471d6b4b8c9a57a10fd0770f9`.
- Diagnóstico `29830245100`: SUCCESS; confirmó una coincidencia por nombre, pero el collector leía el campo de ID equivocado.
- Clasificador `29830535734`: SUCCESS; el valor incorrecto produjo `NotAuthorizedOrNotFound`/404.
- Recuperación V2 `29831204462`: falló con `COMMAND_ID_HASH_MISMATCH`.

Causa corregida: `ListInstanceAgentCommands` expone el ID como `instance-agent-command-id`; leer `.id` producía la cadena `null`. No existe evidencia de un fallo IAM en este incidente.

### Recuperación V3

- RUN_ID=`29831821481`
- JOB_ID=`88638214819`
- RESULT=`FAILURE_FAIL_CLOSED`
- ARTIFACT_ID=`8495615436`
- ARTIFACT_DIGEST=`sha256:30dab7da04881e6c70e6423558eac9ac66ba1cda6be7ba9f27e4014ec200c442`
- ARTIFACT_CHECKSUMS=`6/6_VALID`
- COMMAND_ID_HASH_MATCHED=`true`
- EXECUTION_SUMMARY_MATCH_COUNT=`1`
- LIFECYCLE_STATE=`ACCEPTED`
- DELIVERY_STATE=`EXPIRED`
- OUTPUT_BYTES=`0`
- SANITIZED_OUTPUT_RECORDED=`false`
- NEW_COMMAND_CREATED=`false`
- COMMAND_CANCELED=`false`
- PRODUCTION_CHANGED=`false`

El comando exacto fue identificado por el SHA-256 registrado en el artifact original. Su execution summary indica `ACCEPTED` y `EXPIRED`. Oracle define `EXPIRED` como entrega expirada porque la instancia no solicitó el comando. Por lo tanto, el payload de inspección no está demostrado como ejecutado y el backend continúa sin inspeccionar.

Todas las etiquetas temporales de PR #29 fueron retiradas. No habrá reintento automático.

## Producción preservada

Última evidencia disponible:

- ACTIVE_DEPLOYMENT_ID=`71016a2b-edc4-4786-8bf4-b56749507554`
- ACTIVE_VERSION_ID=`136e5689-91d3-4431-8af0-d8b3248c6e3c`
- ACTIVE_TRAFFIC=`100%`

Revalidar antes de cualquier promoción.

## Bloqueos vigentes

- El plugin Run Command de Oracle Cloud Agent no retiró la operación existente antes de expirar.
- Backend hunter no verificado.
- Persistencia, imagen activa, release SHA y rollback no inspeccionados.
- Preview no promocionable.
- SHA productivo indeterminado.
- PR #25 y PR #29 permanecen Draft.

## Decisión operativa

- No crear un segundo comando automáticamente.
- No reejecutar PR #28 ni PR #29.
- No mergear, desplegar ni promover.
- Siguiente diagnóstico permitido: estado read-only del plugin Run Command y salud de Oracle Cloud Agent, sin comandos remotos.

## Estado documental

- HANDOFF_BRANCH=`docs/boqa-handoff-pr25-reconstructed`
- VERSIONED_HANDOFF_RECONCILED=`true`
- CANONICAL_DRIVE_SYNC=`COMPLETE`
- DOCUMENTED_PR29_HEAD=`a2a866d3d1d34bde20ab9e869c2aa380058cebab`

## Siguiente acción exacta

Crear y ejecutar un diagnóstico read-only del plugin Run Command de Oracle Cloud Agent para determinar por qué la entrega quedó `EXPIRED`, sin crear ni cancelar comandos.