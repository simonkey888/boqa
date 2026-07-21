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

El comando exacto fue identificado por el SHA-256 registrado en el artifact original. `EXPIRED` demuestra que la instancia no retiró la orden antes de la expiración. El payload de inspección no está demostrado como ejecutado.

## PR #30 — estado observado de Oracle Cloud Agent

- STATUS=`OPEN_DRAFT`
- BASE_SHA=`a2a866d3d1d34bde20ab9e869c2aa380058cebab`
- HEAD_SHA=`38f47c3dae02393db3e79ed90cefe01b84c5e2d3`
- CHANGED_FILES=`2`
- BEHIND_BASE=`0`
- MERGEABLE=`true`
- RUN_ID=`29832880538`
- JOB_ID=`88641716928`
- RESULT=`SUCCESS`
- ARTIFACT_ID=`8496047189`
- ARTIFACT_DIGEST=`sha256:5df29ec7a6fc145107fba364683ee367ff1e0a8f8b22270fc9573a9c001ef8fb`
- ARTIFACT_CHECKSUMS=`6/6_VALID`
- INSTANCE_LIFECYCLE=`RUNNING`
- AGENT_CONFIG_PRESENT=`true`
- ALL_PLUGINS_DISABLED=`false`
- MANAGEMENT_DISABLED=`false`
- RUN_COMMAND_DESIRED_STATE=`DEFAULT`
- OBSERVED_PLUGIN_TOTAL=`11`
- RUN_COMMAND_OBSERVED_MATCHES=`0`
- CLASSIFICATION=`BLOCKED_PLUGIN_MISSING`
- COMMAND_API_USED=`false`
- PRODUCTION_CHANGED=`false`

La configuración no deshabilita plugins ni management. El plugin Compute Instance Run Command no aparece en el conjunto observado de la instancia.

## PR #31 — compatibilidad de imagen y catálogo de plugins

- STATUS=`OPEN_DRAFT`
- BASE_SHA=`38f47c3dae02393db3e79ed90cefe01b84c5e2d3`
- HEAD_SHA=`7cffe43e457b91ade200268cf43c782d127ecb1b`
- CHANGED_FILES=`2`
- BEHIND_BASE=`0`
- MERGEABLE=`true`
- RUN_ID=`29833641694`
- JOB_ID=`88644319715`
- RESULT=`SUCCESS`
- ARTIFACT_ID=`8496368042`
- ARTIFACT_DIGEST=`sha256:a12ae8ff9aee9436a4cc811a8f27cc3aee3fecaa4fbacbc7a0db028a694125af`
- ARTIFACT_CHECKSUMS=`6/6_VALID`
- OPERATING_SYSTEM=`Canonical Ubuntu`
- OPERATING_SYSTEM_VERSION=`22.04`
- IMAGE_PRE_OCTOBER_2020=`false`
- IMAGE_AGE_BUCKET=`LT_1Y`
- AVAILABLE_PLUGIN_TOTAL=`11`
- RUN_COMMAND_AVAILABLE_MATCHES=`0`
- OBSERVED_PLUGIN_TOTAL=`11`
- RUN_COMMAND_OBSERVED_MATCHES=`0`
- CLASSIFICATION=`BLOCKED_PLATFORM_PLUGIN_NOT_LISTED`
- COMMAND_API_USED=`false`
- PRODUCTION_CHANGED=`false`

La imagen es reciente y no entra en el caso documentado de imágenes anteriores a octubre de 2020. Run Command no aparece ni en el catálogo de plugins devuelto para la imagen ni en el conjunto observado de la instancia. Esto no prueba que Ubuntu 22.04 sea incompatible de forma general; prueba un gap de imagen, instalación o catálogo en esta instancia.

Todas las etiquetas temporales de PR #29, PR #30 y PR #31 fueron retiradas. No hubo reintento automático ni segunda orden remota.

## Producción preservada

Última evidencia disponible:

- ACTIVE_DEPLOYMENT_ID=`71016a2b-edc4-4786-8bf4-b56749507554`
- ACTIVE_VERSION_ID=`136e5689-91d3-4431-8af0-d8b3248c6e3c`
- ACTIVE_TRAFFIC=`100%`

Revalidar antes de cualquier promoción.

## Bloqueos vigentes

- Compute Instance Run Command no está disponible en la instalación observada de Oracle Cloud Agent.
- Backend hunter no verificado.
- Persistencia, imagen activa del contenedor, release SHA y rollback no inspeccionados.
- Preview no promocionable.
- SHA productivo indeterminado.
- PR #25, PR #29, PR #30 y PR #31 permanecen Draft o abiertos según lo indicado.

## Decisión operativa

- No crear otro Run Command automáticamente.
- No habilitar, instalar, actualizar ni reiniciar Oracle Cloud Agent sin autorización de mutación.
- No mergear, desplegar ni promover.
- La siguiente acción requiere acceso al host para inspeccionar versión/paquete/logs del agente o aplicar una reparación controlada con rollback.

## Estado documental

- HANDOFF_BRANCH=`docs/boqa-handoff-pr25-reconstructed`
- VERSIONED_HANDOFF_RECONCILED=`true`
- CANONICAL_DRIVE_SYNC=`PENDING_PLUGIN_DIAGNOSTIC_UPDATE`
- DOCUMENTED_PR31_HEAD=`7cffe43e457b91ade200268cf43c782d127ecb1b`

## Siguiente acción exacta

Obtener autorización explícita para una intervención controlada en la instancia: inspeccionar localmente Oracle Cloud Agent y, sólo si corresponde, instalar/actualizar o habilitar el plugin Run Command con respaldo, evidencia y rollback.