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

La preview exacta continúa bloqueada por contrato backend faltante y `promotion_ready=false`.

## PR #28 — inspección read-only del backend

- STATUS=`OPEN_DRAFT`
- BASE_SHA=`335a76afc303b7411737a729bdff2a761ce67d39`
- FINAL_AUDITED_HEAD=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- CHANGED_FILES=`3`
- MERGEABLE=`true`

Archivos:

- `.github/scripts/boqa-backend-readonly-inspection-v1.sh`
- `.github/workflows/boqa-backend-readonly-inspection-v1.yml`
- `test/test-backend-readonly-inspection-v1.js`

Auditoría previa:

- Bash syntax: PASS.
- Workflow structural parse: PASS.
- Policy assertions: PASS.
- Fixtures sintéticos: PASS o bloqueo esperado.
- Script inline: `3684` bytes.
- Salida sintética máxima: `756` bytes.
- Cleanup previo al artifact: PASS.

## Incidente de inspección 2026-07-21

- RUN_ID=`29824605280`
- JOB_ID=`88614940825`
- RESULT=`FAILURE_FAIL_CLOSED`
- ARTIFACT_ID=`8492864714`
- ARTIFACT_DIGEST=`sha256:6ffda86943624ddce8f8f3fca1e456fb8dfa4056a34a1203087f16e4f551b444`
- ARTIFACT_CHECKSUMS=`7/7_VALID`
- AUTHORIZATION_GATES=`PASS`
- EXACT_INSTANCE_REVALIDATION=`PASS`
- REMOTE_OPERATION_CREATED=`true`
- TERMINAL_STATE_OBSERVED=`false`
- SANITIZED_OUTPUT_RECORDED=`false`
- BLOCKER=`COMMAND_EXECUTION=NO_TERMINAL_STATE`
- PRODUCTION_CHANGED=`false`
- DEPLOY_PERFORMED=`false`
- RESTART_PERFORMED=`false`
- ROLLBACK_EXECUTED=`false`

La ejecución autorizada no devolvió estado terminal dentro de la ventana observada. No existe evidencia suficiente para clasificar el backend, validar hunter, confirmar persistencia ni evaluar rollback.

No hubo reintento. La autorización de una sola ejecución fue retirada al terminar el run.

## PR #29 — collector read-only de recuperación

- STATUS=`OPEN_DRAFT`
- BASE_BRANCH=`deploy/boqa-backend-readonly-inspection-v1`
- BASE_SHA=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- HEAD_BRANCH=`deploy/boqa-backend-readonly-recovery-v1`
- FINAL_AUDITED_HEAD=`9478ecec700371b5501a1bc385b5cacd823b5831`
- CHANGED_FILES=`2`
- COMMITS=`7`
- BEHIND_BASE=`0`
- MERGEABLE=`true`
- WORKFLOW_RUNS=`0`
- RECOVERY_EXECUTED=`false`
- NEW_REMOTE_OPERATION_CREATED=`false`
- EXISTING_OPERATION_CANCELED=`false`

Archivos:

- `.github/workflows/boqa-backend-readonly-recovery-v1.yml`
- `test/test-backend-readonly-recovery-v1.js`

El collector sólo lee la instancia exacta, localiza una única operación existente, autentica su identidad y payload y consulta su ejecución. No contiene creación, cancelación ni eliminación de operaciones remotas.

Controles:

- PR Draft, número, base, rama, repositorio, actor y SHA exactos.
- Variable de autorización separada y etiqueta separada, todavía no configuradas.
- Permisos GitHub limitados a `contents: read`.
- OCI CLI fijada en `3.89.2`.
- Todas las lecturas OCI usan `--no-retry`.
- Payload original autenticado por SHA-256 `bf01b6b9988ac7d902ddd4cfd59a1ccb1b3bcef2168880a9b106e56b3e47fc41`.
- Salida terminal limitada a 1024 bytes y checksum obligatorio.
- Identificadores retenidos sólo mediante SHA-256.
- Credenciales, payload e identificadores temporales eliminados antes del artifact.

Validación:

- Static trigger and permission policy: PASS.
- Superficie OCI limitada a tres lecturas: PASS.
- YAML parse: PASS.
- Fixture sintético de resolución de operación existente: PASS.
- Fixture sintético de identidad del payload: PASS.
- Fixture sintético de estado terminal, checksum y esquema: PASS.
- Objeto de inspección recuperado preservado: PASS.
- Diff remoto: exactamente 2 archivos.
- Runs sobre HEAD final: 0.

La prueba sintética detectó y corrigió antes de ejecución un defecto que sustituía el objeto recuperado por el booleano de validación JSON.

PR #29 permanece inerte. No existe autorización para ejecutarlo.

## Producción preservada

Última evidencia disponible:

- ACTIVE_DEPLOYMENT_ID=`71016a2b-edc4-4786-8bf4-b56749507554`
- ACTIVE_VERSION_ID=`136e5689-91d3-4431-8af0-d8b3248c6e3c`
- ACTIVE_TRAFFIC=`100%`

Revalidar antes de cualquier promoción.

## Bloqueos vigentes

- Resultado remoto todavía no recuperado.
- Contrato hunter ausente o no verificado.
- Preview no promocionable.
- SHA productivo indeterminado.
- Persistencia y rollback no inspeccionados.
- PR #25, PR #28 y PR #29 permanecen Draft.

## Decisión operativa

- No reejecutar PR #28.
- No iniciar una segunda operación remota.
- No ejecutar PR #29 sin autorización explícita contra su HEAD final.
- No mergear, desplegar ni promover.

## Estado documental

- HANDOFF_BRANCH=`docs/boqa-handoff-pr25-reconstructed`
- VERSIONED_HANDOFF_RECONCILED=`true`
- CANONICAL_DRIVE_SYNC=`COMPLETE`
- DOCUMENTED_PR28_HEAD=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- DOCUMENTED_PR29_HEAD=`9478ecec700371b5501a1bc385b5cacd823b5831`

## Siguiente acción exacta

Auditar independientemente PR #29 sobre `9478ecec700371b5501a1bc385b5cacd823b5831`. Si no aparecen hallazgos materiales, solicitar autorización explícita separada antes de configurar su variable y aplicar una única etiqueta de recuperación.
