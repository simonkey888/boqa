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

`main` fue revalidado el 21 de julio de 2026 y continúa en el SHA indicado.

## PR #25 — preflight de backend

- STATUS=`OPEN_DRAFT`
- BASE=`main`
- BASE_SHA=`f33015c55fe84508377528c2ff718f9c5b28efe7`
- HEAD_BRANCH=`deploy/boqa-backend-preflight-v2`
- HEAD_SHA=`335a76afc303b7411737a729bdff2a761ce67d39`
- CHANGED_FILES=`2`
- MERGEABLE=`true`

Evidencia sobre ese HEAD:

- Browser Smoke `29800920838`: SUCCESS.
- Real Docker Qualification `29800920828`: SUCCESS.
- Cloudflare Preview V6 `29800920819`: SUCCESS.
- Preview checksums: `16/16_VALID`.
- Preview classification: `BLOCKED_BACKEND_CONTRACT`.
- Blocker: `BACKEND_HUNTER_CONTRACT_MISSING`.
- `promotion_ready=false`.

OCI API preflight:

- Run `29800920787`, attempt `2`: SUCCESS.
- Job `88552486316`.
- Artifact `8485009246`.
- Digest `sha256:acb4e760daa146d6a253238333810480e1c7549c4523763602a87db91397e3d9`.
- Checksums `9/9_VALID`.
- Owned instance resolved.
- Instance lifecycle `RUNNING`.
- Instance Agent read visibility confirmed.
- New command executed: `false`.

La ruta OCI API quedó validada. La ruta SSH no fue reejecutada.

## PR #28 — inspección read-only del backend

- STATUS=`OPEN_DRAFT`
- BASE_BRANCH=`deploy/boqa-backend-preflight-v2`
- BASE_SHA=`335a76afc303b7411737a729bdff2a761ce67d39`
- HEAD_BRANCH=`deploy/boqa-backend-readonly-inspection-v1`
- INITIAL_HEAD=`e71a7012f923983a2cf312eb742ad9f56f13e864`
- FINAL_AUDITED_HEAD=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`
- COMMITS=`8`
- CHANGED_FILES=`3`
- BEHIND_BASE=`0`
- MERGEABLE=`true`
- WORKFLOW_RUNS_ON_FINAL_HEAD=`0`
- BACKEND_INSPECTION_EXECUTED=`false`
- OCI_COMMAND_CREATED=`false`

Archivos del diff:

- `.github/scripts/boqa-backend-readonly-inspection-v1.sh`
- `.github/workflows/boqa-backend-readonly-inspection-v1.yml`
- `test/test-backend-readonly-inspection-v1.js`

### Auditoría final

Se corrigieron:

1. detección frágil del mount persistente;
2. posible inclusión de la imagen activa como rollback;
3. aceptación de hashes derivados de metadata vacía;
4. limpieza tardía de material temporal del runner.

El HEAD final usa inspección JSON estructurada, IDs completos de imagen, bloqueo por metadata incompleta y limpieza previa a checksums y artifact upload.

Clasificaciones:

- `INSPECTED`
- `BLOCKED_DOCKER_ACCESS`
- `BLOCKED_CONTAINER_AMBIGUITY`
- `BLOCKED_INSPECT_INCOMPLETE`

Límites verificados:

- Script inline: `3684` bytes.
- Salida sintética máxima observada: `756` bytes.
- Consultas HTTP limitadas a localhost.
- Logs no retenidos; sólo conteos.
- Checksum remoto obligatorio.

Validación realizada:

- Bash syntax: PASS.
- Workflow structural parse: PASS.
- Policy assertions: PASS.
- Fixtures sintéticos: PASS o bloqueo esperado.
- Diff remoto: 3 archivos.
- Ancestry exacta: PASS.
- Cleanup previo al artifact: PASS.
- Runs sobre HEAD final: 0.

No ejecutado:

- suite BOQA completa sobre el HEAD final;
- runtime de GitHub Actions;
- OCI Run Command;
- inspección real del backend;
- deploy, restart o rollback.

## Producción preservada

Última evidencia disponible:

- ACTIVE_DEPLOYMENT_ID=`71016a2b-edc4-4786-8bf4-b56749507554`
- ACTIVE_VERSION_ID=`136e5689-91d3-4431-8af0-d8b3248c6e3c`
- ACTIVE_TRAFFIC=`100%`

Revalidar estos identificadores antes de cualquier promoción.

## Bloqueos vigentes

- Contrato hunter ausente.
- Preview no promocionable.
- SHA productivo indeterminado.
- Persistencia y rollback productivos todavía no inspeccionados.
- PR #25 y PR #28 permanecen Draft.

## Decisión operativa

- No mergear todavía.
- No activar PR #28 sin autorización explícita contra su HEAD final.
- No desplegar ni promover.
- No reintentar automáticamente ante una falla.

## Estado documental

- HANDOFF_BRANCH=`docs/boqa-handoff-pr25-reconstructed`
- VERSIONED_HANDOFF_RECONCILED=`true`
- CANONICAL_DRIVE_SYNC=`COMPLETE`
- DOCUMENTED_PR28_HEAD=`fb1cc8bcfbf0f3d76d5f8860619e953266a388b6`

## Siguiente acción exacta

Obtener autorización explícita separada contra `fb1cc8bcfbf0f3d76d5f8860619e953266a388b6` antes de activar una única inspección read-only. Hasta entonces, mantener PR #28 inerte y Draft.
