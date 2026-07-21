# BOQA — Handoff operativo vivo

LAST_VERIFIED_DATE=2026-07-21  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `REMOTE_MAIN_HEAD=f33015c55fe84508377528c2ff718f9c5b28efe7`
- `LAST_MATERIAL_MAIN_SHA=620ce2bfae2cbd23b2fa2e220fd3fd1ee930177c`
- `LAST_MERGED_PR=PR #27`
- `PRODUCTION_SHA=INDETERMINADO`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`
- `RESTART_PERFORMED=false`
- `ROLLBACK_EXECUTED=false`

`REMOTE_MAIN_HEAD` debe verificarse nuevamente antes de cualquier acción. No se modificó `main` durante la construcción de PR #28.

## Producto integrado en main

- Frontera privada oculta en el Worker público.
- API pública del Worker limitada a contratos explícitos.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Cloudflare Preview V6 crea una versión exacta sin tráfico y clasifica el candidato de forma fail-closed.
- Una ejecución exitosa con `promotion_ready=false` no autoriza deploy.

## PR #25 — backend control-plane preflight

- `PR=25`
- `STATUS=OPEN_DRAFT`
- `BRANCH=deploy/boqa-backend-preflight-v2`
- `BASE_SHA=f33015c55fe84508377528c2ff718f9c5b28efe7`
- `HEAD_SHA=335a76afc303b7411737a729bdff2a761ce67d39`
- `COMMIT_COUNT=1`
- `CHANGED_FILES=2`
- `MERGEABLE=true`

El diff de PR #25 contiene únicamente:

- `.github/workflows/boqa-backend-ssh-preflight-v2.yml`
- `.github/workflows/boqa-backend-oci-api-preflight-v2.yml`

No modificó aplicación, dashboard, Worker, backend, almacenamiento ni workflows de despliegue.

### Gates de producto sobre el HEAD exacto de PR #25

- Browser Smoke run `29800920838`: SUCCESS.
- Browser artifact `8483715389`; digest `sha256:5f75e5ef86efccb65ed49e0b077930bb4eae1e93efc22a79ed15de9cfe4c2897`.
- Real Docker Qualification run `29800920828`: SUCCESS.
- Docker artifact `8483724710`; digest `sha256:2d3cd118451acb4ae02748002f17e1a7a6ae9a4b69c3aaad22629a04fbe954ab`.
- Cloudflare Preview V6 run `29800920819`: SUCCESS.
- Preview artifact `8483741556`; digest `sha256:31e63c437f154aa4cb494165fa8c587683206c6cfffbf0ca297b4cfeb9c9ef22`.
- Preview artifact checksums: `16/16_VALID`.
- `CLASSIFICATION=BLOCKED_BACKEND_CONTRACT`
- `BLOCKER=BACKEND_HUNTER_CONTRACT_MISSING`
- `PROMOTION_READY=false`

### OCI API preflight validado

- `RUN_ID=29800920787`
- `RUN_ATTEMPT=2`
- `JOB_ID=88552486316`
- `RESULT=SUCCESS`
- `ARTIFACT_ID=8485009246`
- `ARTIFACT_DIGEST=sha256:acb4e760daa146d6a253238333810480e1c7549c4523763602a87db91397e3d9`
- `ARTIFACT_CHECKSUMS=9/9_VALID`
- `OWNED_INSTANCE_RESOLVED=true`
- `INSTANCE_LIFECYCLE=RUNNING`
- `INSTANCE_AGENT_READ=true`
- `NEW_COMMAND_EXECUTED=false`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`

La ruta OCI API quedó validada. La ruta SSH no fue reejecutada y no es la ruta seleccionada.

## Credenciales y limpieza

- Los siete valores canónicos requeridos por la ruta OCI están presentes como GitHub Actions repository secrets.
- No se registran valores, fingerprints, OCIDs ni material privado en este handoff.
- La clave pública nueva está registrada en OCI; la clave previa se conserva.
- La clave privada temporal, GitHub CLI temporal, configuración local y archivos auxiliares fueron eliminados de Cloud Shell.
- No se descargó material sensible en la PC del usuario.

## PR #28 — backend read-only inspection v1

- `PR=28`
- `STATUS=OPEN_DRAFT`
- `BASE_BRANCH=deploy/boqa-backend-preflight-v2`
- `BASE_SHA=335a76afc303b7411737a729bdff2a761ce67d39`
- `HEAD_BRANCH=deploy/boqa-backend-readonly-inspection-v1`
- `HEAD_SHA=e71a7012f923983a2cf312eb742ad9f56f13e864`
- `MERGEABLE=true`
- `COMMIT_COUNT=3`
- `CHANGED_FILES=3`
- `BACKEND_INSPECTION_EXECUTED=false`
- `WORKFLOW_RUNS_ON_HEAD=0`

El diff exacto contiene únicamente:

- `.github/scripts/boqa-backend-readonly-inspection-v1.sh`
- `.github/workflows/boqa-backend-readonly-inspection-v1.yml`
- `test/test-backend-readonly-inspection-v1.js`

### Diseño de activación

El workflow nuevo no se ejecuta al abrir, reabrir o sincronizar PR #28. Sólo escucha un evento `pull_request:labeled` dirigido a la rama base de PR #25 y exige simultáneamente:

- etiqueta exacta `authorized-backend-readonly-inspection`;
- variable `BOQA_BACKEND_INSPECTION_AUTHORIZED_SHA` igual al HEAD exacto de PR #28;
- PR del mismo repositorio;
- rama head exacta;
- ancestry exacta desde `335a76afc303b7411737a729bdff2a761ce67d39`;
- diff limitado a los tres archivos declarados.

No se aplicó la etiqueta y no se creó ni modificó la variable de autorización durante la construcción. El workflow permanece inerte.

### Inspección futura prevista

Sólo después de una autorización explícita separada, el workflow podría crear un único OCI Instance Agent Run Command con:

- script fijo y versionado;
- tamaño `3979` bytes, dentro del límite inline de OCI;
- `--no-retry` en la creación del comando;
- timeout de `120` segundos;
- salida JSON sanitizada menor o igual a `1024` bytes;
- verificación del checksum devuelto por OCI;
- GET locales únicamente a `/api/health` y `/api/hunter/status`;
- inventario agregado de contenedor, imagen, política de restart, mounts, bindings y candidatos de rollback;
- lectura acotada a las últimas 200 líneas de logs, reteniendo sólo conteos;
- identificadores de imagen, instancia, comando y rollback representados mediante hash cuando corresponde.

El script no contiene mutaciones de archivos del host, gestión de paquetes, control de procesos o servicios, mutaciones Docker, targets HTTP no locales, comandos dinámicos del operador ni dependencia de Object Storage.

Clasificaciones fail-closed:

- `INSPECTED`
- `BLOCKED_DOCKER_ACCESS`
- `BLOCKED_CONTAINER_AMBIGUITY`

Sólo `INSPECTED` con ejecución OCI exitosa, exit code 0, un contenedor productivo inequívoco, hashes válidos y `mutated=false` puede pasar.

### Validación de construcción

- Bash syntax: PASS.
- Workflow YAML parse: PASS.
- Test estático de política: PASS.
- Script inline: `3979` bytes.
- Remote blob hashes: coinciden con los archivos validados.
- Diff remoto contra PR #25: exactamente 3 archivos.
- Suite completa BOQA: NOT_EXECUTED durante esta construcción.
- OCI Run Command: NOT_CREATED.
- Backend runtime inspection: NOT_EXECUTED.

## Strix

- `STRIX_CLASSIFICATION=USEFUL_REFERENCE_DEFERRED`
- No se agregó Strix como dependencia, imagen, workflow ni runtime.
- Cualquier evaluación futura de Strix debe ocurrir sólo en laboratorio sintético aislado y fuera del camino crítico actual.

## Producción preservada

Última evidencia auditada de Cloudflare Preview V6:

- `ACTIVE_DEPLOYMENT_ID=71016a2b-edc4-4786-8bf4-b56749507554`
- `ACTIVE_VERSION_ID=136e5689-91d3-4431-8af0-d8b3248c6e3c`
- `ACTIVE_TRAFFIC=100%`

Estos identificadores deben revalidarse antes de cualquier promoción. PR #28 no accedió ni modificó producción.

## Bloqueos vigentes

- El backend activo no ofrece un contrato válido en `/api/hunter/status`.
- La preview exacta informa `promotion_ready=false`.
- `BOQA_RELEASE_SHA` productivo continúa indeterminado.
- Persistencia y rollback todavía no fueron inspeccionados desde el runtime productivo.
- PR #25 y PR #28 permanecen Draft.
- El documento canónico de Drive todavía requiere sincronización de esta actualización.

## Decisión operativa

- No mergear PR #25 ni PR #28 todavía.
- No aplicar la etiqueta de ejecución.
- No crear ni modificar la variable de autorización todavía.
- No ejecutar OCI Run Command sin autorización explícita separada contra el HEAD exacto.
- No desplegar backend ni promover Worker.
- No reintentar automáticamente ante un fallo futuro.
- No publicar datos, rutas privadas, valores de secretos ni identificadores crudos.

## Reglas permanentes

- No validar infraestructura de terceros.
- No ampliar scope automáticamente.
- No trabajar directamente sobre `main`.
- No inventar estado hunter desde health genérico.
- No confundir CI verde, versión subida, deploy y producción activa.
- No declarar deploy sin versión, deployment, tráfico, contratos, browser smoke, backend, almacenamiento y rollback verificados.
- Mantener sincronizados este archivo y el documento canónico de Drive.

## Estado documental

- `HANDOFF_BRANCH=docs/boqa-handoff-pr25-reconstructed`
- `VERSIONED_HANDOFF_UPDATED=true`
- `CANONICAL_DRIVE_SYNC=PENDING`

## Siguiente acción exacta

Auditar independientemente el diff y la política de PR #28 sobre el HEAD exacto `e71a7012f923983a2cf312eb742ad9f56f13e864`. No ejecutar todavía. Cualquier ejecución futura requiere autorización explícita para fijar ese SHA en la variable de repositorio y aplicar la etiqueta exacta una sola vez.
