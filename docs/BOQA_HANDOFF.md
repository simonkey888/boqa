# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T15:35:00-03:00  
TIMEZONE=America/Argentina/Cordoba

## Estado verificado

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `LAST_MERGED_PR=PR #23`
- `PRODUCTION_SHA=INDETERMINADO`
- Producción no fue modificada por los flujos de preview ni preflight.

## Producto integrado

- Frontera privada oculta en el Worker público.
- API pública limitada a `GET /api/health` y `GET /api/hunter/status`.
- Dashboard validado en desktop 1440, mobile 390 y mobile 360.
- Browser y Docker finales sobre `main`: PASS.

## Diagnóstico Cloudflare concluido

Los builds exactos de PR #24 demostraron:

- Workers Builds configurado sólo para preview;
- trigger productivo igual a cero;
- build fijado a rama y SHA exactos;
- versión y preview URL identificables;
- deployment productivo idéntico antes y después;
- `/health` del Worker: 200;
- `/api/health` del backend: 200 y `status=ok`;
- `/api/hunter/status` del backend activo: 404 HTML;
- la ruta histórica `/api/defensive/status`: 404 HTML;
- no existe un contrato hunter semánticamente válido en el backend productivo actual.

No se mapeará el health del agente antiguo a `Hunter ACTIVE`: sería una afirmación falsa.

## Flujo activo — Cloudflare preview v6

- `BRANCH=deploy/boqa-cloudflare-preview-v6`
- `BASE_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `STATUS=IN_PROGRESS`

Objetivo del gate limpio:

1. construir una versión exacta mediante Builds API;
2. demostrar que producción no cambia;
3. validar rutas privadas y operativas ocultas;
4. clasificar la preview como `PROMOTION_READY` o `BLOCKED_BACKEND_CONTRACT`;
5. cuando el backend carezca de hunter, validar la degradación honesta del dashboard en desktop/390/360;
6. concluir SUCCESS como gate operativo sólo si la clasificación y la evidencia son coherentes;
7. mantener `promotion_ready=false` mientras falte el contrato backend.

El workflow puede quedar integrado aunque clasifique correctamente un bloqueo externo. Esa conclusión no autoriza promoción productiva.

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

Agregar el gate preview v6 limpio, abrir Draft PR, exigir Browser y Docker verdes, obtener una clasificación Cloudflare verificable y fusionar únicamente el mecanismo de entrega. Mantener producción sin cambios y PR #25 bloqueado hasta disponer de acceso backend.
