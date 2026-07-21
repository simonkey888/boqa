# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-21T00:26:00-03:00  
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

## Flujo activo — PR #26 Cloudflare preview v6

- `PR=26`
- `BRANCH=deploy/boqa-cloudflare-preview-v6`
- `BASE_SHA=bc6f45acefe693f3cc2940d91f715d11ee50da93`
- `PREVIOUS_HEAD=b763913ddf23b36d98ef5233ae3bf8bb1374bcbe`
- `LAST_CODE_FIX_SHA=bc3b34f9486362ace3bc47c11f910b5c289abeea`
- `STATUS=CI_RERUN_PENDING`
- `PROMOTION_READY=false`
- `PRODUCTION_CHANGED=false`
- `DEPLOY_PERFORMED=false`

### Gates del HEAD anterior

- Browser Smoke run `29699660940`: SUCCESS.
- Browser artifact `8446068371`; digest `sha256:a52b6ec205a9e0eabc53940d32b85f88fc48cf27b03b589901efe92ec4142d25`.
- Real Docker Qualification run `29699660937`: SUCCESS.
- Docker artifact `8446073928`; digest `sha256:fa2b258024b5908442b5bae1ea99996517f3e12cb6d62b00cb7287e34b4e9065`.
- Cloudflare Preview V6 run `29699661015`: FAILURE.
- Preview artifact `8446090384`; digest `sha256:4a25ec6fa53ccddd2f80f85c9e18ee992a69ecfdb18c92b4d28436630da0d58a`.

### Diagnóstico causal

La versión exacta fue construida correctamente y el deployment productivo permaneció idéntico antes y después. El backend activo respondió:

- `/api/health`: 200, `status=ok`;
- `/api/hunter/status`: 404 sin contrato hunter válido.

La clasificación `BLOCKED_BACKEND_CONTRACT` fue correcta. El fallo ocurrió después, en el browser smoke, porque el dashboard mostró `Respuesta JSON inválida` para el 404 HTML y el test exigía exclusivamente `Respuesta HTTP 404`.

### Corrección aplicada

El smoke mantiene como condiciones obligatorias:

- estado general `DEGRADED`;
- hunter `UNAVAILABLE`;
- health `FRESH` y `ok`;
- clasificación directa del endpoint como 404;
- cero page errors;
- cero errores críticos inesperados;
- cero requests fallidos inesperados;
- cero overflow horizontal;
- desktop 1440, mobile 390 y mobile 360.

Para el motivo visible del hunter acepta únicamente las dos representaciones veraces posibles del mismo 404 según el transporte: `Respuesta HTTP 404` o `Respuesta JSON inválida`. El valor observado se registra en la evidencia por viewport.

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

Verificar el HEAD final de PR #26 y auditar Browser Smoke, Real Docker Qualification y Cloudflare Preview V6 sobre ese mismo SHA. Integrar únicamente el mecanismo de entrega si los tres gates quedan verdes y la preview conserva `promotion_ready=false` mientras falte el contrato backend.
