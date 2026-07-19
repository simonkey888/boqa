# BOQA — Handoff operativo vivo

LAST_VERIFIED_AT=2026-07-19T14:07:30-03:00  
TIMEZONE=America/Argentina/Cordoba

## Fuentes de verdad

1. Producción verificada.
2. Cloudflare y backend activos.
3. HEAD remoto de `main`.
4. GitHub Actions y artifacts.
5. Código del repositorio.
6. Google Doc canónico `CONTEXTO BOQA`.
7. Memoria de chat.

## Estado actual

- `REPOSITORY=simonkey888/boqa`
- `MAIN_SHA=ede06de817d607e6717f6ea71f2e40aac68ea7a2`
- `LAST_MERGED_PR=PR #15`
- `PRODUCTION_URL=https://boqa.simondalmasso44.workers.dev/`
- `PRODUCTION_SHA=INDETERMINADO`
- `ACTIVE_WORKER_VERSION_ID=136e5689-91d3-4431-8af0-d8b3248c6e3c` — no revalidado en este delta.
- `ACTIVE_DEPLOYMENT_ID=71016a2b-edc4-4786-8bf4-b56749507554` — no revalidado en este delta.
- Producción no fue modificada por el hardening de esta rama.

## Flujos activos

### Hardening público/privado

- `BRANCH=fix/boqa-public-private-boundary-v2`
- `BASE_SHA=ede06de817d607e6717f6ea71f2e40aac68ea7a2`
- `HEAD_SHA=fcf1f4c453cd66a38ed2109e8426bdd81bf36f28`
- `COMMIT_WORKER=5ae28ec99b63b5892d4e11b128268d9005a5fcc1`
- `COMMIT_TEST=7469e409d26381b86163d20687e7e5aa4b656d64`
- `COMMIT_HANDOFF=fcf1f4c453cd66a38ed2109e8426bdd81bf36f28`
- `FILES=worker.js; test/test-public-private-boundary.js; docs/BOQA_HANDOFF.md`
- `VALIDATION_STATUS=PENDING_CI`
- `PRODUCTION_IMPACT=false`

El Worker público devuelve `404` genérico con `no-store` para:

- `/cobros`
- `/cobros.html`
- `/cobros.js`
- `/private.css`
- `/api/private/billing`
- cualquier subruta de `/api/private/billing/`

La normalización cubre URL codificada, barras repetidas y diferencias de mayúsculas/minúsculas. El dashboard público no contiene enlaces, copy ni llamadas a APIs privadas de cobros. El módulo privado permanece en el backend/repositorio para una futura superficie separada y autenticada; no debe publicarse en la URL pública de BOQA.

### Cloudflare preview

- `PR=20`
- `BRANCH=deploy/boqa-cloudflare-preview-v4`
- `HEAD_SHA=6727a171d208db85a7d5511216076e3e1671dc02`
- `WORKERS_BUILDS_RUN=29695897188` — SUCCESS
- `CONFIG_GATE_RUN=29696143600` — SUCCESS
- `REAL_DOCKER_RUN=29696143586` — SUCCESS
- `BROWSER_SMOKE_RUN=29696143594` — SUCCESS
- Workers Builds está conectado sólo para preview.
- `PRODUCTION_TRIGGER_COUNT=0`

### Backend production preflight

- `PR=19`
- `BRANCH=deploy/boqa-backend-production-v1`
- `HEAD_SHA=22313cc54c5bd60fd46248dec9841e6c8effd101`
- `STATUS=BLOCKED`
- `BLOCKER=MISSING_BACKEND_SSH_OR_OCI_API_ACCESS`

## Secretos y accesos

El usuario declaró existentes, tanto en GitHub Actions como en Cloudflare:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`
- `DASHBOARD_PASSWORD`

No leer, imprimir ni documentar valores. Los nombres `BOQA_API_KEY` y `BOQA_HMAC_SECRET` fueron verificados en el handoff previo. El acceso remoto del backend sigue pendiente mediante una variante aceptada por PR #19.

## Reglas permanentes

- No validar terceros.
- No imprimir secretos.
- No trabajar directamente sobre `main`.
- `BOQA_RELEASE_SHA` debe coincidir con el SHA realmente desplegado.
- La URL pública no debe revelar Centro de Pagos, rutas privadas, datos financieros ni metadatos sensibles.
- Las rutas privadas deben responder `404` en el Worker público.
- No promover el `main` actual hasta integrar y validar este hardening.
- No declarar producción desplegada sin versión, deployment, tráfico, health, browser smoke y rollback state.
- Actualizar este archivo y el Google Doc canónico ante cada cambio material, deploy, rollback o incidente.

## Next exact action

1. Crear Draft PR desde `fix/boqa-public-private-boundary-v2` hacia `main` con head esperado `fcf1f4c453cd66a38ed2109e8426bdd81bf36f28`.
2. Exigir tests, Docker qualification, browser smoke y preview exacta.
3. Verificar que rutas y assets privados respondan `404` sin revelar su propósito.
4. Integrar primero este hardening si CI queda verde.
5. Rebasar o reconstruir PR #20 sobre el nuevo `main`, manteniendo cero trigger productivo.
6. Resolver el acceso remoto de PR #19 y completar el preflight del backend.
7. Promover únicamente una versión que incluya el hardening y completar validación productiva más rollback state.
