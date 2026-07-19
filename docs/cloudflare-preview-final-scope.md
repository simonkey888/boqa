# Cloudflare preview final scope

This branch validates the exact release source `ede06de817d607e6717f6ea71f2e40aac68ea7a2` by uploading a Cloudflare Worker preview version only.

It must not create or modify a production deployment, change traffic percentages, deploy the backend, write secret values, or test third-party infrastructure.

The gate records the current production deployment as a rollback reference, verifies required Worker secret names, validates the source and Worker bundle, audits desktop and mobile preview rendering, and confirms the anonymous private billing boundary.

Do not merge this branch into `main`; close it after evidence is collected.
