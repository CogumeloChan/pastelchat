# PastelChat — versão corrigida

Esta versão corrige o endpoint de criação de conta/login e inclui `/api/health` + `render.yaml` para deploy do servidor e PostgreSQL.

## Importante
O PastelChat **não pode funcionar como somente HTML estático**: cadastro, login, banco, chat e chamadas precisam do `server.js`. Se o seu provedor publicou só a pasta `public`, o navegador mostrará `Failed to fetch`.

### Local com Docker
`docker compose up --build` e abra `http://localhost:3000`.

### Render
Use o arquivo `render.yaml` e siga `DEPLOY-RENDER.md`.
