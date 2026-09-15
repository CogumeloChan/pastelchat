# Colocar o PastelChat no ar pelo Render

O erro **Failed to fetch** aparece quando a página consegue abrir, mas o navegador não consegue alcançar a API. O PastelChat precisa do servidor Node.js e do PostgreSQL; publicar apenas `public/index.html` não basta.

## Jeito recomendado

1. Crie um repositório no GitHub e coloque **todos os arquivos desta pasta** nele.
2. No Render, crie um **Blueprint** apontando para esse repositório. O arquivo `render.yaml` já configura o serviço Node + banco PostgreSQL.
3. Aguarde o deploy terminar.
4. Abra a URL do serviço Render, não o arquivo HTML diretamente.
5. Teste `https://SEU-ENDERECO/api/health`: deve aparecer `{"ok":true}`.
6. Depois crie a conta no PastelChat.

O Blueprint gera automaticamente o JWT secret e conecta o serviço ao Postgres.

> Se você estiver usando um host que só aceita sites estáticos, ele não vai executar `server.js`. Nesse caso, use um serviço de backend Node ou um provedor que suporte o Blueprint.

## Local

Com Docker:

```bash
docker compose up --build
```

Depois abra `http://localhost:3000`.
