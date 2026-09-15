# PastelChat v11 — correção de ligações

Principais mudanças:

- Ligações em grupo agora usam uma sala de chamada no WebSocket (`call-join` / `call-leave`).
- O servidor distribui a lista de participantes ativos da chamada.
- Cada participante cria conexões WebRTC ponto-a-ponto com todos os outros participantes, evitando o problema em que uma pessoa ouvia apenas parte do grupo.
- Negociação determinística para reduzir colisões de offer/answer.
- ICE candidates ficam em fila até existir `remoteDescription`.
- Reconexão simples quando um peer entra em estado `failed`.
- Áudio remoto usa elemento `<audio>` separado e não silenciado.
- Removido o bloco duplicado de handlers de câmera/tela/finalização que existia na v10.
- Câmera e compartilhamento de tela continuam em transceivers separados.

## TURN
A v11 continua funcionando com STUN e aceita TURN pela rota `/api/rtc-config` usando:

- `TURN_URL`
- `TURN_USERNAME`
- `TURN_CREDENTIAL`

Para redes móveis, CGNAT e alguns Wi‑Fis restritivos, TURN ainda é recomendado para máxima confiabilidade.
