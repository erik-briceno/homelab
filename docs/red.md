# Red y acceso

```mermaid
flowchart LR
    internet((Internet)) --> router[Router Digi<br/>TP-Link XGB430v Pro]
    router --> nas[NAS Ugreen DXP2800<br/>Docker]
    router --> lan[Dispositivos de casa]
    lan -- DNS --> adguard
    subgraph nas_docker [Contenedores en el NAS]
        adguard[AdGuard Home]
        umami[Umami]
        n8n[n8n]
        listmonk[Listmonk]
        cloudflared[Cloudflare Tunnel]
        tailscale[Tailscale]
    end
    nas --- nas_docker
    cf[Cloudflare] <-- túnel saliente --> cloudflared
    usuarios((Visitantes)) --> cf
    movil[iPhone] <-- WireGuard --> tailscale
```

## Dos formas de entrar desde fuera

| Vía | Para qué | Puertos abiertos en el router |
|---|---|---|
| Cloudflare Tunnel | Servicios públicos (Umami, webhooks de n8n, Listmonk) con HTTPS | Ninguno: el túnel sale desde el NAS |
| Tailscale | Acceso privado mío al panel del NAS y a la red de casa | Ninguno: conexión WireGuard punto a punto |

## Por qué así

- **Sin puertos abiertos.** El router no expone nada a Internet; se reduce la superficie de ataque.
- **Exit node.** Con Tailscale el móvil puede salir a Internet por la conexión de casa, útil en wifis públicas.
- **Un compose por servicio.** Cada servicio se levanta, actualiza o borra por separado sin tocar los demás.
- **Secretos fuera del repo.** Cada carpeta usa un `.env` local que no se sube; en el repo solo está `.env.example`.
