# Homelab · NAS Ugreen DXP2800

Servidor doméstico con Docker en un NAS Ugreen DXP2800. Lo uso para aprender administración de sistemas en un entorno real: contenedores, redes, DNS, VPN y publicación segura de servicios.

## Servicios

| Servicio | Qué hace | Carpeta |
|---|---|---|
| [Umami](https://umami.is) | Analítica web sin cookies | [`services/umami`](services/umami) |
| [n8n](https://n8n.io) | Automatizaciones y webhooks | [`services/n8n`](services/n8n) |
| [Listmonk](https://listmonk.app) | Listas de correo y newsletters | [`services/listmonk`](services/listmonk) |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) | Publica servicios con HTTPS sin abrir puertos | [`services/cloudflared`](services/cloudflared) |
| [Tailscale](https://tailscale.com) | VPN WireGuard y *exit node* para el móvil | [`services/tailscale`](services/tailscale) |
| [AdGuard Home](https://adguard.com/adguard-home/overview.html) | DNS de la red con bloqueo de publicidad | [`services/adguard`](services/adguard) |

Esquema de red y decisiones de diseño: [`docs/red.md`](docs/red.md).

## Hardware

- **NAS:** Ugreen DXP2800 (2 bahías), Docker sobre UGOS
- **Red:** fibra Digi con router TP-Link XGB430v Pro
- **Acceso remoto:** Tailscale (privado) y Cloudflare Tunnel (público)

## Cómo levantar un servicio

```bash
cd services/n8n
cp ../../.env.example .env   # rellena solo las variables de este servicio
docker compose up -d
docker compose logs -f
```

Actualizar a la última imagen:

```bash
docker compose pull && docker compose up -d
```

## Seguridad

- Ningún puerto abierto en el router: lo público entra por Cloudflare Tunnel y lo privado por Tailscale.
- Contraseñas y tokens en `.env` locales, excluidos con `.gitignore`.
- Bases de datos solo accesibles dentro de la red de Docker de cada servicio.

## Qué he aprendido

- Docker Compose: redes, volúmenes, variables de entorno y *healthchecks*.
- DNS: resolver de la red con AdGuard Home y diagnóstico de consultas.
- VPN: Tailscale con WireGuard y configuración de un *exit node*.
- Publicación segura: túneles de Cloudflare en vez de redirección de puertos.

## Próximos pasos

- [ ] Panel propio para ver la red de casa desde el móvil
- [ ] Copias de seguridad automáticas de los volúmenes
- [ ] Avisos con n8n cuando un contenedor se cae o el disco se llena

---

Erik Briceño · Técnico en Sistemas Microinformáticos y Redes, estudiante de ASIX · [LinkedIn](https://www.linkedin.com/in/erik-briceno/)
