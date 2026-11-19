# Homelab · NAS Ugreen DXP2800

Servidor doméstico con Docker en un NAS Ugreen DXP2800. Lo uso para aprender administración de sistemas en un entorno real: contenedores, DNS, VPN y redes.

## Qué tengo funcionando

| Servicio | Qué hace | Puerto | Carpeta |
|---|---|---|---|
| [AdGuard Home](https://adguard.com/adguard-home/overview.html) | DNS de toda la red de casa con bloqueo de publicidad y rastreadores | 53 (DNS), 3000 (panel) | [`services/red-casa`](services/red-casa) |
| Panel "Red de casa" | Panel propio en Python (FastAPI + SQLite) para ver los dispositivos de la red y su actividad | 8088 | [`services/red-casa`](services/red-casa) |
| [Tailscale](https://tailscale.com) | VPN WireGuard: *exit node* y *subnet router* para entrar a casa desde el móvil | — | [`services/tailscale`](services/tailscale) |
| [n8n](https://n8n.io) | Automatizaciones y webhooks | 5678 | [`services/n8n`](services/n8n) |

Esquema de red, puertos y decisiones de diseño: [`docs/red.md`](docs/red.md).

## El panel "Red de casa"

AdGuard me dice qué dominios consulta cada IP, pero no qué dispositivo es cada IP. El panel lo resuelve:

- Lee la tabla ARP del NAS para relacionar IP y MAC de cada dispositivo.
- Usa los datos de AdGuard Home para mostrar la actividad DNS de cada uno.
- Guarda el histórico en SQLite y lo muestra en una web con contraseña.
- Se puede abrir desde el móvil fuera de casa gracias a Tailscale.

Corre sobre la imagen oficial `python:3.12-slim`: el código se monta como volumen de solo lectura y las dependencias se instalan al arrancar, así que no hay que construir imagen propia.

## Hardware

- **NAS:** Ugreen DXP2800 (2 bahías), Docker sobre UGOS
- **Red:** fibra Digi con router TP-Link XGB430v Pro
- **Acceso remoto:** Tailscale, sin puertos abiertos en el router

## Cómo levantar un servicio

```bash
cd services/red-casa
docker compose up -d
docker compose logs -f
```

Actualizar a la última imagen:

```bash
docker compose pull && docker compose up -d
```

## Seguridad

- Ningún puerto abierto en el router: el acceso desde fuera es solo por Tailscale.
- Credenciales en ficheros `.env` locales, excluidos con `.gitignore`.
- El código del panel se monta en solo lectura dentro del contenedor.
- La familia sabe que el DNS de casa registra las consultas.

## Próximos pasos

- [ ] Volver a levantar Umami (analítica web), Listmonk (newsletters) y Cloudflare Tunnel (publicar servicios con HTTPS)
- [ ] Copias de seguridad automáticas de los volúmenes
- [ ] Avisos con n8n cuando un contenedor se cae o el disco se llena
- [ ] Publicar el código del panel en este repositorio

---

Erik Briceño · Técnico en Sistemas Microinformáticos y Redes, estudiante de ASIX · [LinkedIn](https://www.linkedin.com/in/erik-briceno/)
