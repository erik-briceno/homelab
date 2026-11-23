#!/usr/bin/env python3
"""Genera los flujos de n8n de la red de casa.

Uso: python3 build.py config.json <salida_dir>

config.json (no se sube al repositorio: lleva el tema de ntfy y el secreto del webhook):
{
  "nas": "192.168.1.X",
  "ntfy_topic": "tema-secreto",
  "pause_secret": "texto-aleatorio",
  "threat_lists": [ids de las listas de amenazas en AdGuard],
  "bypass_list": id de la lista HaGeZi DoH/VPN/Proxy bypass
}
"""
import json, sys, uuid, pathlib

CFG = json.loads(pathlib.Path(sys.argv[1]).read_text())
OUT = pathlib.Path(sys.argv[2])
NAS, TOPIC = CFG["nas"], CFG["ntfy_topic"]
AG = f"http://{NAS}:3000"
PAUSE_PATH = f"red-pausar-{CFG['pause_secret']}"
PAUSE_URL = f"http://{NAS}:5678/webhook/{PAUSE_PATH}"
NSFW_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"
CRED = {"httpBasicAuth": {"id": "", "name": "AdGuard Home"}}


def nid():
    return str(uuid.uuid4())


def http(name, url, pos, auth=True, on_error=True, full=False, method="GET", body=None, text=False):
    p = {"url": url, "options": {"timeout": 20000}}
    if method != "GET":
        p["method"] = method
    if full:
        p["options"]["response"] = {"response": {"fullResponse": True, "neverError": True}}
    if text:
        p["options"]["response"] = {"response": {"responseFormat": "text"}}
    if body:
        p["sendBody"] = True
        p["specifyBody"] = "json"
        p["jsonBody"] = body
    if auth:
        p["authentication"] = "genericCredentialType"
        p["genericAuthType"] = "httpBasicAuth"
    n = {"parameters": p, "id": nid(), "name": name,
         "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2,
         "position": pos, "executeOnce": True}
    if on_error:
        n["onError"] = "continueRegularOutput"
    if auth:
        n["credentials"] = CRED
    return n


def code(name, js, pos):
    return {"parameters": {"jsCode": js}, "id": nid(), "name": name,
            "type": "n8n-nodes-base.code", "typeVersion": 2, "position": pos}


def ntfy(pos, name="Aviso al móvil (ntfy)"):
    return {"parameters": {
        "method": "POST", "url": "https://ntfy.sh",
        "sendBody": True, "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify({ topic: '" + TOPIC + "', title: $json.title, message: $json.message, priority: $json.priority, tags: $json.tags, actions: $json.actions || [] }) }}",
        "options": {"timeout": 10000}},
        "id": nid(), "name": name,
        "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "position": pos}


def schedule(name, rule, pos):
    return {"parameters": {"rule": {"interval": [rule]}}, "id": nid(), "name": name,
            "type": "n8n-nodes-base.scheduleTrigger", "typeVersion": 1.2, "position": pos}


def chain(nodes):
    c = {}
    for a, b in zip(nodes, nodes[1:]):
        c[a["name"]] = {"main": [[{"node": b["name"], "type": "main", "index": 0}]]}
    return c


def wf(name, nodes):
    return {"name": name, "nodes": nodes, "connections": chain(nodes),
            "settings": {"executionOrder": "v1", "timezone": "Europe/Madrid"}, "pinData": {}}


# Apps que se miden en el resumen y se pueden cortar desde el móvil.
# Las claves son los ids de "servicios bloqueados" de AdGuard Home.
APPS = {
    "tiktok": "TikTok", "instagram": "Instagram", "youtube": "YouTube", "discord": "Discord",
    "twitch": "Twitch", "roblox": "Roblox", "epic_games": "Fortnite/Epic", "minecraft": "Minecraft",
    "playstation": "PlayStation", "xboxlive": "Xbox", "steam": "Steam", "riot_games": "Riot Games",
    "leagueoflegends": "League of Legends", "valorant": "Valorant", "snapchat": "Snapchat",
    "netflix": "Netflix", "twitter": "X (Twitter)",
}

ANALIZAR = r"""
// Analiza AdGuard y el panel y devuelve un aviso por cada cosa nueva.
// La memoria entre ejecuciones (staticData) solo se guarda en ejecuciones automáticas.
const sd = $getWorkflowStaticData('global');
const now = Date.now();
const out = [];
const node = n => { try { return $(n).first().json; } catch (e) { return { error: String(e) }; } };

// 1. Servicios caídos o recuperados
sd.down = sd.down || {};
function salud(nombre, ok, detalle) {
  if (!ok && !sd.down[nombre]) {
    sd.down[nombre] = now;
    out.push({ title: `${nombre} no responde`, message: detalle, priority: 5, tags: ['rotating_light'] });
  } else if (ok && sd.down[nombre]) {
    const min = Math.max(1, Math.round((now - sd.down[nombre]) / 60000));
    delete sd.down[nombre];
    out.push({ title: `${nombre} vuelve a funcionar`, message: `Ha estado caído unos ${min} min.`, priority: 3, tags: ['white_check_mark'] });
  }
}
const estado = node('AdGuard: estado');
salud('AdGuard Home', estado.running === true && estado.protection_enabled !== false,
  estado.running === true ? 'La protección está desactivada.' : 'El DNS de casa no contesta: sin AdGuard no hay bloqueo de amenazas.');
const panel = node('Panel: estado');
salud('Panel Red de casa', !panel.error && (panel.statusCode || 200) < 500, 'El panel del puerto 8088 no contesta.');

// 2. Dominios peligrosos (Navegación segura + listas de amenazas)
const LISTAS_AMENAZAS = __THREAT_IDS__;
const LISTA_BYPASS = __BYPASS_ID__;
const log = (node('AdGuard: bloqueos').data || []);
const primera = !sd.lastTs;
const ultimo = sd.lastTs || '';
const nuevosLog = log.filter(e => e.time > ultimo);
if (log.length) sd.lastTs = log.reduce((m, e) => (e.time > m ? e.time : m), ultimo);
const quienEs = e => (e.client_info && e.client_info.name) || e.client;

sd.vistos = Object.fromEntries(Object.entries(sd.vistos || {}).filter(([, t]) => now - t < 3600e3));
const peligrosos = nuevosLog.filter(e => e.reason === 'FilteredSafeBrowsing' ||
  (e.rules || []).some(r => LISTAS_AMENAZAS.includes(r.filter_list_id)));
if (!primera) {
  const nuevos = [];
  for (const e of peligrosos) {
    const clave = `${e.client}|${e.question.name}`;
    if (sd.vistos[clave]) continue;
    sd.vistos[clave] = now;
    nuevos.push({ quien: quienEs(e), dominio: e.question.name, tipo: e.reason === 'FilteredSafeBrowsing' ? 'phishing o malware' : 'lista de amenazas' });
  }
  for (const n of nuevos.slice(0, 5)) {
    out.push({ title: 'Web peligrosa bloqueada', message: `${n.quien} intentó entrar en ${n.dominio} (${n.tipo}). AdGuard lo ha bloqueado.`, priority: 4, tags: ['warning'] });
  }
  if (nuevos.length > 5) out.push({ title: 'Más bloqueos peligrosos', message: `Y ${nuevos.length - 5} más en los últimos minutos. Revisa el registro de AdGuard.`, priority: 4, tags: ['warning'] });
}

// 3. Intentos de saltarse el filtro: DNS cifrado externo o VPN (un aviso por dispositivo y dominio al día)
const RUTINA = ['doh.dns.apple.com'];  // los iPhone lo consultan solos, no es un intento de saltarse nada
sd.bypass = Object.fromEntries(Object.entries(sd.bypass || {}).filter(([, t]) => now - t < 24 * 3600e3));
if (!primera) {
  for (const e of nuevosLog) {
    if (!(e.rules || []).some(r => r.filter_list_id === LISTA_BYPASS)) continue;
    if (RUTINA.includes(e.question.name)) continue;
    const clave = `${e.client}|${e.question.name}`;
    if (sd.bypass[clave]) continue;
    sd.bypass[clave] = now;
    out.push({ title: 'Posible intento de saltarse el filtro', message: `${quienEs(e)} ha intentado usar ${e.question.name} (DNS alternativo o VPN). AdGuard lo ha bloqueado.`, priority: 4, tags: ['detective'] });
  }
}

// 4. Dispositivos nuevos en la red (solo IPv4 de la LAN)
const cl = node('AdGuard: clientes');
const ips = [
  ...(cl.auto_clients || []).map(c => ({ ip: c.ip, nombre: c.name, origen: c.source })),
  ...(cl.clients || []).flatMap(c => (c.ids || []).map(ip => ({ ip, nombre: c.name, origen: 'cliente guardado' }))),
].filter(c => /^192\.168\.\d+\.\d+$/.test(c.ip));
if (ips.length) {
  const conocidos = new Set(sd.conocidos || []);
  if (sd.conocidos) {
    for (const c of ips) if (!conocidos.has(c.ip)) {
      out.push({ title: 'Dispositivo nuevo en la red', message: `${c.nombre || 'Sin nombre'} (${c.ip}) ha aparecido en la wifi de casa. Detectado por ${c.origen || 'AdGuard'}.`, priority: 4, tags: ['iphone'] });
    }
  }
  ips.forEach(c => conocidos.add(c.ip));
  sd.conocidos = [...conocidos];
}

return out.map(json => ({ json }));
"""

RESUMEN = r"""
// Resumen de las últimas 24 h a partir del registro de consultas de AdGuard.
const LISTAS_AMENAZAS = __THREAT_IDS__;
const APPS = __APPS__;
const PAUSE_URL = '__PAUSE_URL__';

const cl = $('AdGuard: clientes').first().json;
const log = $('AdGuard: registro').first().json.data || [];
const servicios = $('AdGuard: servicios').first().json.blocked_services || [];
const nsfwTxt = $('Lista +18 (HaGeZi)').first().json.data || '';

const nombres = {};
(cl.clients || []).forEach(c => (c.ids || []).forEach(ip => { nombres[ip] = c.name; }));
const nombre = ip => nombres[ip] || ip;

const desde = Date.now() - 24 * 3600e3;
const hoy = log.filter(e => Date.parse(e.time) >= desde);

// Totales
const consultas = hoy.length;
const bloqueadas = hoy.filter(e => /^Filtered/.test(e.reason)).length;
const amenazas = hoy.filter(e => e.reason === 'FilteredSafeBrowsing' ||
  (e.rules || []).some(r => LISTAS_AMENAZAS.includes(r.filter_list_id))).length;
const pct = consultas ? ((bloqueadas / consultas) * 100).toFixed(1) : '0';

// Busca un dominio y sus dominios padre en un Map o Set (a.b.tiktok.com -> b.tiktok.com -> tiktok.com)
function buscar(nombreDominio, mapa) {
  const partes = nombreDominio.toLowerCase().replace(/\.$/, '').split('.');
  for (let i = 0; i < partes.length - 1; i++) {
    const d = partes.slice(i).join('.');
    if (mapa.has(d)) return mapa.get ? mapa.get(d) : d;
  }
  return null;
}

// Webs +18: solo un número total y anónimo (visitas = dispositivo + dominio + hora distintos)
const nsfw = new Set(nsfwTxt.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')));
const visitas18 = new Set();
for (const e of hoy) {
  const d = nsfw.size ? buscar(e.question.name, nsfw) : null;
  if (d) visitas18.add(`${e.client}|${d}|${e.time.slice(0, 13)}`);
}

// Uso aproximado de apps: franjas de 5 min con al menos 3 consultas a esa app (filtra el tráfico de fondo)
const dominioApp = new Map();
for (const s of servicios) {
  if (!APPS[s.id]) continue;
  for (const r of s.rules) {
    const m = r.match(/^\|\|([a-z0-9.\-]+)\^/);
    if (m && !dominioApp.has(m[1])) dominioApp.set(m[1], s.id);
  }
}
const franjas = {};
for (const e of hoy) {
  const app = buscar(e.question.name, dominioApp);
  if (!app) continue;
  const k = `${e.client}|${app}|${Math.floor(Date.parse(e.time) / 300000)}`;
  franjas[k] = (franjas[k] || 0) + 1;
}
const uso = {};      // uso[ip][app] = minutos
const usoCasa = {};  // usoCasa[app] = minutos
for (const [k, n] of Object.entries(franjas)) {
  if (n < 3) continue;
  const [ip, app] = k.split('|');
  uso[ip] = uso[ip] || {};
  uso[ip][app] = (uso[ip][app] || 0) + 5;
  usoCasa[app] = (usoCasa[app] || 0) + 5;
}
const fmt = m => (m >= 60 ? `${Math.floor(m / 60)} h${m % 60 ? ' ' + (m % 60) + ' min' : ''}` : `${m} min`);
const lineas = Object.entries(uso)
  .map(([ip, apps]) => [ip, apps, Object.values(apps).reduce((a, b) => a + b, 0)])
  .sort((a, b) => b[2] - a[2]).slice(0, 6)
  .map(([ip, apps]) => '· ' + nombre(ip) + ': ' + Object.entries(apps).sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([app, m]) => `${APPS[app]} ${fmt(m)}`).join(', '));

const top = Object.entries(usoCasa).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([app]) => app);
const actions = top.map(app => ({
  action: 'http', label: `Cortar ${APPS[app]} 1 h`, url: PAUSE_URL, method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ app, min: 60 }), clear: false,
}));

const msg = [
  `Consultas: ${consultas} · bloqueadas: ${bloqueadas} (${pct} %) · amenazas: ${amenazas}`,
  `Webs +18 en casa: ${visitas18.size ? visitas18.size + ' visitas (sin detalle)' : 'ninguna'}`,
  '',
  lineas.length ? 'Uso aproximado de apps:\n' + lineas.join('\n') : 'Sin uso de apps destacable.',
].join('\n');

return [{ json: { title: 'Resumen de la red (24 h)', message: msg, priority: 2, tags: ['bar_chart'], actions } }];
"""

PAUSA_PREPARAR = r"""
// Recibe {app, min} desde el botón del aviso y prepara la lista de servicios bloqueados con la app añadida.
const APPS = __APPS__;
const body = $('Botón del móvil').first().json.body || {};
const app = String(body.app || '');
const min = Math.min(Math.max(parseInt(body.min, 10) || 60, 5), 480);
if (!APPS[app]) throw new Error(`App no permitida: ${app}`);
const actual = $('AdGuard: bloqueadas ahora').first().json;
const ids = [...new Set([...(actual.ids || []), app])];
return [{ json: { app, nombre: APPS[app], min, update: { ids, schedule: actual.schedule || { time_zone: 'Europe/Madrid' } } } }];
"""

PAUSA_QUITAR = r"""
// Pasado el tiempo, quita la app de la lista de servicios bloqueados.
const p = $('Preparar corte').first().json;
const actual = $('AdGuard: bloqueadas después').first().json;
const ids = (actual.ids || []).filter(id => id !== p.app);
return [{ json: { ...p, update: { ids, schedule: actual.schedule || { time_zone: 'Europe/Madrid' } } } }];
"""


def build():
    threat = json.dumps(CFG["threat_lists"])
    bypass = json.dumps(CFG["bypass_list"])
    apps = json.dumps(APPS, ensure_ascii=False)

    alertas = wf("Red de casa · Alertas", [
        schedule("Cada 5 minutos", {"field": "minutes", "minutesInterval": 5}, [0, 0]),
        http("AdGuard: estado", f"{AG}/control/status", [220, 0]),
        http("AdGuard: bloqueos", f"{AG}/control/querylog?limit=500&response_status=blocked", [440, 0]),
        http("AdGuard: clientes", f"{AG}/control/clients", [660, 0]),
        http("Panel: estado", f"http://{NAS}:8088/", [880, 0], auth=False, full=True),
        code("Analizar", ANALIZAR.replace("__THREAT_IDS__", threat).replace("__BYPASS_ID__", bypass), [1100, 0]),
        ntfy([1320, 0]),
    ])

    resumen = wf("Red de casa · Resumen diario", [
        schedule("Cada noche 22:00", {"field": "days", "triggerAtHour": 22}, [0, 0]),
        http("AdGuard: clientes", f"{AG}/control/clients", [220, 0], on_error=False),
        http("AdGuard: registro", f"{AG}/control/querylog?limit=20000&response_status=all", [440, 0], on_error=False),
        http("AdGuard: servicios", f"{AG}/control/blocked_services/all", [660, 0], on_error=False),
        http("Lista +18 (HaGeZi)", NSFW_URL, [880, 0], auth=False, text=True),
        code("Preparar resumen", RESUMEN.replace("__THREAT_IDS__", threat).replace("__APPS__", apps)
             .replace("__PAUSE_URL__", PAUSE_URL), [1100, 0]),
        ntfy([1320, 0]),
    ])

    webhook = {"parameters": {"httpMethod": "POST", "path": PAUSE_PATH, "responseMode": "onReceived", "options": {}},
               "id": nid(), "name": "Botón del móvil", "type": "n8n-nodes-base.webhook",
               "typeVersion": 2, "position": [0, 0], "webhookId": nid()}
    put_body = "={{ JSON.stringify($json.update) }}"
    aviso_corte = code("Texto: cortada", "const p = $('Preparar corte').first().json;\n"
                       "return [{ json: { title: `${p.nombre} cortado ${p.min} min`, message: `Bloqueado en toda la casa. Volverá a funcionar solo a las ${new Date(Date.now() + p.min * 60000).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Madrid' })}.`, priority: 3, tags: ['no_entry'] } }];", [880, 0])
    espera = {"parameters": {"resume": "timeInterval", "amount": "={{ $('Preparar corte').first().json.min }}", "unit": "minutes"},
              "id": nid(), "name": "Esperar", "type": "n8n-nodes-base.wait", "typeVersion": 1.1,
              "position": [1320, 0], "webhookId": nid()}
    aviso_vuelta = code("Texto: vuelve", "const p = $('Preparar corte').first().json;\n"
                        "return [{ json: { title: `${p.nombre} vuelve a funcionar`, message: 'Se ha terminado el corte.', priority: 2, tags: ['white_check_mark'] } }];", [2200, 0])
    pausa = wf("Red de casa · Cortar app", [
        webhook,
        http("AdGuard: bloqueadas ahora", f"{AG}/control/blocked_services/get", [220, 0], on_error=False),
        code("Preparar corte", PAUSA_PREPARAR.replace("__APPS__", apps), [440, 0]),
        http("AdGuard: bloquear", f"{AG}/control/blocked_services/update", [660, 0], on_error=False, method="PUT", body=put_body),
        aviso_corte,
        ntfy([1100, 0], "Aviso: cortada"),
        espera,
        http("AdGuard: bloqueadas después", f"{AG}/control/blocked_services/get", [1540, 0], on_error=False),
        code("Quitar corte", PAUSA_QUITAR, [1760, 0]),
        http("AdGuard: desbloquear", f"{AG}/control/blocked_services/update", [1980, 0], on_error=False, method="PUT", body=put_body),
        aviso_vuelta,
        ntfy([2420, 0], "Aviso: vuelve"),
    ])
    return {"red-alertas.json": alertas, "red-resumen.json": resumen, "red-cortar-app.json": pausa}


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for fname, w in build().items():
        (OUT / fname).write_text(json.dumps(w, ensure_ascii=False, indent=2))
    print("ok")
