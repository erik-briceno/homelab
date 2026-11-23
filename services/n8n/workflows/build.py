#!/usr/bin/env python3
"""Genera los flujos de n8n de alertas de red.

Uso: python3 build.py <IP_DEL_NAS> <TEMA_NTFY> <salida_dir> '[ids de listas de amenazas]'
El tema de ntfy es secreto: no se sube al repositorio.
"""
import json, sys, uuid, pathlib

NAS, TOPIC, OUT = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
AG = f"http://{NAS}:3000"
CRED = {"httpBasicAuth": {"id": "", "name": "AdGuard Home"}}


def http(name, url, pos, auth=True, on_error=True, full=False):
    p = {"url": url, "options": {"timeout": 10000}}
    if full:
        p["options"]["response"] = {"response": {"fullResponse": True, "neverError": True}}
    if auth:
        p["authentication"] = "genericCredentialType"
        p["genericAuthType"] = "httpBasicAuth"
    n = {"parameters": p, "id": str(uuid.uuid4()), "name": name,
         "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2,
         "position": pos, "executeOnce": True}
    if on_error:
        n["onError"] = "continueRegularOutput"
    if auth:
        n["credentials"] = CRED
    return n


def code(name, js, pos):
    return {"parameters": {"jsCode": js}, "id": str(uuid.uuid4()), "name": name,
            "type": "n8n-nodes-base.code", "typeVersion": 2, "position": pos}


def ntfy(pos):
    return {"parameters": {
        "method": "POST", "url": "https://ntfy.sh",
        "sendBody": True, "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify({ topic: '" + TOPIC + "', title: $json.title, message: $json.message, priority: $json.priority, tags: $json.tags }) }}",
        "options": {"timeout": 10000}},
        "id": str(uuid.uuid4()), "name": "Aviso al móvil (ntfy)",
        "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "position": pos}


def schedule(name, rule, pos):
    return {"parameters": {"rule": {"interval": [rule]}}, "id": str(uuid.uuid4()), "name": name,
            "type": "n8n-nodes-base.scheduleTrigger", "typeVersion": 1.2, "position": pos}


def chain(nodes):
    c = {}
    for a, b in zip(nodes, nodes[1:]):
        c[a["name"]] = {"main": [[{"node": b["name"], "type": "main", "index": 0}]]}
    return c


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
const log = (node('AdGuard: bloqueos').data || []);
const primera = !sd.lastTs;
const ultimo = sd.lastTs || '';
sd.vistos = Object.fromEntries(Object.entries(sd.vistos || {}).filter(([, t]) => now - t < 3600e3));
const peligrosos = log.filter(e => e.time > ultimo && (
  e.reason === 'FilteredSafeBrowsing' ||
  (e.rules || []).some(r => LISTAS_AMENAZAS.includes(r.filter_list_id))));
if (log.length) sd.lastTs = log.reduce((m, e) => (e.time > m ? e.time : m), ultimo);
if (!primera) {
  const nuevos = [];
  for (const e of peligrosos) {
    const quien = (e.client_info && e.client_info.name) || e.client;
    const clave = `${e.client}|${e.question.name}`;
    if (sd.vistos[clave]) continue;
    sd.vistos[clave] = now;
    nuevos.push({ quien, dominio: e.question.name, tipo: e.reason === 'FilteredSafeBrowsing' ? 'phishing o malware' : 'lista de amenazas' });
  }
  for (const n of nuevos.slice(0, 5)) {
    out.push({ title: 'Web peligrosa bloqueada', message: `${n.quien} intentó entrar en ${n.dominio} (${n.tipo}). AdGuard lo ha bloqueado.`, priority: 4, tags: ['warning'] });
  }
  if (nuevos.length > 5) out.push({ title: 'Más bloqueos peligrosos', message: `Y ${nuevos.length - 5} más en los últimos minutos. Revisa el registro de AdGuard.`, priority: 4, tags: ['warning'] });
}

// 3. Dispositivos nuevos en la red (solo IPv4 de la LAN)
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
// Las estadísticas de AdGuard vienen por horas (24 h) o por días (30 días).
// Para el resumen de hoy cojo la última hora x24 o el último día.
const s = $('AdGuard: estadísticas').first().json;
const cl = $('AdGuard: clientes').first().json;
const nombres = {};
(cl.clients || []).forEach(c => (c.ids || []).forEach(ip => { nombres[ip] = c.name; }));
const horas = s.time_units === 'hours';
const hoy = a => (horas ? (a || []).slice(-24) : (a || []).slice(-1)).reduce((x, y) => x + y, 0);
const consultas = hoy(s.dns_queries);
const bloqueadas = hoy(s.blocked_filtering);
const peligrosas = hoy(s.replaced_safebrowsing);
const pct = consultas ? ((bloqueadas / consultas) * 100).toFixed(1) : '0';
const top = (s.top_clients || [])[0];
const ip = top ? Object.keys(top)[0] : null;
const topTxt = ip ? `${nombres[ip] || ip} (${Object.values(top)[0]} consultas)` : 'sin datos';
const dom = (s.top_blocked_domains || [])[0];
const domTxt = dom ? Object.keys(dom)[0] : 'ninguno';
const periodo = horas ? '24 h' : '30 días';
return [{ json: {
  title: 'Resumen de la red de hoy',
  message: `Consultas DNS hoy: ${consultas}\nBloqueadas: ${bloqueadas} (${pct} %)\nAmenazas bloqueadas: ${peligrosas}\nDispositivo más activo (${periodo}): ${topTxt}\nDominio más bloqueado (${periodo}): ${domTxt}`,
  priority: 2, tags: ['bar_chart'] } }];
"""


def build(threat_ids):
    t = schedule("Cada 5 minutos", {"field": "minutes", "minutesInterval": 5}, [0, 0])
    a = http("AdGuard: estado", f"{AG}/control/status", [220, 0])
    b = http("AdGuard: bloqueos", f"{AG}/control/querylog?limit=500&response_status=blocked", [440, 0])
    c = http("AdGuard: clientes", f"{AG}/control/clients", [660, 0])
    d = http("Panel: estado", f"http://{NAS}:8088/", [880, 0], auth=False, full=True)
    e = code("Analizar", ANALIZAR.replace("__THREAT_IDS__", json.dumps(threat_ids)), [1100, 0])
    f = ntfy([1320, 0])
    alertas = {"name": "Red de casa · Alertas", "nodes": [t, a, b, c, d, e, f],
               "connections": chain([t, a, b, c, d, e, f]),
               "settings": {"executionOrder": "v1", "timezone": "Europe/Madrid"}, "pinData": {}}

    t2 = schedule("Cada noche 22:00", {"field": "days", "triggerAtHour": 22}, [0, 0])
    s = http("AdGuard: estadísticas", f"{AG}/control/stats", [220, 0], on_error=False)
    c2 = http("AdGuard: clientes", f"{AG}/control/clients", [440, 0], on_error=False)
    r = code("Preparar resumen", RESUMEN, [660, 0])
    f2 = ntfy([880, 0])
    resumen = {"name": "Red de casa · Resumen diario", "nodes": [t2, s, c2, r, f2],
               "connections": chain([t2, s, c2, r, f2]),
               "settings": {"executionOrder": "v1", "timezone": "Europe/Madrid"}, "pinData": {}}
    return alertas, resumen


if __name__ == "__main__":
    ids = json.loads(sys.argv[4]) if len(sys.argv) > 4 else []
    OUT.mkdir(parents=True, exist_ok=True)
    al, re_ = build(ids)
    (OUT / "red-alertas.json").write_text(json.dumps(al, ensure_ascii=False, indent=2))
    (OUT / "red-resumen.json").write_text(json.dumps(re_, ensure_ascii=False, indent=2))
    print("ok")
