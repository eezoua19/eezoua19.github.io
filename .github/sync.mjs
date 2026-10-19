// Copies what the admin published (signed config) and her encrypted replies
// from the ntfy.sh relay into site/config.json and site/replies.json.
// The relay only keeps messages for 12 hours; this runs every few minutes.
import fs from "node:fs";

const RELAY = process.env.RELAY_URL || "https://ntfy.sh/";
const CFG_TOPIC = "rdv-cfg-e63268770e8d0ae4f6c36f76";
const REPLY_TOPIC = "rdv-bf33f8acda41ab7dcd2c3bff";
const SIGN_PUB = {"kty": "EC", "crv": "P-256", "x": "n9pHuz7fSbzrqFOJS-k-kxuUw0gp9pvDCRB55IfL10I", "y": "IQuHGfYrjYeLf9t34z68rQz6fKH1lC1AHt9xfCJyahY"};
const CONFIG = "site/config.json", REPLIES = "site/replies.json", VOICES = "site/voices";

async function poll(topic) {
  const r = await fetch(RELAY + topic + "/json?poll=1&since=all");
  if (!r.ok) throw new Error(topic + ": HTTP " + r.status);
  return (await r.text()).split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)).filter((e) => e.event === "message");
}
const b64 = (t) => Uint8Array.from(Buffer.from(t, "base64"));
const key = await crypto.subtle.importKey("jwk", { ...SIGN_PUB, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

// 1. Config: keep the newest version that carries a valid admin signature
const current = JSON.parse(fs.readFileSync(CONFIG, "utf8"));
let best = current;
for (const ev of await poll(CFG_TOPIC)) {
  try {
    const m = JSON.parse(ev.message);
    if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64(m.s), new TextEncoder().encode(m.c)))) continue;
    const c = JSON.parse(m.c);
    if ((+c.updatedAt || 0) > (+best.updatedAt || 0)) best = c;
  } catch {}
}
if (best !== current) { fs.writeFileSync(CONFIG, JSON.stringify(best, null, 2) + "\n"); console.log("config.json updated", best.updatedAt); }

// 2. Replies: append new encrypted replies, drop the ones the admin deleted
const store = fs.existsSync(REPLIES) ? JSON.parse(fs.readFileSync(REPLIES, "utf8")) : { items: [] };
const before = JSON.stringify(store);
const deleted = new Set(best.deletedReplies || []);
for (const ev of await poll(REPLY_TOPIC)) {
  try {
    const m = JSON.parse(ev.message);
    if (!m.e || !m.iv || !m.c || !/^[A-Za-z0-9]+$/.test(ev.id) || deleted.has(ev.id)) continue;
    let item = store.items.find((x) => x.id === ev.id);
    if (!item) { item = { id: ev.id, time: ev.time, sealed: ev.message }; store.items.push(item); }
    // Encrypted voice message: the relay keeps the attachment for 3 hours only
    if (ev.attachment && ev.attachment.url && !item.voice && (ev.attachment.size || 0) < 8e6) {
      const r = await fetch(ev.attachment.url);
      if (r.ok) {
        fs.mkdirSync(VOICES, { recursive: true });
        fs.writeFileSync(`${VOICES}/${ev.id}.bin`, Buffer.from(await r.arrayBuffer()));
        item.voice = `voices/${ev.id}.bin`;
      }
    }
  } catch {}
}
for (const x of store.items) if (deleted.has(x.id) && x.voice) fs.rmSync(`site/${x.voice}`, { force: true });
store.items = store.items.filter((x) => !deleted.has(x.id)).slice(-500);
if (JSON.stringify(store) !== before) { fs.writeFileSync(REPLIES, JSON.stringify(store, null, 1) + "\n"); console.log("replies.json:", store.items.length, "replies"); }

// 3. Visits ("she opened the ticket"), encrypted like the replies
const VISITS = "site/visits.json";
const vstore = fs.existsSync(VISITS) ? JSON.parse(fs.readFileSync(VISITS, "utf8")) : { items: [] };
const vbefore = JSON.stringify(vstore);
for (const ev of await poll(REPLY_TOPIC + "-v")) {
  try {
    const m = JSON.parse(ev.message);
    if (!m.e || !m.iv || !m.c || !/^[A-Za-z0-9]+$/.test(ev.id) || vstore.items.some((x) => x.id === ev.id)) continue;
    vstore.items.push({ id: ev.id, time: ev.time, sealed: ev.message });
  } catch {}
}
vstore.items = vstore.items.slice(-300);
if (JSON.stringify(vstore) !== vbefore) { fs.writeFileSync(VISITS, JSON.stringify(vstore, null, 1) + "\n"); console.log("visits.json:", vstore.items.length, "visits"); }
