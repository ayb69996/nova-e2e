// Nova Mail — chiffrement de bout en bout : la partie « calcul » (aucune interface, aucun réseau).
//
// Tout se passe dans le navigateur, avec Web Crypto (intégré au navigateur, rien à télécharger) :
//  - chaque compte a deux clés P-256 : une pour recevoir (ECDH), une pour signer (ECDSA) ;
//  - un message est chiffré avec une clé aléatoire K (AES-256-GCM), et K est « emballée » pour chaque
//    destinataire avec une clé éphémère (ECDH + HKDF-SHA-256) : seul le destinataire peut la déballer ;
//  - l'expéditeur signe le tout (sauf depuis une adresse masquée, pour ne pas révéler qui il est) ;
//  - les pièces jointes sont chiffrées avec la même clé K et partent sous le nom « piece-N.nova ».
// Format versionné (v:1) : on pourra changer d'algorithme plus tard sans casser les anciens messages.
(function (root) {
  'use strict';
  const C = root.crypto, S = C.subtle, te = new TextEncoder(), td = new TextDecoder();
  const EC = {name: 'ECDH', namedCurve: 'P-256'}, SIG = {name: 'ECDSA', namedCurve: 'P-256'};
  const BEGIN = '-----BEGIN NOVA E2E MESSAGE-----', END = '-----END NOVA E2E MESSAGE-----';
  const INTRO = 'Ce message est chiffré de bout en bout avec Nova Mail.';

  function b64u(bytes) {
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes); let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(s) {
    s = String(s || '').replace(/[^A-Za-z0-9_-]/g, '');
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  const rand = (n) => C.getRandomValues(new Uint8Array(n));
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const pubJwk = (j) => ({kty: 'EC', crv: 'P-256', x: j.x, y: j.y});

  async function fingerprint(pub) {
    return hex(await S.digest('SHA-256', te.encode(JSON.stringify(['nova-e2e-fp-v1', pub.enc.x, pub.enc.y, pub.sig.x, pub.sig.y]))));
  }
  // Empreinte lisible : 8 groupes de 4 caractères (assez pour comparer à voix haute).
  const prettyFp = (fp) => String(fp || '').slice(0, 32).toUpperCase().match(/.{4}/g)?.join(' ') || '';

  // Nouvelle identité : clés publiques à publier + parties privées (à chiffrer avant de quitter l'appareil).
  async function createIdentity() {
    const e = await S.generateKey(EC, true, ['deriveBits']), s = await S.generateKey(SIG, true, ['sign', 'verify']);
    const ej = await S.exportKey('jwk', e.privateKey), sj = await S.exportKey('jwk', s.privateKey);
    const pub = {v: 1, enc: pubJwk(ej), sig: pubJwk(sj)};
    return {pub, fp: await fingerprint(pub), priv: {enc: {x: ej.x, y: ej.y, d: ej.d}, sig: {x: sj.x, y: sj.y, d: sj.d}}};
  }
  // Clés privées utilisables mais NON exportables (même un script ne peut plus les recopier).
  async function importPrivate(priv) {
    const encKey = await S.importKey('jwk', {kty: 'EC', crv: 'P-256', ...priv.enc}, EC, false, ['deriveBits']);
    const sigKey = await S.importKey('jwk', {kty: 'EC', crv: 'P-256', ...priv.sig}, SIG, false, ['sign']);
    return {encKey, sigKey};
  }

  const aes = (raw, usages = ['encrypt', 'decrypt']) => S.importKey('raw', raw, {name: 'AES-GCM'}, false, usages);
  // Paquet privé : les clés privées chiffrées avec la clé maîtresse M (32 octets aléatoires).
  async function sealPkg(master, priv) {
    const iv = rand(12), ct = await S.encrypt({name: 'AES-GCM', iv, additionalData: te.encode('nova-e2e-pkg-v1')}, await aes(master), te.encode(JSON.stringify(priv)));
    return {v: 1, iv: b64u(iv), ct: b64u(ct)};
  }
  async function openPkg(master, pkg) {
    const pt = await S.decrypt({name: 'AES-GCM', iv: unb64u(pkg.iv), additionalData: te.encode('nova-e2e-pkg-v1')}, await aes(master), unb64u(pkg.ct));
    return JSON.parse(td.decode(pt));
  }
  // M protégée par un secret (mot de passe, ou clé de secours) : PBKDF2-SHA-256 puis AES-GCM.
  async function kek(secret, salt, iter) {
    const base = await S.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return S.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  }
  async function wrapMaster(master, secret, iter = 310000) {
    const salt = rand(16), iv = rand(12);
    const ct = await S.encrypt({name: 'AES-GCM', iv, additionalData: te.encode('nova-e2e-wrap-v1')}, await kek(secret, salt, iter), master);
    return {v: 1, iter, salt: b64u(salt), iv: b64u(iv), ct: b64u(ct)};
  }
  async function unwrapMaster(w, secret) {
    const pt = await S.decrypt({name: 'AES-GCM', iv: unb64u(w.iv), additionalData: te.encode('nova-e2e-wrap-v1')}, await kek(secret, unb64u(w.salt), w.iter), unb64u(w.ct));
    return new Uint8Array(pt);
  }

  async function wrapKeyFor(ephPriv, ephPubJwk, recipientEncPub, fp) {
    const pubKey = await S.importKey('jwk', pubJwk(recipientEncPub), EC, false, []);
    const bits = await S.deriveBits({name: 'ECDH', public: pubKey}, ephPriv, 256);
    const hk = await S.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    return S.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: te.encode('nova-e2e-v1'), info: te.encode('wrap|' + fp + '|' + ephPubJwk.x + '|' + ephPubJwk.y)}, hk, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  }
  const sigData = (env) => te.encode(JSON.stringify(['nova-e2e-sig-v1', env.from, env.sfp || '', env.eph.x, env.eph.y, env.rcpt, env.iv, env.ct]));
  const attAad = (i) => te.encode('nova-e2e-att-v1|' + i);
  const attName = (i) => 'piece-' + (i + 1) + '.nova';

  // Chiffre un message. recipients : [{fp, pub}] ; signer : {fp, sigKey} ou null (adresse masquée).
  // atts : [{name, type, size, bytes?}]. Avec bytes, la pièce est chiffrée ici et son empreinte (SHA-256 du
  // chiffré) entre dans le contenu signé : personne, même un autre destinataire, ne peut l'échanger.
  async function encryptMessage({from, subject, text, html, atts = [], recipients, signer}) {
    if (!recipients?.length) throw new Error('Aucun destinataire');
    const kRaw = rand(32), K = await aes(kRaw), eph = await S.generateKey(EC, true, ['deriveBits']);
    const ej = await S.exportKey('jwk', eph.publicKey);
    const meta = atts.map((a) => ({name: String(a.name || 'fichier'), type: String(a.type || 'application/octet-stream'), size: Number(a.size || 0), iv: b64u(rand(12))}));
    const encAtts = [];
    for (let i = 0; i < atts.length; i++) if (atts[i].bytes) {
      const c = await encryptAttachment(K, meta, i, atts[i].bytes);
      meta[i].h = hex(await S.digest('SHA-256', c)); meta[i].size = atts[i].bytes.length; encAtts[i] = c;
    }
    const body = {v: 1, from: String(from || '').toLowerCase(), subject: String(subject || ''), text: String(text || ''), ...(html ? {html: String(html)} : {}), atts: meta, date: new Date().toISOString()};
    const iv = rand(12), ct = await S.encrypt({name: 'AES-GCM', iv, additionalData: te.encode('nova-e2e-body-v1')}, K, te.encode(JSON.stringify(body)));
    const rcpt = [];
    for (const r of recipients) {
      const wk = await wrapKeyFor(eph.privateKey, ej, r.pub.enc, r.fp), wiv = rand(12);
      rcpt.push({fp: r.fp, iv: b64u(wiv), k: b64u(await S.encrypt({name: 'AES-GCM', iv: wiv}, wk, kRaw))});
    }
    const env = {v: 1, alg: 'p256-hkdf-aesgcm', from: body.from, eph: {x: ej.x, y: ej.y}, rcpt, iv: b64u(iv), ct: b64u(ct)};
    if (signer) { env.sfp = signer.fp; env.sig = b64u(await S.sign({name: 'ECDSA', hash: 'SHA-256'}, signer.sigKey, sigData(env))); }
    return {env, armor: armor(env), meta, K, attName, encAtts};
  }
  async function encryptAttachment(K, meta, i, bytes) {
    return new Uint8Array(await S.encrypt({name: 'AES-GCM', iv: unb64u(meta[i].iv), additionalData: attAad(i)}, K, bytes));
  }
  async function decryptAttachment(K, meta, i, bytes) {
    if (meta[i]?.h && hex(await S.digest('SHA-256', bytes)) !== meta[i].h) throw new Error('Pièce jointe modifiée : elle ne correspond pas au message signé.');
    return new Uint8Array(await S.decrypt({name: 'AES-GCM', iv: unb64u(meta[i].iv), additionalData: attAad(i)}, K, bytes));
  }

  function armor(env) {
    const data = b64u(te.encode(JSON.stringify(env))).match(/.{1,76}/g).join('\n');
    return INTRO + '\nPour le lire, ouvre-le dans Nova Mail : https://mail.nova-corps.de\n\n' + BEGIN + '\n' + data + '\n' + END + '\n';
  }
  // Seulement un message qui FINIT par le bloc, précédé de notre courte introduction (sans citation « > ») :
  // une réponse qui cite un message chiffré n'est pas prise pour le message cité.
  function isArmored(text) {
    const t = String(text || '').trim(), i = t.indexOf(BEGIN);
    if (i < 0 || !t.endsWith(END)) return false;
    const intro = t.slice(0, i);
    return intro.length <= 600 && intro.includes('Nova Mail') && !/^\s*>/m.test(intro);
  }
  function parseArmor(text) {
    if (!isArmored(text)) return null;
    const t = String(text).trim(), a = t.indexOf(BEGIN), b = t.lastIndexOf(END);
    try {
      const env = JSON.parse(td.decode(unb64u(t.slice(a + BEGIN.length, b))));
      const ok = env && env.v === 1 && env.eph && typeof env.eph.x === 'string' && typeof env.eph.y === 'string' && Array.isArray(env.rcpt) && typeof env.iv === 'string' && typeof env.ct === 'string';
      return ok ? env : null;
    } catch { return null; }
  }

  // Ouvre un message avec SES clés. Renvoie {body, K} ; erreur code 'nokey' si le message n'est pas pour cette clé.
  async function openEnvelope(env, me) {
    const mine = env.rcpt.find((r) => r && r.fp === me.fp);
    if (!mine) throw Object.assign(new Error('Ce message n’a pas été chiffré pour cette clé.'), {code: 'nokey'});
    const ephPub = await S.importKey('jwk', pubJwk(env.eph), EC, false, []);
    const bits = await S.deriveBits({name: 'ECDH', public: ephPub}, me.encKey, 256);
    const hk = await S.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
    const wk = await S.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: te.encode('nova-e2e-v1'), info: te.encode('wrap|' + me.fp + '|' + env.eph.x + '|' + env.eph.y)}, hk, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
    const kRaw = new Uint8Array(await S.decrypt({name: 'AES-GCM', iv: unb64u(mine.iv)}, wk, unb64u(mine.k)));
    const K = await aes(kRaw);
    const body = JSON.parse(td.decode(await S.decrypt({name: 'AES-GCM', iv: unb64u(env.iv), additionalData: te.encode('nova-e2e-body-v1')}, K, unb64u(env.ct))));
    if (!body || body.v !== 1) throw Object.assign(new Error('Contenu chiffré illisible.'), {code: 'bad'});
    body.atts = Array.isArray(body.atts) ? body.atts : [];
    return {body, K};
  }
  // Vérifie la signature avec la clé publique de l'expéditeur (et que l'adresse signée est bien la sienne).
  async function verifyEnvelope(env, pub, fromAddress) {
    if (!env.sig || !env.sfp || !pub) return false;
    if (String(fromAddress || '').toLowerCase() !== env.from) return false;
    if (await fingerprint(pub) !== env.sfp) return false;
    try {
      const k = await S.importKey('jwk', pubJwk(pub.sig), SIG, false, ['verify']);
      return await S.verify({name: 'ECDSA', hash: 'SHA-256'}, k, unb64u(env.sig), sigData(env));
    } catch { return false; }
  }

  root.NovaE2ECore = {b64u, unb64u, rand, fingerprint, prettyFp, createIdentity, importPrivate, sealPkg, openPkg, wrapMaster, unwrapMaster,
    encryptMessage, encryptAttachment, decryptAttachment, armor, isArmored, parseArmor, openEnvelope, verifyEnvelope, attName, INTRO, BEGIN, END};
})(typeof window !== 'undefined' ? window : globalThis);
