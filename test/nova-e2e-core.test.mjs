import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
// Empreinte recalculée indépendamment (même formule que le serveur de Nova Mail).
const serverFp=(pub)=>createHash('sha256').update(JSON.stringify(['nova-e2e-fp-v1',pub.enc.x,pub.enc.y,pub.sig.x,pub.sig.y])).digest('hex');
const ctx={crypto:globalThis.crypto,TextEncoder,TextDecoder,btoa,atob,Uint8Array,JSON,Error,Object,Array,String,Number,Date,console};ctx.globalThis=ctx;
vm.runInNewContext(readFileSync(new URL('../nova-e2e-core.js',import.meta.url),'utf8'),ctx);
const E=ctx.NovaE2ECore;
async function account(){const id=await E.createIdentity();return {...id,keys:await E.importPrivate(id.priv)}}

test('empreinte identique navigateur / serveur ; paquet privé ouvrable avec mot de passe et clé de secours',async()=>{
  const a=await account();
  assert.equal(a.fp,serverFp(JSON.parse(JSON.stringify(a.pub))));
  const M=E.rand(32),pkg=await E.sealPkg(M,a.priv);
  const pw=await E.wrapMaster(M,'mot de passe',10000),rk=await E.wrapMaster(M,'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',10000);
  for(const [w,s] of [[pw,'mot de passe'],[rk,'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567']]){const m2=await E.unwrapMaster(w,s);assert.deepEqual(JSON.parse(JSON.stringify(await E.openPkg(m2,pkg))),JSON.parse(JSON.stringify(a.priv)))}
  await assert.rejects(E.unwrapMaster(pw,'faux'));
  assert.ok(pkg.ct.length<4000);
});
test('Alice → Bob : Bob lit, signature vérifiée ; Carol ne peut pas lire ; pièce jointe chiffrée',async()=>{
  const alice=await account(),bob=await account(),carol=await account();
  const r=await E.encryptMessage({from:'alice@nova-corps.de',subject:'Secret',text:'Bonjour Bob é ✓',html:'<b>Bonjour</b>',atts:[{name:'photo.png',type:'image/png',size:3}],recipients:[{fp:bob.fp,pub:bob.pub}],signer:{fp:alice.fp,sigKey:alice.keys.sigKey}});
  assert.ok(E.isArmored(r.armor));assert.equal(r.armor.includes('Secret'),false);assert.equal(r.armor.includes('Bonjour'),false);
  const piece=await E.encryptAttachment(r.K,r.meta,0,new Uint8Array([1,2,3]));
  const env=E.parseArmor(r.armor.replace(/\n/g,'\r\n'));
  const got=await E.openEnvelope(env,{fp:bob.fp,encKey:bob.keys.encKey});
  assert.equal(got.body.subject,'Secret');assert.equal(got.body.text,'Bonjour Bob é ✓');assert.equal(got.body.html,'<b>Bonjour</b>');assert.equal(got.body.atts[0].name,'photo.png');
  assert.deepEqual([...await E.decryptAttachment(got.K,got.body.atts,0,piece)],[1,2,3]);
  await assert.rejects(E.decryptAttachment(got.K,got.body.atts,1-1,piece.map((x,i)=>i===0?x^1:x)),'pièce modifiée refusée');
  assert.equal(await E.verifyEnvelope(env,alice.pub,'Alice@nova-corps.de'),true);
  assert.equal(await E.verifyEnvelope(env,carol.pub,'alice@nova-corps.de'),false,'mauvaise clé');
  assert.equal(await E.verifyEnvelope(env,alice.pub,'carol@nova-corps.de'),false,'adresse usurpée');
  const tampered={...env,from:'carol@nova-corps.de'};assert.equal(await E.verifyEnvelope(tampered,alice.pub,'carol@nova-corps.de'),false);
  await assert.rejects(E.openEnvelope(env,{fp:carol.fp,encKey:carol.keys.encKey}),e=>e.code==='nokey');
  await assert.rejects(E.openEnvelope({...env,rcpt:[{...env.rcpt[0],fp:carol.fp}]},{fp:carol.fp,encKey:carol.keys.encKey}),'carol ne peut pas déballer la clé de bob');
});
test('adresse masquée : pas de signature ni d’empreinte ; une réponse qui cite le bloc n’est pas prise pour lui',async()=>{
  const bob=await account();
  const r=await E.encryptMessage({from:'x1@nova-corps.de',subject:'s',text:'t',recipients:[{fp:bob.fp,pub:bob.pub}],signer:null});
  assert.equal(r.env.sig,undefined);assert.equal(r.env.sfp,undefined);
  assert.equal(E.isArmored('Merci !\n\n> '+r.armor),false);
  assert.equal(E.parseArmor('bonjour'),null);
  assert.ok(E.parseArmor(r.armor.replace('chiffré','chiffrÃ©')),'accent abîmé par un serveur : toujours lisible');
  assert.equal(E.isArmored('Merci\n> Nova Mail\n'+r.armor.slice(r.armor.indexOf(E.BEGIN))),false);
  // Pièce jointe signée : un autre destinataire (qui connaît K) ne peut pas la remplacer.
  const carol=await account();
  const s2=await E.encryptMessage({from:'a@nova-corps.de',subject:'s',text:'t',atts:[{name:'f',bytes:new Uint8Array([1,2])}],recipients:[{fp:bob.fp,pub:bob.pub},{fp:carol.fp,pub:carol.pub}],signer:null});
  const g=await E.openEnvelope(E.parseArmor(s2.armor),{fp:carol.fp,encKey:carol.keys.encKey});
  assert.deepEqual([...await E.decryptAttachment(g.K,g.body.atts,0,s2.encAtts[0])],[1,2]);
  const evil=await E.encryptAttachment(g.K,g.body.atts,0,new Uint8Array([6,6,6]));
  await assert.rejects(E.decryptAttachment(g.K,g.body.atts,0,evil),/modifiée/);
  assert.equal(E.prettyFp('ab'.repeat(32)),'ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB');
});
