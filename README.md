# nova-e2e

Le cœur du chiffrement de bout en bout de [Nova Mail](https://mail.nova-corps.de) : un seul fichier, `nova-e2e-core.js`, environ 170 lignes, sans aucune dépendance.
*English below.*

## Pourquoi ce dépôt

Nova Mail promet qu’entre deux comptes Nova qui l’ont activé, le serveur ne peut pas lire les messages. Une promesse ne suffit pas : ce fichier est exactement celui que ton navigateur exécute, publié pour que chacun puisse le relire, le tester et signaler un problème.

Le reste de Nova Mail (l’application, le serveur) n’est pas public.

## Ce que fait le fichier

Tout se passe dans le navigateur, avec Web Crypto (intégré au navigateur) :

- Chaque compte a deux clés **P-256** : une pour recevoir (**ECDH**), une pour signer (**ECDSA**).
- Un message est chiffré avec une clé aléatoire K (**AES-256-GCM**). K est « emballée » pour chaque destinataire avec une clé éphémère (**ECDH + HKDF-SHA-256**) : seul ce destinataire peut la déballer.
- L’expéditeur signe le message, sauf depuis une adresse masquée, pour ne pas révéler qui il est.
- Les pièces jointes sont chiffrées avec K, et leur empreinte entre dans le contenu signé : personne ne peut les échanger.
- Les clés privées quittent l’appareil seulement chiffrées par une clé maîtresse, elle-même protégée par ton mot de passe (**PBKDF2-SHA-256, 310 000 itérations**) ou par ta clé de secours.
- Format versionné (`v: 1`).

## Ce que le serveur voit quand même

- Qui écrit à qui (adresses), la date, la taille du message et le nombre de pièces jointes.
- Un objet fixe : « Message chiffré (Nova Mail) ».
- Les mails échangés avec Gmail, Outlook… ne sont pas chiffrés de bout en bout.

## Vérifier que c’est bien le fichier utilisé par Nova Mail

Empreinte SHA-256 de `nova-e2e-core.js` (version 1) :

```
0bcc3e12a4bc5eee8ebe7d94cdb567cbdc718121116545ea800569b1a2d846ee
```

Compare-la avec le fichier servi par le site :

```
# Linux / macOS
curl -s "https://mail.nova-corps.de/nova-e2e-core.js?v=1" | shasum -a 256

# Windows (PowerShell)
Invoke-WebRequest "https://mail.nova-corps.de/nova-e2e-core.js?v=1" -OutFile core.js; Get-FileHash core.js -Algorithm SHA256
```

## Lancer les tests

Node.js 20 ou plus récent :

```
npm test
```

## Limites, en toute honnêteté

- **Pas encore d’audit** : ce code n’a pas été vérifié par un expert indépendant.
- **Application web** : comme pour toute messagerie web, le serveur pourrait en théorie envoyer un jour une version modifiée de ce fichier. Publier le code et son empreinte permet de le remarquer, pas de l’empêcher.

## Signaler une faille

Écris à l’adresse indiquée dans [security.txt](https://mail.nova-corps.de/.well-known/security.txt), avec « Sécurité » en objet. Merci de ne rien publier avant la correction.

## Licence

MIT, voir [LICENSE](LICENSE).

---

## English

The end-to-end encryption core of [Nova Mail](https://mail.nova-corps.de): a single file, `nova-e2e-core.js`, about 170 lines, no dependencies. This is exactly the file your browser runs, published so anyone can review it, test it and report problems. The rest of Nova Mail (app and server) is not public.

**What it does** (Web Crypto, in the browser): two **P-256** keys per account (**ECDH** to receive, **ECDSA** to sign); each message encrypted with a random key K (**AES-256-GCM**); K wrapped for each recipient with an ephemeral key (**ECDH + HKDF-SHA-256**); messages signed except from masked addresses; attachments encrypted with K and bound to the signed content; private keys leave the device only encrypted under a master key protected by your password (**PBKDF2-SHA-256, 310,000 iterations**) or your recovery key. Versioned format (`v: 1`).

**What the server still sees:** who writes to whom, the date, message size and number of attachments, and a fixed subject (“Message chiffré (Nova Mail)”). Emails exchanged with Gmail, Outlook, etc. are not end-to-end encrypted.

**Verify the file served by Nova Mail:** its SHA-256 must be `0bcc3e12a4bc5eee8ebe7d94cdb567cbdc718121116545ea800569b1a2d846ee` (see the commands above).

**Tests:** `npm test` (Node.js 20+).

**Limits:** no independent audit yet; as with any web-based email, the server could in theory serve a modified file one day. Publishing the code and its hash makes that detectable, not impossible.

**Report a vulnerability:** see [security.txt](https://mail.nova-corps.de/.well-known/security.txt). Please don’t publish before a fix.

**License:** MIT.
