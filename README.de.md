<p align="center">
  <a href="README.md">English</a>
  &nbsp;·&nbsp;
  <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <img src="docs/assets/logo.png" width="180" alt="Agent Credential Bridge">
</p>

<h1 align="center">Agent Credential Bridge</h1>

<p align="center"><strong>Gib einem KI-Agenten die <em>Nutzung</em> eines Secrets — nie das Secret selbst.</strong></p>

<p align="center">
  Agenten sind stark im Werkzeuge-Benutzen und schwach im Geheimnisse-Hüten.<br>
  Dieser Broker injiziert Credentials an der Outbound-Grenze, nicht ins Modell.
</p>

<p align="center">
  <a href="https://github.com/ShredFred/bitwarden-agent-credential-bridge/releases"><img alt="Experimental release" src="https://img.shields.io/badge/release-experimental-ff6b00?style=for-the-badge"></a>
  <a href="LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-1f6feb?style=for-the-badge"></a>
  <a href="https://github.com/ShredFred/bitwarden-agent-credential-bridge/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ShredFred/bitwarden-agent-credential-bridge/ci.yml?branch=main&style=for-the-badge"></a>
  <img alt="Node.js 20+" src="https://img.shields.io/badge/node-%3E%3D20-339933?style=for-the-badge&logo=nodedotjs&logoColor=white">
</p>

<p align="center"><strong>Built with</strong></p>

<p align="center">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-000000?style=flat-square&logo=apple&logoColor=white">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black">
  <img alt="Secrets Manager" src="https://img.shields.io/badge/Secrets_Manager-486581?style=flat-square">
  <img alt="GitHub Actions" src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white">
</p>

<p align="center">
  <em>Löst über <strong>dein</strong> Secrets-Manager-Maschinenkonto auf. Kein Bitwarden-Produkt.</em>
</p>

<p align="center">
  <a href="README.md#how-it-works">How it works (EN)</a> ·
  <a href="docs/manifesto.md">Manifest</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="README.md#install-on-windows">Install</a>
</p>

---

## Was das ist

Ein fail-closed Credential-Broker für Coding-Agenten. Der Agent darf eine
erlaubte API aufrufen, ein Formular anmelden oder eine gepinnte SSH/FTP-Op
ausführen. Die Bridge injiziert das Credential an der Outbound-Grenze.
Passwörter, Tokens, Cookies und Session-Material bleiben im Bridge-Speicher.
Tauchen sie auf einer agentenlesbaren Fläche auf, schlagen Tests fehl.

Die Operatorin fügt einmal einen Bitwarden-Secrets-Manager-**Maschinen-Token**
in ein lokales Setup-Fenster ein. Danach arbeiten Agenten. Secrets nicht.

Ausführliche Diagramme, der Vergleich mit dem Bitwarden Agent Access SDK und
die Installationsschritte stehen in der [englischen README](README.md).

## Manifest

Agenten bekommen **Nutzung**, nicht Besitz. Policies sind Allow-Listen.
Nicht unterstützte Klassen scheitern geschlossen. Secrets fahren nie über
`process.env`. `authorization_ready` ist Evidenz, kein Slogan. Der Helper
bleibt vault-frei. Grenzen stehen öffentlich.

Lesen: [Agent Credential Manifesto](docs/manifesto.md).

## FAQ

**Ist das das Bitwarden Agent Access SDK?**
Nein. [Agent Access](https://github.com/bitwarden/agent-access) ist Bitwardens
offenes Protokoll (Noise-Tunnel, Pairing, optional `aac run` in die
Kind-Umgebung). Diese Bridge ist ein unabhängiger Research-Harness mit einer
anderen Injektionsgrenze. Details: [How it works](docs/how-it-works.md).

**Setzt ein SM-Unlock `authorization_ready` auf true?**
Nein.

**Wo liegt der Maschinen-Token?**
Windows DPAPI, macOS Keychain oder eine Linux-Datei mit Mode `0600` unter XDG.
Nie in Git, Chat oder Agent-`process.env`.

**Ist das produktionsreife Isolation?**
Nein. Experimental. Same-User-Prozessspeicher ist keine Distinct-Writer-Grenze.

**Sicherheitslücke?**
Nur private Advisories:
[Security advisories](https://github.com/ShredFred/bitwarden-agent-credential-bridge/security/advisories/new).

## Disclaimer

Experimental, kein Hosted Service, kein Bitwarden-Produkt. Du kontrollierst
Vault und Agent. Keine Marken-Endorsement. Apache-2.0, ohne Gewähr. Siehe
[Trademark](docs/trademark.md) und die [englische README](README.md#disclaimer).

## Über den Autor

[Frederik Stadler](https://www.linkedin.com/in/frederikstadler) (GitHub
[ShredFred](https://github.com/ShredFred)), Berlin. Operations, Systeme,
Automation. Dieses Repo ist ein persönliches Open-Source-Research-Projekt,
kein offizielles Produkt eines Arbeitgebers.

## License and trademark

Code: [Apache-2.0](LICENSE). Namen und Marken: [Trademark](docs/trademark.md).

## Let's connect

[![Website](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ShredFred/bitwarden-agent-credential-bridge)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/frederikstadler)
[![Discord](https://img.shields.io/badge/Discussions-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://github.com/ShredFred/bitwarden-agent-credential-bridge/discussions)
[![Email](https://img.shields.io/badge/Email-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:frederikstadler+bridge@gmail.com)

[Buy Me a Coffee](https://buymeacoffee.com/shredfred). Die öffentliche
Community läuft über **GitHub Discussions**, bis ein Discord-Invite steht.
