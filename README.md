# 🛡️ WPScan Segurança

Scanner de **vulnerabilidades para WordPress** com análise passiva e não invasiva,
interface em **azul-marinho e branco**, proteção por **reCAPTCHA v3** e backend
serverless pronto para a **Vercel**.

> ⚠️ **Uso responsável:** utilize apenas em sites de sua propriedade ou com
> autorização explícita por escrito. O usuário precisa confirmar o aviso
> *"COMPREENDO QUE TENHO AUTORIZAÇÃO PARA ESCANEAR ESTE SITE."* antes de cada análise.

---

## ✨ O que ele faz

A varredura (toda no backend) avalia:

- 🔎 **Detecção de WordPress** e da versão (meta generator, `/wp-json/`, feed, `readme.html`)
- 📦 **Plugins** detectados — com consulta opcional à API oficial do WPScan
- 🕳️ **Arquivos sensíveis expostos** (`wp-config.php.bak`, `.env`, `debug.log`, backups)
- 📂 **Listagem de diretórios** habilitada
- 👤 **Enumeração de usuários** (API REST e `?author=`)
- 📡 **XML-RPC** habilitado (força bruta / DDoS por pingback)
- 🔐 **Cabeçalhos de segurança** ausentes (HSTS, CSP, X-Frame-Options, etc.)
- 🔒 **HTTPS** ausente

Para cada achado o sistema mostra **severidade**, **descrição**, **evidência**,
**a fonte com link de consulta** (WPScan, NVD/CVE, OWASP) e **orientação de
correção responsável**.

---

## 📁 Estrutura

```
.
├── index.html        # Frontend (HTML + CSS + JS, tema azul-marinho/branco)
├── api/
│   └── scan.js       # Backend serverless: reCAPTCHA + toda a lógica de varredura
├── package.json
├── vercel.json
├── .env.example
└── .gitignore
```

---

## 🚀 Deploy na Vercel

1. **Importe o repositório** em [vercel.com/new](https://vercel.com/new).
2. (Recomendado) Em **Settings → Environment Variables**, defina:
   - `RECAPTCHA_SECRET` → sua chave secreta do reCAPTCHA v3
   - `WPSCAN_API_TOKEN` *(opcional)* → token da [API do WPScan](https://wpscan.com/api) para dados de CVE em tempo real
3. Clique em **Deploy**. Pronto. ✅

> O domínio do deploy precisa estar registrado no painel do reCAPTCHA
> (https://www.google.com/recaptcha/admin) para a verificação funcionar.

### Rodando localmente

```bash
npm install -g vercel
vercel dev
```

Acesse `http://localhost:3000`.

---

## 🔑 reCAPTCHA v3

- **Chave do site (pública):** usada no `index.html` (já configurada).
- **Chave secreta:** usada **apenas no backend** (`api/scan.js`), via variável
  de ambiente `RECAPTCHA_SECRET`. O token enviado pelo navegador é validado no
  servidor antes da varredura, e requisições com score baixo são bloqueadas.

---

## ⚖️ Aviso legal

Ferramenta criada para fins **educacionais e de segurança defensiva**. A análise
é passiva (não explora falhas, apenas observa respostas públicas). Os resultados
são indicativos e **não substituem uma auditoria profissional**. Pratique
**divulgação responsável** ao reportar problemas em sites de terceiros.
