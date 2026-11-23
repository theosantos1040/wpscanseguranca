// WPScan Segurança — Backend serverless (Vercel)
// Análise passiva e não invasiva de segurança para sites WordPress.
// Toda a lógica pesada roda aqui no servidor; o frontend só exibe os resultados.

// ---- Configuração ----------------------------------------------------------
// A chave secreta do reCAPTCHA DEVE ficar em variável de ambiente na Vercel.
// O valor padrão abaixo é apenas um fallback para funcionar "out of the box".
const RECAPTCHA_SECRET =
  process.env.RECAPTCHA_SECRET || '';

// Opcional: se você tiver um token da API oficial do WPScan, defina
// WPSCAN_API_TOKEN nas variáveis de ambiente para obter dados de CVE em tempo
// real. Sem ele, a ferramenta usa verificações próprias + links de consulta.
const WPSCAN_API_TOKEN = process.env.WPSCAN_API_TOKEN || '';

const RECAPTCHA_MIN_SCORE = 0.5;
const FETCH_TIMEOUT_MS = 8000;
const UA =
  'Mozilla/5.0 (compatible; WPScanSeguranca/1.0; +https://github.com/) Defensive-Security-Scanner';

// ---- Helpers ---------------------------------------------------------------
function timeoutFetch(url, opts = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), opts.timeout || FETCH_TIMEOUT_MS);
  return fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': UA, Accept: '*/*' },
    ...opts,
    signal: controller.signal,
  }).finally(() => clearTimeout(id));
}

function normalizeUrl(raw) {
  let u = String(raw || '').trim();
  if (!u) return null;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try {
    const parsed = new URL(u);
    // Bloqueia alvos internos/privados (SSRF básico).
    const host = parsed.hostname.toLowerCase();
    const blocked =
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host === '::1' ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      /^10\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^169\.254\./.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host);
    if (blocked) return { blocked: true };
    parsed.hash = '';
    return { url: parsed.origin, parsed };
  } catch {
    return null;
  }
}

async function verifyRecaptcha(token, ip) {
  if (!token) return { ok: false, reason: 'Token reCAPTCHA ausente.' };
  try {
    const body = new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token });
    if (ip) body.append('remoteip', ip);
    const r = await timeoutFetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      timeout: 6000,
    });
    const data = await r.json();
    if (!data.success) return { ok: false, reason: 'Falha na verificação do reCAPTCHA.' };
    if (typeof data.score === 'number' && data.score < RECAPTCHA_MIN_SCORE) {
      return { ok: false, reason: 'Atividade suspeita detectada (score baixo no reCAPTCHA).' };
    }
    return { ok: true, score: data.score };
  } catch {
    return { ok: false, reason: 'Não foi possível validar o reCAPTCHA.' };
  }
}

// Tenta baixar uma URL e retorna { status, headers, text } (texto limitado).
async function safeGet(url, { method = 'GET', maxBytes = 200000 } = {}) {
  try {
    const r = await timeoutFetch(url, { method });
    let text = '';
    if (method === 'GET') {
      const full = await r.text();
      text = full.slice(0, maxBytes);
    }
    return { ok: true, status: r.status, url: r.url, headers: r.headers, text };
  } catch (e) {
    return { ok: false, error: e.name === 'AbortError' ? 'timeout' : e.message };
  }
}

// ---- Construtores de fontes ------------------------------------------------
function wpscanSource() {
  return { name: 'WPScan Vulnerability DB', url: 'https://wpscan.com/wordpresses' };
}
function cveSource(id) {
  return { name: id, url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` };
}
function searchCveSource(query) {
  return {
    name: 'Buscar CVEs',
    url: `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(query)}`,
  };
}
function owaspSource(name, url) {
  return { name, url };
}

// ---- Verificações de segurança ---------------------------------------------
async function detectWordPress(base, home) {
  const result = { isWordPress: false, version: null, signals: [] };
  const html = home.text || '';

  if (/wp-content|wp-includes/i.test(html)) {
    result.isWordPress = true;
    result.signals.push('Caminhos wp-content/wp-includes encontrados no HTML');
  }
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([0-9.]+)?/i);
  if (gen) {
    result.isWordPress = true;
    if (gen[1]) result.version = gen[1];
    result.signals.push('Meta tag generator do WordPress presente');
  }
  // RSD / wp-json
  if (/\/xmlrpc\.php\?rsd|wp-json/i.test(html)) {
    result.isWordPress = true;
  }

  // Confirma via wp-json (API REST)
  const api = await safeGet(base + '/wp-json/');
  if (api.ok && api.status === 200 && /"name"|"namespaces"|wp\/v2/i.test(api.text)) {
    result.isWordPress = true;
    result.signals.push('API REST (/wp-json/) acessível');
  }

  // Tenta versão pelo feed
  if (!result.version) {
    const feed = await safeGet(base + '/feed/');
    if (feed.ok) {
      const m = feed.text.match(/generator>https?:\/\/wordpress\.org\/\?v=([0-9.]+)/i);
      if (m) { result.version = m[1]; result.isWordPress = true; }
    }
  }
  // readme.html
  if (!result.version) {
    const readme = await safeGet(base + '/readme.html');
    if (readme.ok && readme.status === 200) {
      const m = readme.text.match(/Version\s*([0-9.]+)/i);
      if (m) result.version = m[1];
    }
  }
  return result;
}

function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

// Versão estável mais recente conhecida (atualize conforme necessário).
const LATEST_WP = '6.7.1';

function checkVersionDisclosure(findings, version, base) {
  if (!version) return;
  findings.push({
    severity: 'low',
    title: 'Versão do WordPress exposta publicamente',
    description: `A versão do WordPress (${version}) está visível externamente. Expor a versão facilita que atacantes busquem exploits específicos para essa versão.`,
    evidence: `Versão detectada: WordPress ${version}`,
    remediation:
      'Remova a meta tag generator (ex.: remove_action("wp_head", "wp_generator")), restrinja o acesso a /readme.html e mantenha tudo atualizado. Considere um plugin de hardening como o Wordfence ou Sucuri.',
    sources: [wpscanSource(), owaspSource('OWASP — Fingerprint Web Server', 'https://owasp.org/www-project-web-security-testing-guide/')],
  });

  if (compareVersions(version, LATEST_WP) < 0) {
    findings.push({
      severity: 'high',
      title: 'WordPress desatualizado',
      description: `A versão instalada (${version}) é anterior à versão estável mais recente (${LATEST_WP}). Versões antigas frequentemente contêm vulnerabilidades de segurança já corrigidas e publicamente conhecidas.`,
      evidence: `Instalada: ${version} · Mais recente: ${LATEST_WP}`,
      remediation:
        'Atualize o núcleo do WordPress para a versão mais recente o quanto antes. Faça backup completo antes, ative atualizações automáticas de segurança e teste o site após atualizar.',
      sources: [
        wpscanSource(),
        searchCveSource('WordPress ' + version),
        owaspSource('WordPress — Atualizando', 'https://wordpress.org/documentation/article/updating-wordpress/'),
      ],
    });
  }
}

async function checkExposedFiles(findings, base) {
  const checks = [
    {
      path: '/wp-config.php.bak',
      severity: 'critical',
      title: 'Backup do wp-config.php exposto',
      description:
        'Um arquivo de backup do wp-config.php está acessível. Ele pode conter as credenciais do banco de dados, chaves secretas (salts) e outras configurações sensíveis.',
      remediation:
        'Remova imediatamente qualquer arquivo de backup (.bak, .old, ~, .save) do diretório web. Troque as senhas do banco de dados e regenere as chaves de segurança (salts) do WordPress.',
      match: (r) => r.status === 200 && /DB_PASSWORD|DB_NAME|define\(/i.test(r.text),
    },
    {
      path: '/.env',
      severity: 'critical',
      title: 'Arquivo .env exposto',
      description: 'Arquivo de variáveis de ambiente acessível publicamente, podendo conter senhas e chaves de API.',
      remediation: 'Bloqueie o acesso a arquivos .env no servidor web e mova segredos para fora da raiz pública. Rotacione qualquer credencial exposta.',
      match: (r) => r.status === 200 && /[A-Z_]+=.+/.test(r.text) && /DB_|API|SECRET|PASSWORD/i.test(r.text),
    },
    {
      path: '/wp-content/debug.log',
      severity: 'medium',
      title: 'Log de depuração (debug.log) acessível',
      description: 'O arquivo debug.log do WordPress está exposto e pode revelar caminhos do servidor, erros e informações internas úteis a um atacante.',
      remediation: 'Defina WP_DEBUG_LOG para um caminho fora da raiz pública ou desative o debug em produção (WP_DEBUG=false). Bloqueie o acesso ao arquivo via servidor.',
      match: (r) => r.status === 200 && r.text.length > 0,
    },
    {
      path: '/wp-config.php~',
      severity: 'critical',
      title: 'Backup temporário do wp-config.php exposto',
      description: 'Arquivo temporário de editor contendo a configuração principal do WordPress acessível publicamente.',
      remediation: 'Remova arquivos temporários do servidor e configure o servidor web para negar acesso a esses padrões de arquivo.',
      match: (r) => r.status === 200 && /DB_PASSWORD|define\(/i.test(r.text),
    },
  ];

  for (const c of checks) {
    const r = await safeGet(base + c.path);
    if (r.ok && c.match(r)) {
      findings.push({
        severity: c.severity,
        title: c.title,
        description: c.description,
        evidence: `${base + c.path} → HTTP ${r.status}`,
        remediation: c.remediation,
        sources: [owaspSource('OWASP — Sensitive Data Exposure', 'https://owasp.org/www-project-top-ten/'), wpscanSource()],
      });
    }
  }
}

async function checkDirectoryListing(findings, base) {
  const dirs = ['/wp-content/uploads/', '/wp-includes/', '/wp-content/plugins/'];
  for (const d of dirs) {
    const r = await safeGet(base + d);
    if (r.ok && r.status === 200 && /Index of \/|<title>Index of/i.test(r.text)) {
      findings.push({
        severity: 'low',
        title: `Listagem de diretório habilitada (${d})`,
        description: `O diretório ${d} permite listar seu conteúdo. Isso expõe a estrutura de arquivos, plugins instalados e possíveis arquivos sensíveis.`,
        evidence: `${base + d} retorna "Index of"`,
        remediation:
          'Desative a listagem de diretórios. No Apache, use "Options -Indexes" no .htaccess. No Nginx, remova "autoindex on". Adicione arquivos index.php vazios nas pastas de uploads.',
        sources: [owaspSource('OWASP — Directory Listing', 'https://owasp.org/www-community/Improper_Error_Handling')],
      });
    }
  }
}

async function checkUserEnumeration(findings, base) {
  // Via API REST
  const api = await safeGet(base + '/wp-json/wp/v2/users');
  if (api.ok && api.status === 200 && /"slug"|"name"/i.test(api.text)) {
    let users = [];
    try {
      const arr = JSON.parse(api.text);
      if (Array.isArray(arr)) users = arr.map((u) => u.slug || u.name).filter(Boolean).slice(0, 10);
    } catch {}
    findings.push({
      severity: 'medium',
      title: 'Enumeração de usuários via API REST',
      description:
        'A API REST do WordPress (/wp-json/wp/v2/users) revela os nomes de usuário do site. Atacantes usam essa lista para ataques de força bruta direcionados.',
      evidence: users.length ? `Usuários expostos: ${users.join(', ')}` : 'Endpoint /wp-json/wp/v2/users acessível',
      remediation:
        'Bloqueie o endpoint de usuários da API REST para usuários não autenticados (plugins como Wordfence fazem isso) ou use código para filtrar a rota. Use nomes de usuário não óbvios e ative autenticação de dois fatores.',
      sources: [wpscanSource(), owaspSource('OWASP — Testing for Account Enumeration', 'https://owasp.org/www-project-web-security-testing-guide/')],
    });
    return;
  }
  // Via ?author=1 (redirecionamento revela o slug)
  const author = await safeGet(base + '/?author=1');
  if (author.ok && /\/author\/([^\/"']+)/i.test(author.text + author.url)) {
    const m = (author.url + author.text).match(/\/author\/([a-z0-9_.-]+)/i);
    findings.push({
      severity: 'low',
      title: 'Enumeração de usuários via ?author=',
      description: 'É possível descobrir nomes de usuário acessando /?author=N, que redireciona para a página do autor revelando o login.',
      evidence: m ? `Usuário identificado: ${m[1]}` : 'Redirecionamento de autor detectado',
      remediation: 'Bloqueie consultas ?author= no servidor web ou via plugin de segurança e evite que o "nome de exibição" seja igual ao login.',
      sources: [wpscanSource()],
    });
  }
}

async function checkXmlRpc(findings, base) {
  const r = await safeGet(base + '/xmlrpc.php');
  if (r.ok && (r.status === 405 || /XML-RPC server accepts POST requests only/i.test(r.text))) {
    findings.push({
      severity: 'medium',
      title: 'XML-RPC habilitado',
      description:
        'O endpoint xmlrpc.php está ativo. Ele pode ser abusado para ataques de força bruta amplificados (método system.multicall) e para ataques de negação de serviço (pingback DDoS).',
      evidence: `${base}/xmlrpc.php → HTTP ${r.status}`,
      remediation:
        'Se você não usa XML-RPC (apps móveis antigos, pingbacks), desative-o. Bloqueie o acesso ao arquivo no servidor web ou use o filtro "xmlrpc_enabled". Plugins como Wordfence permitem desativá-lo.',
      sources: [wpscanSource(), cveSource('CVE-2013-0235')],
    });
  }
}

function checkSecurityHeaders(findings, headers) {
  const get = (h) => headers.get(h);
  const missing = [];
  const map = [
    ['strict-transport-security', 'HSTS (Strict-Transport-Security)', 'Força o uso de HTTPS, prevenindo ataques de downgrade e interceptação.'],
    ['content-security-policy', 'Content-Security-Policy', 'Mitiga ataques de Cross-Site Scripting (XSS) e injeção de conteúdo.'],
    ['x-frame-options', 'X-Frame-Options', 'Previne ataques de clickjacking impedindo o site de ser carregado em iframes.'],
    ['x-content-type-options', 'X-Content-Type-Options', 'Evita que o navegador interprete arquivos com MIME type incorreto (MIME sniffing).'],
    ['referrer-policy', 'Referrer-Policy', 'Controla quais informações de referência são enviadas a outros sites.'],
  ];
  for (const [h, label, why] of map) {
    if (!get(h)) missing.push(`${label} — ${why}`);
  }
  if (missing.length) {
    findings.push({
      severity: missing.length >= 4 ? 'medium' : 'low',
      title: `Cabeçalhos de segurança ausentes (${missing.length})`,
      description: 'O servidor não envia cabeçalhos HTTP de segurança importantes:\n• ' + missing.join('\n• '),
      remediation:
        'Configure os cabeçalhos no servidor web (Apache/Nginx) ou via plugin. Comece com X-Content-Type-Options, X-Frame-Options e HSTS. Implemente Content-Security-Policy com cautela, testando para não quebrar funcionalidades.',
      sources: [owaspSource('OWASP — Secure Headers Project', 'https://owasp.org/www-project-secure-headers/'), owaspSource('Mozilla Observatory', 'https://developer.mozilla.org/docs/Web/HTTP/Headers')],
    });
  }
  // Server / X-Powered-By disclosure
  const server = get('server');
  const powered = get('x-powered-by');
  if (server || powered) {
    findings.push({
      severity: 'info',
      title: 'Divulgação de software do servidor',
      description: 'O servidor revela detalhes de sua stack tecnológica nos cabeçalhos de resposta.',
      evidence: [server && `Server: ${server}`, powered && `X-Powered-By: ${powered}`].filter(Boolean).join(' · '),
      remediation: 'Oculte ou minimize os cabeçalhos Server e X-Powered-By para dificultar o fingerprinting (ex.: ServerTokens Prod no Apache, server_tokens off no Nginx, expose_php Off no PHP).',
      sources: [owaspSource('OWASP — Information Leakage', 'https://owasp.org/www-project-web-security-testing-guide/')],
    });
  }
}

function checkHttps(findings, parsed) {
  if (parsed.protocol !== 'https:') {
    findings.push({
      severity: 'high',
      title: 'Site sem HTTPS',
      description: 'O site foi acessado por HTTP sem criptografia. Dados (incluindo senhas de login no /wp-admin) trafegam em texto puro e podem ser interceptados.',
      evidence: `Protocolo: ${parsed.protocol}`,
      remediation: 'Instale um certificado TLS (Let’s Encrypt é gratuito), force o redirecionamento de HTTP para HTTPS e ative o cabeçalho HSTS.',
      sources: [owaspSource('OWASP — Transport Layer Security', 'https://owasp.org/www-project-web-security-testing-guide/'), owaspSource('Let’s Encrypt', 'https://letsencrypt.org/')],
    });
  }
}

// Detecta plugins a partir do HTML e (opcionalmente) consulta a API do WPScan.
async function checkPlugins(findings, base, html) {
  const regex = /\/wp-content\/plugins\/([a-z0-9\-_]+)\/[^"'\s)]*?(?:\?ver=([0-9.]+))?/gi;
  const plugins = new Map();
  let m;
  while ((m = regex.exec(html)) !== null) {
    const slug = m[1].toLowerCase();
    if (!plugins.has(slug) || (m[2] && !plugins.get(slug))) {
      plugins.set(slug, m[2] || null);
    }
  }
  if (!plugins.size) return;

  const list = [...plugins.entries()].slice(0, 12);
  findings.push({
    severity: 'info',
    title: `Plugins detectados (${list.length})`,
    description: 'Plugins identificados no HTML do site. Plugins desatualizados são a principal porta de entrada para invasões em WordPress.',
    evidence: list.map(([s, v]) => (v ? `${s} v${v}` : s)).join(', '),
    remediation: 'Mantenha todos os plugins atualizados, remova os que não usa e verifique cada um na base do WPScan. Prefira plugins com manutenção ativa.',
    sources: [{ name: 'WPScan — Plugins', url: 'https://wpscan.com/plugins' }],
  });

  // Consulta a API oficial do WPScan, se houver token configurado.
  if (WPSCAN_API_TOKEN) {
    for (const [slug, version] of list) {
      try {
        const r = await timeoutFetch(`https://wpscan.com/api/v3/plugins/${slug}`, {
          headers: { Authorization: `Token token=${WPSCAN_API_TOKEN}`, 'User-Agent': UA },
          timeout: 6000,
        });
        if (!r.ok) continue;
        const data = await r.json();
        const entry = data[slug];
        const vulns = (entry && entry.vulnerabilities) || [];
        for (const v of vulns) {
          const fixedIn = v.fixed_in;
          const affected = !version || !fixedIn || compareVersions(version, fixedIn) < 0;
          if (!affected) continue;
          const sources = [{ name: 'WPScan', url: `https://wpscan.com/vulnerability/${v.id || ''}` }];
          if (v.references && Array.isArray(v.references.cve)) {
            v.references.cve.slice(0, 3).forEach((id) => sources.push(cveSource('CVE-' + id)));
          }
          findings.push({
            severity: 'high',
            title: `Plugin vulnerável: ${slug}${version ? ' v' + version : ''}`,
            description: `${v.title}. ${fixedIn ? 'Corrigido na versão ' + fixedIn + '.' : ''}`,
            evidence: `Plugin: ${slug}${version ? ' (versão ' + version + ')' : ''}`,
            remediation: fixedIn
              ? `Atualize o plugin "${slug}" para a versão ${fixedIn} ou superior imediatamente. Se não houver correção, desative e remova o plugin.`
              : `Atualize ou remova o plugin "${slug}". Verifique alternativas mantidas pelo desenvolvedor.`,
            sources,
          });
        }
      } catch {
        /* ignora falhas pontuais da API */
      }
    }
  } else {
    // Sem token: orienta consulta manual com links diretos por plugin.
    for (const [slug, version] of list) {
      findings.push({
        severity: 'info',
        title: `Verificar plugin: ${slug}${version ? ' v' + version : ''}`,
        description: 'Consulte manualmente se este plugin (e versão) possui vulnerabilidades conhecidas na base do WPScan e no banco de CVEs.',
        evidence: version ? `${slug} versão ${version}` : slug,
        remediation: 'Compare a versão instalada com a mais recente do plugin e aplique atualizações pendentes.',
        sources: [
          { name: `WPScan — ${slug}`, url: `https://wpscan.com/plugin/${slug}` },
          searchCveSource(`${slug} wordpress plugin`),
        ],
      });
    }
  }
}

// ---- Handler principal -----------------------------------------------------
export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Método não permitido. Use POST.' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const { url, authorized, token } = body || {};

  // 1) Confirmação de autorização obrigatória
  if (authorized !== true) {
    res.status(400).json({ error: 'É necessário confirmar que você tem autorização para escanear este site.' });
    return;
  }

  // 2) Validação de URL + proteção SSRF
  const norm = normalizeUrl(url);
  if (!norm) {
    res.status(400).json({ error: 'URL inválida. Informe um endereço como https://exemplo.com.' });
    return;
  }
  if (norm.blocked) {
    res.status(400).json({ error: 'Não é permitido escanear endereços locais ou de redes internas.' });
    return;
  }

  // 3) Verificação do reCAPTCHA v3 (no backend, com a chave secreta)
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress;
  const captcha = await verifyRecaptcha(token, ip);
  if (!captcha.ok) {
    res.status(403).json({ error: captcha.reason });
    return;
  }

  const base = norm.url;
  const findings = [];

  try {
    // Requisição inicial à página principal
    const home = await safeGet(base + '/');
    if (!home.ok) {
      res.status(502).json({
        error: `Não foi possível acessar o site (${home.error}). Verifique se a URL está correta e online.`,
      });
      return;
    }

    checkHttps(findings, norm.parsed);
    checkSecurityHeaders(findings, home.headers);

    const wp = await detectWordPress(base, home);

    if (wp.isWordPress) {
      checkVersionDisclosure(findings, wp.version, base);
      await checkExposedFiles(findings, base);
      await checkDirectoryListing(findings, base);
      await checkUserEnumeration(findings, base);
      await checkXmlRpc(findings, base);
      await checkPlugins(findings, base, home.text);
    } else {
      findings.push({
        severity: 'info',
        title: 'WordPress não confirmado',
        description:
          'Não foi possível confirmar com certeza que este site usa WordPress. As verificações específicas de WordPress foram limitadas. Os cabeçalhos de segurança e o HTTPS ainda foram avaliados.',
        remediation: 'Se o site for WordPress, verifique se ele não está bloqueando bots — alguns firewalls escondem as assinaturas do CMS.',
        sources: [wpscanSource()],
      });
    }

    res.status(200).json({
      target: base,
      isWordPress: wp.isWordPress,
      version: wp.version,
      scannedAt: new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
      recaptchaScore: captcha.score,
      findings,
    });
  } catch (e) {
    res.status(500).json({ error: 'Erro interno durante a varredura. Tente novamente em instantes.' });
  }
}
