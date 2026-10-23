'use strict';

const fs = require('node:fs');
const path = require('node:path');
const ICON = fs.readFileSync(path.join(__dirname, '..', 'public', 'icon.svg'), 'utf8');
const STYLES = fs.readFileSync(path.join(__dirname, '..', 'public', 'styles.css'), 'utf8');
const REGISTRATION_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';

function html(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function shell(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function normalizedBase(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new TypeError('Discovery base must be an HTTP(S) URL without credentials, query, or fragment');
  }
  return url.href.replace(/\/+$/, '');
}

function configuredRegistrations(registration = {}) {
  if (typeof registration.agentId === 'number' && !Number.isSafeInteger(registration.agentId)) return [];
  const agentId = String(registration.agentId ?? '').trim();
  const agentRegistry = String(registration.agentRegistry ?? '').trim();
  if (!/^\d+$/.test(agentId) || !/^eip155:[1-9]\d*:0x[0-9a-fA-F]{40}$/.test(agentRegistry)) return [];
  if (BigInt(agentId) > (1n << 256n) - 1n) return [];
  return [{ agentId: BigInt(agentId).toString(), agentRegistry }];
}

function createDiscovery({ base, manifest, skills, payment, registration = {} }) {
  const origin = normalizedBase(base);
  const name = String(manifest.name || 'PhantomOperator');
  const description = 'Privacy and OPSEC API for public-web metadata audits, PII exposure scans, and exposure scoring. Pay per successful call with USDC on Base via x402.';
  const image = `${origin}/icon.svg`;
  const entries = Object.entries(skills).map(([id, skill]) => ({
    id, ...skill,
    title: manifest.skills?.find(entry => entry.id === id)?.name || id.replace(/-/g, ' '),
  }));
  const registrations = configuredRegistrations(registration);
  const href = route => `${origin}${route}`;
  const money = skill => Number(skill.priceUsd).toFixed(2);
  const requirements = skill => ({
    scheme: 'exact', network: payment.network, amount: String(Math.round(skill.priceUsd * 1e6)),
    asset: payment.asset, payTo: payment.payTo, maxTimeoutSeconds: 300,
    extra: { name: 'USD Coin', version: '2' },
  });
  const curl = skill => `curl -i ${shell(href(skill.path))} \\\n  -H 'Content-Type: application/json' \\\n  --data ${shell(JSON.stringify(skill.inputExample))}`;

  const nav = `<nav aria-label="Main navigation"><a href="${html(href('/'))}"><img src="${html(image)}" width="32" height="32" alt="">${html(name)}</a> · <a href="${html(href('/#skills'))}">Skills and prices</a> · <a href="${html(href('/openapi.json'))}">OpenAPI</a> · <a href="${html(href('/llms.txt'))}">For agents</a> · <a href="${html(href('/terms'))}">Terms</a></nav>`;
  function page({ title, summary, canonical, content }) {
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${html(title)}</title><meta name="description" content="${html(summary)}">
<link rel="stylesheet" href="${html(href('/styles.css'))}"><link rel="canonical" href="${html(href(canonical))}"><link rel="icon" type="image/svg+xml" href="${html(image)}">
<meta property="og:type" content="website"><meta property="og:site_name" content="${html(name)}"><meta property="og:title" content="${html(title)}"><meta property="og:description" content="${html(summary)}"><meta property="og:url" content="${html(href(canonical))}"><meta property="og:image" content="${html(image)}"><meta property="og:image:alt" content="PhantomOperator shield and eye symbol">
</head><body itemscope itemtype="https://schema.org/SoftwareApplication">
${nav}<main><meta itemprop="applicationCategory" content="SecurityApplication"><meta itemprop="operatingSystem" content="Any"><link itemprop="url" href="${html(href('/'))}">
${content}</main><footer><p><a href="${html(href('/agent-registration.json'))}">Agent registration metadata</a> · <a href="${html(href('/.well-known/x402'))}">x402 resources</a> · <a href="https://github.com/normancomics/PhantomOperator">Source code</a></p><p>Public-web evidence supports investigation; it does not certify privacy or prove a person's identity.</p></footer></body></html>`;
  }

  function skillSummary(skill) {
    return `<section itemprop="offers" itemscope itemtype="https://schema.org/Offer"><h3><a itemprop="url" href="${html(href(skill.path))}"><span itemprop="name">${html(skill.title)}</span></a></h3><p>${html(skill.description)}</p><p><meta itemprop="priceCurrency" content="USD"><strong><span itemprop="price" content="${money(skill)}">$${money(skill)}</span> USDC per successful request</strong> · Base mainnet</p><p><code>POST ${html(skill.path)}</code>${skill.requiresConsent ? ' · Self-assessment or explicitly authorized targets only; consent is required.' : ''}</p></section>`;
  }

  function homepage() {
    const example = entries.find(entry => entry.id === 'metadata-audit') || entries[0];
    const registrationText = registrations.length
      ? `Registry reference configured: <code>${html(registrations[0].agentRegistry)}</code>, agent <code>${html(registrations[0].agentId)}</code>. This metadata is a reference; verify the registry record independently.`
      : 'Onchain agent registration is not configured. Publishing this metadata does not register the agent or establish reputation.';
    return page({
      title: `${name} — privacy and OPSEC API`, summary: description, canonical: '/',
      content: `<header><p>PUBLIC-WEB PRIVACY TOOLS · X402 PAYMENTS</p><h1 itemprop="name">${html(name)}</h1><p itemprop="description">Inspect metadata leaks. Find public exposure signals. Turn evidence into a privacy review.</p><p>Three API skills, transparent per-call prices, and machine-readable integration documents. Payments use USDC on Base mainnet.</p><p><a href="#skills">Explore the skills</a> · <a href="#integrate">Make your first request</a></p></header>
<section id="skills"><h2>Choose the evidence you need</h2>${entries.map(skillSummary).join('\n')}</section>
<section id="integrate"><h2>Integrate in three steps</h2><ol><li>Choose a skill and read its input schema. Scans of a person's exposure require their authorization and <code>consent: true</code>.</li><li>Send a JSON POST request. Without payment authorization, the API returns HTTP 402 and a <code>PAYMENT-REQUIRED</code> header describing the exact price and receiver.</li><li>Use an x402-compatible client to authorize payment, then retry with <code>PAYMENT-SIGNATURE</code>. Payment settlement is attempted after successful processing; application errors and invalid input are not settled by this server.</li></ol>
${example ? `<h3>Inspect a payment challenge without paying</h3><pre><code>${html(curl(example))}</code></pre><p>This plain curl request does not authorize or send funds. Read the challenge and verify its network, asset, price, and receiver before authorizing a payment.</p><h3>Illustrative response shape</h3><pre><code>${html(JSON.stringify(example.outputExample, null, 2))}</code></pre><p>This is a documentation example, not a scan result.</p>` : ''}
<p><a href="${html(href('/openapi.json'))}">OpenAPI 3.1 document</a> · <a href="${html(href('/skills'))}">JSON skill catalog</a> · <a href="${html(href('/llms.txt'))}">Agent integration index</a></p></section>
<section><h2>Evidence, privacy, and limits</h2><p>Metadata audits inspect publicly reachable web pages. Threat scans and OPSEC scores use public search results and heuristic rules. Coverage depends on source availability; findings may be incomplete or incorrect and should be reviewed.</p><p>Search queries are sent to DuckDuckGo; metadata audits contact the target website. Base payment activity is public. Submit only data you are authorized to assess and review the <a href="${html(href('/terms'))}">terms and acceptable-use policy</a>.</p><p>This deployment does not perform data-broker removals, email-breach lookups, or full privacy sweeps. The API is an investigation aid, not a removal guarantee or an anonymity guarantee.</p></section>
<section><h2>Payment details</h2><dl><dt>Protocol</dt><dd>x402 v2 · exact</dd><dt>Network</dt><dd><code>${html(payment.network)}</code></dd><dt>Asset</dt><dd>USDC · <code>${html(payment.asset)}</code></dd><dt>Payment receiver</dt><dd><code>${html(payment.payTo)}</code></dd><dt>Facilitator</dt><dd><code>${html(payment.facilitator)}</code></dd></dl></section>
<section><h2>Agent identity</h2><p>${registrationText}</p><p>Discoverable documentation does not imply registry endorsement, search-engine ranking, or verified reputation.</p></section>`,
    });
  }

  function skillPage(skill) {
    return page({
      title: `${skill.title} API — $${money(skill)} USDC | ${name}`,
      summary: skill.description, canonical: skill.path,
      content: `<p><a href="${html(href('/#skills'))}">All skills</a></p><h1>${html(skill.title)}</h1><p>${html(skill.description)}</p><p><strong>$${money(skill)} USDC per successful request on Base mainnet</strong></p><p><code>POST ${html(skill.path)}</code></p>
${skill.requiresConsent ? '<p><strong>Authorization required:</strong> assess yourself or a target who explicitly authorized you. Include <code>"consent": true</code> and accept the terms.</p>' : ''}
<h2>Request body</h2><pre><code>${html(JSON.stringify(skill.inputExample, null, 2))}</code></pre><h3>Input schema</h3><pre><code>${html(JSON.stringify(skill.bodySchema, null, 2))}</code></pre>
<h2>Try the unpaid request</h2><pre><code>${html(curl(skill))}</code></pre><p>An unpaid request returns HTTP 402. Use an x402-compatible client to inspect the challenge, authorize payment, and retry with <code>PAYMENT-SIGNATURE</code>. This curl example does not sign or pay.</p>
<h2>Illustrative response shape</h2><pre><code>${html(JSON.stringify(skill.outputExample, null, 2))}</code></pre><p>Example values show structure only; they are not findings from a real scan. Results are heuristic and source coverage can vary.</p><h2>Payment and terms</h2><p>Receiver: <code>${html(payment.payTo)}</code>. Network: <code>${html(payment.network)}</code>. Asset: <code>${html(payment.asset)}</code>.</p><p><a href="${html(href('/terms'))}">Read the terms</a> · <a href="${html(href('/openapi.json'))}">View the complete OpenAPI document</a></p>`,
    });
  }

  const resultSchemas = {
    PublicSearchProvenance: {
      type: 'object', properties: {
        provider: { const: 'DuckDuckGo HTML', type: 'string' },
        method: { const: 'public-search-snippet', type: 'string' },
        sourceUrl: { type: 'string', format: 'uri' }, observedAt: { type: 'string', format: 'date-time' },
        fetchedPage: { const: false, type: 'boolean' },
      },
    },
    ThreatScanResult: {
      type: 'array', items: { type: 'object', required: ['title', 'link', 'description', 'threatLevel', 'reasons'], properties: {
        title: { type: 'string' }, link: { type: 'string' }, description: { type: 'string' },
        threatLevel: { enum: ['benign', 'medium', 'high', 'critical'], type: 'string' }, reasons: { type: 'array', items: { type: 'string' } },
        evidence: { type: 'object', properties: { kind: { const: 'search-result-snippet', type: 'string' }, text: { type: 'string' } } },
        provenance: { $ref: '#/components/schemas/PublicSearchProvenance' },
        limitations: { type: 'array', items: { type: 'string' } },
      } },
    },
    MetadataAuditResult: {
      type: 'object', required: ['overallRisk', 'findings'], properties: {
        url: { type: 'string', format: 'uri' }, statusCode: { type: 'integer' },
        overallRisk: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'critical'] },
        findingCounts: { type: 'object', additionalProperties: { type: 'integer', minimum: 0 } },
        findings: { type: 'array', items: { type: 'object', properties: {
          category: { type: 'string' }, riskLevel: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
          label: { type: 'string' }, field: { type: 'string' }, value: { type: ['string', 'null'], description: 'Observed value; null means the configured security header was absent.' },
          evidence: { type: 'object', properties: {
            sourceUrl: { type: 'string', format: 'uri' }, observedAt: { type: 'string', format: 'date-time' },
            location: { type: 'string' }, field: { type: 'string' }, observation: { type: 'string' },
          } },
        } } },
        recommendation: { type: 'string' }, timestamp: { type: 'string', format: 'date-time' },
        scope: { const: 'http-headers-and-static-html', type: 'string' },
        status: { type: 'string', enum: ['complete', 'partial'] },
        provenance: { type: 'object', properties: {
          requestedUrl: { type: 'string', format: 'uri' }, finalUrl: { type: 'string', format: 'uri' },
          fetchedAt: { type: 'string', format: 'date-time' }, httpStatus: { type: 'integer' },
          contentType: { type: ['string', 'null'] }, bytesReceived: { type: 'integer', minimum: 0 },
          resolvedAddress: { type: 'string' }, transport: { const: 'dns-pinned-direct', type: 'string' },
          inspectedHtml: { type: 'boolean' }, redirects: { type: 'array', items: { type: 'object', properties: {
            url: { type: 'string', format: 'uri' }, statusCode: { type: 'integer' }, location: { type: 'string', format: 'uri' },
          } } },
        } },
        limitations: { type: 'array', items: { type: 'string' } },
      },
    },
    OpsecScoreResult: {
      type: 'object', required: ['score', 'grade', 'breakdown'], properties: {
        target: { type: 'object', properties: { fullName: { type: 'string' }, handle: { type: 'string' }, email: { type: 'string' } } },
        score: { type: 'integer', minimum: 0, maximum: 100 }, grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'F'] },
        breakdown: { type: 'object', properties: {
          searchExposure: { type: 'object', properties: { score: { type: 'number' }, criticalFindings: { type: 'integer' }, highFindings: { type: 'integer' }, totalResults: { type: 'integer' } } },
          dataBrokerExposure: { type: 'object', properties: { score: { type: 'number' }, brokerCount: { type: 'integer' }, brokers: { type: 'array', items: { type: 'string' } } } },
          pasteLeaks: { type: 'object', properties: { score: { type: 'number' }, pasteCount: { type: 'integer' }, sites: { type: 'array', items: { type: 'object', properties: { domain: { type: 'string' }, url: { type: 'string' } } } } } },
          socialFootprint: { type: 'object', properties: { score: { type: 'number' }, platformCount: { type: 'integer' }, platforms: { type: 'array', items: { type: 'string' } } } },
        } },
        topThreats: { type: 'array', items: { type: 'object', properties: {
          source: { type: 'string' }, snippet: { type: 'string' }, relevanceScore: { type: 'number' },
          threatLevel: { type: 'string', enum: ['benign', 'medium', 'high', 'critical'] },
          provenance: { $ref: '#/components/schemas/PublicSearchProvenance' },
        } } },
        recommendations: { type: 'array', items: { type: 'object', properties: { priority: { type: 'string' }, action: { type: 'string' }, detail: { type: 'string' } } } },
        timestamp: { type: 'string', format: 'date-time' },
        provider: { const: 'DuckDuckGo HTML', type: 'string' },
        coverage: { type: 'object', properties: {
          complete: { const: true, type: 'boolean', description: 'Each requested identifier search completed; this does not mean the whole web was searched.' }, identifiersSearched: { type: 'integer', minimum: 1 },
          searchesCompleted: { type: 'integer', minimum: 1 }, searchesWithResults: { type: 'integer', minimum: 1 },
          resultsRetrieved: { type: 'integer', minimum: 1 }, uniqueResults: { type: 'integer', minimum: 1 },
          maxResultsPerSearch: { const: 15, type: 'integer' }, scope: { const: 'public-search-snippets', type: 'string' },
        } },
        limitations: { type: 'array', items: { type: 'string' } },
      },
    },
  };
  const resultSchemaNames = { 'threat-scan': 'ThreatScanResult', 'metadata-audit': 'MetadataAuditResult', 'opsec-score': 'OpsecScoreResult' };
  const errorResponse = description => ({ description, content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } });
  const openapi = {
    openapi: '3.1.0', jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
    info: { title: `${name} API`, version: String(manifest.version || '0.1.0'), description, termsOfService: href('/terms') },
    servers: [{ url: origin }],
    paths: Object.fromEntries(entries.map(skill => [skill.path, { post: {
      operationId: skill.id.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()),
      summary: skill.title, description: `${skill.description}${skill.requiresConsent ? ' Explicit authorization and consent:true are required.' : ''} Amounts are fixed in USDC on Base; an unpaid call returns an x402 challenge.`,
      parameters: [{ name: 'PAYMENT-SIGNATURE', in: 'header', required: false, description: 'Base64-encoded x402 payment payload returned by a compatible paying client after inspecting the HTTP 402 challenge. X-PAYMENT is also accepted.', schema: { type: 'string' } }],
      requestBody: { required: true, content: { 'application/json': { schema: skill.bodySchema, example: skill.inputExample } } },
      responses: {
        '200': { description: 'Skill completed and payment settled. Example values are illustrative, not observed findings.', headers: { 'PAYMENT-RESPONSE': { description: 'Base64-encoded facilitator settlement response.', schema: { type: 'string' } } }, content: { 'application/json': { schema: { type: 'object', required: ['skill', 'result'], properties: { skill: { const: skill.id, type: 'string' }, result: resultSchemaNames[skill.id] ? { $ref: `#/components/schemas/${resultSchemaNames[skill.id]}` } : {} } }, example: skill.outputExample } } },
        '400': errorResponse('Invalid JSON, invalid input, or missing consent; payment is not settled.'),
        '402': { description: 'Payment authorization is required or settlement failed.', headers: { 'PAYMENT-REQUIRED': { description: 'Base64-encoded x402 v2 challenge when payment is required.', schema: { type: 'string' } } }, content: { 'application/json': { schema: { type: 'object' }, example: { x402Version: 2, error: 'Payment required', resource: { url: href(skill.path), description: skill.description, mimeType: 'application/json' }, accepts: [requirements(skill)] } } } },
        '413': errorResponse('Request body exceeds the byte limit; payment is not settled.'),
        '415': errorResponse('Use Content-Type: application/json; payment is not settled.'),
        '422': errorResponse('Metadata target is unsafe or did not return supported HTML; payment is not settled.'),
        '429': { ...errorResponse('Rate limit exceeded.'), headers: { 'Retry-After': { description: 'Seconds before retrying.', schema: { type: 'string' } } } },
        '500': errorResponse('Application processing failed; payment is not settled.'),
        '502': errorResponse('An upstream assessment or payment-facilitator request failed. If settlement was attempted but could not be confirmed, check your wallet before retrying.'),
        '503': errorResponse('Assessment is unavailable or search coverage is incomplete or has no usable evidence; payment is not settled.'),
        '504': errorResponse('Metadata retrieval exceeded its time limit; payment is not settled.'),
      },
      'x-x402': { version: 2, requirements: requirements(skill), facilitator: payment.facilitator },
    } } ])),
    components: { schemas: { ...resultSchemas, Error: { type: 'object', required: ['error'], properties: { error: { type: 'string' } }, additionalProperties: true } } },
  };

  const agentRegistration = {
    type: REGISTRATION_TYPE, name, description, image,
    services: [{ name: 'web', endpoint: origin }, { name: 'OpenAPI', endpoint: href('/openapi.json'), version: '3.1.0' }],
    x402Support: true, active: true, registrations,
  };
  const llms = [
    `# ${name}`, '', `> ${description}`, '',
    'Only assess yourself or explicitly authorized targets. Follow the terms. Results are heuristic and may be incomplete.', '',
    '## Integration',
    `- [Homepage](${href('/')})`, `- [OpenAPI 3.1](${href('/openapi.json')})`,
    `- [Skill catalog](${href('/skills')})`, `- [Terms](${href('/terms')})`,
    `- [x402 resources](${href('/.well-known/x402')})`, `- [Agent registration metadata](${href('/agent-registration.json')})`, '',
    '## Paid skills',
    ...entries.map(skill => `- [${skill.title}](${href(skill.path)}): POST JSON; ${money(skill)} USDC per successful request.${skill.requiresConsent ? ' Requires consent:true.' : ''} ${skill.description}`), '',
    '## Payments',
    `x402 v2 exact; network ${payment.network}; asset ${payment.asset}; receiver ${payment.payTo}; facilitator ${payment.facilitator}.`,
    'Unpaid requests return HTTP 402 and PAYMENT-REQUIRED. Retry with a compatible client using PAYMENT-SIGNATURE (or X-PAYMENT). This service attempts settlement after successful processing.', '',
    '## Registration',
    registrations.length ? `Configured registry reference: ${registrations[0].agentRegistry}, agentId ${registrations[0].agentId}. Verify its onchain record independently.` : 'No onchain registration is configured; the registration document is metadata, not proof of registration or reputation.', '',
    '## Limits',
    'No data-broker removal, paid email-breach lookup, full privacy sweep, or guarantees of complete coverage. No MCP or A2A endpoint is offered by this deployment.', '',
  ].join('\n');
  const sitemapUrls = [href('/'), ...entries.map(skill => href(skill.path))];
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${sitemapUrls.map(url => `<url><loc>${html(url)}</loc></url>`).join('')}</urlset>\n`;
  const docs = {
    '/openapi.json': ['application/json; charset=utf-8', openapi],
    '/llms.txt': ['text/plain; charset=utf-8', llms],
    '/robots.txt': ['text/plain; charset=utf-8', `User-agent: *\nAllow: /\nSitemap: ${href('/sitemap.xml')}\n`],
    '/sitemap.xml': ['application/xml; charset=utf-8', sitemap],
    '/agent-registration.json': ['application/json; charset=utf-8', agentRegistration],
    '/.well-known/agent-registration.json': ['application/json; charset=utf-8', { registrations }],
    '/icon.svg': ['image/svg+xml; charset=utf-8', ICON],
    '/styles.css': ['text/css; charset=utf-8', STYLES],
  };
  return {
    route(pathname) {
      if (pathname === '/') return { status: 200, contentType: 'text/html; charset=utf-8', body: homepage() };
      const skill = entries.find(entry => entry.path === pathname);
      if (skill) return { status: 200, contentType: 'text/html; charset=utf-8', body: skillPage(skill) };
      if (!Object.hasOwn(docs, pathname)) return null;
      const [contentType, body] = docs[pathname];
      return { status: 200, contentType, body };
    },
  };
}

module.exports = { createDiscovery };
