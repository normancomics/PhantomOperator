# Metadata audit security and privacy

`metadata-audit` inspects one successful HTTP response's headers and static HTML.
It does not inspect image EXIF, run page JavaScript, load linked resources, submit
forms, or prove who owns a page. Third-party resource findings describe references
in the HTML; they do not mean those resources were fetched or identified as
tracking software.

## Fetch boundary

Only absolute HTTP and HTTPS URLs without credentials are accepted. URL
normalization runs before address checks, including alternate IPv4 notation and
bracketed IPv6. The fetcher rejects loopback, private, link-local, multicast,
documentation and other special-purpose address ranges. IPv6 is limited to global
unicast, excluding transition ranges that could embed an internal IPv4 address.
This conservative policy may also reject some publicly reachable special-purpose
addresses.

Every hostname is resolved before connecting. All answers must pass the public
address policy. The connection receives one validated address through a pinned
DNS callback while preserving the original HTTP Host and HTTPS certificate
hostname. Connections are not pooled. Each redirect, including a redirect to the
same hostname, repeats URL validation and DNS checks. TLS verification remains
enabled.

An ordinary forward proxy can resolve a destination independently and defeat
local DNS pinning. When a configured proxy applies, metadata retrieval fails
closed with `PROXY_PINNING_UNSUPPORTED` (HTTP 503). It does not silently connect
around the proxy. Explicit `NO_PROXY` settings are respected, but destination
checks still apply. Supported proxy-side destination pinning would require a
documented transport contract before it could be enabled safely.

Retrieval has a 15-second total deadline across DNS, redirects and the body, at
most five redirects, 16 KiB response headers and a 2 MiB response-body limit.
Requests ask for identity content encoding and reject unexpected compression.
These limits cannot be raised through the fetch options. The system does not
offer an authentication cookie or custom authorization-header forwarding option.

## Results and errors

Successful observations include a source URL, observation time and evidence for
each finding. Response provenance records the final URL, redirect chain, HTTP
status, content type, byte count and selected public address. The result describes
the received document, which may differ by time, geography or user agent. A
successful HTTP response alone cannot establish that a site served its usual
page rather than an application-level challenge.

Non-success responses, empty bodies and unsupported content types produce errors
rather than a clean assessment. Important error codes are:

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `UNSAFE_TARGET` | 422 | URL, address or DNS answers violate the public-target policy. |
| `UNSUPPORTED_CONTENT_TYPE` | 422 | Response is not declared HTML or XHTML. |
| `PROXY_PINNING_UNSUPPORTED` | 503 | Configured proxy cannot provide the required destination-pinning guarantee. |
| `DNS_FAILED`, `UPSTREAM_FAILED`, `EMPTY_RESPONSE` | 502 | A usable successful document could not be retrieved. |
| `RESPONSE_TOO_LARGE`, `TOO_MANY_REDIRECTS`, `UNSUPPORTED_CONTENT_ENCODING` | 502 | Target exceeds retrieval limits or ignores the requested encoding. |
| `FETCH_TIMEOUT` | 504 | Total retrieval deadline elapsed. |

HTML is decoded as UTF-8. A declared different charset marks the report `partial`
and includes a text-decoding limitation; clients must not present it as a complete
text inspection. Absence of configured risk signals is not evidence of complete
privacy or safety.

## Trust and data flow (CROPS record)

- **Censorship resistance and exit:** The operator, DNS resolver, hosting provider
  and network policy can deny requests. This is a hosted HTTP analysis service;
  consumers can inspect and run the source with their own infrastructure.
- **Open source:** Retrieval policy and analysis rules are visible in
  `lib/safe-fetch.js` and `agents/MetadataAgent.js`; deterministic tests cover
  address validation, DNS rebinding, redirects, budgets and proxy failure.
- **Privacy:** The target server receives the service's IP address, user agent and
  requested URL, including its query. Reports can contain personal information
  already present in the inspected page. This agent does not persist fetched
  pages, reports or target URLs and emits no request logs. Deployments must assess
  HTTP access logs, caller retention and infrastructure logging separately. Fetch
  errors do not echo target URLs, proxy credentials or upstream diagnostic text.
- **Security and authority:** This agent performs bounded read-only web requests;
  it does not read wallet keys, sign transactions or change on-chain state. Payment
  verification, settlement and billing are separate server responsibilities.
  Application checks do not replace host-level egress isolation or protect against
  a compromised resolver, OS routing stack or transport implementation.
