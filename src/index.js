/**
 * List of supported OAuth providers.
 */
const supportedProviders = ['github', 'gitlab'];
/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Parse the `ALLOWED_DOMAINS` environment variable into a list of domain patterns.
 * @param {string} [allowedDomains] - Comma-separated domain patterns.
 * @returns {string[]} Domain patterns, without empty entries.
 */
const parseAllowedDomains = (allowedDomains) =>
  (allowedDomains ?? '')
    .split(',')
    .map((str) => str.trim())
    .filter(Boolean);

/**
 * Check if a domain matches any of the allowed domain patterns. A `*` in a pattern matches
 * any number of characters, including dots, mirroring the documented `ALLOWED_DOMAINS`
 * behavior.
 * @param {string} domain - Domain to check, such as a site ID or a hostname.
 * @param {string[]} allowedDomains - Allowed domain patterns.
 * @returns {boolean} `true` if the domain is allowed.
 */
const isAllowedDomain = (domain, allowedDomains) =>
  allowedDomains.some((pattern) =>
    // Escape the pattern, then replace a wildcard for regex
    new RegExp(`^${escapeRegExp(pattern).replace('\\*', '.+')}$`).test(domain),
  );

/**
 * Output HTML response that communicates with the window opener.
 * @param {object} args - Options.
 * @param {string} [args.provider] - Backend name, e,g. `github`.
 * @param {string} [args.token] - OAuth token.
 * @param {string} [args.error] - Error message when an OAuth token is not available.
 * @param {string} [args.errorCode] - Error code to be used to localize the error message in
 * Sveltia CMS.
 * @param {string[]} [args.allowedDomains] - Allowed domain patterns. The result is only ever
 * sent to a window whose hostname matches one of these patterns; a token is never output
 * when the list is empty.
 * @returns {Response} Response with HTML.
 */
const outputHTML = ({ provider = 'unknown', token, error, errorCode, allowedDomains = [] }) => {
  // Fail closed: without an allow-list there is no window the token may be sent to
  const misconfigured = Boolean(token) && !allowedDomains.length;
  const state = error || misconfigured ? 'error' : 'success';

  const content =
    error || misconfigured
      ? {
          provider,
          error: misconfigured ? 'Allowed domains are not configured on the authenticator.' : error,
          errorCode: misconfigured ? 'MISCONFIGURED_ALLOWED_DOMAINS' : errorCode,
        }
      : { provider, token };

  // Regex sources for the allowed domain patterns, applied to the replying window's hostname
  const allowedPatterns = allowedDomains.map(
    (pattern) => `^${escapeRegExp(pattern).replace('\\*', '.+')}$`,
  );

  // Origins the handshake may be announced to; a wildcard pattern names no single origin,
  // so only exact domains can be announced to
  const allowedOrigins = allowedDomains
    .filter((pattern) => !pattern.includes('*'))
    .map((pattern) => `https://${pattern}`);

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          const allowedPatterns = ${JSON.stringify(allowedPatterns)};
          const allowedOrigins = ${JSON.stringify(allowedOrigins)};

          window.addEventListener('message', ({ data, origin }) => {
            let hostname = '';

            try {
              hostname = new URL(origin).hostname;
            } catch {
              return;
            }

            if (
              data === 'authorizing:${provider}' &&
              allowedPatterns.some((pattern) => new RegExp(pattern).test(hostname))
            ) {
              window.opener?.postMessage(
                'authorization:${provider}:${state}:${JSON.stringify(content)}',
                origin
              );
            }
          });
          allowedOrigins.forEach((origin) => {
            window.opener?.postMessage('authorizing:${provider}', origin);
          });
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        // Delete CSRF token
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
      },
    },
  );
};

/**
 * Handle the `auth` method, which is the first request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { origin, searchParams } = new URL(url);
  const { provider, site_id: domain } = Object.fromEntries(searchParams);
  const allowedDomains = parseAllowedDomains(env.ALLOWED_DOMAINS);

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      allowedDomains,
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  // Fail closed when no domain is configured to use the authenticator
  if (!allowedDomains.length) {
    return outputHTML({
      provider,
      allowedDomains,
      error: 'Allowed domains are not configured on the authenticator.',
      errorCode: 'MISCONFIGURED_ALLOWED_DOMAINS',
    });
  }

  // Check if the domain is allowed
  if (!isAllowedDomain(domain ?? '', allowedDomains)) {
    return outputHTML({
      provider,
      allowedDomains,
      error: 'Your domain is not allowed to use the authenticator.',
      errorCode: 'UNSUPPORTED_DOMAIN',
    });
  }

  // Generate a random string for CSRF protection
  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');
  let authURL = '';

  // GitHub
  if (provider === 'github') {
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return outputHTML({
        allowedDomains,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo,user',
      state: csrfToken,
    });

    authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;
  }

  // GitLab
  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        allowedDomains,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    const params = new URLSearchParams({
      client_id: GITLAB_CLIENT_ID,
      redirect_uri: `${origin}/callback`,
      response_type: 'code',
      scope: 'api',
      state: csrfToken,
    });

    authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params.toString()}`;
  }

  // Redirect to the authorization server
  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      // Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent by the
      // browser after redirect
      'Set-Cookie':
        `csrf-token=${provider}_${csrfToken}; ` +
        `HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
    },
  });
};

/**
 * Handle the `callback` method, which is the second request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { origin, searchParams } = new URL(url);
  const { code, state } = Object.fromEntries(searchParams);
  const allowedDomains = parseAllowedDomains(env.ALLOWED_DOMAINS);

  const [, provider, csrfToken] =
    headers.get('Cookie')?.match(/\bcsrf-token=([a-z-]+?)_([0-9a-f]{32})\b/) ?? [];

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      allowedDomains,
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  if (!code || !state) {
    return outputHTML({
      allowedDomains,
      provider,
      error: 'Failed to receive an authorization code. Please try again later.',
      errorCode: 'AUTH_CODE_REQUEST_FAILED',
    });
  }

  if (!csrfToken || state !== csrfToken) {
    return outputHTML({
      allowedDomains,
      provider,
      error: 'Potential CSRF attack detected. Authentication flow aborted.',
      errorCode: 'CSRF_DETECTED',
    });
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  let tokenURL = '';
  let requestBody = {};

  // GitHub
  if (provider === 'github') {
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return outputHTML({
        allowedDomains,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
    requestBody = {
      code,
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
    };
  }

  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        allowedDomains,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
    requestBody = {
      code,
      client_id: GITLAB_CLIENT_ID,
      client_secret: GITLAB_CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: `${origin}/callback`,
    };
  }

  let response;
  let token = '';
  let error = '';

  try {
    response = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });
  } catch {
    //
  }

  if (!response) {
    return outputHTML({
      allowedDomains,
      provider,
      error: 'Failed to request an access token. Please try again later.',
      errorCode: 'TOKEN_REQUEST_FAILED',
    });
  }

  try {
    ({ access_token: token, error } = await response.json());
  } catch {
    return outputHTML({
      allowedDomains,
      provider,
      error: 'Server responded with malformed data. Please try again later.',
      errorCode: 'MALFORMED_RESPONSE',
    });
  }

  return outputHTML({ provider, token, error, allowedDomains });
};

export default {
  /**
   * The main request handler.
   * @param {Request} request - HTTP request.
   * @param {{ [key: string]: string }} env - Environment variables.
   * @returns {Promise<Response>} HTTP response.
   * @see https://developers.cloudflare.com/workers/runtime-apis/fetch/
   * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
   * @see https://docs.gitlab.com/ee/api/oauth2.html#authorization-code-flow
   */
  async fetch(request, env) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
      return handleAuth(request, env);
    }

    if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
      return handleCallback(request, env);
    }

    return new Response('', { status: 404 });
  },
};
