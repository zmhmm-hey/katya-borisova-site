/**
 * Cloudflare Worker: serves the static site AND handles GitHub OAuth login
 * for the Decap CMS admin panel (backend: github), replacing the old
 * Netlify Identity + Git Gateway login.
 *
 * Requires two Worker secrets (set in Cloudflare Dashboard -> Workers & Pages
 * -> katya-borisova-site -> Settings -> Variables and Secrets):
 *   CLIENT_ID     - GitHub OAuth App client ID
 *   CLIENT_SECRET - GitHub OAuth App client secret
 *
 * GitHub OAuth App "Authorization callback URL" must be:
 *   https://katyaborisova.art/callback
 */

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";

async function hmac(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function handleAuth(url, env) {
  if (!env.CLIENT_ID || !env.CLIENT_SECRET) {
    return new Response(
      "OAuth is not configured: missing CLIENT_ID / CLIENT_SECRET Worker secrets.",
      { status: 500 }
    );
  }

  // Stateless CSRF protection: sign a random nonce with the client secret,
  // send both to GitHub, verify the signature again in /callback.
  const nonce = crypto.randomUUID();
  const sig = await hmac(env.CLIENT_SECRET, nonce);
  const state = `${nonce}.${sig}`;

  const redirectUri = `${url.origin}/callback`;
  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("client_id", env.CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", "repo,user");
  authorizeUrl.searchParams.set("state", state);

  return Response.redirect(authorizeUrl.toString(), 302);
}

function popupResponse(message) {
  const html = `<!doctype html>
<html>
  <body>
    <script>
      (function () {
        function receiveMessage(e) {
          window.opener.postMessage(${JSON.stringify(message)}, e.origin);
          window.removeEventListener("message", receiveMessage, false);
        }
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage("authorizing:github", "*");
      })();
    </script>
  </body>
</html>`;
  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" },
  });
}

async function handleCallback(url, env) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state") || "";
  const [nonce, sig] = state.split(".");

  if (!code || !nonce || !sig) {
    return new Response("Missing OAuth code or state.", { status: 400 });
  }

  const expectedSig = await hmac(env.CLIENT_SECRET, nonce);
  if (sig !== expectedSig) {
    return new Response("Invalid OAuth state.", { status: 400 });
  }

  const redirectUri = `${url.origin}/callback`;
  const tokenResp = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });

  const tokenData = await tokenResp.json();

  if (!tokenResp.ok || tokenData.error || !tokenData.access_token) {
    return new Response(
      `GitHub OAuth error: ${tokenData.error_description || tokenData.error || "unknown error"}`,
      { status: 400 }
    );
  }

  const message = `authorization:github:success:${JSON.stringify({
    token: tokenData.access_token,
    provider: "github",
  })}`;

  return popupResponse(message);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/auth") {
      return handleAuth(url, env);
    }
    if (url.pathname === "/callback") {
      return handleCallback(url, env);
    }

    // Everything else: serve the static site as before.
    return env.ASSETS.fetch(request);
  },
};
