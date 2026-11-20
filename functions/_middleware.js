// 越谷メソッド パスワード保護（Cloudflare Pages Functions 用）
// 置き場所：GitHubリポジトリの functions/_middleware.js
// 必要な設定：Pages → Settings → Variables and Secrets に Secret「TEAM_PASSWORD」

const COOKIE = 'km_auth';
const MAX_AGE = 60 * 60 * 24 * 30; // ログイン状態を30日保持
const PUBLIC_PATHS = ['/favicon.png', '/spc-logo.png']; // ログイン画面で使うロゴだけは公開

async function makeToken(pw) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('koshigaya-method-v1'));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(req, name) {
  const c = req.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : '';
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const HTML_HEADERS = {
  'Content-Type': 'text/html; charset=UTF-8',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
  'Referrer-Policy': 'same-origin'
};

function loginPage(error) {
  const msg = error ? '<p class="err">パスワードが違います。もう一度入力してください。</p>' : '';
  return new Response(`<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>越谷メソッド ログイン</title>
<link rel="icon" href="/favicon.png">
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:linear-gradient(180deg,#f7f0eb,#efe4dd);font-family:'Noto Sans JP',sans-serif;color:#171413;padding:16px}
.box{width:100%;max-width:380px;background:#fffdfa;border:1px solid #d9cbc2;border-radius:20px;padding:28px 22px;text-align:center;box-shadow:0 10px 24px #01234615}
img{width:72px;height:72px}small{display:block;color:#9B070A;font-weight:700;letter-spacing:.12em;margin-top:8px}
h1{margin:2px 0 4px;color:#012346;font-size:24px}p{margin:0 0 18px;color:#5d5450;font-size:14px}
input{width:100%;font-size:17px;padding:13px;border:1.5px solid #bfb0a7;border-radius:12px;margin-bottom:12px}
button{width:100%;min-height:52px;font-size:16px;font-weight:800;color:#fff;background:#9B070A;border:0;border-radius:12px;cursor:pointer}
.err{color:#9B070A;font-weight:700;margin:0 0 12px}.note{margin:16px 0 0;font-size:12px}
</style></head><body><form class="box" method="POST" action="/login">
<img src="/favicon.png" alt="越谷ボーイズ">
<small>KOSHIGAYA BOYS</small><h1>越谷メソッド</h1><p>チーム関係者専用ログイン</p>${msg}
<input type="password" name="password" placeholder="チーム共通パスワード" autocomplete="current-password" required autofocus>
<button type="submit">ログインする</button><p class="note">選手・保護者・監督・スタッフ専用</p>
</form></body></html>`, { status: error ? 401 : 200, headers: HTML_HEADERS });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (PUBLIC_PATHS.includes(url.pathname)) return next();

  const pw = env.TEAM_PASSWORD;
  if (!pw) {
    return new Response('設定エラー：Secret「TEAM_PASSWORD」が見つかりません。設定後に再デプロイしてください。',
      { status: 500, headers: { 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'no-store' } });
  }
  const token = await makeToken(pw);

  if (url.pathname === '/logout') {
    return new Response(null, { status: 302, headers: {
      Location: '/', 'Set-Cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  }

  if (url.pathname === '/login' && request.method === 'POST') {
    const form = await request.formData();
    const input = String(form.get('password') || '');
    if (safeEqual(input, pw)) {
      return new Response(null, { status: 303, headers: {
        Location: '/', 'Cache-Control': 'no-store',
        'Set-Cookie': `${COOKIE}=${token}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax` } });
    }
    return loginPage(true);
  }

  if (!safeEqual(getCookie(request, COOKIE), token)) return loginPage(false);

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'no-store');
  out.headers.set('X-Robots-Tag', 'noindex, nofollow');
  return out;
}
