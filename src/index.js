const SESSION_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...extraHeaders,
    },
  });
}

function randomId(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  return [...array]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return [...new Uint8Array(hash)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password, salt) {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    256
  );

  return [...new Uint8Array(bits)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `dragonheart_session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DURATION / 1000}`,
  ].join("; ");
}

function deleteSessionCookie() {
  return [
    "dragonheart_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, "dragonheart_session");

  if (!token) {
    return null;
  }

  const tokenHash = await sha256(token);

  const session = await env.dragonheart-auth
    .prepare(`
      SELECT
        auth_sessions.id AS session_id,
        auth_sessions.user_id,
        auth_sessions.expires_at,
        users.email
      FROM auth_sessions
      JOIN users
        ON users.id = auth_sessions.user_id
      WHERE auth_sessions.token_hash = ?
    `)
    .bind(tokenHash)
    .first();

  if (!session) {
    return null;
  }

  if (session.expires_at <= Date.now()) {
    await env.dragonheart-auth
      .prepare("DELETE FROM auth_sessions WHERE id = ?")
      .bind(session.session_id)
      .run();

    return null;
  }

  return {
    id: session.user_id,
    email: session.email,
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    try {
      /*
       * ============================
       * AUTH
       * ============================
       */

      // 회원가입
      if (
        url.pathname === "/auth/signup" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const email = String(body.email || "")
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        if (!email || !password) {
          return json(
            { error: "Email and password are required." },
            400
          );
        }

        if (password.length < 8) {
          return json(
            { error: "Password must be at least 8 characters." },
            400
          );
        }

        const existingUser = await env.dragonheart-auth
          .prepare("SELECT id FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (existingUser) {
          return json(
            { error: "Email is already registered." },
            409
          );
        }

        const userId = randomId(16);
        const salt = randomId(16);
        const passwordHash = await hashPassword(password, salt);
        const now = Date.now();

        await env.dragonheart-auth
          .prepare(`
            INSERT INTO users (
              id,
              email,
              password_hash,
              password_salt,
              created_at
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            userId,
            email,
            passwordHash,
            salt,
            now
          )
          .run();

        return json(
          {
            success: true,
            user: {
              id: userId,
              email,
            },
          },
          201
        );
      }

      // 로그인
      if (
        url.pathname === "/auth/login" &&
        request.method === "POST"
      ) {
        const body = await request.json();

        const email = String(body.email || "")
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        if (!email || !password) {
          return json(
            { error: "Email and password are required." },
            400
          );
        }

        const user = await env.dragonheart-auth
          .prepare(`
            SELECT
              id,
              email,
              password_hash,
              password_salt
            FROM users
            WHERE email = ?
          `)
          .bind(email)
          .first();

        if (!user) {
          return json(
            { error: "Invalid email or password." },
            401
          );
        }

        const passwordHash = await hashPassword(
          password,
          user.password_salt
        );

        if (passwordHash !== user.password_hash) {
          return json(
            { error: "Invalid email or password." },
            401
          );
        }

        const sessionToken = randomId(32);
        const tokenHash = await sha256(sessionToken);

        const sessionId = randomId(16);

        const now = Date.now();
        const expiresAt = now + SESSION_DURATION;

        await env.dragonheart-auth
          .prepare(`
            INSERT INTO auth_sessions (
              id,
              user_id,
              token_hash,
              expires_at,
              created_at
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            sessionId,
            user.id,
            tokenHash,
            expiresAt,
            now
          )
          .run();

        return json(
          {
            success: true,
            user: {
              id: user.id,
              email: user.email,
            },
          },
          200,
          {
            "Set-Cookie": sessionCookie(sessionToken),
          }
        );
      }

      // 현재 로그인 사용자
      if (
        url.pathname === "/auth/me" &&
        request.method === "GET"
      ) {
        const user = await getCurrentUser(request, env);

        if (!user) {
          return json(
            {
              authenticated: false,
            },
            401
          );
        }

        return json({
          authenticated: true,
          user,
        });
      }

      // 로그아웃
      if (
        url.pathname === "/auth/logout" &&
        request.method === "POST"
      ) {
        const token = getCookie(
          request,
          "dragonheart_session"
        );

        if (token) {
          const tokenHash = await sha256(token);

          await env.dragonheart-auth
            .prepare(
              "DELETE FROM auth_sessions WHERE token_hash = ?"
            )
            .bind(tokenHash)
            .run();
        }

        return json(
          {
            success: true,
          },
          200,
          {
            "Set-Cookie": deleteSessionCookie(),
          }
        );
      }

      /*
       * ============================
       * 기존 DragonHeart API
       * ============================
       */

      if (request.method !== "POST") {
        return json(
          {
            error: "Method Not Allowed. Use POST.",
          },
          405
        );
      }

      const body = await request.json();

      // 플레이 세션
      if (url.pathname === "/api/sessions") {
        const query = `
          INSERT INTO play_sessions (
            play_time,
            ending,
            ended,
            easter_egg_ending,
            version
          )
          VALUES (?, ?, ?, ?, ?)
        `;

        const info = await env.selement
          .prepare(query)
          .bind(
            body.play_time,
            body.ending ? 1 : 0,
            body.ended ? 1 : 0,
            body.easter_egg_ending ? 1 : 0,
            body.version
          )
          .run();

        return json(
          {
            success: true,
            meta: info.meta,
          },
          201
        );
      }

      // 크래시 로그
      if (url.pathname === "/api/errors") {
        const query = `
          INSERT INTO crash_logs (
            error_type,
            version
          )
          VALUES (?, ?)
        `;

        const info = await env.selement
          .prepare(query)
          .bind(
            body.error_type,
            body.version
          )
          .run();

        return json(
          {
            success: true,
            meta: info.meta,
          },
          201
        );
      }

      return json(
        {
          error: "Not Found",
        },
        404
      );

    } catch (error) {
      console.error(error);

      return json(
        {
          error: "Internal Server Error",
        },
        500
      );
    }
  },
};