export default {
  async fetch(request, env, ctx) {
    // 보안 및 규격을 위해 POST 요청만 허용합니다. (클라이언트에서 데이터를 보낼 때만 수신)
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method Not Allowed. Use POST." }), { 
        status: 405,
        headers: { "Content-Type": "application/json" }
      });
    }

    const url = new URL(request.url);
    
    try {
      // 클라이언트가 보낸 JSON 데이터를 파싱합니다.
      const body = await request.json();

      // 1. 플레이 세션 데이터 저장 경로 /api/sessions 는 deprecated 입니다. /api/selement/sessions 를 대신 사용할 예정입니다.
      if (url.pathname === "/api/sessions" || url.pathname === "/api/selement/sessions") {
        const query = `
          INSERT INTO play_sessions (play_time, ending, ended, easter_egg_ending, version) 
          VALUES (?, ?, ?, ?, ?)
        `;
        
        // SQLite(D1)는 Boolean이 없으므로 true/false를 1/0으로 변환하여 바인딩합니다.
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

        return new Response(JSON.stringify({ success: true, meta: info.meta }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      }

      // 2. 크래시 로그 데이터 저장 경로 /api/errors 는 deprecated 입니다. /api/selement/errors 를 대신 사용할 예정입니다.
      if (url.pathname === "/api/errors" || url.pathname === "/api/selement/errors") {
        const query = `
          INSERT INTO crash_logs (error_type, version) 
          VALUES (?, ?)
        `;

        const info = await env.selement
          .prepare(query)
          .bind(body.error_type, body.version)
          .run();

        return new Response(JSON.stringify({ success: true, meta: info.meta }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      }

      // 정의되지 않은 주소로 요청이 들어왔을 때 처리
      return new Response(JSON.stringify({ error: "Not Found" }), { 
        status: 404,
        headers: { "Content-Type": "application/json" }
      });

    } catch (error) {
      // 데이터 포맷 불일치나 SQL 에러 등 예외 발생 시 에러 메시지 반환
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};