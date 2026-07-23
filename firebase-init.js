/* ============================================================
   고급화학 팀 탐구 · 공유 인증/저장 모듈 (firebase-init.js)
   ------------------------------------------------------------
   ⚠️ 교사가 반드시 해야 하는 단 하나의 작업:
   아래 FIREBASE_CONFIG 자리에 본인의 Firebase 프로젝트 설정값을
   붙여넣으세요. (설정 방법은 배포 안내 문서 참고)

   이 파일이 하는 일:
   - 팀 로그인/로그아웃 (이름 + 비밀번호, 서버 없이 Firestore로 확인)
   - 관리자 계정 자동 생성 (이름: 관리자 / 비번: 관리자, 최초 1회)
   - 관리자용: 팀 계정 생성 · 비밀번호 재설정 · 팀 목록 조회
   - 설계실/기록장 데이터를 Firestore에 저장·불러오기

   보안 관련 솔직한 안내:
   이건 "편의용" 로그인입니다. 은행 수준 보안이 아니라, 학급 프로젝트가
   기기 간에 이어지도록 하는 목적입니다. 비밀번호는 SHA-256으로
   해시해서 저장하지만, 그 이상의 보안(세션 만료, 무차별 대입 방지 등)은
   없습니다. 민감한 개인정보는 어디에도 입력하지 마세요.
   ============================================================ */

const FIREBASE_CONFIG = {
  apiKey: "AIzaSyA0WhdcbkaUcWnwiX7fpwowSKQ8QjYHnIA",
  authDomain: "chemini-69c3d.firebaseapp.com",
  projectId: "chemini-69c3d",
  storageBucket: "chemini-69c3d.firebasestorage.app",
  messagingSenderId: "656529519829",
  appId: "1:656529519829:web:9450e7f8c7bc892a099e5c",
  measurementId: "G-GZCCRVGRRE"
};

/* ---- Firestore 준비 (설정이 비어있으면 오프라인 모의 모드로 동작) ---- */
let db = null;
let FIREBASE_READY = false;
try {
  if (FIREBASE_CONFIG.apiKey && !FIREBASE_CONFIG.apiKey.includes("여기에") && typeof firebase !== "undefined") {
    firebase.initializeApp(FIREBASE_CONFIG);
    db = firebase.firestore();
    FIREBASE_READY = true;
  }
} catch (e) {
  console.warn("Firebase 초기화 실패 — 설정값을 확인하세요.", e);
}

/* ============================================================
   AUTH — 로그인 상태 관리
   ============================================================ */
const AUTH = {
  KEY: "gochem_auth_v1",

  async _hash(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  },

  _sanitize(name) {
    return name.trim().replace(/[\/\.\#\$\[\]]/g, "-").slice(0, 60);
  },

  async _ensureAdminSeed() {
    if (!FIREBASE_READY) return;
    const ref = db.collection("teams").doc("admin");
    const snap = await ref.get();
    if (!snap.exists) {
      const hash = await this._hash("admin");
      await ref.set({ name: "admin", passwordHash: hash, isAdmin: true, createdAt: Date.now() });
    }
  },

  async login(name, password) {
    name = (name || "").trim();
    password = password || "";
    if (!name || !password) return { ok: false, error: "이름과 비밀번호를 모두 입력하세요." };
    if (!FIREBASE_READY) return { ok: false, error: "저장소 연결 설정이 안 되어 있습니다. 교사에게 문의하세요. (firebase-init.js 설정 필요)" };

    await this._ensureAdminSeed();
    const id = this._sanitize(name);
    try {
      const snap = await db.collection("teams").doc(id).get();
      if (!snap.exists) return { ok: false, error: "등록되지 않은 이름입니다. 선생님께 계정 생성을 요청하세요." };
      const data = snap.data();
      const hash = await this._hash(password);
      if (hash !== data.passwordHash) return { ok: false, error: "비밀번호가 올바르지 않습니다." };
      const identity = { id, name: data.name, isAdmin: !!data.isAdmin, ts: Date.now() };
      localStorage.setItem(this.KEY, JSON.stringify(identity));
      return { ok: true, identity };
    } catch (e) {
      return { ok: false, error: "로그인 중 오류가 발생했습니다: " + e.message };
    }
  },

  logout() {
    localStorage.removeItem(this.KEY);
    location.reload();
  },

  current() {
    try { return JSON.parse(localStorage.getItem(this.KEY)); } catch (e) { return null; }
  },

  /* ---- 관리자 전용 ---- */
  async createTeam(name, password) {
    const id = this._sanitize(name);
    const hash = await this._hash(password);
    await db.collection("teams").doc(id).set({ name, passwordHash: hash, isAdmin: false, createdAt: Date.now() });
    return id;
  },
  async resetPassword(teamId, newPassword) {
    const hash = await this._hash(newPassword);
    await db.collection("teams").doc(teamId).update({ passwordHash: hash });
  },
  async listTeams() {
    const qs = await db.collection("teams").orderBy("createdAt").get();
    return qs.docs.map(d => ({ id: d.id, ...d.data() }));
  },
  async deleteTeam(teamId) {
    await db.collection("teams").doc(teamId).delete();
    await db.collection("designs").doc(teamId).delete().catch(() => {});
    await db.collection("labnotes").doc(teamId).delete().catch(() => {});
  }
};

/* ============================================================
   STORE — 설계/기록 데이터 저장·조회 (Firestore)
   ============================================================ */
const STORE = {
  async saveDesign(teamId, data) {
    if (!FIREBASE_READY) return false;
    try { await db.collection("designs").doc(teamId).set({ ...data, updatedAt: Date.now() }); return true; }
    catch (e) { console.warn("saveDesign 실패", e); return false; }
  },
  async loadDesign(teamId) {
    if (!FIREBASE_READY) return null;
    try { const s = await db.collection("designs").doc(teamId).get(); return s.exists ? s.data() : null; }
    catch (e) { return null; }
  },
  async saveLab(teamId, data) {
    if (!FIREBASE_READY) return false;
    try { await db.collection("labnotes").doc(teamId).set({ ...data, updatedAt: Date.now() }); return true; }
    catch (e) { console.warn("saveLab 실패", e); return false; }
  },
  async loadLab(teamId) {
    if (!FIREBASE_READY) return null;
    try { const s = await db.collection("labnotes").doc(teamId).get(); return s.exists ? s.data() : null; }
    catch (e) { return null; }
  },
  /* 현황판: 전체 팀의 설계 데이터를 한 번에 */
  async loadAllDesigns() {
    if (!FIREBASE_READY) return [];
    try {
      const qs = await db.collection("designs").get();
      return qs.docs.map(d => ({ teamId: d.id, ...d.data() }));
    } catch (e) { return []; }
  },
  /* 실시간 구독 (현황판용) */
  watchAllDesigns(callback) {
    if (!FIREBASE_READY) return () => {};
    return db.collection("designs").onSnapshot(qs => {
      callback(qs.docs.map(d => ({ teamId: d.id, ...d.data() })));
    }, err => console.warn("watchAllDesigns 오류", err));
  }
};

/* ============================================================
   LOGIN GATE — 로그인 안 되어 있으면 화면을 덮는 폼
   ============================================================ */
const LoginGate = {
  inject(onSuccess) {
    const me = AUTH.current();
    if (me) { if (onSuccess) onSuccess(me); return me; }

    const wrap = document.createElement("div");
    wrap.id = "loginGate";
    wrap.innerHTML = `
      <div class="lg-card">
        <div class="lg-logo">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6M10 3v6l-4 9a2 2 0 002 3h8a2 2 0 002-3l-4-9V3"/></svg>
        </div>
        <h2>고급화학 팀 탐구</h2>
        <p class="lg-sub">팀 이름과 비밀번호로 로그인하세요.</p>
        <input type="text" id="lgName" placeholder="팀 이름 (예: 3팀 킬레인)" autocomplete="username">
        <input type="password" id="lgPw" placeholder="비밀번호" autocomplete="current-password">
        <button id="lgBtn">로그인</button>
        <p class="lg-err" id="lgErr"></p>
        <p class="lg-note">계정이 없다면 선생님께 요청하세요.</p>
      </div>`;
    const style = document.createElement("style");
    style.textContent = `
      #loginGate{position:fixed;inset:0;z-index:9999;background:rgba(245,245,247,.97);
        backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:center;
        font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard Variable",Pretendard,system-ui,sans-serif}
      .lg-card{background:#fff;border-radius:20px;box-shadow:0 12px 40px rgba(0,0,0,.12);
        padding:38px 34px;width:340px;max-width:88vw;text-align:center}
      .lg-logo{color:#0071e3;margin-bottom:10px}
      .lg-card h2{font-size:19px;font-weight:700;letter-spacing:-0.02em;margin-bottom:6px;color:#1d1d1f}
      .lg-sub{font-size:13.5px;color:#6e6e73;margin-bottom:20px;line-height:1.5}
      #loginGate input{width:100%;font-size:14.5px;padding:12px 14px;margin-bottom:10px;
        border:2px solid #e8e8ed;border-radius:12px;box-sizing:border-box;font-family:inherit}
      #loginGate input:focus{outline:none;border-color:#0071e3}
      #loginGate button{width:100%;padding:12px;border:none;border-radius:980px;background:#0071e3;
        color:#fff;font-size:14.5px;font-weight:600;cursor:pointer;margin-top:4px;font-family:inherit;transition:.15s}
      #loginGate button:hover{background:#0077ed}
      #loginGate button:disabled{background:#d2d2d7;cursor:not-allowed}
      .lg-err{color:#d0342c;font-size:12.5px;margin-top:12px;min-height:16px;line-height:1.5}
      .lg-note{font-size:11.5px;color:#a1a1a6;margin-top:14px}
    `;
    document.head.appendChild(style);
    document.body.appendChild(wrap);

    const doLogin = async () => {
      const name = document.getElementById("lgName").value;
      const pw = document.getElementById("lgPw").value;
      const btn = document.getElementById("lgBtn");
      const err = document.getElementById("lgErr");
      btn.disabled = true; btn.textContent = "확인 중…"; err.textContent = "";
      const r = await AUTH.login(name, pw);
      btn.disabled = false; btn.textContent = "로그인";
      if (r.ok) { wrap.remove(); style.remove(); if (onSuccess) onSuccess(r.identity); }
      else { err.textContent = r.error; }
    };
    document.getElementById("lgBtn").onclick = doLogin;
    document.getElementById("lgPw").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
    document.getElementById("lgName").addEventListener("keydown", e => { if (e.key === "Enter") document.getElementById("lgPw").focus(); });
    return null;
  }
};
