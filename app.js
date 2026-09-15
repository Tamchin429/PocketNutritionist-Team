// app.js
// PocketNutritionist team-web（チーム管理者用ブラウザ）。
//
// 認証：Supabase Auth のメールアドレス＋パスワード（signInWithPassword/signUp）。
// Magic Linkは廃止した。team-webに自由な無条件サインアップは無く、admin-webで事前登録された
// メールアドレス（team_admin_invitations）だけが初回アカウント設定（signUp）を行える
// （team-auth Edge Functionのcheck_invitationで事前確認してから初めてsignUpを呼ぶ）。
// service_role・ADMIN_API_TOKENは一切使わず、ブラウザからはpublishable key + 本人のJWTで
// Supabaseへ直接アクセスする（admin-webのローカルproxy方式はここでは使わない）。
// 権限の判定・データの可視範囲はすべてRLS（team_admins/teams/team_invite_codes/
// team_contracts）に委ねる。クライアントからuser_idを指定して書き込む処理は行わない
// （RPCはauth.uid()のみを使う既存のSECURITY DEFINER関数をそのまま呼ぶだけ）。

// セッション（Supabase Authの標準localStorage保存）はorigin単位で分離されるため、
// 127.0.0.1経由でアクセスされた場合はlocalhostへ正規化する（Email確認/パスワード再設定の
// redirect先もlocalhostに固定しているため、通常は自然にlocalhost側へ揃うが保険として揃える）。
// hash/search（Auth callbackの#access_token/?code=/type=recovery等）はそのまま維持して
// 同一パスへ置き換えるため、認証コールバック処理は正規化後のページ読み込みでそのまま継続できる
const isNormalizingHost = window.location.hostname === "127.0.0.1";
if (isNormalizingHost) {
  window.location.replace(
    "http://localhost:8081" + window.location.pathname + window.location.search + window.location.hash
  );
}

// Email確認/パスワード再設定のリンクから戻ってきた直後かどうか（claim処理の実行判定に使う）。
// supabase-jsのdetectSessionInUrlがhashを消費してhistory.replaceStateする前に、
// このスクリプトの同期実行タイミングで判定しておく
const cameFromAuthCallback =
  window.location.hash.includes("access_token") ||
  window.location.hash.includes("type=recovery") ||
  window.location.search.includes("code=");

// 確認リンク（Email Confirmation/パスワード再設定共通）が無効・期限切れの場合、Supabaseは
// session確立の代わりにhashへerror_code=otp_expired等を付けてteam-webへ戻す。この場合は
// 無言でログイン画面へ戻さず、専用の再送導線（view-link-expired）を表示する。
// showView("login")で他の画面へ移動した後は表示しない（一度だけ表示するためのフラグ）
let shouldShowLinkExpiredOnce =
  window.location.hash.includes("error_code=otp_expired") ||
  window.location.search.includes("error_code=otp_expired");

// パスワード再設定リンクから戻った場合、supabase-js（実装：@supabase/supabase-js@2.45.4の
// 配布バンドルを実際に読んで確認済み）はhashへ
// #access_token=...&refresh_token=...&expires_in=...&token_type=bearer&type=recovery
// を付けてteam-webへ戻す（implicit flow。本プロジェクトのflowTypeはデフォルトのimplicit）。
// このtype=recoveryは、onAuthStateChangeの"PASSWORD_RECOVERY"イベントとしても通知されるが、
// そのイベントはsupabase-js内部でsetTimeout(...,0)を使って非同期に一度だけ発火されるため、
// 先にこちら側のgetSession()/renderForSession()が「有効なsessionが張られた」と判断して
// loadDashboard()を呼んでしまう競合が実際に発生する（実メールでの実機確認で再現）。
// イベントの発火・購読タイミングに依存せず、URLの時点で同期的にrecovery modeへ入れることで
// この競合を根本的に防ぐ
const isPasswordRecoveryFromUrl = window.location.hash.includes("type=recovery");

// Safariタブを閉じてrecovery完了前に新しいタブでlocalhost:8081を開いた場合でも
// reset画面へ戻れるようにするためのフラグ。sessionStorageはタブ（正確にはブラウジング
// コンテキスト）単位で分離されており、新しいタブ・新しいウィンドウからは参照できないため
// 要件を満たせない。localStorageはoriginで共有されるため、新しいタブから読める。
//
// 保存するのは「recovery中であること」と「開始時刻」だけで、access_token/refresh_token/
// email/password/user_id等は一切保存しない（Supabase Auth自身のsession保存
// （supabase-js標準のlocalStorage利用）とは別のkeyであり、tokenの中身には触れない）。
// 保存期間は無期限ではなく、下記TTLで必ず自然消滅させる（放置されたrecovery状態が
// いつまでも有効なsessionと結びついて残り続けることを防ぐ）
const PASSWORD_RECOVERY_STORAGE_KEY = "pn-team-password-recovery";
const PASSWORD_RECOVERY_TTL_MS = 30 * 60 * 1000; // 30分

function readStoredRecoveryState() {
  try {
    const raw = window.localStorage.getItem(PASSWORD_RECOVERY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.active !== true || typeof parsed.startedAt !== "number") {
      clearStoredRecoveryFlag(); // 壊れた/形式違いの値は残さず消す
      return null;
    }
    if (Date.now() - parsed.startedAt > PASSWORD_RECOVERY_TTL_MS) {
      clearStoredRecoveryFlag(); // TTL超過分はここで確実に削除する
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function hasStoredRecoveryFlag() {
  return readStoredRecoveryState() !== null;
}

function setStoredRecoveryFlag() {
  try {
    window.localStorage.setItem(
      PASSWORD_RECOVERY_STORAGE_KEY,
      JSON.stringify({ active: true, startedAt: Date.now() })
    );
  } catch {
    // localStorageが使えない環境（プライベートブラウズ制限等）でも、isPasswordRecovery自体は
    // メモリ上のフラグとして機能するため、この呼び出し自体の失敗は無視してよい
  }
}

function clearStoredRecoveryFlag() {
  try {
    window.localStorage.removeItem(PASSWORD_RECOVERY_STORAGE_KEY);
  } catch {
    // 同上：削除に失敗しても致命的ではない
  }
}

const client = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});

let currentTeamId = null;

// ---------------------------------------------------------------------------
// 共通ユーティリティ
// ---------------------------------------------------------------------------
// 表示するuser-controlled text（メール・チーム名・招待コード等）はすべてinnerHTMLではなく
// textContentで代入している（本ファイル内にinnerHTMLの使用箇所は無い）。そのためescape関数は
// 不要で、代わりにtextContent代入そのものが常に安全なエスケープとして機能する設計にしている。

const views = {
  login: document.getElementById("view-login"),
  signup: document.getElementById("view-signup"),
  linkExpired: document.getElementById("view-link-expired"),
  resetRequest: document.getElementById("view-reset-request"),
  resetPassword: document.getElementById("view-reset-password"),
  loading: document.getElementById("view-loading"),
  contractGate: document.getElementById("view-contract-gate"),
  createTeam: document.getElementById("view-create-team"),
  dashboard: document.getElementById("view-dashboard"),
};

// ログイン状態を持たない（または認証フロー途中の）画面ではlogoutボタンを出さない。
// resetPasswordはSupabaseの一時的なrecovery sessionが張られた状態だが、通常ログインとは
// 別の一時フローのため、ここでは「ログイン済み」として扱わずlogoutを出さない
const LOGGED_OUT_VIEWS = new Set([
  "login",
  "signup",
  "linkExpired",
  "resetRequest",
  "resetPassword",
  "loading",
]);

// 現在表示中のview名。onAuthStateChangeはページ読み込み直後にINITIAL_SESSIONを
// 追加で発火することがあり、renderForSessionが同じsession(null)で複数回呼ばれる場合がある。
// view-link-expiredを一度表示した後にこの再呼び出しでログイン画面へ巻き戻されないよう、
// 「今どの画面を表示しているか」を見て判断できるようにしておく
let currentViewName = null;

function showView(name) {
  Object.entries(views).forEach(([key, el]) => {
    el.hidden = key !== name;
  });
  document.getElementById("logoutBtn").hidden = LOGGED_OUT_VIEWS.has(name);
  currentViewName = name;
  // dashboard表示中だけ、認証画面用の簡易ヘッダー（.site-header）を隠し、
  // ページ全体の横幅制限も解除する（ダッシュボード側は独自のサイドバー+topbarを持つため）
  document.body.classList.toggle("app-shell-active", name === "dashboard");
}

let toastTimer = null;
function showToast(message) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.hidden = true;
  }, 2200);
}

// ページ全体をブロックする大きなローディング表示は使わず、通信中のstatus-msg要素へ
// 小さなspinner＋テキストを添えるだけの共通表示にする（login/signup/dashboard初期読込/
// 選手詳細取得/招待コード再発行/パスワード再設定送信など、通信を伴う全箇所で共通利用する）
function setLoadingStatus(el, text) {
  el.style.color = "";
  el.textContent = "";
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  spinner.setAttribute("aria-hidden", "true");
  el.appendChild(spinner);
  el.appendChild(document.createTextNode(text));
}

// RPC（regenerate_team_invite_code/remove_team_member等）が返す内部エラー文言を、
// Supabaseの英語文言のまま出さず日本語へ変換する。既存RPCが実際にraiseするメッセージ
// （'not authorized for this team'等）だけを個別にマップし、それ以外は通信エラーとして扱う
function japaneseRpcErrorMessage(error) {
  const message = error && error.message ? error.message : "";
  if (message.includes("not authorized")) {
    return "この操作を行う権限がありません。";
  }
  if (message.includes("target user is not an active member")) {
    return "この選手は既にチームから外れています。";
  }
  return "通信に失敗しました。時間を空けて再度お試しください。";
}

// team-auth（check_invitation）が返すエラーは、既にこちらの実装が用意した日本語文言
// （例：「有効なメールアドレスを入力してください。」）であり、Supabase Auth自体が返す
// 英語エラーとは区別してそのまま表示してよい。全角/日本語文字を含むかどうかで簡易判定する
function isJapaneseMessage(message) {
  return /[　-ヿ㐀-䶿一-鿿＀-￯]/.test(message || "");
}

// signup/resend confirmationの共通エラーハンドラ：team-auth由来の日本語エラー（招待/契約状態の
// 案内）はそのまま見せ、Supabase Auth（signUp/resend）由来の英語エラーだけを日本語へ変換する
function japaneseSignupFlowErrorMessage(error, rateLimitMessage) {
  const message = error && error.message ? error.message : "";
  if (message.includes("email rate limit exceeded")) {
    return rateLimitMessage;
  }
  if (isJapaneseMessage(message)) {
    return message;
  }
  return "通信に失敗しました。時間を空けて再度お試しください。";
}

const roleLabel = { owner: "Owner", admin: "Admin" };

// アカウント画面表示用。ログイン中に取得できたら保持し、以後はここから読む
let currentUserRole = null;
let currentUserEmail = null;
let currentTeamName = null;

const CONTRACT_STATUS_LABEL = {
  active: "契約中",
  pending: "準備中",
  suspended: "停止中",
  ended: "契約終了",
};

// チーム画面の契約状態badge。色分けは他のbadge（Owner=黄色系, 入力済み=緑系等）と
// 衝突しないよう、活動中のみ緑系、それ以外はグレー系にまとめる
// （dashboard自体がactive以外はcontract gateで止まるため、通常この画面はactiveのみ表示するが、
// 表示ロジック自体はpending/suspended/endedにも対応させておく）
function buildContractStatusBadge(status) {
  const badge = document.createElement("span");
  const cls = status === "active" ? "badge-today-done" : "badge-gray";
  badge.className = `badge-pill ${cls}`;
  badge.textContent = CONTRACT_STATUS_LABEL[status] || status;
  return badge;
}

// 契約期間（開始〜終了）をまとめて1行で表示する。開始日未設定は「—」、
// 終了日未設定は無期限の意味で「期間指定なし」とし、いずれも推測日付は出さない
function formatContractPeriod(startsAt, endsAt) {
  const start = startsAt ? new Date(startsAt).toLocaleDateString("ja-JP") : "—";
  const end = endsAt ? new Date(endsAt).toLocaleDateString("ja-JP") : "期間指定なし";
  return `${start} 〜 ${end}`;
}

// ---------------------------------------------------------------------------
// 認証共通：Email確認/パスワード再設定のredirect先
// ---------------------------------------------------------------------------

// team-webの実行環境（開発/本番）ごとのredirect先を1箇所にまとめる。
// signup（emailRedirectTo）・確認メール再送（emailRedirectTo）・パスワード再設定
// （redirectTo）の3箇所すべてがこの関数の戻り値だけを使い、URL文字列を直書きしない。
//
// window.location.originだけでは判定できない理由：GitHub Pagesは
// https://tamchin429.github.io/PocketNutritionist-Team/ のようにsub-pathを持つため、
// originだけを使うと https://tamchin429.github.io/ （リポジトリのsub-path無し）に
// 戻ってしまい、Supabase側のRedirect URL許可リストとも一致しない。
// 必ずこの関数が返す固定文字列（Supabase Dashboardの許可リストと完全一致させたもの）を使う
function getTeamWebRedirectUrl() {
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    return "http://localhost:8081/";
  }
  return "https://tamchin429.github.io/PocketNutritionist-Team/";
}

const TEAM_WEB_ORIGIN = getTeamWebRedirectUrl();

// team-auth Edge Function（check_invitation専用。service_role/ADMIN_API_TOKENはteam-webへは
// 一切出さない）。未ログイン状態でもsupabase-jsが自動でanon keyをBearerとして付与するため、
// 呼び出し側でtokenを意識する必要はない
async function readFunctionErrorMessage(error) {
  if (!error || !error.context || typeof error.context.json !== "function") return null;
  try {
    const body = await error.context.json();
    return body && typeof body.error === "string" ? body.error : null;
  } catch {
    return null;
  }
}

async function checkInvitation(email) {
  const { data, error } = await client.functions.invoke("team-auth", {
    body: { action: "check_invitation", email },
  });
  if (error) {
    // functions.invoke()が非2xxを受け取った場合、error.messageは"Edge Function returned a
    // non-2xx status code"という汎用文言になり、team-auth側が返した実際のJSONエラー文言
    // （例：「有効なメールアドレスを入力してください。」）が失われる。context（元のResponse）
    // からJSONを読み直し、実際のエラー文言が取れればそちらを優先する
    const detailedMessage = await readFunctionErrorMessage(error);
    throw new Error(detailedMessage || error.message);
  }
  return data;
}

const CONTRACT_GATE_MESSAGE = {
  pending: "チーム契約は現在準備中です。",
  suspended: "チーム契約は現在一時停止されています。",
  ended: "チーム契約は終了しています。",
};

// team_contracts行が存在しないチーム向けの文言。以前は「行が無ければ後方互換で
// dashboardへ入れる」運用だったが、admin-webでのチーム契約管理が本運用になったため、
// team_contractsが無いチームはteam-webを利用不可として扱う（本番仕様）
// #contractGateMessageは.hintクラス（white-space指定なし）で表示するため、改行文字は
// 使わず一文にする（他のcontract gate文言と表示スタイルを揃える）
const CONTRACT_MISSING_MESSAGE =
  "このチームには有効な契約情報が登録されていません。PocketNutritionist運営者へお問い合わせください。";
const CONTRACT_FETCH_ERROR_MESSAGE = "契約情報を取得できませんでした。通信環境を確認してください。";

function contractStatusMessageForSignup(status) {
  return CONTRACT_GATE_MESSAGE[status] || "現在この招待では登録できません。";
}

// ---------------------------------------------------------------------------
// 確認メール再送（resend）
// ---------------------------------------------------------------------------
// 新しいSupabase Auth userを作り直さない・新しいメールアドレスも不要。既存のpending
// invitationと、signUp時に作られた（まだ未確認の）既存userに対して、確認メールだけを
// 再送する。emailはlocalStorageへ独自保存せず、画面の状態（JS変数・input値）だけで扱う

// resend成功後、連打防止のため一定時間はボタンを再度disabledにする（厳密なカウントダウン
// タイマーは実装しない。ページを離れれば当然リセットされる程度の簡易的なものでよい）
const RESEND_COOLDOWN_MS = 30000;

function japaneseResendErrorMessage(error) {
  return japaneseSignupFlowErrorMessage(
    error,
    "確認メールの送信回数が上限に達しています。しばらく時間を空けてから再度お試しください。"
  );
}

// email確認前のresendは、初回signupと同じくcheck_invitationで招待・契約状態を再確認してから
// 行う（対象emailがteam_admin_invitationsに存在するかをteam-webから直接SELECTしない方針は
// 初回登録時と同じ）
async function resendConfirmationEmail(email, statusEl, buttonEl) {
  if (!email) {
    statusEl.style.color = "var(--danger)";
    statusEl.textContent = "メールアドレスを入力してください";
    return;
  }

  buttonEl.disabled = true;
  statusEl.style.color = "";
  setLoadingStatus(statusEl, "確認中...");
  // 送信に成功した場合だけ、連打防止のためボタンを一定時間disabledのままにする
  // （それ以外の全ての終了経路ではfinallyで必ずdisabled=falseへ戻す）
  let succeeded = false;
  try {
    const invitation = await checkInvitation(email);

    if (!invitation.invited) {
      statusEl.style.color = "var(--danger)";
      statusEl.textContent = "このメールアドレスはチーム管理者として登録されていません。";
      return;
    }
    if (invitation.already_registered) {
      statusEl.style.color = "var(--danger)";
      statusEl.textContent = "このメールアドレスは既に認証済みです。ログインしてください。";
      return;
    }
    if (!invitation.can_signup) {
      statusEl.style.color = "var(--danger)";
      statusEl.textContent = contractStatusMessageForSignup(invitation.contract_status);
      return;
    }

    setLoadingStatus(statusEl, "再送中...");
    // 既存のSupabase Auth user（signUp時に作成済み・未確認）へ確認メールだけを再送する。
    // 新しいuserは作らない・新しいメールアドレスも不要
    const { error } = await client.auth.resend({
      type: "signup",
      email,
      options: { emailRedirectTo: TEAM_WEB_ORIGIN },
    });
    if (error) throw error;

    statusEl.style.color = "var(--success)";
    statusEl.textContent =
      "確認メールを再送しました。最新のメール内のリンクを開いてください（古い確認メールのリンクは使用できません）。";
    succeeded = true;

    // 連打防止：成功後もしばらくボタンを無効化したままにする
    setTimeout(() => {
      buttonEl.disabled = false;
    }, RESEND_COOLDOWN_MS);
  } catch (error) {
    statusEl.style.color = "var(--danger)";
    statusEl.textContent = japaneseResendErrorMessage(error);
  } finally {
    if (!succeeded) {
      buttonEl.disabled = false;
    }
  }
}

// ---------------------------------------------------------------------------
// ログイン（メールアドレス＋パスワード）
// ---------------------------------------------------------------------------

const loginEmailInput = document.getElementById("loginEmailInput");
const loginPasswordInput = document.getElementById("loginPasswordInput");
const loginSubmitBtn = document.getElementById("loginSubmitBtn");
const loginStatus = document.getElementById("loginStatus");

// ログイン失敗時、Supabaseの内部文言をそのまま出さず日本語へ変換する
function japaneseAuthErrorMessage(error) {
  const message = error && error.message ? error.message : "";
  if (message.includes("Invalid login credentials")) {
    return "メールアドレスまたはパスワードが正しくありません。";
  }
  if (message.includes("Email not confirmed")) {
    return "メールアドレスの確認が完了していません。メール内のリンクから確認を完了してください。";
  }
  return "ログインに失敗しました: " + message;
}

loginSubmitBtn.addEventListener("click", async () => {
  const email = loginEmailInput.value.trim();
  const password = loginPasswordInput.value;
  if (!email || !password) {
    loginStatus.style.color = "var(--danger)";
    loginStatus.textContent = "メールアドレスとパスワードを入力してください";
    return;
  }
  loginSubmitBtn.disabled = true;
  loginStatus.style.color = "";
  setLoadingStatus(loginStatus, "ログイン中...");
  try {
    const { error } = await client.auth.signInWithPassword({ email, password });
    if (error) throw error;
    loginStatus.textContent = "";
    loginPasswordInput.value = "";
    // 以後の画面遷移はonAuthStateChange（SIGNED_IN）→renderForSessionが行う
  } catch (error) {
    loginStatus.style.color = "var(--danger)";
    loginStatus.textContent = japaneseAuthErrorMessage(error);
  } finally {
    loginSubmitBtn.disabled = false;
  }
});

const signupResendArea = document.getElementById("signupResendArea");
const signupResendStatus = document.getElementById("signupResendStatus");
const resendConfirmationBtn = document.getElementById("resendConfirmationBtn");

document.getElementById("showSignupBtn").addEventListener("click", () => {
  document.getElementById("signupEmailInput").value = loginEmailInput.value.trim();
  document.getElementById("signupPasswordInput").value = "";
  document.getElementById("signupPasswordConfirmInput").value = "";
  document.getElementById("signupStatus").textContent = "";
  signupResendArea.hidden = true;
  signupResendStatus.textContent = "";
  resendConfirmationBtn.disabled = false;
  showView("signup");
});

document.getElementById("showResetRequestBtn").addEventListener("click", () => {
  document.getElementById("resetRequestEmailInput").value = loginEmailInput.value.trim();
  document.getElementById("resetRequestStatus").textContent = "";
  showView("resetRequest");
});

document.getElementById("backToLoginFromSignupBtn").addEventListener("click", () => showView("login"));
document.getElementById("backToLoginFromResetBtn").addEventListener("click", () => showView("login"));
document.getElementById("backToLoginFromLinkExpiredBtn").addEventListener("click", () => showView("login"));

// ---------------------------------------------------------------------------
// 初回アカウント設定（招待済みメールのみsignUpできる）
// ---------------------------------------------------------------------------

const signupEmailInput = document.getElementById("signupEmailInput");
const signupPasswordInput = document.getElementById("signupPasswordInput");
const signupPasswordConfirmInput = document.getElementById("signupPasswordConfirmInput");
const signupSubmitBtn = document.getElementById("signupSubmitBtn");
const signupStatus = document.getElementById("signupStatus");

// 確認メール再送の対象email。localStorageへ独自保存はせず、画面の状態（この変数）だけで
// 保持する。ページを再読み込みした場合は保持されないため、再送画面（view-link-expired）側で
// emailを入力し直せる構成にしている
let lastSignupEmail = null;

document.getElementById("signupSubmitBtn").addEventListener("click", async () => {
  const email = signupEmailInput.value.trim();
  const password = signupPasswordInput.value;
  const passwordConfirm = signupPasswordConfirmInput.value;

  if (!email) {
    signupStatus.style.color = "var(--danger)";
    signupStatus.textContent = "メールアドレスを入力してください";
    return;
  }
  if (password.length < 8) {
    signupStatus.style.color = "var(--danger)";
    signupStatus.textContent = "パスワードは8文字以上で入力してください";
    return;
  }
  if (password !== passwordConfirm) {
    signupStatus.style.color = "var(--danger)";
    signupStatus.textContent = "パスワード（確認）が一致しません";
    return;
  }

  signupSubmitBtn.disabled = true;
  signupStatus.style.color = "";
  setLoadingStatus(signupStatus, "確認中...");
  try {
    // team_admin_invitationsをteam-webから直接SELECTすることはしない。
    // 招待の有無・登録可否の判定はすべてteam-auth Edge Function（service_role）に閉じ込める
    const invitation = await checkInvitation(email);

    if (!invitation.invited) {
      signupStatus.style.color = "var(--danger)";
      signupStatus.textContent = "このメールアドレスはチーム管理者として登録されていません。";
      return;
    }
    if (invitation.already_registered) {
      signupStatus.style.color = "var(--danger)";
      signupStatus.textContent = "このメールアドレスは既に登録済みです。ログインしてください。";
      return;
    }
    if (!invitation.can_signup) {
      signupStatus.style.color = "var(--danger)";
      signupStatus.textContent = contractStatusMessageForSignup(invitation.contract_status);
      return;
    }

    setLoadingStatus(signupStatus, "登録中...");
    const { error: signUpError } = await client.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: TEAM_WEB_ORIGIN },
    });
    if (signUpError) throw signUpError;

    signupStatus.style.color = "var(--success)";
    signupStatus.textContent = "確認メールを送信しました。メール内のリンクを開いて登録を完了してください。";
    signupPasswordInput.value = "";
    signupPasswordConfirmInput.value = "";

    lastSignupEmail = email;
    signupResendStatus.textContent = "";
    resendConfirmationBtn.disabled = false;
    signupResendArea.hidden = false;
  } catch (error) {
    signupStatus.style.color = "var(--danger)";
    signupStatus.textContent = japaneseSignupFlowErrorMessage(
      error,
      "登録メールの送信回数が上限に達しています。しばらく時間を空けてから再度お試しください。"
    );
  } finally {
    signupSubmitBtn.disabled = false;
  }
});

resendConfirmationBtn.addEventListener("click", () => {
  resendConfirmationEmail(lastSignupEmail, signupResendStatus, resendConfirmationBtn);
});

document.getElementById("linkExpiredResendBtn").addEventListener("click", () => {
  const email = document.getElementById("linkExpiredEmailInput").value.trim();
  resendConfirmationEmail(
    email,
    document.getElementById("linkExpiredStatus"),
    document.getElementById("linkExpiredResendBtn")
  );
});

// ---------------------------------------------------------------------------
// パスワード再設定
// ---------------------------------------------------------------------------

document.getElementById("resetRequestSubmitBtn").addEventListener("click", async () => {
  const email = document.getElementById("resetRequestEmailInput").value.trim();
  const status = document.getElementById("resetRequestStatus");
  const btn = document.getElementById("resetRequestSubmitBtn");
  if (!email) {
    status.style.color = "var(--danger)";
    status.textContent = "メールアドレスを入力してください";
    return;
  }
  btn.disabled = true;
  status.style.color = "";
  setLoadingStatus(status, "送信中...");
  try {
    const { error } = await client.auth.resetPasswordForEmail(email, { redirectTo: TEAM_WEB_ORIGIN });
    if (error) throw error;
    status.style.color = "var(--success)";
    status.textContent = "パスワード再設定用のメールを送信しました。メール内のリンクを開いてください。";
  } catch (error) {
    status.style.color = "var(--danger)";
    const message = error && error.message ? error.message : "";
    status.textContent = message.includes("email rate limit exceeded")
      ? "送信回数が上限に達しています。しばらく時間を空けてから再度お試しください。"
      : "通信に失敗しました。時間を空けて再度お試しください。";
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("newPasswordSubmitBtn").addEventListener("click", async () => {
  const newPassword = document.getElementById("newPasswordInput").value;
  const newPasswordConfirm = document.getElementById("newPasswordConfirmInput").value;
  const status = document.getElementById("resetPasswordStatus");

  if (newPassword.length < 8) {
    status.style.color = "var(--danger)";
    status.textContent = "パスワードは8文字以上で入力してください";
    return;
  }
  if (newPassword !== newPasswordConfirm) {
    status.style.color = "var(--danger)";
    status.textContent = "パスワード（確認）が一致しません";
    return;
  }

  const newPasswordSubmitBtn = document.getElementById("newPasswordSubmitBtn");
  newPasswordSubmitBtn.disabled = true;
  status.style.color = "";
  setLoadingStatus(status, "更新中...");
  try {
    const { error } = await client.auth.updateUser({ password: newPassword });
    if (error) throw error;
    document.getElementById("newPasswordInput").value = "";
    document.getElementById("newPasswordConfirmInput").value = "";
    status.textContent = "";

    // パスワード変更自体は完了したため、localStorageの「タブを閉じても復元する」フラグは
    // ここで削除する（今後タブを閉じて再度localhost:8081を開いてもreset画面には戻さない）。
    // ただしisPasswordRecovery（メモリ上のフラグ）はまだtrueのまま維持し、ユーザーが
    // 「チーム管理画面へ進む」を押すまではdashboardへ自動遷移させない
    // （SIGNED_IN/INITIAL_SESSION等が裏で発火してもresetPassword画面を維持し続ける）
    clearStoredRecoveryFlag();

    document.getElementById("resetPasswordFormArea").hidden = true;
    document.getElementById("resetPasswordDoneArea").hidden = false;
  } catch (error) {
    status.style.color = "var(--danger)";
    status.textContent = "通信に失敗しました。時間を空けて再度お試しください。";
  } finally {
    newPasswordSubmitBtn.disabled = false;
  }
});

document.getElementById("proceedToDashboardBtn").addEventListener("click", async () => {
  isPasswordRecovery = false;
  // 次回のresetPassword表示に備えて元の状態へ戻しておく
  document.getElementById("resetPasswordDoneArea").hidden = true;
  document.getElementById("resetPasswordFormArea").hidden = false;
  const { data: { session } } = await client.auth.getSession();
  await renderForSession(session);
});

// ---------------------------------------------------------------------------
// ログアウト
// ---------------------------------------------------------------------------

document.getElementById("logoutBtn").addEventListener("click", async () => {
  // 操作ミス防止のため軽い確認を入れる（既存remove_team_member等の他の破壊的操作と
  // 同じwindow.confirmパターンに揃える）
  if (!window.confirm("ログアウトしますか？")) return;

  // recovery中に何らかの理由でログアウトされた場合に備え、localStorageのrecovery状態も消しておく
  // （ログアウト後にタブを閉じて再度開いた際、reset画面へ戻ってしまわないようにするため）
  clearStoredRecoveryFlag();
  isPasswordRecovery = false;
  await client.auth.signOut();
  // onAuthStateChangeがSIGNED_OUTを発火し、ログイン画面へ自動的に戻る
});

// ---------------------------------------------------------------------------
// アカウント画面
// ---------------------------------------------------------------------------
// ログインメールアドレス・チーム内権限のみ表示（取得できる実データのみ）。
// パスワード変更は新しい仕組みを作らず、既存のパスワード再設定（resetRequest）画面を
// そのまま再利用する

function renderAccountPage() {
  document.getElementById("accountEmailValue").textContent = currentUserEmail || "-";
  document.getElementById("accountRoleValue").textContent = roleLabel[currentUserRole] || "-";
  document.getElementById("accountTeamNameValue").textContent = currentTeamName || "-";
}

document.getElementById("accountChangePasswordBtn").addEventListener("click", () => {
  document.getElementById("resetRequestEmailInput").value = currentUserEmail || "";
  document.getElementById("resetRequestStatus").textContent = "";
  showView("resetRequest");
});

// ---------------------------------------------------------------------------
// チーム作成（team_adminsが0件の場合）
// ---------------------------------------------------------------------------

const newTeamNameInput = document.getElementById("newTeamNameInput");
const createTeamBtn = document.getElementById("createTeamBtn");
const createTeamStatus = document.getElementById("createTeamStatus");

createTeamBtn.addEventListener("click", async () => {
  const name = newTeamNameInput.value.trim();
  if (!name) {
    createTeamStatus.style.color = "var(--danger)";
    createTeamStatus.textContent = "チーム名を入力してください";
    return;
  }
  createTeamBtn.disabled = true;
  createTeamStatus.style.color = "";
  setLoadingStatus(createTeamStatus, "作成中...");
  try {
    // 既存RPC create_team(p_name)。team作成・team_adminsへのowner登録・招待コード発行を
    // すべてサーバー側（SECURITY DEFINER）で行う。クライアントはuser_idを渡さない
    const { data, error } = await client.rpc("create_team", { p_name: name });
    if (error) throw error;
    const created = Array.isArray(data) ? data[0] : data;
    currentTeamId = created.team_id;
    createTeamStatus.textContent = "";
    newTeamNameInput.value = "";
    await loadDashboard();
  } catch (error) {
    createTeamStatus.style.color = "var(--danger)";
    createTeamStatus.textContent = japaneseRpcErrorMessage(error);
  } finally {
    createTeamBtn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// チーム管理画面（アプリシェル）：サイドバーのページ切り替え
// ---------------------------------------------------------------------------
// view-dashboard内だけの軽量ルーター。トップレベルのshowView()（login/dashboard等の
// 切り替え）とは独立しており、既存のview切り替えロジックには一切触れない

const teamPages = {
  home: document.getElementById("team-page-home"),
  players: document.getElementById("team-page-players"),
  team: document.getElementById("team-page-team"),
  account: document.getElementById("team-page-account"),
};
const teamPageTitleLabel = { home: "ホーム", players: "選手", team: "チーム", account: "アカウント" };
const teamNavItems = document.querySelectorAll(".team-nav-item");
const teamPageTitleEl = document.getElementById("teamPageTitle");

function showTeamPage(name) {
  Object.entries(teamPages).forEach(([key, el]) => {
    if (el) el.hidden = key !== name;
  });
  teamNavItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.teamPage === name);
  });
  teamPageTitleEl.textContent = teamPageTitleLabel[name] || "";
  if (name === "account") {
    renderAccountPage();
  }
}

teamNavItems.forEach((item) => {
  item.addEventListener("click", () => showTeamPage(item.dataset.teamPage));
});

// ---------------------------------------------------------------------------
// チーム管理画面：表示・招待コードのコピー・再発行
// ---------------------------------------------------------------------------

const dashboardTeamName = document.getElementById("dashboardTeamName");
const dashboardRole = document.getElementById("dashboardRole");
const inviteCodeValue = document.getElementById("inviteCodeValue");
const inviteCodeExpiry = document.getElementById("inviteCodeExpiry");
const dashboardStatus = document.getElementById("dashboardStatus");

async function loadDashboard() {
  // 二重防御：パスワード再設定リンクから戻った直後（isPasswordRecovery中）は、
  // どの経路からloadDashboard()が呼ばれても絶対にdashboard/createTeam/contractGateへ
  // 進ませない。本来はrenderForSession側の判定でloadDashboard自体が呼ばれないはずだが、
  // 万一の呼び出し順の変化に備えてここでも同じ判定を入れておく
  if (isPasswordRecovery) {
    showView("resetPassword");
    return;
  }

  showView("loading");
  dashboardStatus.textContent = "";
  try {
    // 自分が管理者登録されているチームを取得（RLSにより自分の行しか返らない）。
    // Phase 1は1管理者=1チーム運用を想定し、先頭の1件を使う
    const { data: adminRows, error: adminError } = await client
      .from("team_admins")
      .select("team_id, role")
      .order("created_at", { ascending: true })
      .limit(1);
    if (adminError) throw adminError;

    if (!adminRows || adminRows.length === 0) {
      showView("createTeam");
      return;
    }

    // 複数件が返る可能性（将来の複数チーム管理）に備え、[0]決め打ちではなく変数名を分けて
    // 先頭行だけをPhase 1の対象として扱う（adminRows自体は今後の選択UI追加に備えて残す）
    const { team_id: teamId, role } = adminRows[0];
    currentTeamId = teamId;

    // 契約状態ゲート（本番仕様）：admin-webでteam_contractsが作成され、かつ
    // status='active'のチームだけがteam-webを利用できる。RLS
    // （team_contracts_select_own_managed_team）により、自分が管理するチームの契約行のみ
    // 見える。以前は「契約行が無ければ後方互換でdashboardへ入れる」運用だったが、
    // チーム契約管理が本運用になったため廃止し、行が無い場合も利用不可として扱う
    const { data: contract, error: contractError } = await client
      .from("team_contracts")
      .select("status, starts_at, ends_at")
      .eq("team_id", teamId)
      .maybeSingle();

    if (contractError) {
      // 通信/権限エラー（行が無いこと自体はmaybeSingle()がerrorを返さないため、
      // ここに来るのは実際の取得失敗のみ）と、契約情報が存在しないことを区別する
      document.getElementById("contractGateMessage").textContent = CONTRACT_FETCH_ERROR_MESSAGE;
      showView("contractGate");
      return;
    }

    if (!contract) {
      document.getElementById("contractGateMessage").textContent = CONTRACT_MISSING_MESSAGE;
      showView("contractGate");
      return;
    }

    if (contract.status !== "active") {
      document.getElementById("contractGateMessage").textContent =
        CONTRACT_GATE_MESSAGE[contract.status] || "現在このチームはご利用いただけません。";
      showView("contractGate");
      return;
    }

    const { data: team, error: teamError } = await client
      .from("teams")
      .select("id, name")
      .eq("id", teamId)
      .maybeSingle();
    if (teamError) throw teamError;

    const teamName = team ? team.name : "(取得できませんでした)";
    dashboardTeamName.textContent = teamName;
    dashboardRole.textContent = roleLabel[role] || role;
    currentUserRole = role;
    currentTeamName = teamName;

    // チーム画面：契約情報（取得できる項目のみ表示。ダミー値・推測日付は入れない）
    const statusValueEl = document.getElementById("teamContractStatusValue");
    statusValueEl.textContent = "";
    statusValueEl.appendChild(buildContractStatusBadge(contract.status));
    document.getElementById("teamContractPeriodValue").textContent = formatContractPeriod(
      contract.starts_at,
      contract.ends_at
    );

    // ホーム・topbar・サイドバーの共通表示
    document.getElementById("homeTeamName").textContent = teamName;
    document.getElementById("topbarTeamName").textContent = teamName;
    const roleBadge = document.getElementById("topbarRoleBadge");
    roleBadge.textContent = roleLabel[role] || role;
    roleBadge.hidden = false;
    roleBadge.classList.toggle("badge-yellow", role === "owner");
    const avatarEl = document.getElementById("topbarAvatar");
    avatarEl.textContent = (teamName || "?").trim().charAt(0).toUpperCase() || "?";
    const contractBadge = document.getElementById("sidebarContractBadge");
    contractBadge.textContent = "契約中";
    contractBadge.hidden = false;

    // アカウント画面用（画面を開いた時に毎回取得し直すのではなく、ここで一度だけ取得して
    // 使い回す。ログイン中に別アカウントへ切り替わることは無いため十分）
    if (!currentUserEmail) {
      const { data: userData } = await client.auth.getUser();
      currentUserEmail = userData && userData.user ? userData.user.email : null;
    }

    await loadInviteCode(teamId);
    await loadMembers(teamId);

    showTeamPage("home");
    showView("dashboard");
  } catch (error) {
    showView("dashboard");
    dashboardStatus.style.color = "var(--danger)";
    dashboardStatus.textContent = japaneseRpcErrorMessage(error);
  }
}

async function loadInviteCode(teamId) {
  // 現在有効な（revoked_atがnullの）招待コードのみ取得。RLSにより自分が管理するチームの
  // コードしか見えない
  const { data, error } = await client
    .from("team_invite_codes")
    .select("code, expires_at")
    .eq("team_id", teamId)
    .is("revoked_at", null)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;

  if (!data) {
    inviteCodeValue.textContent = "--------";
    inviteCodeExpiry.hidden = true;
    return;
  }
  inviteCodeValue.textContent = data.code;
  if (data.expires_at) {
    inviteCodeExpiry.hidden = false;
    inviteCodeExpiry.textContent = `有効期限: ${new Date(data.expires_at).toLocaleString("ja-JP")}`;
  } else {
    inviteCodeExpiry.hidden = true;
  }
}

document.getElementById("copyInviteCodeBtn").addEventListener("click", async () => {
  const code = inviteCodeValue.textContent.trim();
  if (!code || code === "--------") return;
  try {
    await navigator.clipboard.writeText(code);
    showToast("コピーしました");
  } catch (error) {
    dashboardStatus.style.color = "var(--danger)";
    dashboardStatus.textContent = "コピーできませんでした。手動でコピーしてください。";
  }
});

document.getElementById("regenerateInviteCodeBtn").addEventListener("click", async () => {
  if (!currentTeamId) return;
  if (!window.confirm("現在の招待コードは無効になります。\n新しい招待コードを発行しますか？")) return;

  const btn = document.getElementById("regenerateInviteCodeBtn");
  btn.disabled = true;
  dashboardStatus.style.color = "";
  setLoadingStatus(dashboardStatus, "再発行中...");
  try {
    // 既存RPC regenerate_team_invite_code(p_team_id)。権限確認（owner/admin）は
    // サーバー側（SECURITY DEFINER）で行われる
    const { data, error } = await client.rpc("regenerate_team_invite_code", { p_team_id: currentTeamId });
    if (error) throw error;
    inviteCodeValue.textContent = data;
    inviteCodeExpiry.hidden = true;
    dashboardStatus.textContent = "";
    showToast("招待コードを再発行しました");
  } catch (error) {
    dashboardStatus.style.color = "var(--danger)";
    dashboardStatus.textContent = japaneseRpcErrorMessage(error);
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// 選手を招待（modal）
// ---------------------------------------------------------------------------
// 招待コードは常時画面に表示せず、チーム画面の「選手を招待」ボタンからmodalで表示する。
// コード自体はloadDashboard()内のloadInviteCode()で既に取得済みのため、ここでは
// 表示中の値をそのままmodalへ出すだけでよい（開くたびに再取得はしない）

const inviteModalBackdrop = document.getElementById("inviteModalBackdrop");
const inviteModalPanel = document.getElementById("inviteModalPanel");

function openInviteModal() {
  dashboardStatus.textContent = "";
  inviteModalPanel.hidden = false;
  inviteModalBackdrop.hidden = false;
}

function closeInviteModal() {
  inviteModalPanel.hidden = true;
  inviteModalBackdrop.hidden = true;
}

document.getElementById("openInviteModalBtn").addEventListener("click", openInviteModal);
document.getElementById("closeInviteModalBtn").addEventListener("click", closeInviteModal);
inviteModalBackdrop.addEventListener("click", closeInviteModal);

// ---------------------------------------------------------------------------
// 所属選手一覧（Phase 2）
// ---------------------------------------------------------------------------
// 表示するのはteam_members（active分のみ）・profiles.display_name・
// team_share_permissions（condition）だけで、健康データそのものは扱わない。
// （team_share_permissionsにはmeal categoryの行も残っているが、チーム共有はcondition
// のみに整理済みのため表示上は使わない。DB側は今回変更していない）
// team_idは常にcurrentTeamId（team_adminsから解決した自分の管理チーム）のみを使い、
// クライアントから別チームのIDを指定してSELECT範囲を広げることはしない。
// permissionの変更UIはここには置かない（閲覧のみ）。

const membersCount = document.getElementById("membersCount");
const membersStatus = document.getElementById("membersStatus");
const membersEmptyHint = document.getElementById("membersEmptyHint");
const membersList = document.getElementById("membersList");

let currentDetailMember = null;
// 選手検索欄で絞り込む対象。loadMembers()完了時点の全件（enriched）をそのまま保持する
let currentMembersData = [];

// ローカルのタイムゾーンでの"YYYY-MM-DD"（record_dateと同じ形式）を作る。
// new Date().toISOString()はUTC基準になり日付がずれる場合があるため使わない
function todayDateString() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

function memberSleepText(cond) {
  if (!cond || (cond.sleep_hours == null && cond.sleep_minutes == null)) return "-";
  return `${cond.sleep_hours ?? 0}時間${cond.sleep_minutes ?? 0}分`;
}

function memberFatigueText(cond) {
  return cond && cond.fatigue_level != null ? String(cond.fatigue_level) : "-";
}

function memberTodayInputText(member) {
  if (!member.conditionShared) return "共有OFF";
  if (member.latestCondition && member.latestCondition.record_date === todayDateString()) return "入力済み";
  return "未入力";
}

function memberLastUpdatedText(member) {
  if (!member.conditionShared || !member.latestCondition) return "-";
  return formatRecordDate(member.latestCondition.record_date);
}

// 疲労度の視覚化：数値だけでなく低め/中程度/高めの目安を添える。医療的な断定は避け、
// あくまで目安の色分け（低め=青、中程度=黄、高め=赤・警告色として限定使用）にとどめる
function fatigueBucket(level) {
  if (level == null) return null;
  if (level <= 3) return { key: "low", label: "低め" };
  if (level <= 6) return { key: "mid", label: "中程度" };
  return { key: "high", label: "高め" };
}

// ホーム/選手一覧で共通利用する「疲労度」セル。数値＋目安badgeを1つの要素にまとめて返す
function buildFatigueCellContent(cond) {
  const wrap = document.createElement("span");
  wrap.className = "fatigue-cell";
  const level = cond ? cond.fatigue_level : null;
  if (level == null) {
    wrap.textContent = "-";
    return wrap;
  }
  const numberEl = document.createElement("span");
  numberEl.className = "fatigue-number";
  numberEl.textContent = String(level);
  wrap.appendChild(numberEl);

  const bucket = fatigueBucket(level);
  const badge = document.createElement("span");
  badge.className = `badge-pill fatigue-badge-${bucket.key}`;
  badge.textContent = bucket.label;
  wrap.appendChild(badge);
  return wrap;
}

// 睡眠：時間表示に加え、6時間未満の場合だけ控えめな「短め」badgeを添える
// （「危険」「不足確定」等の断定的な健康判断はしない）
function buildSleepCellContent(cond) {
  const wrap = document.createElement("span");
  wrap.className = "sleep-cell";
  if (!cond || (cond.sleep_hours == null && cond.sleep_minutes == null)) {
    wrap.textContent = "-";
    return wrap;
  }
  const textEl = document.createElement("span");
  textEl.textContent = memberSleepText(cond);
  wrap.appendChild(textEl);

  const totalMinutes = (cond.sleep_hours ?? 0) * 60 + (cond.sleep_minutes ?? 0);
  if (totalMinutes > 0 && totalMinutes < 360) {
    const badge = document.createElement("span");
    badge.className = "badge-pill sleep-short-badge";
    badge.textContent = "短め";
    wrap.appendChild(badge);
  }
  return wrap;
}

// 本日の入力状態バッジ。共有OFFの選手はコンディション自体を出さず「共有OFF」badgeのみにする
function buildTodayBadge(member) {
  const badge = document.createElement("span");
  if (!member.conditionShared) {
    badge.className = "badge-pill badge-gray";
    badge.textContent = "共有OFF";
    return badge;
  }
  const inputted = memberTodayInputText(member) === "入力済み";
  badge.className = inputted ? "badge-pill badge-today-done" : "badge-pill badge-gray";
  badge.textContent = inputted ? "入力済み" : "未入力";
  return badge;
}

// 気分：iOS側のConditionFeeling（既存feelingLabelマップ）にある値だけを日本語表示する。
// 未知の値やnullは"-"のまま（新しいenumを作らない）
function memberFeelingText(cond) {
  if (!cond || !cond.feeling) return "-";
  return feelingLabel[cond.feeling] || cond.feeling;
}

// コンディション共有ONの選手だけ、直近の同期データ（1件ずつ）をまとめて取得する。
// team_condition_sharesのRLS（team_admins + active member + condition共有ON）により、
// 共有OFFの選手のuser_idを渡しても0件が返るだけだが、「共有OFFの選手の機微情報は
// 一覧に出さない」方針を明確にするため、そもそも共有ONの選手だけを対象に問い合わせる
async function fetchLatestConditionByUser(teamId, sharedUserIds) {
  if (sharedUserIds.length === 0) return new Map();
  const { data, error } = await client
    .from("team_condition_shares")
    .select("user_id, record_date, weight_kg, sleep_hours, sleep_minutes, fatigue_level, feeling")
    .eq("team_id", teamId)
    .in("user_id", sharedUserIds)
    .order("record_date", { ascending: false });
  if (error) throw error;

  // record_date降順で取得しているため、同じuser_idの最初の出現が最新の1件になる
  const map = new Map();
  (data || []).forEach((row) => {
    if (!map.has(row.user_id)) map.set(row.user_id, row);
  });
  return map;
}

async function loadMembers(teamId) {
  membersStatus.style.color = "";
  setLoadingStatus(membersStatus, "取得中...");
  membersEmptyHint.hidden = true;
  document.getElementById("playerSearchEmptyHint").hidden = true;
  document.getElementById("membersTableWrap").hidden = true;
  membersList.textContent = "";
  currentMembersData = [];

  try {
    const { data: memberRows, error: memberError } = await client
      .from("team_members")
      .select("user_id, joined_at, status")
      .eq("team_id", teamId)
      .eq("status", "active")
      .order("joined_at", { ascending: false });
    if (memberError) throw memberError;

    const members = memberRows || [];
    membersCount.textContent = `${members.length}人`;

    if (members.length === 0) {
      membersStatus.textContent = "";
      membersEmptyHint.hidden = false;
      renderHomeSummary([]);
      return;
    }

    const userIds = members.map((m) => m.user_id);

    // display_nameはprofilesを直接SELECTしない（profiles_select_ownはauth.uid() = user_idの
    // 自分の行しか許可しておらず、team管理者からは見えないため）。代わりに、
    // user_id + display_nameだけを返す専用RPC（get_team_member_profiles）を使う。
    // team_share_permissionsは既存のRLS（team_adminsの行が存在すれば閲覧可）でそのまま取得できる。
    // data_category=condition の行だけをサーバー側で絞り込む（mealの行はDBに残っているが、
    // チーム共有はconditionのみに整理済みのため表示では使わない）
    const [profilesResult, permissionsResult] = await Promise.all([
      client.rpc("get_team_member_profiles", { p_team_id: teamId }),
      client
        .from("team_share_permissions")
        .select("user_id, is_shared")
        .eq("team_id", teamId)
        .eq("data_category", "condition")
        .in("user_id", userIds),
    ]);
    if (profilesResult.error) throw profilesResult.error;
    if (permissionsResult.error) throw permissionsResult.error;

    const displayNameByUserId = new Map(
      (profilesResult.data || []).map((p) => [p.user_id, p.display_name])
    );
    const conditionSharedByUserId = new Map(
      (permissionsResult.data || []).map((row) => [row.user_id, !!row.is_shared])
    );

    const sharedUserIds = userIds.filter((id) => conditionSharedByUserId.get(id));
    const latestConditionByUserId = await fetchLatestConditionByUser(teamId, sharedUserIds);

    const enriched = members.map((m) => {
      return {
        userId: m.user_id,
        joinedAt: m.joined_at,
        status: m.status,
        displayName: displayNameByUserId.get(m.user_id) || null,
        conditionShared: conditionSharedByUserId.get(m.user_id) || false,
        latestCondition: latestConditionByUserId.get(m.user_id) || null,
      };
    });

    membersStatus.textContent = "";
    currentMembersData = enriched;
    applyPlayersView();
    renderHomeSummary(enriched);
  } catch (error) {
    membersStatus.style.color = "var(--danger)";
    membersStatus.textContent = "選手一覧を取得できませんでした。";
  }
}

// 一覧行はcreateElement + textContentのみで組み立てる（display_name等のuser-controlled
// textをinnerHTMLへ入れない。本ファイル全体で一貫している方針）
function buildMemberRow(member) {
  const row = document.createElement("tr");

  const nameCell = document.createElement("td");
  nameCell.className = "member-name-cell";
  nameCell.textContent = member.displayName || "未設定";
  row.appendChild(nameCell);

  const shareCell = document.createElement("td");
  const shareBadge = document.createElement("span");
  shareBadge.className = member.conditionShared ? "badge-pill" : "badge-pill badge-gray";
  shareBadge.textContent = member.conditionShared ? "共有ON" : "共有OFF";
  shareCell.appendChild(shareBadge);
  row.appendChild(shareCell);

  const todayCell = document.createElement("td");
  todayCell.appendChild(buildTodayBadge(member));
  row.appendChild(todayCell);

  const fatigueCell = document.createElement("td");
  fatigueCell.className = "cell-muted";
  fatigueCell.appendChild(buildFatigueCellContent(member.conditionShared ? member.latestCondition : null));
  row.appendChild(fatigueCell);

  const sleepCell = document.createElement("td");
  sleepCell.className = "cell-muted";
  sleepCell.appendChild(buildSleepCellContent(member.conditionShared ? member.latestCondition : null));
  row.appendChild(sleepCell);

  const updatedCell = document.createElement("td");
  updatedCell.className = "cell-muted";
  updatedCell.textContent = memberLastUpdatedText(member);
  row.appendChild(updatedCell);

  const detailCell = document.createElement("td");
  const detailLink = document.createElement("span");
  detailLink.className = "detail-link";
  detailLink.textContent = "詳細";
  detailCell.appendChild(detailLink);
  row.appendChild(detailCell);

  row.addEventListener("click", () => openMemberDetail(member));
  return row;
}

function renderMembersList(members) {
  const wrap = document.getElementById("membersTableWrap");
  const searchEmptyHint = document.getElementById("playerSearchEmptyHint");
  membersList.textContent = "";

  if (members.length === 0) {
    wrap.hidden = true;
    // 所属選手自体が0人の場合はmembersEmptyHint（呼び出し元）が既に表示されるため、
    // ここでの「該当する選手が見つかりません」は検索で絞り込んだ結果0件の時だけ出す
    searchEmptyHint.hidden = currentMembersData.length === 0;
    return;
  }
  searchEmptyHint.hidden = true;
  wrap.hidden = false;
  members.forEach((member) => {
    membersList.appendChild(buildMemberRow(member));
  });
}

// ---------------------------------------------------------------------------
// 選手一覧：検索・フィルタ・並び順
// ---------------------------------------------------------------------------
// スタッフが毎日見て「誰が未入力か」を素早く把握できるよう、初期表示は
// 「共有ONかつ未入力」を先頭、その中では名前順→「共有ONかつ入力済み」→「共有OFF」の順にする。
// 複雑な自動並び替え（疲労度順等）は行わない（おすすめ順のシンプルな並びにとどめる）

let currentPlayerFilter = "all"; // "all" | "not-inputted" | "inputted" | "shared"

function playerSortRank(member) {
  if (!member.conditionShared) return 2;
  return memberTodayInputText(member) === "入力済み" ? 1 : 0;
}

function sortPlayersForDisplay(members) {
  return [...members].sort((a, b) => {
    const rankDiff = playerSortRank(a) - playerSortRank(b);
    if (rankDiff !== 0) return rankDiff;
    return (a.displayName || "未設定").localeCompare(b.displayName || "未設定", "ja");
  });
}

function applyPlayersView() {
  const term = document.getElementById("playerSearchInput").value.trim().toLowerCase();
  let list = currentMembersData;

  if (currentPlayerFilter === "not-inputted") {
    list = list.filter((m) => m.conditionShared && memberTodayInputText(m) === "未入力");
  } else if (currentPlayerFilter === "inputted") {
    list = list.filter((m) => m.conditionShared && memberTodayInputText(m) === "入力済み");
  } else if (currentPlayerFilter === "shared") {
    list = list.filter((m) => m.conditionShared);
  }

  if (term) {
    list = list.filter((member) => (member.displayName || "未設定").toLowerCase().includes(term));
  }

  renderMembersList(sortPlayersForDisplay(list));
}

document.getElementById("playerSearchInput").addEventListener("input", applyPlayersView);

document.querySelectorAll("#playerFilterToggle .filter-toggle-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    currentPlayerFilter = btn.dataset.playerFilter;
    document.querySelectorAll("#playerFilterToggle .filter-toggle-btn").forEach((b) => {
      b.classList.toggle("active", b === btn);
    });
    applyPlayersView();
  });
});

// ---------------------------------------------------------------------------
// ホーム：概要カード・選手コンディション
// ---------------------------------------------------------------------------
// loadMembers()が取得した実データ（enriched）だけを使って表示する。まだ取得ロジックが
// 無い指標（管理者の利用枠等。team_adminsはRLSで本人の行しか見えないためteam-webからは
// 正確な人数を算出できない）はダミー表示せず、カード自体を出さない

function renderHomeSummary(members) {
  const shared = members.filter((m) => m.conditionShared);
  const today = todayDateString();
  const todayCount = shared.filter((m) => m.latestCondition && m.latestCondition.record_date === today).length;
  const notInputCount = shared.length - todayCount;

  document.getElementById("statMemberCount").textContent = `${members.length}人`;
  document.getElementById("statSharedCount").textContent = `${shared.length}人`;
  document.getElementById("statTodayCount").textContent = `${todayCount} / ${shared.length}`;
  document.getElementById("statNotInputCount").textContent = `${notInputCount}人`;

  const statusEl = document.getElementById("homeConditionStatus");
  const emptyHint = document.getElementById("homeConditionEmptyHint");
  const tableWrap = document.getElementById("homeConditionTableWrap");
  const tbody = document.getElementById("homeConditionTableBody");
  tbody.textContent = "";
  statusEl.style.color = "";
  statusEl.textContent = "";

  if (shared.length === 0) {
    tableWrap.hidden = true;
    emptyHint.hidden = false;
    return;
  }
  emptyHint.hidden = true;
  tableWrap.hidden = false;

  // 表自体は「共有ONの選手全員」を常に出す（未入力の選手も一覧できることが今回の目的の
  // 1つのため）。0件の時だけ、ブロックせず補足の一文として案内する
  if (todayCount === 0) {
    statusEl.textContent = "本日のコンディション入力はまだありません。";
  }

  // 未入力の選手を先に把握できるよう、ホームの一覧も選手一覧と同じ並び順にする
  sortPlayersForDisplay(shared).forEach((member) => {
    const row = document.createElement("tr");

    const nameCell = document.createElement("td");
    nameCell.className = "member-name-cell";
    nameCell.textContent = member.displayName || "未設定";
    row.appendChild(nameCell);

    const todayCell = document.createElement("td");
    todayCell.appendChild(buildTodayBadge(member));
    row.appendChild(todayCell);

    const fatigueCell = document.createElement("td");
    fatigueCell.className = "cell-muted";
    fatigueCell.appendChild(buildFatigueCellContent(member.latestCondition));
    row.appendChild(fatigueCell);

    const sleepCell = document.createElement("td");
    sleepCell.className = "cell-muted";
    sleepCell.appendChild(buildSleepCellContent(member.latestCondition));
    row.appendChild(sleepCell);

    const weightCell = document.createElement("td");
    weightCell.className = "cell-muted";
    weightCell.textContent =
      member.latestCondition && member.latestCondition.weight_kg != null
        ? `${member.latestCondition.weight_kg}kg`
        : "-";
    row.appendChild(weightCell);

    const feelingCell = document.createElement("td");
    feelingCell.className = "cell-muted";
    feelingCell.textContent = memberFeelingText(member.latestCondition);
    row.appendChild(feelingCell);

    const updatedCell = document.createElement("td");
    updatedCell.className = "cell-muted";
    updatedCell.textContent = memberLastUpdatedText(member);
    row.appendChild(updatedCell);

    tbody.appendChild(row);
  });
}

// ---------------------------------------------------------------------------
// 選手詳細（modal）・チームから外す
// ---------------------------------------------------------------------------

const memberDetailBackdrop = document.getElementById("memberDetailBackdrop");
const memberDetailPanel = document.getElementById("memberDetailPanel");
const memberDetailName = document.getElementById("memberDetailName");
const memberDetailUserId = document.getElementById("memberDetailUserId");
const memberDetailJoinedAt = document.getElementById("memberDetailJoinedAt");
const memberDetailStatus = document.getElementById("memberDetailStatus");
const memberDetailCondition = document.getElementById("memberDetailCondition");
const memberDetailActionStatus = document.getElementById("memberDetailActionStatus");
const removeMemberBtn = document.getElementById("removeMemberBtn");

const memberStatusLabel = { active: "在籍中", left: "離脱済み", removed: "除名済み" };
const feelingLabel = { excellent: "絶好調", good: "良好", normal: "普通", slightlyPoor: "やや不調", poor: "不調" };

function openMemberDetail(member) {
  currentDetailMember = member;
  memberDetailActionStatus.textContent = "";
  memberDetailName.textContent = member.displayName || "未設定";
  memberDetailUserId.textContent = member.userId;
  memberDetailJoinedAt.textContent = member.joinedAt
    ? new Date(member.joinedAt).toLocaleDateString("ja-JP")
    : "-";
  memberDetailStatus.textContent = memberStatusLabel[member.status] || member.status;
  memberDetailCondition.textContent = member.conditionShared ? "ON" : "OFF";

  const conditionBadge = document.getElementById("memberDetailConditionBadge");
  conditionBadge.textContent = member.conditionShared ? "共有ON" : "共有OFF";
  conditionBadge.classList.toggle("badge-gray", !member.conditionShared);

  // 最新コンディションカード・7日サマリー・グラフは取得完了（loadMemberConditionShares）まで
  // 一旦隠しておく。グラフのタブ選択も選手を開き直すたびに「疲労度」へ戻す
  document.getElementById("memberDetailLatestCard").hidden = true;
  document.getElementById("memberDetailLatestEmpty").hidden = true;
  document.getElementById("memberDetailSummaryArea").hidden = true;
  currentChartMetric = "fatigue";
  document.querySelectorAll("#chartTabs .chart-tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.chartMetric === "fatigue");
  });

  memberDetailPanel.hidden = false;
  memberDetailBackdrop.hidden = false;

  loadMemberConditionShares(member);
}

// "YYYY-MM-DD"（Postgresのdate型がPostgRESTから返す形式）を、タイムゾーン変換を経由せず
// そのまま"YYYY/MM/DD"表示に変換する（new Date()経由だとUTC深夜0時として解釈され、
// タイムゾーンによって表示日が1日ずれる可能性があるため、文字列のまま組み立てる）
function formatRecordDate(dateStr) {
  const parts = String(dateStr).split("-");
  return parts.length === 3 ? `${parts[0]}/${parts[1]}/${parts[2]}` : dateStr;
}

function buildConditionRow(row) {
  const container = document.createElement("div");
  container.className = "condition-list-row";

  const dateEl = document.createElement("div");
  dateEl.className = "condition-date";
  dateEl.textContent = formatRecordDate(row.record_date);
  container.appendChild(dateEl);

  const parts = [];
  if (row.weight_kg != null) parts.push(`体重 ${row.weight_kg}kg`);
  if (row.sleep_hours != null || row.sleep_minutes != null) {
    parts.push(`睡眠 ${row.sleep_hours ?? 0}時間${row.sleep_minutes ?? 0}分`);
  }
  if (row.fatigue_level != null) parts.push(`疲労度 ${row.fatigue_level}`);
  if (row.feeling) parts.push(`体調 ${feelingLabel[row.feeling] || row.feeling}`);
  if (row.body_fat_percent != null) parts.push(`体脂肪率 ${row.body_fat_percent}%`);
  if (row.post_workout_weight_kg != null) parts.push(`練習後体重 ${row.post_workout_weight_kg}kg`);

  const detailEl = document.createElement("div");
  detailEl.className = "condition-detail";
  detailEl.textContent = parts.length > 0 ? parts.join("／") : "記録なし";
  container.appendChild(detailEl);

  return container;
}

// 直近7日の先頭行（record_date降順の1件目＝最新）を使って、選手詳細上部の
// 「最新コンディション」カードを埋める。新しい問い合わせは行わず、7日分の取得結果を再利用する。
// 存在する値だけ表示し、無い項目は"-"のままにする（ダミー値を作らない）
function renderLatestConditionCard(latest) {
  const card = document.getElementById("memberDetailLatestCard");
  const emptyEl = document.getElementById("memberDetailLatestEmpty");

  if (!latest) {
    card.hidden = true;
    emptyEl.hidden = false;
    return;
  }

  emptyEl.hidden = true;
  card.hidden = false;
  document.getElementById("memberDetailLatestDate").textContent = formatRecordDate(latest.record_date);
  document.getElementById("memberDetailLatestWeight").textContent =
    latest.weight_kg != null ? `${latest.weight_kg}kg` : "-";
  document.getElementById("memberDetailLatestSleep").textContent = memberSleepText(latest);
  document.getElementById("memberDetailLatestFatigue").textContent = memberFatigueText(latest);
  document.getElementById("memberDetailLatestFeeling").textContent = latest.feeling
    ? feelingLabel[latest.feeling] || latest.feeling
    : "-";
  document.getElementById("memberDetailLatestBodyFat").textContent =
    latest.body_fat_percent != null ? `${latest.body_fat_percent}%` : "-";
  document.getElementById("memberDetailLatestPostWorkout").textContent =
    latest.post_workout_weight_kg != null ? `${latest.post_workout_weight_kg}kg` : "-";
}

// ---------------------------------------------------------------------------
// 選手詳細：直近7日サマリー・推移グラフ
// ---------------------------------------------------------------------------
// いずれも新しい問い合わせは行わず、loadMemberConditionShares()が既に取得した
// 直近7日分（最大7件）のrowsだけを使う。データが2件未満の場合は全体を非表示にする

// 直近7日分のrows（record_date昇順）。チャートのタブ切替時に再取得せずここから再描画する
let currentDetailConditionRowsAsc = [];
let currentChartMetric = "fatigue";

function shortDateLabel(dateStr) {
  const parts = String(dateStr).split("-");
  return parts.length === 3 ? `${Number(parts[1])}/${Number(parts[2])}` : dateStr;
}

function renderConditionSummaryAndChart(rowsDesc) {
  const area = document.getElementById("memberDetailSummaryArea");
  currentDetailConditionRowsAsc = [...rowsDesc].reverse(); // グラフは古い→新しい順で左から右へ

  if (rowsDesc.length < 2) {
    area.hidden = true;
    return;
  }
  area.hidden = false;

  // 入力回数：直近7日の取得件数（存在するデータのみで計算。0埋め等はしない）
  document.getElementById("summaryInputCount").textContent = `${rowsDesc.length} / 7日`;

  const sleepRows = rowsDesc.filter((r) => r.sleep_hours != null || r.sleep_minutes != null);
  if (sleepRows.length > 0) {
    const totalMinutes = sleepRows.reduce((sum, r) => sum + (r.sleep_hours ?? 0) * 60 + (r.sleep_minutes ?? 0), 0);
    const avgMinutes = Math.round(totalMinutes / sleepRows.length);
    document.getElementById("summaryAvgSleep").textContent = `${Math.floor(avgMinutes / 60)}時間${avgMinutes % 60}分`;
  } else {
    document.getElementById("summaryAvgSleep").textContent = "-";
  }

  const fatigueRows = rowsDesc.filter((r) => r.fatigue_level != null);
  if (fatigueRows.length > 0) {
    const avgFatigue = fatigueRows.reduce((sum, r) => sum + r.fatigue_level, 0) / fatigueRows.length;
    document.getElementById("summaryAvgFatigue").textContent = avgFatigue.toFixed(1);
  } else {
    document.getElementById("summaryAvgFatigue").textContent = "-";
  }

  // 体重変化：直近7日のうち体重が記録されている最初（最も古い）と最後（最も新しい）の差分。
  // 体重の記録が1件以下の場合は変化を出しようがないため"-"のままにする
  const weightRowsAsc = currentDetailConditionRowsAsc.filter((r) => r.weight_kg != null);
  const weightChangeEl = document.getElementById("summaryWeightChange");
  if (weightRowsAsc.length >= 2) {
    const diff = weightRowsAsc[weightRowsAsc.length - 1].weight_kg - weightRowsAsc[0].weight_kg;
    const sign = diff > 0 ? "+" : "";
    weightChangeEl.textContent = `${sign}${Math.round(diff * 10) / 10}kg`;
  } else {
    weightChangeEl.textContent = "-";
  }

  renderMiniChart(currentChartMetric);
}

function createSvgElement(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, value));
  return el;
}

const CHART_METRIC_CONFIG = {
  fatigue: {
    extract: (row) => (row.fatigue_level != null ? row.fatigue_level : null),
  },
  sleep: {
    extract: (row) => (row.sleep_hours != null || row.sleep_minutes != null
      ? (row.sleep_hours ?? 0) * 60 + (row.sleep_minutes ?? 0)
      : null),
  },
  weight: {
    extract: (row) => (row.weight_kg != null ? row.weight_kg : null),
  },
};

// 軽量な折れ線グラフを素のSVG（createElementNS）で描画する。外部チャートライブラリは使わない。
// 値が存在する日だけを点として使い（欠損日を0や補間で埋めない）、2点未満なら案内文言を出す
function renderMiniChart(metric) {
  currentChartMetric = metric;
  const wrap = document.getElementById("miniChartWrap");
  wrap.textContent = "";

  const config = CHART_METRIC_CONFIG[metric];
  const points = currentDetailConditionRowsAsc
    .map((row) => ({ label: shortDateLabel(row.record_date), value: config.extract(row) }))
    .filter((p) => p.value != null);

  if (points.length < 2) {
    const note = document.createElement("p");
    note.className = "hint";
    note.style.margin = "0";
    note.textContent = "推移を表示するには2日以上のデータが必要です。";
    wrap.appendChild(note);
    return;
  }

  const width = 320;
  const height = 120;
  const padX = 26;
  const padY = 16;
  const values = points.map((p) => p.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = points.length > 1 ? (width - padX * 2) / (points.length - 1) : 0;

  const coords = points.map((p, i) => ({
    x: padX + stepX * i,
    y: height - padY - ((p.value - min) / range) * (height - padY * 2),
    label: p.label,
  }));

  const svg = createSvgElement("svg", {
    viewBox: `0 0 ${width} ${height}`,
    class: "mini-chart-svg",
    role: "img",
    "aria-label": "推移グラフ",
  });

  const pathD = coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");
  svg.appendChild(createSvgElement("path", { d: pathD, class: "mini-chart-line" }));
  coords.forEach((c) => {
    svg.appendChild(createSvgElement("circle", { cx: c.x.toFixed(1), cy: c.y.toFixed(1), r: 3, class: "mini-chart-dot" }));
  });
  wrap.appendChild(svg);

  const labelsRow = document.createElement("div");
  labelsRow.className = "mini-chart-labels";
  coords.forEach((c) => {
    const span = document.createElement("span");
    span.textContent = c.label;
    labelsRow.appendChild(span);
  });
  wrap.appendChild(labelsRow);
}

document.querySelectorAll("#chartTabs .chart-tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#chartTabs .chart-tab-btn").forEach((b) => b.classList.toggle("active", b === btn));
    renderMiniChart(btn.dataset.chartMetric);
  });
});

function appendConditionHint(text) {
  const memberDetailConditionList = document.getElementById("memberDetailConditionList");
  const note = document.createElement("p");
  note.className = "hint";
  note.textContent = text;
  memberDetailConditionList.appendChild(note);
}

// team_condition_sharesを直接SELECTする。condition共有がOFFの選手・削除済みの選手については
// RLS（team_admins + active member + team_share_permissions.condition=trueを要求）が
// 自動的に0件を返すため、ここでの追加のアクセス制御は不要（member.conditionSharedは
// 表示文言の分岐にのみ使う）
async function loadMemberConditionShares(member) {
  const memberDetailConditionStatus = document.getElementById("memberDetailConditionStatus");
  const memberDetailConditionList = document.getElementById("memberDetailConditionList");
  memberDetailConditionList.textContent = "";

  if (!member.conditionShared) {
    memberDetailConditionStatus.textContent = "";
    appendConditionHint("この選手はコンディション共有をOFFにしています。");
    renderLatestConditionCard(null);
    renderConditionSummaryAndChart([]);
    return;
  }

  memberDetailConditionStatus.style.color = "";
  setLoadingStatus(memberDetailConditionStatus, "取得中...");
  try {
    const { data, error } = await client
      .from("team_condition_shares")
      .select(
        "record_date, weight_kg, sleep_hours, sleep_minutes, fatigue_level, feeling, body_fat_percent, post_workout_weight_kg"
      )
      .eq("team_id", currentTeamId)
      .eq("user_id", member.userId)
      .order("record_date", { ascending: false })
      .limit(7);
    if (error) throw error;

    memberDetailConditionStatus.textContent = "";
    const rows = data || [];
    if (rows.length === 0) {
      appendConditionHint("まだ同期されたデータがありません。");
      renderLatestConditionCard(null);
      renderConditionSummaryAndChart([]);
      return;
    }
    renderLatestConditionCard(rows[0]);
    // サマリー・グラフは直近7日の取得結果（rows）をそのまま再利用する（追加の問い合わせはしない）
    renderConditionSummaryAndChart(rows);
    rows.forEach((row) => memberDetailConditionList.appendChild(buildConditionRow(row)));
  } catch (error) {
    memberDetailConditionStatus.style.color = "var(--danger)";
    memberDetailConditionStatus.textContent = "コンディションを取得できませんでした。";
    renderConditionSummaryAndChart([]);
    renderLatestConditionCard(null);
  }
}

function closeMemberDetail() {
  memberDetailPanel.hidden = true;
  memberDetailBackdrop.hidden = true;
  currentDetailMember = null;
}

document.getElementById("closeMemberDetailBtn").addEventListener("click", closeMemberDetail);
memberDetailBackdrop.addEventListener("click", closeMemberDetail);

removeMemberBtn.addEventListener("click", async () => {
  if (!currentDetailMember || !currentTeamId) return;
  if (!window.confirm("この選手をチームから削除しますか？\n選手本人のアカウントは削除されません。")) return;

  removeMemberBtn.disabled = true;
  memberDetailActionStatus.style.color = "";
  setLoadingStatus(memberDetailActionStatus, "処理中...");
  try {
    // 既存RPC remove_team_member(p_team_id, p_target_user_id)。owner/adminの権限確認は
    // サーバー側（SECURITY DEFINER）で行われる。ブラウザ側の判定だけに依存しない
    const { error } = await client.rpc("remove_team_member", {
      p_team_id: currentTeamId,
      p_target_user_id: currentDetailMember.userId,
    });
    if (error) throw error;
    closeMemberDetail();
    await loadMembers(currentTeamId);
    showToast("選手をチームから削除しました");
  } catch (error) {
    memberDetailActionStatus.style.color = "var(--danger)";
    memberDetailActionStatus.textContent = japaneseRpcErrorMessage(error);
  } finally {
    removeMemberBtn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// セッション監視
// ---------------------------------------------------------------------------

// Email確認/パスワード再設定リンクから戻った直後にだけclaim処理を1回試みるためのフラグ。
// 通常のメール＋パスワードログイン（cameFromAuthCallback=false）では呼ばない
let claimAttempted = false;

// パスワード再設定リンクから戻った場合、onAuthStateChangeがPASSWORD_RECOVERYを発火する。
// このフラグをtrueにしている間は、以後PASSWORD_RECOVERY以外のイベント（SIGNED_IN/
// INITIAL_SESSION等。Supabaseはrecoveryセッション確立時にこれらも続けて発火することがある）で
// renderForSessionが再度呼ばれても、新パスワード入力画面から一切動かさない。
// updateUser成功後、ユーザーが「チーム管理画面へ進む」を押した時だけfalseに戻す
// （dashboardへの遷移をユーザー操作なしに自動で行わせないため）。
// 初期値はisPasswordRecoveryFromUrl（URLの時点での同期判定）から取る。イベント発火を
// 待たずに最初からrecovery modeへ入ることで、init()の最初のgetSession()/loadDashboard()が
// 新しいrecovery sessionを「通常ログイン済み」と誤認して先にdashboardへ進んでしまう競合を防ぐ
let isPasswordRecovery = isPasswordRecoveryFromUrl;

async function renderForSession(session, event) {
  if (event === "PASSWORD_RECOVERY") {
    isPasswordRecovery = true;
    showView("resetPassword");
    return;
  }
  if (isPasswordRecovery) {
    // SIGNED_IN/INITIAL_SESSION等がこの後に発火しても、パスワード更新が完了するまでは
    // 絶対にここより下（dashboard判定）へ進ませない
    showView("resetPassword");
    return;
  }

  if (!session) {
    currentTeamId = null;

    // 確認リンクが無効/期限切れ（otp_expired）でセッションが確立しなかった場合、無言で
    // ログイン画面へ戻さず、専用の再送導線を表示する。「ログイン画面に戻る」を押すと
    // currentViewNameが"login"になるため、以後は通常通りlogin判定に戻る
    if (currentViewName === "linkExpired") {
      // supabase-jsはページ読み込み直後にINITIAL_SESSIONを追加で発火することがあり、
      // renderForSessionが同じsession(null)で再度呼ばれる場合がある。既にlinkExpiredを
      // 表示済みならそのまま維持し、ログイン画面へ巻き戻さない
      return;
    }
    if (shouldShowLinkExpiredOnce) {
      shouldShowLinkExpiredOnce = false;
      document.getElementById("linkExpiredEmailInput").value = "";
      document.getElementById("linkExpiredStatus").textContent = "";
      showView("linkExpired");
      return;
    }
    showView("login");
    return;
  }

  // Email確認直後（サインアップのconfirmationリンクから戻った直後）だけ、pending招待の
  // claimを試みる。通常ログインでは呼ばない（招待が無いのが正常なため、毎回エラーにしない）
  if (cameFromAuthCallback && !claimAttempted) {
    claimAttempted = true;
    try {
      await client.rpc("claim_team_admin_invitation");
    } catch (error) {
      // 招待が無い（既存の通常ユーザーがconfirmationリンク以外の経路で来た等）場合や
      // 上限到達等はここでは無視し、以降は通常のdashboard判定へ進む
      // （エラー内容はコンソールにのみ残す。UIへ内部エラー文言は出さない）
      console.warn("[TeamAuth] claim_team_admin_invitation skipped:", error.message);
    }
  }

  await loadDashboard();
}

async function init() {
  showView("loading");

  // localStorageのrecovery状態（URLにtype=recoveryが無い、＝タブを閉じて再度開いた
  // ケース）。有効かどうか（＝sessionがまだ生きているか）はgetSession()の結果を見るまで
  // 確定できないため、ここでは値を覚えておくだけでshowViewはまだ行わない
  const hadStoredRecoveryFlagOnLoad = hasStoredRecoveryFlag();

  // URLの時点でrecoveryと判定済みの場合は、getSession()の結果を待たず最優先でreset画面を
  // 表示する。isPasswordRecoveryFromUrlはスクリプト先頭で同期的に判定済みのため、
  // ここでの分岐にasync処理の完了順は一切関係ない
  if (isPasswordRecoveryFromUrl) {
    showView("resetPassword");
  }

  // onAuthStateChangeは登録した瞬間から今後発火するイベントを拾えるようになる。
  // getSession()より先に登録しておくことで、getSession()が内部で待つ初期化処理
  // （detectSessionInUrlによるURL解析・PASSWORD_RECOVERY/SIGNED_IN通知）を
  // 取りこぼさないようにする（Supabase公式が推奨する登録順）
  client.auth.onAuthStateChange((event, session) => {
    if (event === "PASSWORD_RECOVERY") {
      isPasswordRecovery = true;
      // 有効sessionが実際に成立した時点でのみフラグを保存する（無効/期限切れの
      // recoveryリンクの場合はsessionが無いため、ここでは保存されない）
      if (session) setStoredRecoveryFlag();
    }
    renderForSession(session, event);
    // recovery URLから来た場合、session確立後（この時点でsessionは既に有効）にURLから
    // access_token等を除去する。session確立前に消すとdetectSessionInUrlの処理と競合する
    // おそれがあるため、必ずここ（イベント通知後）で行う
    if (isPasswordRecoveryFromUrl && session && window.location.hash) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  });

  const {
    data: { session },
  } = await client.auth.getSession();

  if (isPasswordRecoveryFromUrl) {
    if (session) {
      // 有効sessionが確認できた時点でフラグを保存する（タブを閉じても復元できるように）
      isPasswordRecovery = true;
      setStoredRecoveryFlag();
    } else {
      // URLはrecovery形式だがsessionが確立しなかった（無効/期限切れ等）。
      // 同期的に立てていたisPasswordRecoveryは取り消し、通常のrenderForSession(null)判定
      // （otp_expired専用画面等）へ委ねる
      isPasswordRecovery = false;
    }
    await renderForSession(session);
    return;
  }

  if (hadStoredRecoveryFlagOnLoad) {
    if (session) {
      // localStorageのrecovery状態＋有効session：タブを閉じて再度開いたケース。
      // URLにtype=recoveryが無くてもreset画面へ戻す
      isPasswordRecovery = true;
      showView("resetPassword");
    } else {
      // フラグはあるがsessionが無効（ログアウト済み・session期限切れ等）。
      // 無限にreset画面を出し続けないよう、フラグを削除して通常のログイン判定へ戻す
      clearStoredRecoveryFlag();
      isPasswordRecovery = false;
      await renderForSession(session);
    }
    return;
  }

  await renderForSession(session);
}

// location.replace()はナビゲーション完了まで同期実行を止めないため、127.0.0.1正規化中は
// このページ上でのinit()（getSession等）を実行しない（正規化後のlocalhost側ページ読み込みで
// 改めてinit()が走る）
if (!isNormalizingHost) {
  init();
}
