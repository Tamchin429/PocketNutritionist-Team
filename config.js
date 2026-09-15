// config.js
// PocketNutritionist team-web（チーム管理者用ブラウザ）共通設定。
//
// ここに置くのはブラウザ埋め込み前提の公開情報のみ（Supabase URL・publishable key）。
// service_role key・ADMIN_API_TOKENは絶対にここへ書かない（admin-webのlocal proxy方式は
// team-webでは使わず、Supabase Auth JWT + RLSだけで動作する設計のため、
// そもそもこのファイルに秘密情報を置く必要が無い）。
const SUPABASE_URL = "https://rropgpnyoywrudmmzqyr.supabase.co";

// SupabaseのPublishable key（クライアント埋め込み前提の公開キー。Secret keyではない。
// iOS側Services（AuthSessionService.swift等）と同じ値を使用している）
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_eHqp_KJXosrIaE-lyhIoFw_-p1MwEVQ";
