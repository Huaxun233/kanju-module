// 看剧 kanju.ai 站源模块（Xghub JS 站源，manifest runtime=js api=1）
//
// 接口协议（2026-11 实测）：
//   1. 所有 /v1/* 请求需要 HMAC 签名头：
//      signature = HMAC-SHA256(SECRET, METHOD + "\n" + path + search + "\n" + ts + "\n" + nonce) hex
//      headers: x-ai-movie-timestamp(毫秒) x-ai-movie-nonce(32hex) x-ai-movie-signature
//   2. catalog/episodes/playback 端点需要匿名会话 cookie：
//      POST /v1/users/anonymous {anonymous_id:<uuid>} → set-cookie
//   3. 浏览/搜索走 /v1/browse/catalog?kind=|q=；详情 /v1/catalog/<id>；
//      集数 /v1/catalog/<id>/episodes?offset=；播放 /v1/playback/resolve/<token>。
//   4. 播放响应 line_options[]：url 以 http 开头的是直链 m3u8；
//      url 以 resolve:// 开头的是二次令牌，需再调 /v1/playback/resolve/<token>。
//
// goja 环境没有 HMAC 与 URLSearchParams，签名用 host.sha256 手写 HMAC，查询串手工拼接。

const BASE = "https://kanju.ai";
const SECRET = "557d0e4ae929f438da6bd84412374e6086b8af09b3fed54bf22601d5bf8c54a0";

// ---------- 工具 ----------

function enc(value) {
  return encodeURIComponent(String(value));
}

function query(params) {
  const parts = [];
  for (const key in params) {
    if (params[key] !== undefined && params[key] !== null) {
      parts.push(enc(key) + "=" + enc(params[key]));
    }
  }
  return parts.join("&");
}

function bytesConcat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function xorPad(key, pad) {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    out[i] = (i < key.length ? key[i] : 0) ^ pad;
  }
  return out;
}

// HMAC-SHA256，返回 hex。key 与 message 都是字符串。
function hmacSha256Hex(keyText, messageText) {
  let key = host.utf8Encode(keyText);
  if (key.length > 64) key = new Uint8Array(host.sha256(key));
  const inner = bytesConcat([xorPad(key, 0x36), host.utf8Encode(messageText)]);
  const innerHash = new Uint8Array(host.sha256(inner));
  const outer = bytesConcat([xorPad(key, 0x5c), innerHash]);
  return host.hexEncode(host.sha256(outer));
}

function randomHex(bytes) {
  return host.hexEncode(host.randomBytes(bytes));
}

function uuid() {
  const h = randomHex(16);
  return (
    h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" +
    h.slice(16, 20) + "-" + h.slice(20, 32)
  );
}

// ---------- 会话 ----------

const SESSION_KEY = "kanju:session";
const ANON_KEY = "kanju:anon-id";

function ensureSession() {
  let cookie = host.cacheGet(SESSION_KEY);
  if (cookie && String(cookie).indexOf("=") >= 0) {
    return String(cookie);
  }
  let anonId = host.cacheGet(ANON_KEY);
  if (!anonId) {
    anonId = uuid();
    host.cacheSet(ANON_KEY, anonId, 90 * 24 * 3600 * 1000);
  }
  const path = "/v1/users/anonymous";
  const response = api("POST", path, { anonymous_id: anonId });
  if (response.status !== 200 && response.status !== 201) {
    throw new Error("看剧匿名会话创建失败（HTTP " + response.status + "）");
  }
  const cookies = (response.headers && response.headers["set-cookie"]) || [];
  const parts = [];
  for (const line of cookies) {
    parts.push(String(line).split(";")[0]);
  }
  cookie = parts.join("; ");
  if (!cookie) {
    throw new Error("看剧匿名会话未返回会话 cookie");
  }
  host.cacheSet(SESSION_KEY, cookie, 12 * 3600 * 1000);
  return cookie;
}

function dropSession() {
  host.cacheSet(SESSION_KEY, null, 0);
}

// ---------- API ----------

function api(method, pathWithQuery, body, cookie) {
  const ts = String(Date.now());
  const nonce = randomHex(16);
  const signature = hmacSha256Hex(SECRET, method + "\n" + pathWithQuery + "\n" + ts + "\n" + nonce);
  const headers = {
    "User-Agent": "Mozilla/5.0",
    Accept: "application/json",
    "x-ai-movie-timestamp": ts,
    "x-ai-movie-nonce": nonce,
    "x-ai-movie-signature": signature,
  };
  if (cookie) headers["cookie"] = cookie;
  const request = { method: method, url: BASE + pathWithQuery, headers: headers, timeoutMs: 20000 };
  if (body !== undefined && body !== null) {
    headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(body);
  }
  return host.fetch(request);
}

function apiJson(method, pathWithQuery, body, cookie) {
  const response = api(method, pathWithQuery, body, cookie);
  if (response.status < 200 || response.status >= 300) {
    throw new Error("看剧接口 " + pathWithQuery + " 返回 HTTP " + response.status);
  }
  try {
    return JSON.parse(response.body);
  } catch (error) {
    throw new Error("看剧接口 " + pathWithQuery + " 返回的不是 JSON");
  }
}

// ---------- 分类 ----------

const CATEGORIES = [
  { id: "short_drama", name: "短剧" },
  { id: "movie", name: "电影" },
  { id: "series", name: "剧集" },
  { id: "anime", name: "动漫" },
  { id: "variety", name: "综艺" },
  { id: "documentary", name: "纪录片" },
];

function validCategory(category) {
  return category === "" || CATEGORIES.some((entry) => entry.id === category);
}

// ---------- 卡片 → Drama ----------

function toDrama(card) {
  return {
    id: card.id,
    source: host.source,
    sourceId: card.id,
    title: card.title || card.normalized_title || "未知",
    name: card.title || card.normalized_title || "未知",
    desc: card.description || "",
    intro: card.description || "",
    coverUrl: card.poster_url || card.backdrop_url || "",
    totalEpisode: card.current_episode_count || (card.availability && card.availability.episode_count) || "",
    remark: String(card.remarks || ""),
    tags: Array.isArray(card.genres) ? card.genres : [],
    category: card.content_kind || "",
  };
}

// ---------- 导出 ----------

module.exports = {
  validCategory,

  categories() {
    return CATEGORIES;
  },

  catalogPage(page, category) {
    if (!validCategory(category)) {
      throw new Error("看剧模块没有分类 " + category);
    }
    const kind = category || CATEGORIES[0].id;
    const data = apiJson("GET", "/v1/browse/catalog?" + query({
      kind: kind,
      page: page,
      limit: 24,
      sort: "updated_desc",
    }));
    const cards = data.cards || [];
    const pagination = data.pagination || {};
    return { items: cards.map(toDrama), hasMore: !!pagination.has_more };
  },

  search(page, queryText) {
    if (String(queryText).trim() === "") {
      return { items: [], hasMore: false };
    }
    const data = apiJson("GET", "/v1/browse/catalog?" + query({
      q: String(queryText).trim(),
      page: page,
      limit: 24,
    }));
    const cards = data.cards || [];
    const pagination = data.pagination || {};
    return { items: cards.map(toDrama), hasMore: !!pagination.has_more };
  },

  detail(sourceId) {
    const id = String(sourceId).trim();
    if (id === "") {
      throw new Error("看剧模块剧集 ID 为空");
    }
    const cookie = ensureSession();
    const detail = apiJson("GET", "/v1/catalog/" + enc(id), undefined, cookie);
    const card = detail.card || detail.catalog || detail;
    const drama = toDrama(card);

    // 集数分页拉全（每页 48）
    const chapters = [];
    let offset = 0;
    for (let guard = 0; guard < 40; guard++) {
      const eps = apiJson("GET", "/v1/catalog/" + enc(id) + "/episodes?" + query({
        offset: offset,
        limit: 48,
      }), undefined, cookie);
      const list = eps.episodes || [];
      for (const ep of list) {
        const track = String(ep.episode_track || "");
        const isExtra = track !== "" && track.indexOf("正片") < 0;
        chapters.push({
          id: host.chapterId(id, ep.token || ep.key || ep.id),
          source: host.source,
          title: (isExtra ? "[花絮] " : "") + (ep.title || ep.key || "第 " + (chapters.length + 1) + " 集"),
          currentEpisode: ep.episode_number || chapters.length + 1,
          vip: false,
        });
      }
      const pagination = eps.episode_pagination || {};
      if (!pagination.has_more || list.length === 0) break;
      offset += list.length;
    }
    return { drama: drama, chapters: chapters };
  },

  resolveMedia(task) {
    const chapterId = task && task.chapter && task.chapter.id;
    if (!chapterId) {
      throw new Error("播放任务缺少分集 ID");
    }
    // chapter.id = "kanju:<dramaId>:<token>"，token 是最后一段
    const token = String(chapterId).split(":").pop();
    let cookie = ensureSession();
    let url = resolveToken(token, cookie);
    if (!url) {
      // 会话可能过期：重建再试一次
      dropSession();
      cookie = ensureSession();
      url = resolveToken(token, cookie);
    }
    if (!url) {
      throw new Error("看剧未拿到可播放的直链");
    }
    return { url: url, credentials: { cookie: cookie, origin: BASE, referer: BASE + "/" } };
  },
};

// 解析一次 /v1/playback/resolve/<token>：
// 返回 { url, next } —— url 是 http 直链时 next 为空；resolve:// 时 next 是下一跳 token。
function resolveOnce(token, cookie) {
  const data = apiJson("GET", "/v1/playback/resolve/" + enc(token), undefined, cookie);
  const lines = data.line_options || [];
  for (const line of lines) {
    const url = String(line.url || "");
    if (url.indexOf("http://") === 0 || url.indexOf("https://") === 0) {
      return { url: url, next: null };
    }
  }
  for (const line of lines) {
    const url = String(line.url || "");
    if (url.indexOf("resolve://") === 0) {
      return { url: null, next: url.slice("resolve://".length) };
    }
  }
  return { url: null, next: null };
}

function resolveToken(token, cookie) {
  let current = token;
  for (let hop = 0; hop < 3; hop++) {
    const result = resolveOnce(current, cookie);
    if (result.url) return result.url;
    if (!result.next) return null;
    current = result.next;
  }
  return null;
}
