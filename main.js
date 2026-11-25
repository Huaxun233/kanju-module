// kanju.ai 站源模块（Xghub JS 模块，CommonJS）
// 接口全图见 kanju-probe；签名 HMAC-SHA256(SECRET, `${METHOD}\n${pathname}${search}\n${ts}\n${nonce}`) hex
var BASE = "https://kanju.ai";
var SECRET = "557d0e4ae929f438da6bd84412374e6086b8af09b3fed54bf22601d5bf8c54a0";

var CATEGORIES = [
  { key: "short_drama", name: "短剧" },
  { key: "movie", name: "电影" },
  { key: "series", name: "剧集" },
  { key: "anime", name: "动漫" },
  { key: "variety", name: "综艺" },
  { key: "documentary", name: "纪录片" },
];

// ---------- 轻工具 ----------
function randomHex(len) {
  var s = "";
  while (s.length < len) s += Math.floor(Math.random() * 16).toString(16);
  return s.slice(0, len);
}

function queryString(params) {
  var parts = [];
  for (var k in params) {
    if (params[k] === undefined || params[k] === null || params[k] === "") continue;
    parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
  }
  return parts.join("&");
}

// 手写 HMAC-SHA256（host.sha256 接受字节数组，返回字节数组）
// 注意：真实宿主返回 Uint8Array，Array.prototype.concat 会把整个 TypedArray
// 当成单个元素塞进去导致签名错误，必须按下标逐字节拼接（与 hongguo 模块同法）。
function concatBytes(a, b) {
  var out = new Uint8Array(a.length + b.length);
  var offset = 0;
  for (var i = 0; i < a.length; i++) out[offset++] = a[i];
  for (var j = 0; j < b.length; j++) out[offset++] = b[j];
  return out;
}

function hmacSha256(keyBytes, messageBytes) {
  var blockSize = 64;
  var key = keyBytes;
  if (key.length > blockSize) key = host.sha256(key);
  var ipad = new Uint8Array(blockSize);
  var opad = new Uint8Array(blockSize);
  for (var i = 0; i < blockSize; i++) {
    var b = i < key.length ? key[i] : 0;
    ipad[i] = b ^ 0x36;
    opad[i] = b ^ 0x5c;
  }
  var inner = host.sha256(concatBytes(ipad, messageBytes));
  return host.sha256(concatBytes(opad, inner));
}

function bytesOf(str) {
  // UTF-8 编码字符串 → 字节数组
  var u8 = host.utf8Encode(str);
  return u8;
}

function hexOf(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  }
  return out;
}

// ---------- 签名请求 ----------
var sessionCookie = "";
var anonymousId = "";

function signedRequest(pathWithQuery, method) {
  method = (method || "GET").toUpperCase();
  var ts = String(Date.now());
  var nonce = randomHex(32);
  var message = method + "\n" + pathWithQuery + "\n" + ts + "\n" + nonce;
  var sig = hexOf(hmacSha256(bytesOf(SECRET), bytesOf(message)));
  var res = host.fetch({
    method: method,
    url: BASE + pathWithQuery,
    headers: {
      "x-ai-movie-timestamp": ts,
      "x-ai-movie-nonce": nonce,
      "x-ai-movie-signature": sig,
      Cookie: sessionCookie || "",
    },
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error("kanju 接口请求失败（HTTP " + res.status + "）");
  }
  // 记录会话 cookie（若有）
  var setCookies = headerValues(res.headers, "set-cookie");
  for (var i = 0; i < setCookies.length; i++) {
    var part = String(setCookies[i]).split(";")[0];
    if (part) sessionCookie = sessionCookie ? sessionCookie + "; " + part : part;
  }
  return JSON.parse(res.body);
}

// Go 宿主 Header map key 规范化为 "Set-Cookie"，node 测试台是小写；大小写不敏感取
function headerValues(headers, name) {
  var out = [];
  var lower = String(name).toLowerCase();
  for (var k in headers) {
    if (String(k).toLowerCase() === lower) {
      var arr = headers[k];
      if (arr && arr.length) for (var i = 0; i < arr.length; i++) out.push(String(arr[i]));
    }
  }
  return out;
}

function createSession() {
  var anonId = host.cacheGet("kanju:anon-id");
  if (!anonId) {
    anonId = randomHex(32);
    host.cacheSet("kanju:anon-id", anonId, 90 * 24 * 3600 * 1000);
  }
  var ts = String(Date.now());
  var nonce = randomHex(32);
  var message = "POST\n/v1/users/anonymous\n" + ts + "\n" + nonce;
  var sig = hexOf(hmacSha256(bytesOf(SECRET), bytesOf(message)));
  var res = host.fetch({
    method: "POST",
    url: BASE + "/v1/users/anonymous",
    headers: {
      "x-ai-movie-timestamp": ts,
      "x-ai-movie-nonce": nonce,
      "x-ai-movie-signature": sig,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ anonymous_id: anonId }),
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error("kanju 匿名会话创建失败（HTTP " + res.status + "）");
  }
  var setCookies = headerValues(res.headers, "set-cookie");
  var cookieParts = [];
  for (var i = 0; i < setCookies.length; i++) {
    var part = String(setCookies[i]).split(";")[0];
    if (part && part.indexOf("=") >= 0) cookieParts.push(part);
  }
  if (!cookieParts.length) {
    throw new Error("kanju 匿名会话未返回会话 cookie");
  }
  sessionCookie = cookieParts.join("; ");
  host.cacheSet("kanju:session", sessionCookie, 2 * 3600 * 1000);
  return sessionCookie;
}

function dropSession() {
  sessionCookie = "";
  host.cacheSet("kanju:session", "", 1000);
}

function ensureSession() {
  if (sessionCookie) return;
  var cached = host.cacheGet("kanju:session");
  if (cached && String(cached).indexOf("=") >= 0) {
    sessionCookie = String(cached);
    return;
  }
  createSession();
}

// 兼容宿主期望的导出形式
function validCategory(category) {
  for (var i = 0; i < CATEGORIES.length; i++) {
    if (CATEGORIES[i].key === category) return true;
  }
  return false;
}

function categories() {
  return CATEGORIES.map(function (c) { return c.name; });
}

function catalogPage(page, category) {
  var params = { kind: category || "short_drama", page: page || 1, limit: 24 };
  var q = queryString(params);
  var data = signedRequest("/v1/browse/catalog?" + q);
  var items = (data.cards || []).map(function (c) {
    return {
      id: host.dramaId(c.id),
      source: "kanju",
      sourceId: c.id,
      title: c.title,
      coverUrl: c.poster_url || c.backdrop_url || "",
      remark: c.remarks || "",
      totalEpisode: c.episode_count || 0,
      tags: [c.content_kind || ""],
    };
  });
  return { items: items, hasMore: !!(data.pagination && data.pagination.has_more) };
}

function search(page, query) {
  var params = { q: query, page: page || 1, limit: 24 };
  var data = signedRequest("/v1/browse/catalog?" + queryString(params));
  var items = (data.cards || []).map(function (c) {
    return {
      id: host.dramaId(c.id),
      source: "kanju",
      sourceId: c.id,
      title: c.title,
      coverUrl: c.poster_url || c.backdrop_url || "",
      remark: c.remarks || "",
      totalEpisode: c.episode_count || 0,
      tags: [c.content_kind || ""],
    };
  });
  return { items: items, hasMore: !!(data.pagination && data.pagination.has_more) };
}

function detail(sourceId) {
  ensureSession();
  var d = signedRequest("/v1/catalog/" + encodeURIComponent(sourceId));
  var drama = {
    id: host.dramaId(sourceId),
    source: "kanju",
    sourceId: d.id || sourceId,
    title: d.title,
    name: d.title,
    desc: d.description || "",
    intro: d.description || "",
    coverUrl: d.poster_url || d.backdrop_url || "",
    totalEpisode: d.current_episode_count || 0,
    remark: d.remarks || "",
    tags: d.genres || [],
  };
  // 分集列表
  var episodes = [];
  var offset = 0;
  var guard = 0;
  while (guard++ < 40) {
    var ed = signedRequest("/v1/catalog/" + encodeURIComponent(sourceId) + "/episodes?offset=" + offset + "&limit=48");
    var list = ed.episodes || [];
    for (var i = 0; i < list.length; i++) {
      episodes.push(list[i]);
    }
    var pg = ed.episode_pagination || {};
    if (!pg.has_more) break;
    offset += list.length;
  }
  var chapters = episodes.map(function (ep, idx) {
    return {
      id: host.chapterId(drama.sourceId, String(ep.token || ep.id || idx)),
      source: "kanju",
      title: ep.title || "第" + (idx + 1) + "集",
      videoUrl: "",
      currentEpisode: idx,
      vip: false,
      token: ep.token || "",
    };
  });
  return { drama: drama, chapters: chapters };
}

function resolveOnce(token) {
  var data = signedRequest("/v1/playback/resolve/" + token);
  var lines = data.line_options || [];
  for (var i = 0; i < lines.length; i++) {
    var u = String(lines[i].url || "");
    if (u.indexOf("http") === 0) {
      return { url: u, credentials: { cookie: sessionCookie } };
    }
  }
  throw new Error("kanju 该分集无可播放直链");
}

function resolveMedia(task) {
  ensureSession();
  var chapter = task.chapter || {};
  var token = chapter.token || String(chapter.id || "").split(":").pop();
  try {
    return resolveOnce(token);
  } catch (eFirst) {
    // 会话失效/无权访问：丢弃旧会话，重建匿名会话再试一次
    dropSession();
    createSession();
    return resolveOnce(token);
  }
}

module.exports = {
  validCategory: validCategory,
  categories: categories,
  catalogPage: catalogPage,
  search: search,
  detail: detail,
  resolveMedia: resolveMedia,
};
