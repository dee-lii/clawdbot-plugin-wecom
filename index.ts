import type { ClawdbotPluginApi, PluginRuntime } from "clawdbot/plugin-sdk";
import { emptyPluginConfigSchema } from "clawdbot/plugin-sdk";
import type { IncomingMessage, ServerResponse } from "node:http";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// 企业微信账户配置
interface WeComAccountConfig {
  accountId: string;
  enabled: boolean;
  corpId: string;
  corpSecret: string;
  agentId: string;
  token: string;
  encodingAesKey: string;
}

// Access Token 缓存
interface TokenCache {
  token: string;
  expiry: number;
}

const tokenCache: Map<string, TokenCache> = new Map();

// 运行时存储
let pluginRuntime: PluginRuntime | null = null;
let pluginConfig: any = null;
let pluginLogger: any = null;

// 设置运行时
function setWeComRuntime(runtime: PluginRuntime, config: any, logger: any): void {
  pluginRuntime = runtime;
  pluginConfig = config;
  pluginLogger = logger;
}

// 获取运行时
function getWeComRuntime(): PluginRuntime {
  if (!pluginRuntime) {
    throw new Error("WeCom runtime not initialized");
  }
  return pluginRuntime;
}

// 获取 Access Token
async function getAccessToken(config: WeComAccountConfig): Promise<string> {
  const cacheKey = `${config.corpId}:${config.agentId}`;
  const cached = tokenCache.get(cacheKey);

  if (cached && Date.now() < cached.expiry) {
    return cached.token;
  }

  const url = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${config.corpId}&corpsecret=${config.corpSecret}`;
  const response = await fetch(url);
  const data = (await response.json()) as {
    access_token: string;
    expires_in: number;
    errcode?: number;
    errmsg?: string;
  };

  if (data.errcode && data.errcode !== 0) {
    throw new Error(`获取 access_token 失败: ${data.errcode} ${data.errmsg}`);
  }

  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiry: Date.now() + (data.expires_in - 120) * 1000,
  });

  return data.access_token;
}

// 验证签名
function validateSignature(
  token: string,
  timestamp: string,
  nonce: string,
  encrypt: string,
  signature: string
): boolean {
  const parts = [token, timestamp, nonce, encrypt].sort();
  const str = parts.join("");
  const hash = crypto.createHash("sha1").update(str).digest("hex");
  return signature === hash;
}

// 解密消息
function decryptMessage(
  encodingAesKey: string,
  corpId: string,
  cipherText: string
): string {
  const key = Buffer.from(encodingAesKey + "=", "base64");
  const data = Buffer.from(cipherText, "base64");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, key.subarray(0, 16));
  decipher.setAutoPadding(false);

  let decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

  const padLen = decrypted[decrypted.length - 1];
  if (padLen > 32) {
    throw new Error("padding out of range");
  }
  decrypted = decrypted.subarray(0, decrypted.length - padLen);

  const msgLen = decrypted.readUInt32BE(16);
  const msg = decrypted.subarray(20, 20 + msgLen).toString("utf8");
  const receivedCorpId = decrypted.subarray(20 + msgLen).toString("utf8");

  if (receivedCorpId !== corpId) {
    throw new Error("CorpID 不匹配");
  }

  return msg;
}

// 解析 XML 消息
function parseXmlMessage(xml: string): Record<string, string> {
  const result: Record<string, string> = {};
  const regex = /<(\w+)>(?:<!\[CDATA\[(.*?)\]\]>|([^<]*))<\/\1>/g;
  let match;
  while ((match = regex.exec(xml)) !== null) {
    result[match[1]] = match[2] ?? match[3] ?? "";
  }
  return result;
}

// 读取请求体
async function readRequestBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// 解析 URL 查询参数
function parseQuery(url: string): Record<string, string> {
  const query: Record<string, string> = {};
  const queryStart = url.indexOf("?");
  if (queryStart === -1) return query;
  const queryString = url.slice(queryStart + 1);
  for (const pair of queryString.split("&")) {
    const [key, value] = pair.split("=");
    if (key) {
      query[decodeURIComponent(key)] = decodeURIComponent(value ?? "");
    }
  }
  return query;
}

// 获取账户配置
function resolveAccountConfig(accountId?: string): WeComAccountConfig {
  if (!pluginConfig) {
    return { accountId: "default", enabled: false } as WeComAccountConfig;
  }
  const accounts = pluginConfig.channels?.wecom?.accounts ?? {};
  const id = accountId ?? "default";
  const account = accounts[id];
  if (account) {
    return { ...account, accountId: id };
  }
  const cfg = pluginConfig.plugins?.entries?.wecom?.config;
  if (cfg) {
    return {
      accountId: id,
      enabled: true,
      corpId: cfg.corpId,
      corpSecret: cfg.corpSecret,
      agentId: cfg.agentId,
      token: cfg.token,
      encodingAesKey: cfg.encodingAesKey,
    };
  }
  return { accountId: id, enabled: false } as WeComAccountConfig;
}

// 上传临时素材（图片）
async function uploadMedia(
  config: WeComAccountConfig,
  filePath: string,
  type: "image" | "voice" | "video" | "file" = "image"
): Promise<string> {
  const accessToken = await getAccessToken(config);
  const url = `https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=${accessToken}&type=${type}`;

  // 读取文件
  const fileBuffer = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);

  // 获取文件 MIME 类型
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes: Record<string, string> = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
  };
  const contentType = mimeTypes[ext] || "application/octet-stream";

  // 构建 multipart/form-data
  const boundary = `----WebKitFormBoundary${Date.now()}${Math.random().toString(36)}`;
  const parts: Buffer[] = [];

  // 添加文件字段
  parts.push(Buffer.from(`--${boundary}\r\n`));
  parts.push(Buffer.from(`Content-Disposition: form-data; name="media"; filename="${fileName}"\r\n`));
  parts.push(Buffer.from(`Content-Type: ${contentType}\r\n\r\n`));
  parts.push(fileBuffer);
  parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));

  const body = Buffer.concat(parts);

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
      "Content-Length": String(body.length),
    },
    body,
  });

  const result = (await response.json()) as {
    errcode?: number;
    errmsg?: string;
    type?: string;
    media_id?: string;
    created_at?: number;
  };

  if (result.errcode && result.errcode !== 0) {
    throw new Error(`上传素材失败: ${result.errcode} ${result.errmsg}`);
  }

  if (!result.media_id) {
    throw new Error("上传素材失败: 未返回 media_id");
  }

  return result.media_id;
}

// 发送图片消息
async function sendWeComImage(
  config: WeComAccountConfig,
  toUser: string,
  mediaId: string
): Promise<void> {
  const accessToken = await getAccessToken(config);
  const url = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${accessToken}`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      touser: toUser,
      msgtype: "image",
      agentid: parseInt(config.agentId, 10),
      image: { media_id: mediaId },
    }),
  });

  const result = (await response.json()) as { errcode: number; errmsg: string };
  if (result.errcode !== 0) {
    throw new Error(`发送图片失败: ${result.errcode} ${result.errmsg}`);
  }
}

// 发送消息到企业微信
async function sendWeComMessage(
  config: WeComAccountConfig,
  toUser: string,
  content: string
): Promise<void> {
  const accessToken = await getAccessToken(config);
  const url = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${accessToken}`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      touser: toUser,
      msgtype: "text",
      agentid: parseInt(config.agentId, 10),
      text: { content },
    }),
  });

  const result = (await response.json()) as { errcode: number; errmsg: string };
  if (result.errcode !== 0) {
    throw new Error(`发送消息失败: ${result.errcode} ${result.errmsg}`);
  }
}

// 处理入站消息
async function processInboundMessage(
  msg: Record<string, string>,
  text: string,
  accountConfig: WeComAccountConfig
): Promise<void> {
  const core = getWeComRuntime();
  const config = pluginConfig;
  const senderId = msg.FromUserName;
  const messageId = msg.MsgId || `${Date.now()}`;
  const timestamp = parseInt(msg.CreateTime || "0", 10) * 1000;

  pluginLogger?.info("处理企业微信消息", { senderId, text, messageId });

  // 解析路由
  const route = core.channel.routing.resolveAgentRoute({
    cfg: config,
    channel: "wecom",
    accountId: accountConfig.accountId,
    peer: {
      kind: "dm",
      id: `wecom:${senderId}`,  // 添加渠道前缀避免与其他渠道冲突
    },
  });

  // 格式化消息
  const storePath = core.channel.session.resolveStorePath(config.session?.store, {
    agentId: route.agentId,
  });

  const envelopeOptions = core.channel.reply.resolveEnvelopeFormatOptions(config);
  const previousTimestamp = core.channel.session.readSessionUpdatedAt({
    storePath,
    sessionKey: route.sessionKey,
  });

  const body = core.channel.reply.formatAgentEnvelope({
    channel: "WeCom",
    from: senderId,
    timestamp,
    previousTimestamp,
    envelope: envelopeOptions,
    body: text,
  });

  // 构建上下文
  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: text,
    CommandBody: text,
    From: `wecom:${senderId}`,
    To: `wecom:${accountConfig.agentId}`,
    SessionKey: route.sessionKey,
    AccountId: route.accountId,
    ChatType: "direct",
    ConversationLabel: senderId,
    SenderName: senderId,
    SenderId: senderId,
    CommandAuthorized: true,
    Provider: "wecom",
    Surface: "wecom",
    MessageSid: messageId,
    OriginatingChannel: "wecom",
    OriginatingTo: `wecom:${senderId}`,
  });

  // 记录会话
  await core.channel.session.recordInboundSession({
    storePath,
    sessionKey: ctxPayload.SessionKey ?? route.sessionKey,
    ctx: ctxPayload,
    onRecordError: (err: any) => {
      pluginLogger?.error(`wecom: 更新会话失败: ${String(err)}`);
    },
  });

  // 获取表格模式
  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg: config,
    channel: "wecom",
    accountId: accountConfig.accountId,
  });

  // 分发回复
  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg: config,
    dispatcherOptions: {
      deliver: async (payload: any) => {
        try {
          // 调试日志
          console.log("[WECOM DEBUG] Payload keys:", Object.keys(payload));
          console.log("[WECOM DEBUG] Payload:", JSON.stringify(payload, null, 2).substring(0, 500));

          let imageSent = false;

          // 处理图片 - 优先使用 mediaUrl
          if (payload.mediaUrl) {
            const imagePath = payload.mediaUrl;
            console.log("[WECOM DEBUG] Found mediaUrl:", imagePath);
            if (fs.existsSync(imagePath)) {
              try {
                const mediaId = await uploadMedia(accountConfig, imagePath, "image");
                await sendWeComImage(accountConfig, senderId, mediaId);
                pluginLogger?.info("已发送图片到企业微信", { to: senderId, path: imagePath });
                imageSent = true;
              } catch (err) {
                console.error("[WECOM ERROR] Failed to send mediaUrl image:", err);
              }
            }
          }

          // 处理多个图片 - mediaUrls 数组
          if (payload.mediaUrls && Array.isArray(payload.mediaUrls) && payload.mediaUrls.length > 0) {
            console.log("[WECOM DEBUG] Found mediaUrls:", payload.mediaUrls);
            for (const imagePath of payload.mediaUrls) {
              if (fs.existsSync(imagePath)) {
                try {
                  const mediaId = await uploadMedia(accountConfig, imagePath, "image");
                  await sendWeComImage(accountConfig, senderId, mediaId);
                  pluginLogger?.info("已发送图片到企业微信", { to: senderId, path: imagePath });
                  imageSent = true;
                } catch (err) {
                  console.error("[WECOM ERROR] Failed to send mediaUrls image:", err);
                }
              }
            }
          }

          // 处理旧格式的图片
          if (!imageSent && payload.image) {
            const imagePath = payload.image.path || payload.image.url;
            console.log("[WECOM DEBUG] Found image.path:", imagePath);
            if (imagePath && fs.existsSync(imagePath)) {
              try {
                const mediaId = await uploadMedia(accountConfig, imagePath, "image");
                await sendWeComImage(accountConfig, senderId, mediaId);
                pluginLogger?.info("已发送图片到企业微信", { to: senderId, path: imagePath });
                imageSent = true;
              } catch (err) {
                console.error("[WECOM ERROR] Failed to send image:", err);
              }
            }
          }

          // 检查文本中是否包含图片路径（临时方案）
          const replyText = payload.text || payload.body || "";
          if (!imageSent) {
            const imagePathMatch = replyText.match(/\/[^\s]+\.(png|jpg|jpeg|gif|webp)/i);
            if (imagePathMatch) {
              const imagePath = imagePathMatch[0];
              console.log("[WECOM DEBUG] Found image path in text:", imagePath);
              if (fs.existsSync(imagePath)) {
                try {
                  const mediaId = await uploadMedia(accountConfig, imagePath, "image");
                  await sendWeComImage(accountConfig, senderId, mediaId);
                  pluginLogger?.info("已发送图片到企业微信", { to: senderId, path: imagePath });
                  imageSent = true;
                  // 发送剩余文本（去掉图片路径）
                  const textWithoutPath = replyText.replace(imagePathMatch[0], "").trim();
                  if (textWithoutPath && !textWithoutPath.match(/无法|失败|错误|缺失|Bug/)) {
                    await sendWeComMessage(accountConfig, senderId, textWithoutPath);
                  }
                  return;
                } catch (err) {
                  console.error("[WECOM ERROR] Failed to send image from text:", err);
                }
              }
            }
          }

          // 处理文本 - 智能过滤错误提示
          if (replyText) {
            // 如果图片已发送，检查文本是否是错误提示
            if (imageSent) {
              // 检查是否是错误提示（开头包含负面词汇）
              const isErrorMessage = /^(抱歉|很抱歉|非常抱歉|无法|失败|错误)/.test(replyText.trim());
              // 或者包含配置缺失相关的错误
              const isConfigError = /corpId|配置.*缺失|配置.*不完整|Bug/.test(replyText);

              if (isErrorMessage || isConfigError) {
                console.log("[WECOM DEBUG] Image sent successfully, skipping error message text");
                pluginLogger?.info("图片已发送，跳过错误提示文本");
                return;
              }
            }

            await sendWeComMessage(accountConfig, senderId, replyText);
            pluginLogger?.info("已发送回复到企业微信", { to: senderId });
          }
        } catch (err) {
          console.error("[WECOM ERROR]", err);
          pluginLogger?.error(`发送消息失败: ${String(err)}`);
          throw err;
        }
      },
      onError: (err: any, info: any) => {
        pluginLogger?.error(`wecom 回复失败: ${String(err)}`, { info });
      },
    },
    tableMode,
  });
}

// 检查 IP 是否在白名单中
function isWeComIpAllowed(req: IncomingMessage): boolean {
  // 企业微信服务器 IP 段
  const wecomIpRanges = [
    "101.226.103.",
    "101.226.62.",
    "140.207.54.",
  ];

  // 获取客户端 IP（考虑反向代理）
  const forwardedFor = req.headers["x-forwarded-for"];
  const realIp = req.headers["x-real-ip"];
  let clientIp = req.socket.remoteAddress || "";

  // 如果有反向代理，使用转发的 IP
  if (typeof forwardedFor === "string") {
    clientIp = forwardedFor.split(",")[0].trim();
  } else if (typeof realIp === "string") {
    clientIp = realIp;
  }

  // 移除 IPv6 前缀
  clientIp = clientIp.replace(/^::ffff:/, "");

  // 本地开发环境放行
  if (clientIp === "127.0.0.1" || clientIp === "::1" || clientIp === "localhost") {
    return true;
  }

  // 检查是否在企业微信 IP 段内
  return wecomIpRanges.some((range) => clientIp.startsWith(range));
}

// HTTP Handler
export async function handleWeComWebhook(
  req: IncomingMessage,
  res: ServerResponse
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  if (!pathname.startsWith("/webhooks/wecom")) {
    return false;
  }

  // 注释掉 IP 白名单检查，因为企业微信使用腾讯云动态 IP
  // 依赖签名验证就足够安全
  // if (!isWeComIpAllowed(req)) {
  //   const clientIp = req.socket.remoteAddress || "unknown";
  //   pluginLogger?.warn(`拒绝非企业微信 IP 访问: ${clientIp}`);
  //   res.statusCode = 403;
  //   res.end("Forbidden");
  //   return true;
  // }

  const query = parseQuery(req.url ?? "");
  const signature = query.msg_signature;
  const timestamp = query.timestamp;
  const nonce = query.nonce;
  const accountId = query.account ?? "default";

  const accountConfig = resolveAccountConfig(accountId);

  if (!accountConfig.enabled || !accountConfig.corpId) {
    res.statusCode = 404;
    res.end("Account not found");
    return true;
  }

  // GET 请求 - URL 验证
  if (req.method === "GET") {
    const echostr = query.echostr;

    if (!signature || !timestamp || !nonce || !echostr) {
      res.statusCode = 400;
      res.end("Missing parameters");
      return true;
    }

    if (!validateSignature(accountConfig.token, timestamp, nonce, echostr, signature)) {
      pluginLogger?.warn("URL 验证签名失败");
      res.statusCode = 401;
      res.end("Invalid signature");
      return true;
    }

    try {
      const decrypted = decryptMessage(
        accountConfig.encodingAesKey,
        accountConfig.corpId,
        echostr
      );
      res.statusCode = 200;
      res.end(decrypted);
    } catch (error) {
      pluginLogger?.error("解密 echostr 失败", {
        error: error instanceof Error ? error.message : "Unknown",
      });
      res.statusCode = 500;
      res.end("Decrypt failed");
    }
    return true;
  }

  // POST 请求 - 消息处理
  if (req.method === "POST") {
    if (!signature || !timestamp || !nonce) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "Missing required parameters" }));
      return true;
    }

    const body = await readRequestBody(req);
    const encryptMatch = /<Encrypt><!\[CDATA\[(.*?)\]\]><\/Encrypt>/s.exec(body);

    if (!encryptMatch) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "Invalid encrypted message format" }));
      return true;
    }

    const encryptedContent = encryptMatch[1];

    if (!validateSignature(accountConfig.token, timestamp, nonce, encryptedContent, signature)) {
      pluginLogger?.warn("签名验证失败");
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "Invalid signature" }));
      return true;
    }

    let decryptedXml: string;
    try {
      decryptedXml = decryptMessage(
        accountConfig.encodingAesKey,
        accountConfig.corpId,
        encryptedContent
      );
    } catch (error) {
      pluginLogger?.error("解密消息失败", {
        error: error instanceof Error ? error.message : "Unknown",
      });
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "Decrypt failed" }));
      return true;
    }

    const msg = parseXmlMessage(decryptedXml);

    pluginLogger?.info("收到企业微信消息", {
      type: msg.MsgType,
      from: msg.FromUserName,
      event: msg.Event,
      eventKey: msg.EventKey,
    });

    let text = msg.Content || "";

    // 处理菜单点击事件
    if (msg.MsgType === "event" && msg.Event === "click") {
      text = msg.EventKey || "";
    }

    // 忽略空消息和其他事件
    if (!text && msg.MsgType !== "text") {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ ok: true }));
      return true;
    }

    // 立即响应企业微信，避免超时
    res.statusCode = 200;
    res.end("success");

    // 异步处理消息
    processInboundMessage(msg, text, accountConfig).catch((err) => {
      pluginLogger?.error("处理消息失败", {
        error: err instanceof Error ? err.message : String(err),
      });
    });

    return true;
  }

  res.statusCode = 405;
  res.setHeader("Allow", "GET, POST");
  res.end("Method Not Allowed");
  return true;
}

// 创建应用菜单
async function createMenu(config: WeComAccountConfig, logger: any): Promise<void> {
  try {
    const accessToken = await getAccessToken(config);
    const url = `https://qyapi.weixin.qq.com/cgi-bin/menu/create?access_token=${accessToken}&agentid=${config.agentId}`;

    const buttons = [
      {
        name: "会话",
        sub_button: [
          { type: "click", name: "新对话", key: "/reset" },
          { type: "click", name: "压缩上下文", key: "/compact" },
          { type: "click", name: "查看上下文", key: "/context" },
          { type: "click", name: "停止生成", key: "/stop" },
        ],
      },
      {
        name: "模型",
        sub_button: [
          { type: "click", name: "切换模型", key: "/model" },
          { type: "click", name: "GPT-5.2", key: "/model gpt-5.2" },
          { type: "click", name: "Claude Opus", key: "/model claude-opus-4-5" },
          { type: "click", name: "DeepSeek", key: "/model deepseek-chat" },
        ],
      },
      {
        name: "更多",
        sub_button: [
          { type: "click", name: "帮助", key: "/help" },
          { type: "click", name: "状态", key: "/status" },
          { type: "click", name: "命令列表", key: "/commands" },
          { type: "click", name: "我是谁", key: "/whoami" },
        ],
      },
    ];

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ button: buttons }),
    });

    const result = (await response.json()) as { errcode: number; errmsg: string };

    if (result.errcode !== 0) {
      logger.error("创建菜单失败", { error: `${result.errcode} ${result.errmsg}` });
    } else {
      logger.info("企业微信菜单创建成功");
    }
  } catch (error) {
    logger.error("创建菜单异常", {
      error: error instanceof Error ? error.message : "Unknown",
    });
  }
}

// Onboarding 适配器 - 用于 Dashboard 和 CLI 配置
const wecomOnboardingAdapter = {
  channel: "wecom" as const,

  async setup(params: {
    cfg: any;
    prompter: any;
    accountId?: string;
    logger?: any;
  }): Promise<{ cfg: any; accountId: string }> {
    const { cfg, prompter, accountId = "default" } = params;

    // 获取现有配置
    const existing = cfg.plugins?.entries?.wecom?.config ?? {};

    await prompter.note(
      [
        "企业微信配置向导",
        "",
        "请准备以下信息：",
        "1. 企业ID (CorpID) - 在企业微信管理后台 -> 我的企业 中获取",
        "2. 应用ID (AgentID) - 在应用管理 -> 自建应用中获取",
        "3. 应用密钥 (Secret) - 在自建应用详情页获取",
        "4. 回调Token和EncodingAESKey - 在应用 -> 接收消息 中设置",
        "",
        "回调URL请设置为: https://你的域名/webhooks/wecom",
      ].join("\n"),
      "企业微信设置"
    );

    const corpId = await prompter.text({
      message: "企业ID (CorpID)",
      placeholder: "ww1234567890abcdef",
      initialValue: existing.corpId ?? "",
      validate: (v: string) => (v?.trim() ? undefined : "企业ID不能为空"),
    });

    const agentId = await prompter.text({
      message: "应用ID (AgentID)",
      placeholder: "1000002",
      initialValue: existing.agentId ?? "",
      validate: (v: string) => (v?.trim() ? undefined : "应用ID不能为空"),
    });

    const corpSecret = await prompter.password({
      message: "应用密钥 (Secret)",
      validate: (v: string) => (v?.trim() ? undefined : "应用密钥不能为空"),
    });

    const token = await prompter.text({
      message: "回调Token",
      placeholder: "设置接收消息时生成的Token",
      initialValue: existing.token ?? "",
      validate: (v: string) => (v?.trim() ? undefined : "Token不能为空"),
    });

    const encodingAesKey = await prompter.password({
      message: "消息加密密钥 (EncodingAESKey)",
      validate: (v: string) => {
        if (!v?.trim()) return "EncodingAESKey不能为空";
        if (v.length !== 43) return "EncodingAESKey长度应为43位";
        return undefined;
      },
    });

    // 更新配置
    const newCfg = {
      ...cfg,
      plugins: {
        ...cfg.plugins,
        allow: [...new Set([...(cfg.plugins?.allow ?? []), "wecom"])],
        entries: {
          ...cfg.plugins?.entries,
          wecom: {
            ...cfg.plugins?.entries?.wecom,
            enabled: true,
            config: {
              corpId: String(corpId).trim(),
              corpSecret: String(corpSecret).trim(),
              agentId: String(agentId).trim(),
              token: String(token).trim(),
              encodingAesKey: String(encodingAesKey).trim(),
            },
          },
        },
      },
    };

    await prompter.note(
      [
        "配置完成！",
        "",
        "请确保在企业微信管理后台设置：",
        `接收消息URL: https://你的域名/webhooks/wecom`,
        "",
        "重启 gateway 后生效: clawdbot gateway restart",
      ].join("\n"),
      "完成"
    );

    return { cfg: newCfg, accountId };
  },

  // 配置验证
  isConfigured(account: WeComAccountConfig): boolean {
    return Boolean(
      account.enabled &&
        account.corpId?.trim() &&
        account.corpSecret?.trim() &&
        account.agentId?.trim() &&
        account.token?.trim() &&
        account.encodingAesKey?.trim()
    );
  },

  // 描述账户
  describeAccount(account: WeComAccountConfig): {
    accountId: string;
    enabled: boolean;
    configured: boolean;
    corpId?: string;
  } {
    return {
      accountId: account.accountId,
      enabled: account.enabled,
      configured: this.isConfigured(account),
      corpId: account.corpId,
    };
  },
};

// 定义渠道插件
const wecomChannel = {
  id: "wecom",

  meta: {
    id: "wecom",
    label: "企业微信",
    selectionLabel: "企业微信 (WeCom)",
    docsPath: "/channels/wecom",
    blurb: "企业微信消息渠道集成",
    aliases: ["wechat-work", "wework"],
    detailLabel: "企业微信 Enterprise WeChat",
  },

  // 添加 onboarding 支持
  onboarding: wecomOnboardingAdapter,

  capabilities: {
    chatTypes: ["direct"] as const,
    media: true,
    threads: false,
    reactions: false,
    streaming: false,
  },

  // 配置 schema（用于 Dashboard 显示）
  configSchema: {
    schema: {
      type: "object",
      properties: {
        corpId: { type: "string", title: "企业ID (CorpID)" },
        corpSecret: { type: "string", title: "应用密钥 (Secret)" },
        agentId: { type: "string", title: "应用ID (AgentID)" },
        token: { type: "string", title: "回调Token" },
        encodingAesKey: { type: "string", title: "消息加密密钥" },
      },
      required: ["corpId", "corpSecret", "agentId", "token", "encodingAesKey"],
    },
  },

  config: {
    listAccountIds: (cfg: any): string[] => {
      return Object.keys(cfg.channels?.wecom?.accounts ?? {});
    },

    resolveAccount: (cfg: any, accountId?: string): WeComAccountConfig => {
      const accounts = cfg.channels?.wecom?.accounts ?? {};
      const id = accountId ?? "default";
      const account = accounts[id];
      if (account) {
        return { ...account, accountId: id };
      }
      const pluginCfg = cfg.plugins?.entries?.wecom?.config;
      if (pluginCfg) {
        return {
          accountId: id,
          enabled: true,
          corpId: pluginCfg.corpId,
          corpSecret: pluginCfg.corpSecret,
          agentId: pluginCfg.agentId,
          token: pluginCfg.token,
          encodingAesKey: pluginCfg.encodingAesKey,
        };
      }
      return { accountId: id, enabled: false } as WeComAccountConfig;
    },

    // 添加更多配置方法
    defaultAccountId: (_cfg: any): string => "default",

    setAccountEnabled: ({ cfg, accountId, enabled }: { cfg: any; accountId: string; enabled: boolean }): any => {
      return {
        ...cfg,
        plugins: {
          ...cfg.plugins,
          entries: {
            ...cfg.plugins?.entries,
            wecom: {
              ...cfg.plugins?.entries?.wecom,
              enabled,
            },
          },
        },
      };
    },

    isConfigured: (account: WeComAccountConfig): boolean => {
      return Boolean(
        account.corpId?.trim() &&
          account.corpSecret?.trim() &&
          account.agentId?.trim()
      );
    },

    describeAccount: (account: WeComAccountConfig): any => ({
      accountId: account.accountId,
      enabled: account.enabled,
      configured: Boolean(account.corpId?.trim()),
      corpId: account.corpId,
    }),
  },

  outbound: {
    deliveryMode: "direct" as const,

    sendText: async ({
      text,
      recipientId,
      accountConfig,
    }: {
      text: string;
      recipientId: string;
      accountConfig: any;
    }) => {
      const config = accountConfig as WeComAccountConfig;
      try {
        await sendWeComMessage(config, recipientId, text);
        return { ok: true };
      } catch (error) {
        return {
          ok: false,
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },

    sendMedia: async ({
      mediaUrl,
      caption,
      recipientId,
      accountConfig,
    }: {
      mediaUrl: string;
      mediaType: string;
      caption?: string;
      recipientId: string;
      accountConfig: any;
    }) => {
      const config = accountConfig as WeComAccountConfig;
      try {
        if (caption || mediaUrl) {
          await sendWeComMessage(config, recipientId, `${caption || ""}\n${mediaUrl}`);
        }
        return { ok: true };
      } catch (error) {
        return {
          ok: false,
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    },
  },

  gateway: {
    start: async () => {
      pluginLogger?.info("企业微信渠道已启动");
    },

    stop: async () => {
      tokenCache.clear();
    },
  },

  status: {
    getHealth: async () => ({ healthy: true }),
    getDiagnostics: async () => ({ cachedTokens: tokenCache.size }),
  },
};

// 插件对象
const plugin = {
  id: "wecom",
  name: "企业微信 Channel",
  description: "企业微信消息渠道插件",
  configSchema: emptyPluginConfigSchema(),

  register(api: ClawdbotPluginApi) {
    const logger = api.logger;

    // 设置运行时
    setWeComRuntime(api.runtime, api.config, logger);

    // 注册渠道插件
    api.registerChannel({ plugin: wecomChannel as any });

    // 注册 HTTP Handler
    api.registerHttpHandler(handleWeComWebhook);

    // 启动时创建菜单
    const defaultConfig = wecomChannel.config.resolveAccount(api.config, "default");
    if (defaultConfig.enabled && defaultConfig.corpId) {
      createMenu(defaultConfig, logger);
    }

    // 注册 CLI 命令
    api.registerCli(
      ({ program }) => {
        const cmd = program.command("wecom").description("企业微信渠道管理");

        cmd
          .command("menu")
          .description("重新创建应用菜单")
          .option("-a, --account <id>", "账户ID", "default")
          .action(async (options: { account: string }) => {
            const config = wecomChannel.config.resolveAccount(api.config, options.account);
            if (!config.enabled || !config.corpId) {
              console.log("账户未启用");
              return;
            }
            await createMenu(config, console);
            console.log("菜单创建完成");
          });

        cmd
          .command("status")
          .description("检查连接状态")
          .action(async () => {
            console.log("企业微信渠道状态: 已启动");
            console.log("缓存的 Token 数量:", tokenCache.size);
          });
      },
      { commands: ["wecom"] }
    );

    logger.info("企业微信渠道插件已注册");
  },
};

export default plugin;
