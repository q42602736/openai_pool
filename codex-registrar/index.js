const path = require('path');
const fs = require('fs');
const { SMSProvider } = require('./src/smsProvider');
const { MailProvider } = require('./src/mailProvider');
const { BrowserService } = require('./src/browserService');
const { OAuthService } = require('./src/oauthService');
const { generateRandomName, generateRandomPassword } = require('./src/randomIdentity');
const config = require('./src/config');

// command line args
const args = process.argv.slice(2);
const PHASE2_ONLY = args.includes('--phase2');
const PHASE8_ONLY = args.includes('--phase8');
const TARGET_COUNT = parseInt(args.find(a => /^\d+$/.test(a)) || '1', 10);
const ACCOUNTS_FILE = path.join(process.cwd(), 'accounts.json');
const USERNAME_FILE = path.join(process.cwd(), 'username.json');
const SHIBAI_FILE = path.join(process.cwd(), 'shibai.json');
const TOKEN_OUTPUT_DIR = config.tokenOutputDir || path.join(process.cwd(), 'tokens');
const SMS_POLL_INTERVAL = 5000;
const SMS_MAX_ATTEMPTS = 60; // 60 * 5s = 5 min
const PHASE8_ACCOUNT_DELAY_MS = 60 * 1000;

function isProxyConnectionError(error) {
    const msg = String(error?.message || '');
    return msg.includes('ERR_PROXY_CONNECTION_FAILED') || msg.includes('ECONNREFUSED') || msg.includes('tunnel') || msg.includes('proxy');
}

function readCmdlineByPid(pid) {
    if (!pid || process.platform !== 'linux') return '';
    try {
        const raw = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');
        return raw.replace(/\u0000/g, ' ').trim();
    } catch (e) {
        return '';
    }
}

function getParentPid(pid) {
    if (!pid || process.platform !== 'linux') return 0;
    try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        const parts = stat.split(' ');
        return parseInt(parts[3], 10) || 0;
    } catch (e) {
        return 0;
    }
}

function assertNotRunningWithXvfb() {
    if (process.platform !== 'linux') return;

    const parentCmd = readCmdlineByPid(process.ppid);
    const grandParentPid = getParentPid(process.ppid);
    const grandParentCmd = readCmdlineByPid(grandParentPid);
    const xauthority = String(process.env.XAUTHORITY || '').toLowerCase();
    const display = String(process.env.DISPLAY || '').toLowerCase();

    const hit =
        /\bxvfb-run\b/.test(parentCmd) ||
        /\bxvfb-run\b/.test(grandParentCmd) ||
        xauthority.includes('xvfb-run') ||
        display.includes('xvfb');

    if (hit) {
        throw new Error('禁止使用 xvfb 运行项目。请在远程桌面图形会话中直接执行: node index.js');
    }
}

/**
 * 生成随机用户数据
 */
function generateUserData() {
    const fullName = generateRandomName();
    const password = generateRandomPassword();

    const age = 25 + Math.floor(Math.random() * 16);
    const birthYear = new Date().getFullYear() - age;
    const birthMonth = 1 + Math.floor(Math.random() * 12);
    const birthDay = 1 + Math.floor(Math.random() * 28);
    const birthDate = `${birthYear}-${String(birthMonth).padStart(2, '0')}-${String(birthDay).padStart(2, '0')}`;

    return { fullName, password, age, birthDate, birthMonth, birthDay, birthYear };
}

/**
 * 从邮箱中轮询获取验证码
 */
async function pollEmailCode(mailProvider, maxAttempts = 30, interval = 5000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        console.log(`[Mail] 轮询邮箱验证码... (${attempt}/${maxAttempts})`);

        try {
            const mails = await mailProvider.getMails(5, 0);
            if (mails.length > 0) {
                const latest = mails[0];
                const raw = latest.raw || '';

                // 从 MIME 原始邮件中提取正文（跳过邮件头）
                // 正文在 Content-Transfer-Encoding 之后的空行后面
                // 或者在 HTML 内容中查找验证码
                let body = raw;

                // 尝试提取 HTML/text 正文（在最后一个 boundary 后）
                const htmlMatch = raw.match(/Content-Type:\s*text\/html[\s\S]*?\r?\n\r?\n([\s\S]*?)(?:--[^\r\n]+--|$)/i);
                if (htmlMatch) {
                    body = htmlMatch[1];
                } else {
                    // 没有 HTML，取最后一段（通常是正文）
                    const parts = raw.split(/\r?\n\r?\n/);
                    if (parts.length > 1) {
                        body = parts.slice(Math.max(1, parts.length - 3)).join('\n');
                    }
                }

                // 方法1：找 "code" / "验证码" / "verification" 附近的6位数字
                const codePatterns = [
                    /(?:code|验证码|verification|verify)[^\d]{0,30}(\d{6})/i,
                    /(\d{6})[^\d]{0,30}(?:code|验证码|verification)/i,
                    />\s*(\d{6})\s*</,  // HTML 标签之间的6位数字
                ];
                for (const pattern of codePatterns) {
                    const match = body.match(pattern);
                    if (match) {
                        console.log(`[Mail] 收到验证码: ${match[1]} (pattern: ${pattern.source.substring(0, 30)})`);
                        return match[1];
                    }
                }

                // 方法2：兜底 - 在正文中找任何6位数字（排除明显的非验证码）
                const allSixDigits = body.match(/\b(\d{6})\b/g) || [];
                const filtered = allSixDigits.filter(d => !raw.includes(`t=${d}`) && !raw.includes(`x=${d}`));
                if (filtered.length > 0) {
                    console.log(`[Mail] 收到验证码 (兜底): ${filtered[0]}`);
                    return filtered[0];
                }

                console.log(`[Mail] 邮件已收到但未提取到验证码，正文前200字: ${body.substring(0, 200)}`);
            }
        } catch (error) {
            console.error(`[Mail] 查询出错: ${error.message}`);
        }

        await new Promise(r => setTimeout(r, interval));
    }

    throw new Error(`邮箱验证码超时（等待 ${(maxAttempts * interval) / 1000} 秒）`);
}

/**
 * 保存已注册账号到 accounts.json
 */
function extractVerificationCodeFromMailRaw(raw = '') {
    if (!raw || typeof raw !== 'string') return null;

    let body = raw;
    const htmlMatch = raw.match(/Content-Type:\s*text\/html[\s\S]*?\r?\n\r?\n([\s\S]*?)(?:--[^\r\n]+--|$)/i);
    if (htmlMatch) {
        body = htmlMatch[1];
    } else {
        const parts = raw.split(/\r?\n\r?\n/);
        if (parts.length > 1) {
            body = parts.slice(Math.max(1, parts.length - 3)).join('\n');
        }
    }

    const codePatterns = [
        /(?:code|éªŒè¯ç |verification|verify)[^\d]{0,30}(\d{6})/i,
        /(\d{6})[^\d]{0,30}(?:code|éªŒè¯ç |verification)/i,
        />\s*(\d{6})\s*</,
    ];
    for (const pattern of codePatterns) {
        const match = body.match(pattern);
        if (match) return match[1];
    }

    const allSixDigits = body.match(/\b(\d{6})\b/g) || [];
    const filtered = allSixDigits.filter(d => !raw.includes(`t=${d}`) && !raw.includes(`x=${d}`));
    return filtered.length > 0 ? filtered[0] : null;
}

async function pollEmailCodeByAddress(mailProvider, email, maxAttempts = 30, interval = 5000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        console.log(`[Mail][Phase8] polling ${email} code... (${attempt}/${maxAttempts})`);
        try {
            const mails = await mailProvider.getMailsByAddress(email, 5, 0);
            if (Array.isArray(mails) && mails.length > 0) {
                const code = extractVerificationCodeFromMailRaw(mails[0]?.raw || '');
                if (code) {
                    console.log(`[Mail][Phase8] latest code for ${email}: ${code}`);
                    return code;
                }
            }
        } catch (error) {
            console.error(`[Mail][Phase8] query error for ${email}: ${error.message}`);
        }
        await new Promise(r => setTimeout(r, interval));
    }
    throw new Error(`${email} email code timeout`);
}

function readJsonArray(filePath) {
    if (!fs.existsSync(filePath)) return [];
    try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (Array.isArray(parsed)) return parsed;
        if (parsed && typeof parsed === 'object') return [parsed];
        return [];
    } catch (e) {
        return [];
    }
}

function appendToJsonArrayFile(filePath, item) {
    const list = readJsonArray(filePath);
    list.push(item);
    fs.writeFileSync(filePath, JSON.stringify(list, null, 2));
    return list.length;
}

function appendFailedToShibai(entry) {
    const failedEntry = entry && typeof entry === 'object' ? { ...entry } : { raw: entry };
    const total = appendToJsonArrayFile(SHIBAI_FILE, failedEntry);
    console.log(`[Phase8] appended failed record to shibai.json, total=${total}`);
}

function calcAgeFromBirthDate(birthDate) {
    const year = parseInt(String(birthDate || '').slice(0, 4), 10);
    if (!Number.isFinite(year)) return 30;
    return Math.max(18, new Date().getFullYear() - year);
}

function getUsernameRecords() {
    return readJsonArray(USERNAME_FILE);
}

function saveAccount(phone, password, name, birthDate) {
    let accounts = [];
    if (fs.existsSync(ACCOUNTS_FILE)) {
        try { accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8')); } catch (e) {}
    }
    accounts.push({
        phone, password, name, birthDate,
        createdAt: new Date().toISOString(),
        status: 'registered',
    });
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2));
    console.log(`[账号] 已保存到 accounts.json (共 ${accounts.length} 个)`);
}

/**
 * 加载一个未完成 OAuth 的账号
 */
function loadAccount() {
    if (!fs.existsSync(ACCOUNTS_FILE)) return null;
    const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
    const available = accounts.find(a => a.status === 'registered' && a.password);
    return available || null;
}

function findAccountByPhone(phone) {
    if (!phone || !fs.existsSync(ACCOUNTS_FILE)) return null;
    try {
        const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
        return accounts.find(a => a.phone === phone) || null;
    } catch (e) {
        return null;
    }
}

/**
 * 更新账号状态
 */
function updateAccountStatus(phone, status) {
    if (!fs.existsSync(ACCOUNTS_FILE)) return;
    const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
    const account = accounts.find(a => a.phone === phone);
    if (account) {
        account.status = status;
        fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2));
    }
}

function saveUsernameFile({ email, phone, password, name, birthDate, status }) {
    const account = findAccountByPhone(phone);
    const outData = {
        email: email || '',
        phone: phone || '',
        password: password || '',
        name: name || '',
        birthDate: birthDate || '',
        createdAt: account?.createdAt || new Date().toISOString(),
        status: status || account?.status || 'registered',
    };

    let usernameList = [];
    if (fs.existsSync(USERNAME_FILE)) {
        try {
            const parsed = JSON.parse(fs.readFileSync(USERNAME_FILE, 'utf8'));
            if (Array.isArray(parsed)) {
                usernameList = parsed;
            } else if (parsed && typeof parsed === 'object') {
                usernameList = [parsed];
            }
        } catch (e) {
            usernameList = [];
        }
    }

    usernameList.push(outData);
    fs.writeFileSync(USERNAME_FILE, JSON.stringify(usernameList, null, 2));
    console.log(`[账号] 已追加保存账户信息: ${USERNAME_FILE} (共 ${usernameList.length} 条)`);
}

/**
 * 第一阶段：用手机号注册 ChatGPT
 */
async function phase1(smsProvider, browserService, userData) {
    console.log('\n=========================================');
    console.log('[阶段1] 开始 ChatGPT 手机号注册流程');
    console.log('=========================================');

    // 1. 先导航到注册页面（不花钱，失败了可以直接重试）
    await browserService.navigateToSignup();

    // 2. 浏览器就绪后，才获取手机号（花钱操作尽量靠后）
    await smsProvider.getNumber(config.heroSmsService, config.heroSmsCountry);
    await smsProvider.markReady();

    let numberUsed = false;

    try {
        // 3. 选择英国 +44 并输入手机号（去掉 +44 前缀）
        await browserService.selectCountry('44', '英国', 'GB');
        const localNumber = smsProvider.getPhone().replace(/^\+44/, '');
        await browserService.enterPhone(localNumber);
        numberUsed = true;

        // 4. 完成注册资料（密码、验证码、姓名、生日等）
        // 当页面需要 SMS 验证码时，通过回调获取
        await browserService.completeProfile(userData, async () => {
            console.log('[阶段1] 页面需要 SMS 验证码，开始轮询...');
            const code = await smsProvider.pollForCode({
                interval: SMS_POLL_INTERVAL,
                maxAttempts: SMS_MAX_ATTEMPTS,
            });
            return code;
        });

        // 6. 完成 SMS 激活
        await smsProvider.complete();

        // 7. 保存账号信息
        saveAccount(smsProvider.getPhone(), userData.password, userData.fullName, userData.birthDate);

        console.log('[阶段1] ChatGPT 注册流程完成！');
        return true;

    } catch (error) {
        if (!numberUsed) {
            console.error('[阶段1] 流程失败，取消号码退款...');
            await smsProvider.cancel();
        } else {
            await smsProvider.complete().catch(() => {});
        }
        throw error;
    }
}

/**
 * 第 1.5 阶段：首次登录 chatgpt.com 完成 about-you
 */
async function phase1_5(smsProvider, browserService, userData) {
    console.log('\n=========================================');
    console.log('[阶段1.5] 首次登录 chatgpt.com 完成个人资料');
    console.log('=========================================');

    await browserService.loginAndCompleteProfile({
        phone: smsProvider.getPhone(),
        password: userData.password,
        fullName: userData.fullName,
        birthDate: userData.birthDate,
    });

    console.log('[阶段1.5] 完成！');
}

/**
 * 第二阶段：Codex OAuth（手机号登录并绑定临时邮箱）
 */
async function phase2(smsProvider, mailProvider, browserService, oauthService, userData) {
    console.log('\n=========================================');
    console.log('[阶段2] 开始 Codex OAuth（绑定临时邮箱）');
    console.log('=========================================');

    // 1. 创建临时邮箱
    await mailProvider.createAddress();
    console.log(`[阶段2] 邮箱: ${mailProvider.getEmail()}`);

    // 2. 第一轮：手机号登录并绑定临时邮箱（不取 token）
    oauthService.regeneratePKCE();
    const bindEmailAuthUrl = oauthService.getAuthUrl();
    console.log(`[阶段2] 绑定邮箱 OAuth URL: ${bindEmailAuthUrl.substring(0, 100)}...`);

    // 3. 导航到 OAuth 页面并完成邮箱绑定
    await browserService.navigateToOAuth(bindEmailAuthUrl);
    await browserService.oauthLoginAndAuthorize({
        loginMethod: 'phone',
        stopAfterEmailBound: true,
        phone: smsProvider.getPhone(),
        email: mailProvider.getEmail(),
        password: userData.password,
        fullName: userData.fullName,
        age: userData.age,
        birthDate: userData.birthDate,
        redirectUri: oauthService.redirectUri,
        onSmsNeeded: async () => {
            console.log('[阶段2]（绑定邮箱）需要 SMS 验证码...');
            return await smsProvider.pollForCode({ interval: SMS_POLL_INTERVAL, maxAttempts: SMS_MAX_ATTEMPTS });
        },
        onEmailCodeNeeded: async () => {
            console.log('[阶段2]（绑定邮箱）需要邮箱验证码...');
            return await pollEmailCode(mailProvider);
        },
    });
    console.log('[阶段2] 临时邮箱绑定完成');

    return {
        email: mailProvider.getEmail(),
    };
}

/**
 * 第三阶段：重新进入 Codex OAuth（临时邮箱登录并获取 token）
 */
async function phase3(smsProvider, mailProvider, browserService, oauthService, userData) {
    console.log('\n=========================================');
    console.log('[阶段3] 开始 Codex OAuth（临时邮箱登录获取 Token）');
    console.log('=========================================');

    if (!mailProvider.getEmail()) {
        throw new Error('阶段3失败：未检测到已绑定的临时邮箱，请先执行阶段2');
    }

    console.log('[阶段3] 重新发起 Codex OAuth（邮箱登录）...');

    // 重新生成 PKCE，使用临时邮箱登录并获取授权码
    oauthService.regeneratePKCE();
    const authUrl = oauthService.getAuthUrl();
    console.log(`[阶段3] OAuth URL(邮箱登录): ${authUrl.substring(0, 100)}...`);
    await browserService.navigateToOAuth(authUrl);

    // 一站式登录 + 授权（邮箱登录）
    const callbackUrl = await browserService.oauthLoginAndAuthorize({
        loginMethod: 'email',
        phone: smsProvider.getPhone(),
        email: mailProvider.getEmail(),
        password: userData.password,
        fullName: userData.fullName,
        age: userData.age,
        birthDate: userData.birthDate,
        redirectUri: oauthService.redirectUri,
        onSmsNeeded: async () => {
            console.log('[阶段3] 需要 SMS 验证码...');
            return await smsProvider.pollForCode({ interval: SMS_POLL_INTERVAL, maxAttempts: SMS_MAX_ATTEMPTS });
        },
        onEmailCodeNeeded: async () => {
            console.log('[阶段3] 需要邮箱验证码...');
            return await pollEmailCode(mailProvider);
        },
    });

    console.log(`[阶段3] 回调 URL: ${callbackUrl}`);

    // 提取授权参数
    const params = oauthService.extractCallbackParams(callbackUrl);
    if (!params || params.error) {
        throw new Error(`OAuth 授权失败: ${params?.error_description || params?.error || '未知错误'}`);
    }
    if (!params.code) {
        throw new Error('回调 URL 中未找到授权码');
    }

    console.log(`[阶段3] 成功获取授权码: ${params.code.substring(0, 10)}...`);

    // 用授权码换取 Token
    const tokenData = await oauthService.exchangeTokenAndSave(params.code, mailProvider.getEmail());
    return tokenData;
}

/**
 * 单次注册流程
 */
async function runSingleRegistration() {
    console.log('\n=========================================');
    console.log('[主程序] 开始一次全新的注册与授权流程');
    console.log('=========================================');

    const smsProvider = new SMSProvider(config.heroSmsApiKey);
    const mailProvider = new MailProvider({
        baseUrl: config.mailBaseUrl,
        adminPassword: config.mailAdminPassword,
        sitePassword: config.mailSitePassword,
        domain: config.mailDomain,
    });
    const baseProxy = config.proxyHost ? {
        host: config.proxyHost,
        port: config.proxyPort,
        username: config.proxyUsername,
        password: config.proxyPassword,
    } : null;
    let browserService = null;
    let oauthService = null;

    const createServices = (useProxy) => {
        const proxy = useProxy ? baseProxy : null;
        const b = new BrowserService(proxy, {
            useChrome: config.useChrome,
            chromePath: config.chromePath,
        });
        const oauthProxy = proxy ? {
            host: proxy.host,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
        } : null;
        const o = new OAuthService({ proxy: oauthProxy });
        return { b, o };
    };

    const executeFlow = async () => {
        if (PHASE2_ONLY) {
            // --phase2 模式：使用已注册的账号跑 Phase 1.5 + Phase 2
            const account = loadAccount();
            if (!account) {
                throw new Error('accounts.json 中没有可用账号，请先跑完整流程注册');
            }
            console.log(`[主程序] Phase2 模式: 使用账号 ${account.phone} (${account.name})`);
            smsProvider.phoneNumber = account.phone;
            const userData = {
                fullName: account.name,
                password: account.password,
                birthDate: account.birthDate,
                age: new Date().getFullYear() - parseInt(account.birthDate),
            };

            // 先完成首次登录 about-you
            await phase1_5(smsProvider, browserService, userData);

            const phase2Data = await phase2(smsProvider, mailProvider, browserService, oauthService, userData);
            saveUsernameFile({
                email: phase2Data.email,
                phone: account.phone,
                password: account.password,
                name: account.name,
                birthDate: account.birthDate,
                status: 'email_bound',
            });

            const tokenData = await phase3(smsProvider, mailProvider, browserService, oauthService, userData);
            updateAccountStatus(account.phone, 'oauth_done');
            console.log('[主程序] Phase2 完成！');
            console.log(`[主程序] Token 已保存，邮箱: ${tokenData.email}`);
            return true;
        }

        // 正常模式：Phase 1 + Phase 1.5 + Phase 2
        const userData = generateUserData();
        console.log(`[主程序] 用户: ${userData.fullName}, 年龄: ${userData.age}, 生日: ${userData.birthDate}`);

        // 1. 第一阶段：手机号注册
        await phase1(smsProvider, browserService, userData);

        // 1.5. 首次登录完成个人资料
        await phase1_5(smsProvider, browserService, userData);

        // 2. 第二阶段：手机号登录并绑定临时邮箱
        const phase2Data = await phase2(smsProvider, mailProvider, browserService, oauthService, userData);
        saveUsernameFile({
            email: phase2Data.email,
            phone: smsProvider.getPhone(),
            password: userData.password,
            name: userData.fullName,
            birthDate: userData.birthDate,
            status: 'email_bound',
        });

        // 3. 第三阶段：临时邮箱登录并获取 token
        const tokenData = await phase3(smsProvider, mailProvider, browserService, oauthService, userData);

        updateAccountStatus(smsProvider.getPhone(), 'oauth_done');
        console.log('[主程序] 本次注册流程圆满结束！');
        console.log(`[主程序] Token 已保存，邮箱: ${tokenData.email}`);
        return true;
    };

    try {
        const hasProxy = !!baseProxy;

        // 优先走配置代理
        ({ b: browserService, o: oauthService } = createServices(hasProxy));
        await browserService.launch();
        try {
            return await executeFlow();
        } catch (error) {
            if (hasProxy && isProxyConnectionError(error)) {
                console.warn('[主程序] 检测到代理连接失败，自动切换为直连重试本轮任务...');
                await browserService.close().catch(() => {});
                ({ b: browserService, o: oauthService } = createServices(false));
                await browserService.launch();
                return await executeFlow();
            }
            throw error;
        }

    } catch (error) {
        console.error('[主程序] 本次任务执行失败:', error.message);
        throw error;
    } finally {
        await browserService.close();
    }
}

/**
 * 检查 token 数量
 */
async function runPhase8ForEntry(entry, index, total) {
    const email = String(entry?.email || '').trim();
    if (!email) {
        throw new Error('Phase8 entry is missing email');
    }

    const mailProvider = new MailProvider({
        baseUrl: config.mailBaseUrl,
        adminPassword: config.mailAdminPassword,
        sitePassword: config.mailSitePassword,
        domain: config.mailDomain,
    });

    const baseProxy = config.proxyHost ? {
        host: config.proxyHost,
        port: config.proxyPort,
        username: config.proxyUsername,
        password: config.proxyPassword,
    } : null;

    const createServices = (useProxy) => {
        const proxy = useProxy ? baseProxy : null;
        const b = new BrowserService(proxy, {
            useChrome: config.useChrome,
            chromePath: config.chromePath,
        });
        const oauthProxy = proxy ? {
            host: proxy.host,
            port: proxy.port,
            username: proxy.username,
            password: proxy.password,
        } : null;
        const o = new OAuthService({ proxy: oauthProxy });
        return { b, o };
    };

    let browserService = null;
    let oauthService = null;

    const userData = {
        fullName: String(entry?.name || email.split('@')[0] || 'user').trim(),
        password: String(entry?.password || '').trim(),
        birthDate: String(entry?.birthDate || '1996-01-01').trim(),
        age: calcAgeFromBirthDate(entry?.birthDate),
    };

    const executeFlow = async () => {
        oauthService.regeneratePKCE();
        const authUrl = oauthService.getAuthUrl();
        console.log(`[Phase8] (${index}/${total}) OAuth URL: ${authUrl.substring(0, 100)}...`);
        await browserService.navigateToOAuth(authUrl);

        const callbackUrl = await browserService.oauthLoginAndAuthorize({
            loginMethod: 'email',
            preferEmailOtp: true,
            phone: String(entry?.phone || ''),
            email,
            password: userData.password,
            fullName: userData.fullName,
            age: userData.age,
            birthDate: userData.birthDate,
            redirectUri: oauthService.redirectUri,
            onEmailCodeNeeded: async () => {
                console.log(`[Phase8] (${index}/${total}) waiting latest code from ${email}...`);
                return await pollEmailCodeByAddress(mailProvider, email);
            },
            onSmsNeeded: async () => {
                throw new Error('Phase8 hit SMS verification, treated as failed');
            },
        });

        console.log(`[Phase8] (${index}/${total}) callback: ${callbackUrl}`);
        const params = oauthService.extractCallbackParams(callbackUrl);
        if (!params || params.error) {
            throw new Error(`OAuth failed: ${params?.error_description || params?.error || 'unknown'}`);
        }
        if (!params.code) {
            throw new Error('OAuth callback missing code');
        }

        const tokenData = await oauthService.exchangeTokenAndSave(params.code, email);
        console.log(`[Phase8] (${index}/${total}) token saved for ${tokenData.email}`);
        return tokenData;
    };

    try {
        const hasProxy = !!baseProxy;
        ({ b: browserService, o: oauthService } = createServices(hasProxy));
        await browserService.launch();

        try {
            return await executeFlow();
        } catch (error) {
            if (hasProxy && isProxyConnectionError(error)) {
                console.warn('[Phase8] proxy failed, retry this account without proxy...');
                await browserService.close().catch(() => {});
                ({ b: browserService, o: oauthService } = createServices(false));
                await browserService.launch();
                return await executeFlow();
            }
            throw error;
        }
    } finally {
        if (browserService) {
            await browserService.close().catch(() => {});
        }
    }
}

async function startPhase8() {
    console.log('[Start] Phase8 mode: iterate username.json and fetch token by email OTP');

    assertNotRunningWithXvfb();

    if (!config.mailBaseUrl || !config.mailAdminPassword || !config.mailDomain) {
        throw new Error('Phase8 requires mailBaseUrl / mailAdminPassword / mailDomain in config.json');
    }

    const records = getUsernameRecords();
    if (records.length === 0) {
        console.log('[Phase8] username.json is empty');
        return;
    }

    let success = 0;
    let failed = 0;

    for (let i = 0; i < records.length; i++) {
        const entry = records[i];
        const idx = i + 1;
        console.log(`\\n[Phase8] ===== ${idx}/${records.length} =====`);
        console.log(`[Phase8] email: ${entry?.email || '(empty)'}`);

        try {
            await runPhase8ForEntry(entry, idx, records.length);
            success++;
        } catch (error) {
            failed++;
            console.error(`[Phase8] (${idx}/${records.length}) failed: ${error.message}`);
            appendFailedToShibai(entry);
        }

        if (i < records.length - 1) {
            console.log(`[Phase8] wait ${PHASE8_ACCOUNT_DELAY_MS / 1000}s before next account...`);
            await new Promise(r => setTimeout(r, PHASE8_ACCOUNT_DELAY_MS));
        }
    }

    console.log(`\\n[Phase8] done: success=${success}, failed=${failed}, total=${records.length}`);
}

async function checkTokenCount() {
    if (!fs.existsSync(TOKEN_OUTPUT_DIR)) return 0;
    return fs.readdirSync(TOKEN_OUTPUT_DIR).filter(f => f.startsWith('codex-') && f.endsWith('-free.json')).length;
}

/**
 * 归档已有 tokens
 */
function archiveExistingTokens() {
    if (!fs.existsSync(TOKEN_OUTPUT_DIR)) return;
    const files = fs.readdirSync(TOKEN_OUTPUT_DIR).filter(f => f.startsWith('codex-') && f.endsWith('-free.json'));
    for (const file of files) {
        fs.renameSync(path.join(TOKEN_OUTPUT_DIR, file), path.join(TOKEN_OUTPUT_DIR, `old_${file}`));
        console.log(`[归档] ${file} → old_${file}`);
    }
}

/**
 * 启动批量注册
 */
async function startBatch() {
    console.log(`[启动] Codex 远程注册机（手机号 + Puppeteer 模式），目标: ${TARGET_COUNT}`);

    assertNotRunningWithXvfb();

    if (!config.heroSmsApiKey) {
        console.error('[错误] 未配置 heroSmsApiKey');
        process.exit(1);
    }
    if (!config.mailAdminPassword) {
        console.error('[错误] 未配置 mailAdminPassword');
        process.exit(1);
    }

    archiveExistingTokens();

    while (true) {
        const currentCount = await checkTokenCount();
        if (currentCount >= TARGET_COUNT) {
            console.log(`\n[完成] Token 数量 (${currentCount}) 已达目标 (${TARGET_COUNT})。`);
            break;
        }

        console.log(`\n[进度] ${currentCount} / ${TARGET_COUNT}`);

        try {
            await runSingleRegistration();
        } catch (error) {
            console.error('[主程序] 注册失败，30 秒后重试...');
            await new Promise(r => setTimeout(r, 30000));
        }
    }
}

async function main() {
    if (PHASE8_ONLY) {
        await startPhase8();
        return;
    }
    await startBatch();
}

main().catch(console.error);
