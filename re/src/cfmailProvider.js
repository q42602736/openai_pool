const axios = require('axios');
const config = require('./config');

class CFEmailProvider {
    constructor() {
        this.token = config.cfToken;
        this.domain = config.domain;
        this.mailUrl = config.mailUrl;
        this.APIUrl = config.APIUrl;
        this.emailAddress = null;
    }

    /**
     * 生成临时邮箱
     * @returns {Promise<string>} 邮箱地址 (xxx@`domain`.com)
     */
    async generateAlias(emailName) {
        try {
            const response = await axios.post(
                `${this.APIUrl}/admin/new_address`,
                {
                    cf_token: "",
                    name: emailName,
                    domain: `${this.domain}`
                },
                {
                    headers: {
                        'x-admin-auth': `${this.token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            // 响应格式: {"address":"a-b-c"}
            const address = response.data.address;
            const jwt = response.data.jwt;
            this.emailAddress = `${address}`;
            this.jwt = `${jwt}`;
            
            console.log(`[DDG] 生成邮箱别名: ${this.emailAddress}`);
            return this.emailAddress;
        } catch (error) {
            console.error('[DDG] 生成邮箱别名失败:', error.message);
            if (error.response) {
                console.error('[DDG] 响应状态:', error.response.status);
                console.error('[DDG] 响应数据:', error.response.data);
            }
            throw error;
        }
    }

    async fetchInbox(options = {}) {
    const {
        limit = 20,
        offset = 0
    } = options;

    try {
        const url = `${this.APIUrl}/api/mails?limit=${limit}&offset=${offset}`;
        console.log(`[CFMail] 获取收件箱: ${url}`)
        const resp = await axios.get(
            url,
            {
                headers: {
                    Authorization: `Bearer ${this.jwt}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        const results = resp.data.results || [];
        console.log(`[CFMail] 收件箱: 查询到 ${results.length} 条邮件`)

        return resp.data.results || [];
    } catch (error) {
        console.error('[CFMail] 获取收件箱失败:', error.message);
        return [];
    }
}

    extractCode(text) {
        const match = text && text.match(/\b(\d{6})\b/);
        return match ? match[1] : null;
    }

    parseCreatedAt(createdAt) {
        if (!createdAt) return NaN;

        // 把 "2026-04-02 07:19:08" 转为 UTC ISO 格式
        const normalized = createdAt.replace(' ', 'T') + 'Z';
        return new Date(normalized).getTime();
    }

    async pollForCode(options = {}) {
        const {
            fromAddress = 'noreply@tm.openai.com',
            sinceTimestamp = Date.now() - 60 * 1000,
            interval = 5000,
            timeout = 180000,
            signal
        } = options;

        const deadline = Date.now() + timeout;

        const parseMailField = (raw, fieldName) => {
            if (!raw) return '';

            const regex = new RegExp(`^${fieldName}:\\s*(.*(?:\\r?\\n[ \\t].*)*)`, 'mi');
            const match = raw.match(regex);
            if (!match) return '';

            return match[1]
                .replace(/\r?\n[ \t]+/g, ' ')
                .trim();
        };

        const rawIncludesFrom = (raw, from) => {
            if (!raw) return false;
            return new RegExp(`^From:\\s*.*${escapeRegExp(from)}`, 'mi').test(raw);
        };

        const escapeRegExp = (str) => {
            return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        };

        while (Date.now() < deadline) {
            if (signal?.aborted) {
                const err = new Error('验证码轮询已取消');
                err.name = 'AbortError';
                throw err;
            }

            const emails = await this.fetchInbox();
            console.log(`[CFMail] 收件箱总数: ${emails.length}`);

            const parsedEmails = emails.map(email => {
                const raw = email.raw || '';
                const parsedFrom = parseMailField(raw, 'From');
                const parsedSubject = parseMailField(raw, 'Subject');
                const createdAtMs = this.parseCreatedAt(email.created_at);

                return {
                    ...email,
                    raw,
                    parsedFrom,
                    parsedSubject,
                    createdAtMs
                };
            });

            for (const email of parsedEmails) {
                console.log('[CFMail] 邮件检查:', {
                    created_at: email.created_at,
                    createdAtMs: email.createdAtMs,
                    sinceTimestamp,
                    parsedFrom: email.parsedFrom,
                    parsedSubject: email.parsedSubject
                });
            }

            const matched = parsedEmails
                .filter(email =>
                    Number.isFinite(email.createdAtMs) &&
                    email.createdAtMs >= sinceTimestamp &&
                    (
                        !fromAddress ||
                        email.parsedFrom.includes(fromAddress) ||
                        rawIncludesFrom(email.raw, fromAddress)
                    )
                )
                .sort((a, b) => b.createdAtMs - a.createdAtMs);

            console.log(`[CFMail] 命中候选数: ${matched.length}`);

            if (matched.length > 0) {
                const latest = matched[0];

                let code = this.extractCode(latest.parsedSubject);

                if (!code) {
                    code = this.extractCode(latest.raw);
                }

                if (code) {
                    console.log(`[CFMail] 成功提取验证码: ${code}`);
                    return code;
                }

                console.log('[CFMail] 找到候选邮件，但未提取到验证码');
            }

            await new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    if (signal && onAbort) {
                        signal.removeEventListener('abort', onAbort);
                    }
                    resolve();
                }, interval);

                let onAbort = null;

                if (signal) {
                    onAbort = () => {
                        clearTimeout(timer);
                        signal.removeEventListener('abort', onAbort);

                        const err = new Error('验证码轮询已取消');
                        err.name = 'AbortError';
                        reject(err);
                    };

                    signal.addEventListener('abort', onAbort);
                }
            });
        }

        throw new Error('验证码获取超时');
    }



    /**
     * 获取当前邮箱地址
     * @returns {string|null}
     */
    getEmail() {
        return this.emailAddress;
    }
    /**
     * 获取当前邮箱登录 url
     * @returns {string|null}
     */
    getAuthUrl() {
        return `${this.mailUrl}/?jwt=${this.jwt}`
    }
}

module.exports = { CFEmailProvider };
