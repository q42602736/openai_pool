const axios = require('axios');
const { randomInt } = require('node:crypto');

class MailProvider {
    constructor(options) {
        this.baseUrl = options.baseUrl;
        this.adminPassword = options.adminPassword;
        this.sitePassword = options.sitePassword || '';
        this.domain = options.domain;
        this.jwt = null;
        this.address = null;
        this.addressId = null;
        this.addressSessionCache = new Map();
        this.sessionLookupTried = new Set();
    }

    /**
     * 构建请求 headers
     */
    _adminHeaders() {
        const headers = {
            'Content-Type': 'application/json',
            'x-admin-auth': this.adminPassword,
        };
        if (this.sitePassword) {
            headers['x-custom-auth'] = this.sitePassword;
        }
        return headers;
    }

    /**
     * 构建地址 JWT 请求 headers
     */
    _addressHeaders() {
        const headers = {
            'Authorization': `Bearer ${this.jwt}`,
        };
        if (this.sitePassword) {
            headers['x-custom-auth'] = this.sitePassword;
        }
        return headers;
    }

    _normalizeAddress(address) {
        return String(address || '').trim().toLowerCase();
    }

    _extractAddressParts(address) {
        const normalized = String(address || '').trim();
        const at = normalized.lastIndexOf('@');
        if (at <= 0 || at === normalized.length - 1) return null;
        return {
            name: normalized.slice(0, at),
            domain: normalized.slice(at + 1),
            full: normalized,
        };
    }

    _extractMailsFromPayload(payload) {
        if (!payload) return null;
        if (Array.isArray(payload)) return payload;
        if (Array.isArray(payload.results)) return payload.results;
        if (Array.isArray(payload.mails)) return payload.mails;
        if (payload.data) {
            if (Array.isArray(payload.data)) return payload.data;
            if (Array.isArray(payload.data.results)) return payload.data.results;
            if (Array.isArray(payload.data.mails)) return payload.data.mails;
        }
        return null;
    }

    _extractSessionFromPayload(payload, address) {
        if (!payload || typeof payload !== 'object') return null;
        const jwt = payload.jwt || payload.token || payload.access_token || payload?.data?.jwt || payload?.data?.token;
        if (!jwt) return null;

        const resolvedAddress = payload.address || payload.email || payload?.data?.address || payload?.data?.email || address;
        const addressId = payload.address_id || payload.addressId || payload?.data?.address_id || payload?.data?.addressId || null;
        return {
            address: resolvedAddress,
            jwt,
            addressId,
        };
    }

    _cacheCurrentSession() {
        const key = this._normalizeAddress(this.address);
        if (!key || !this.jwt) return;
        this.addressSessionCache.set(key, {
            address: this.address,
            jwt: this.jwt,
            addressId: this.addressId || null,
        });
    }

    _loadSessionFromCache(address) {
        const key = this._normalizeAddress(address);
        if (!key) return false;
        const cached = this.addressSessionCache.get(key);
        if (!cached) return false;
        this.useExistingAddressSession(cached);
        return true;
    }

    /**
     * 生成随机邮箱用户名
     */
    _randomName() {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        const length = 8 + randomInt(5); // 8-12 字符
        let name = '';
        for (let i = 0; i < length; i++) {
            name += chars[randomInt(chars.length)];
        }
        return name;
    }

    /**
     * 创建新邮箱地址
     * @param {string|null} name - 邮箱用户名，null 则随机生成
     * @returns {Promise<{jwt: string, address: string, addressId: number}>}
     */
    async createAddress(name = null) {
        const emailName = name || this._randomName();

        const response = await axios.post(
            `${this.baseUrl}/admin/new_address`,
            { name: emailName, domain: this.domain, enablePrefix: false },
            { headers: this._adminHeaders(), timeout: 15000 }
        );

        const data = response.data;
        this.jwt = data.jwt;
        this.address = data.address;
        this.addressId = data.address_id;
        this._cacheCurrentSession();

        console.log(`[Mail] 创建邮箱: ${this.address}`);
        return { jwt: this.jwt, address: this.address, addressId: this.addressId };
    }

    /**
     * 复用已存在的邮箱会话（用于后续直接收验证码）
     * @param {object} session
     * @param {string} session.address
     * @param {string} session.jwt
     * @param {number|string} [session.addressId]
     */
    useExistingAddressSession(session = {}) {
        const { address, jwt, addressId } = session;
        if (!address || !jwt) {
            throw new Error('邮箱会话信息不完整，无法复用');
        }
        this.address = address;
        this.jwt = jwt;
        this.addressId = addressId || null;
        this._cacheCurrentSession();
        console.log(`[Mail] 已复用邮箱会话: ${this.address}`);
    }

    /**
     * 获取邮箱收件箱 URL（供 Agent 浏览器访问）
     * @returns {string}
     */
    getInboxUrl() {
        return `${this.baseUrl}/?jwt=${this.jwt}`;
    }

    /**
     * 获取邮箱地址
     * @returns {string}
     */
    getEmail() {
        return this.address;
    }

    /**
     * 获取邮件列表
     * @param {number} limit
     * @param {number} offset
     * @returns {Promise<Array>}
     */
    async getMails(limit = 10, offset = 0) {
        const response = await axios.get(
            `${this.baseUrl}/api/mails`,
            {
                params: { limit, offset },
                headers: this._addressHeaders(),
                timeout: 15000,
            }
        );
        return response.data.results || [];
    }

    async _tryCreateAddressSession(address) {
        const normalized = this._normalizeAddress(address);
        if (!normalized) return false;
        if (this.sessionLookupTried.has(normalized)) return false;
        this.sessionLookupTried.add(normalized);

        const parts = this._extractAddressParts(address);
        if (!parts) return false;
        if (this.domain && parts.domain.toLowerCase() !== String(this.domain).toLowerCase()) return false;

        try {
            const created = await this.createAddress(parts.name);
            const createdAddress = this._normalizeAddress(created?.address);
            if (createdAddress === normalized) {
                return true;
            }
        } catch (error) {
            // Ignore and continue with admin endpoint fallback.
        }
        return false;
    }

    async _tryFetchSessionByAdmin(address) {
        const candidates = [
            { method: 'get', url: '/admin/address', params: { address } },
            { method: 'get', url: '/admin/address', params: { email: address } },
            { method: 'post', url: '/admin/address', data: { address } },
            { method: 'post', url: '/admin/get_address', data: { address } },
            { method: 'post', url: '/admin/get_address', data: { email: address } },
            { method: 'post', url: '/admin/get_address_session', data: { address } },
            { method: 'post', url: '/admin/address_session', data: { address } },
        ];

        for (const candidate of candidates) {
            try {
                const response = await axios({
                    method: candidate.method,
                    url: `${this.baseUrl}${candidate.url}`,
                    params: candidate.params,
                    data: candidate.data,
                    headers: this._adminHeaders(),
                    timeout: 15000,
                });
                const session = this._extractSessionFromPayload(response.data, address);
                if (session && this._normalizeAddress(session.address) === this._normalizeAddress(address)) {
                    this.useExistingAddressSession(session);
                    return true;
                }
            } catch (error) {
                // Try next candidate.
            }
        }
        return false;
    }

    async _fetchMailsByAdmin(address, limit, offset) {
        const candidates = [
            { method: 'get', url: '/admin/mails', params: { address, limit, offset } },
            { method: 'get', url: '/admin/mails', params: { email: address, limit, offset } },
            { method: 'post', url: '/admin/mails', data: { address, limit, offset } },
            { method: 'get', url: '/admin/get_mails', params: { address, limit, offset } },
            { method: 'get', url: '/api/mails', params: { address, limit, offset } },
            { method: 'get', url: '/api/mails', params: { email: address, limit, offset } },
        ];

        let lastError = null;
        for (const candidate of candidates) {
            try {
                const response = await axios({
                    method: candidate.method,
                    url: `${this.baseUrl}${candidate.url}`,
                    params: candidate.params,
                    data: candidate.data,
                    headers: this._adminHeaders(),
                    timeout: 15000,
                });
                const mails = this._extractMailsFromPayload(response.data);
                if (Array.isArray(mails)) {
                    return mails;
                }
                const session = this._extractSessionFromPayload(response.data, address);
                if (session) {
                    this.useExistingAddressSession(session);
                    return await this.getMails(limit, offset);
                }
            } catch (error) {
                lastError = error;
            }
        }

        if (lastError) throw lastError;
        return [];
    }

    async getMailsByAddress(address, limit = 10, offset = 0) {
        const normalized = this._normalizeAddress(address);
        if (!normalized) {
            throw new Error('email is empty');
        }

        if (this._normalizeAddress(this.address) === normalized && this.jwt) {
            return await this.getMails(limit, offset);
        }

        if (this._loadSessionFromCache(normalized)) {
            return await this.getMails(limit, offset);
        }

        const hasSession = await this._tryCreateAddressSession(normalized) || await this._tryFetchSessionByAdmin(normalized);
        if (hasSession && this._normalizeAddress(this.address) === normalized && this.jwt) {
            return await this.getMails(limit, offset);
        }

        return await this._fetchMailsByAdmin(normalized, limit, offset);
    }
}

module.exports = { MailProvider };
