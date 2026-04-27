const axios = require('axios');

class SMSProvider {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseUrl = 'https://hero-sms.com/stubs/handler_api.php';
        this.activationId = null;
        this.phoneNumber = null;
    }

    /**
     * 发送 API 请求
     */
    async request(action, params = {}) {
        const response = await axios.get(this.baseUrl, {
            params: { api_key: this.apiKey, action, ...params },
            timeout: 30000,
        });
        return response.data;
    }

    /**
     * 获取手机号码（V2 接口，返回 JSON）
     * @param {string} service - 服务代码（OpenAI = 'dr'）
     * @param {number} country - 国家 ID（英国 = 16）
     * @returns {Promise<{activationId: number, phoneNumber: string}>}
     */
    async getNumber(service = 'dr', country = 16, maxRetries = 5) {
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            let data;
            try {
                data = await this.request('getNumberV2', { service, country });
            } catch (httpErr) {
                console.log(`[SMS] API 请求失败: ${httpErr.message}，${attempt < maxRetries ? '5秒后重试...' : '已达最大重试次数'} (${attempt}/${maxRetries})`);
                if (attempt < maxRetries) {
                    await new Promise(r => setTimeout(r, 5000));
                    continue;
                }
                throw new Error(`HeroSMS API 不可用: ${httpErr.message}`);
            }

            if (typeof data === 'string') {
                if (data === 'NO_BALANCE') throw new Error('HeroSMS 余额不足');
                if (data === 'BAD_KEY') throw new Error('HeroSMS API Key 无效');
                if (data === 'NO_NUMBERS') {
                    console.log(`[SMS] 暂无可用号码，${attempt < maxRetries ? '3秒后重试...' : '已达最大重试次数'} (${attempt}/${maxRetries})`);
                    if (attempt < maxRetries) {
                        await new Promise(r => setTimeout(r, 3000));
                        continue;
                    }
                    throw new Error('当前无可用号码（重试耗尽）');
                }
                throw new Error(`获取号码失败: ${data}`);
            }

            this.activationId = data.activationId;
            this.phoneNumber = String(data.phoneNumber);

            if (!this.phoneNumber.startsWith('+')) {
                this.phoneNumber = `+${this.phoneNumber}`;
            }

            console.log(`[SMS] 获取号码: ${this.phoneNumber} (activation: ${this.activationId}, 费用: $${data.activationCost})`);
            return { activationId: this.activationId, phoneNumber: this.phoneNumber };
        }
    }

    /**
     * 标记准备接收短信
     */
    async markReady() {
        await this.request('setStatus', { id: this.activationId, status: 1 });
        console.log('[SMS] 已标记为准备接收短信');
    }

    /**
     * 查询激活状态（V2 接口）
     * @returns {Promise<{received: boolean, code?: string}>}
     */
    async getStatus() {
        const data = await this.request('getStatusV2', { id: this.activationId });

        if (typeof data === 'string') {
            if (data === 'STATUS_WAIT_CODE') return { received: false };
            if (data === 'STATUS_CANCEL') throw new Error('激活已被取消');
            if (data.startsWith('STATUS_OK:')) {
                return { received: true, code: data.split(':')[1] };
            }
            return { received: false };
        }

        // V2 JSON 响应
        const smsCode = data?.sms?.code;
        if (smsCode && smsCode.length > 0) {
            return { received: true, code: smsCode };
        }
        return { received: false };
    }

    /**
     * 轮询等待短信验证码
     * @param {object} options
     * @param {number} options.interval - 轮询间隔（毫秒，默认 5000）
     * @param {number} options.maxAttempts - 最大尝试次数（默认 60 = 5分钟）
     * @returns {Promise<string>} 验证码
     */
    async pollForCode(options = {}) {
        const { interval = 5000, maxAttempts = 60 } = options;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            console.log(`[SMS] 等待短信验证码... (${attempt}/${maxAttempts})`);

            try {
                const result = await this.getStatus();
                if (result.received) {
                    console.log(`[SMS] 收到验证码: ${result.code}`);
                    return result.code;
                }
            } catch (error) {
                console.error(`[SMS] 查询状态出错: ${error.message}`);
            }

            await new Promise(resolve => setTimeout(resolve, interval));
        }

        throw new Error(`短信验证码超时（等待 ${(maxAttempts * interval) / 1000} 秒）`);
    }

    /**
     * 完成激活（确认已收到验证码）
     */
    async complete() {
        await this.request('setStatus', { id: this.activationId, status: 6 });
        console.log('[SMS] 激活已完成');
    }

    /**
     * 取消激活（退款）
     */
    async cancel() {
        try {
            await this.request('setStatus', { id: this.activationId, status: 8 });
            console.log('[SMS] 激活已取消（退款）');
        } catch (error) {
            // 409 = EARLY_CANCEL_DENIED（刚创建的号码不能立即取消）
            // 其他错误也不应阻塞主流程
            console.error(`[SMS] 取消失败: ${error.message}（号码将在超时后自动退款）`);
        }
    }

    /**
     * 获取格式化的手机号
     * @returns {string}
     */
    getPhone() {
        return this.phoneNumber;
    }
}

module.exports = { SMSProvider };
