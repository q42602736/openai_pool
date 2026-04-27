const { connect } = require('puppeteer-real-browser');
const config = require('./config');

const SLEEP = (ms) => new Promise(r => setTimeout(r, ms));

class BrowserService {
    constructor(proxy, browserOptions = {}) {
        this.browser = null;
        this.page = null;
        this.proxy = proxy; // { host, port, username, password }
        this.browserOptions = {
            useEdge: browserOptions.useEdge ?? config.useEdge,
            edgePath: browserOptions.edgePath || config.edgePath,
        };
    }

    /**
     * 启动浏览器（puppeteer-real-browser，自动绕过 Turnstile）
     */
    async launch() {
        const connectOptions = {
            headless: false,
            turnstile: true,
            args: ['--no-sandbox', '--disable-gpu'],
        };

        // 使用 Edge 浏览器
        if (this.browserOptions.useEdge && this.browserOptions.edgePath) {
            // puppeteer-real-browser 底层使用 chrome-launcher，需通过 customConfig.chromePath 指定路径
            connectOptions.customConfig = {
                ...(connectOptions.customConfig || {}),
                chromePath: this.browserOptions.edgePath,
            };
            // 兜底：部分 chrome-launcher 版本会读取 CHROME_PATH
            process.env.CHROME_PATH = this.browserOptions.edgePath;
            console.log(`[Browser] 使用 Edge 浏览器: ${this.browserOptions.edgePath}`);
        }

        if (this.proxy) {
            connectOptions.proxy = {
                host: this.proxy.host,
                port: this.proxy.port,
                username: this.proxy.username,
                password: this.proxy.password,
            };
            console.log(`[Browser] 使用代理: ${this.proxy.host}:${this.proxy.port}`);
        }

        console.log('[Browser] 启动 puppeteer-real-browser...');
        const { page, browser } = await connect(connectOptions);
        this.browser = browser;

        // 尝试在已有窗口打开新标签页
        let targetPage = null;
        const pages = await browser.pages?.();
        if (pages && pages.length > 0) {
            targetPage = await browser.newPage();
            await targetPage.bringToFront();
        } else {
            targetPage = page;
        }
        this.page = targetPage;
        await targetPage.setViewport({ width: 1280, height: 900 });
        console.log('[Browser] 浏览器已启动 (1280x900)');
    }

    /**
     * 关闭浏览器
     */
    async close() {
        if (this.browser) {
            await this.browser.close().catch(() => {});
            this.browser = null;
            this.page = null;
        }
    }

    /**
     * 等待 Cloudflare 验证通过
     */
    async waitForCloudflare(timeout = 60000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            try {
                const title = await this.page.title();
                if (!title.includes('moment') && !title.includes('稍候') && !title.includes('Checking')) {
                    console.log('[Browser] Cloudflare 验证通过');
                    return;
                }
            } catch (e) {
                // 页面导航时 context 可能被销毁，等一下再试
            }
            await SLEEP(3000);
        }
        throw new Error('Cloudflare 验证超时');
    }

    /**
     * 通过文字匹配点击按钮（完整鼠标事件链，兼容 React）
     */
    async clickButtonByText(text, timeout = 10000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            const clicked = await this.page.evaluate((t) => {
                for (const b of document.querySelectorAll('button, [role="button"]')) {
                    if (b.innerText && b.innerText.includes(t)) {
                        // 完整的鼠标事件链以触发 React 事件处理
                        ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                            b.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                        });
                        return true;
                    }
                }
                return false;
            }, text);
            if (clicked) return;
            await SLEEP(1000);
        }
        throw new Error(`找不到包含"${text}"的按钮`);
    }

    /**
     * 等待选择器出现
     */
    async waitFor(selector, timeout = 30000) {
        await this.page.waitForSelector(selector, { timeout });
    }

    /**
     * 等待页面上出现指定文字
     */
    async waitForTextOnPage(text, timeout = 30000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            try {
                const found = await this.page.evaluate((t) => document.body?.innerText?.includes(t), text);
                if (found) return;
            } catch (e) { /* context destroyed during navigation */ }
            await SLEEP(1000);
        }
        throw new Error(`等待文字"${text}"超时`);
    }

    /**
     * 等待包含指定文字的按钮出现
     */
    async waitForButtonByText(text, timeout = 30000) {
        const start = Date.now();
        while (Date.now() - start < timeout) {
            try {
                const found = await this.page.evaluate((t) => {
                    for (const b of document.querySelectorAll('button, [role="button"], a')) {
                        if (b.innerText && b.innerText.includes(t)) return true;
                    }
                    return false;
                }, text);
                if (found) return;
            } catch (e) { /* context destroyed during navigation */ }
            await SLEEP(2000);
        }
        throw new Error(`等待按钮"${text}"超时`);
    }

    /**
     * 截图（调试用）
     */
    async screenshot(filename) {
        await this.page.screenshot({ path: `/tmp/${filename}` });
        console.log(`[Browser] 截图: /tmp/${filename}`);
    }

    /**
     * 填写 about-you 页面（全名 + 年龄/生日）并提交
     * 适配新版（name + age 数字输入）和旧版（name + spinbutton 日期选择器）
     * @param {string} fullName - 全名
     * @param {number|string} age - 年龄
     * @param {string} birthDate - 生日 YYYY-MM-DD（旧版 spinbutton 兜底用）
     * @param {string} tag - 日志标签
     */
    async fillAboutYouAndSubmit(fullName, age, birthDate, tag = '[AboutYou]') {
        await SLEEP(2000);

        // 填写全名
        const nameInput = await this.page.$('input[name="name"]');
        if (nameInput) {
            await nameInput.click({ clickCount: 3 });
            await this.page.keyboard.type(fullName, { delay: 30 });
            console.log(`${tag} 已填写全名: ${fullName}`);
        }

        // 优先：新版 age 数字输入框
        const ageInput = await this.page.$('input[name="age"]');
        if (ageInput) {
            // 先清空，再用 Puppeteer ElementHandle.type 输入（触发完整键盘事件链）
            await ageInput.click({ clickCount: 3 });
            await ageInput.press('Backspace');
            await ageInput.type(String(age), { delay: 50 });
            // 再用 nativeSetter 确保 React state 同步
            await this.page.evaluate((ageVal) => {
                const inp = document.querySelector('input[name="age"]');
                if (!inp) return;
                const nativeSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
                nativeSetter.call(inp, ageVal);
                inp.dispatchEvent(new Event('input', { bubbles: true }));
                inp.dispatchEvent(new Event('change', { bubbles: true }));
            }, String(age));
            console.log(`${tag} 已填写年龄: ${age}`);
        } else {
            // 兜底：旧版 spinbutton 日期选择器
            const parts = (birthDate || '1990-05-15').split('-');
            const spinbuttons = await this.page.$$('[role="spinbutton"]');
            const sbValues = [];
            for (const sb of spinbuttons) {
                const label = await sb.evaluate(el => el.getAttribute('aria-label') || '');
                if (label.includes('年') || label.includes('year')) sbValues.push({ sb, val: parts[0], label: '年' });
                else if (label.includes('月') || label.includes('month')) sbValues.push({ sb, val: parts[1], label: '月' });
                else if (label.includes('日') || label.includes('day')) sbValues.push({ sb, val: parts[2], label: '日' });
            }
            if (sbValues.length > 0) {
                for (const { sb, val, label } of sbValues) {
                    await sb.click();
                    await SLEEP(300);
                    await this.page.keyboard.type(val, { delay: 80 });
                    console.log(`${tag}   ${label}: 输入 ${val}`);
                    await SLEEP(300);
                }
            } else {
                console.log(`${tag} 未找到年龄或生日输入框`);
            }
        }

        // 失焦
        await this.page.click('body');
        await SLEEP(1000);

        // 原生鼠标点击提交按钮
        const btnPos = await this.page.evaluate(() => {
            for (const b of document.querySelectorAll('button[type="submit"], button')) {
                const text = b.innerText.trim();
                if (text === '继续' || text === 'Continue' || text.includes('完成')) {
                    const rect = b.getBoundingClientRect();
                    return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2, text };
                }
            }
            return null;
        });
        if (btnPos) {
            console.log(`${tag} 点击「${btnPos.text}」...`);
            await this.page.mouse.click(btnPos.x, btnPos.y);
        } else {
            await this.clickSubmitButton();
        }

        await SLEEP(5000);
        await this.waitForCloudflare(60000);
        await SLEEP(3000);
    }

    // ================================================================
    // Phase 1: ChatGPT 注册
    // ================================================================

    /**
     * 导航到注册页面：chatgpt.com → 过 CF → 等页面渲染 → 点免费注册 → 点手机登录
     */
    async navigateToSignup() {
        console.log('[Browser] 导航到 chatgpt.com...');
        await this.page.goto('https://chatgpt.com', {
            waitUntil: 'domcontentloaded',
            timeout: 60000,
        });

        await this.waitForCloudflare();

        // 等待页面完全渲染（等待"免费注册"按钮出现）
        console.log('[Browser] 等待页面渲染...');
        await this.waitForButtonByText('免费注册', 30000);
        // 额外等待确保 React 事件处理器已绑定
        await SLEEP(5000);

        console.log('[Browser] 点击「免费注册」...');
        await this.clickButtonByText('免费注册');

        // 等待弹窗出现（"登录或注册" 标题）
        console.log('[Browser] 等待注册弹窗...');
        await this.waitForTextOnPage('登录或注册', 15000);
        await SLEEP(1000);

        console.log('[Browser] 点击「继续使用手机登录」...');
        await this.clickButtonByText('手机登录', 10000);

        // 等待手机号输入框出现
        console.log('[Browser] 等待手机号输入框...');
        await this.waitFor('input[name="phoneNumberInput"]', 15000);
        console.log('[Browser] 手机号输入页面已就绪');
    }

    /**
     * 选择国家代码（英国 = 44）
     *
     * 支持两种选择器:
     * 1. chatgpt.com 注册弹窗: 标准 <select> 元素
     * 2. auth.openai.com 登录页: React Aria Select 组件（按钮 + 虚拟化 listbox）
     *    - 底层有隐藏 <select>（value 为国家ISO代码如 "GB"）
     *    - 打开后显示虚拟化列表（只渲染可见项），data-key="GB" 标识选项
     *
     * @param {string} dialCode - 国家拨号代码（如 '44'）
     * @param {string} countryHint - 国家名称提示（如 '英国'）
     * @param {string} countryIso - 国家 ISO 代码（如 'GB'），用于 React Aria Select
     */
    async selectCountry(dialCode, countryHint = '', countryIso = '') {
        console.log(`[Browser] 选择国家代码 +${dialCode}...`);

        // 检查是否已经显示了正确的国家（按钮式或 select 式）
        const alreadyCorrect = await this.page.evaluate((code) => {
            // 检查按钮
            for (const b of document.querySelectorAll('button')) {
                const text = b.innerText.trim();
                if (text.includes(`+${code}`) || text.includes(`(${code})`)) {
                    return text;
                }
            }
            // 检查 select
            const select = document.querySelector('select');
            if (select) {
                const selectedOpt = select.options[select.selectedIndex];
                if (selectedOpt && (selectedOpt.text.includes(`(${code})`) || selectedOpt.text.includes(`+${code}`))) {
                    return selectedOpt.text;
                }
            }
            return null;
        }, dialCode);

        if (alreadyCorrect) {
            console.log(`[Browser] 国家已是: ${alreadyCorrect}`);
            return;
        }

        // 检测页面类型：React Aria Select（按钮 + 隐藏 select）vs 标准 select
        const pageType = await this.page.evaluate(() => {
            const hasCountryButton = Array.from(document.querySelectorAll('button')).some(
                b => b.getAttribute('aria-haspopup') === 'listbox' && /\+\d/.test(b.innerText)
            );
            const hasSelect = !!document.querySelector('select');
            if (hasCountryButton) return 'react-aria';  // auth.openai.com 登录页
            if (hasSelect) return 'native-select';       // chatgpt.com 注册弹窗
            return 'unknown';
        });

        console.log(`[Browser] 国家选择器类型: ${pageType}`);

        // ===== React Aria Select（auth.openai.com 登录页）=====
        if (pageType === 'react-aria') {
            // 方法 A（最可靠）: 操作底层隐藏 <select>，利用 React 的 change 事件监听
            // React Aria 的 Select 组件在底层维护一个隐藏的 <select>，
            // 通过 nativeInputValueSetter 设置值并触发 change 事件可以正确更新组件状态
            const isoCode = countryIso || await this.page.evaluate((code, hint) => {
                const select = document.querySelector('select');
                if (!select) return '';
                for (const opt of Array.from(select.options)) {
                    if (hint && opt.text.includes(hint)) return opt.value;
                    if (opt.text.includes(`(${code})`) || opt.text.includes(`+${code}`)) return opt.value;
                }
                return '';
            }, dialCode, countryHint);

            if (isoCode) {
                const result = await this.page.evaluate((iso) => {
                    const select = document.querySelector('select');
                    if (!select) return null;
                    // 用原生 setter 设置值，确保 React 能检测到变化
                    const nativeSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
                    nativeSetter.call(select, iso);
                    select.dispatchEvent(new Event('change', { bubbles: true }));
                    // 验证按钮是否更新
                    for (const b of document.querySelectorAll('button')) {
                        if (b.getAttribute('aria-haspopup') === 'listbox') return b.innerText.trim();
                    }
                    return 'changed';
                }, isoCode);

                if (result && result.includes(`+${dialCode}`)) {
                    console.log(`[Browser] 已选择 (React Aria hidden select): ${result}`);
                    await SLEEP(500);
                    return;
                }
            }

            // 方法 B（备用）: 打开下拉，滚动虚拟化列表到目标位置，真实鼠标点击
            // 虚拟化列表每项 40px，需先确定目标 index 再滚动
            console.log(`[Browser] 方法 A 未成功，尝试方法 B: 打开下拉 + 滚动点击...`);

            // 找到并点击国家按钮
            const btnBox = await this.page.evaluate(() => {
                for (const b of document.querySelectorAll('button')) {
                    if (b.getAttribute('aria-haspopup') === 'listbox' && /\+\d/.test(b.innerText)) {
                        const rect = b.getBoundingClientRect();
                        return { x: rect.x, y: rect.y, w: rect.width, h: rect.height };
                    }
                }
                return null;
            });

            if (btnBox) {
                await this.page.mouse.click(btnBox.x + btnBox.w / 2, btnBox.y + btnBox.h / 2);
                await SLEEP(2000);

                // 确定目标选项的 index（从隐藏 select 中获取）
                const targetIndex = await this.page.evaluate((code, hint) => {
                    const select = document.querySelector('select');
                    if (!select) return -1;
                    const options = Array.from(select.options);
                    for (let i = 0; i < options.length; i++) {
                        if (hint && options[i].text.includes(hint)) return i;
                        if (options[i].text.includes(`(${code})`) || options[i].text.includes(`+${code}`)) return i;
                    }
                    return -1;
                }, dialCode, countryHint);

                if (targetIndex >= 0) {
                    // 滚动虚拟化列表到目标位置（每项 40px）
                    await this.page.evaluate((idx) => {
                        const listbox = document.querySelector('[role="listbox"]');
                        if (!listbox) return;
                        let scroller = listbox;
                        while (scroller && scroller !== document.body) {
                            const style = getComputedStyle(scroller);
                            if (style.overflow === 'auto' || style.overflow === 'scroll' ||
                                style.overflowY === 'auto' || style.overflowY === 'scroll') break;
                            scroller = scroller.parentElement;
                        }
                        if (scroller) scroller.scrollTop = idx * 40;
                    }, targetIndex);
                    await SLEEP(1000);

                    // 查找目标国家的 ISO 代码对应的 option 元素
                    const targetIso = isoCode || await this.page.evaluate((code, hint) => {
                        const select = document.querySelector('select');
                        if (!select) return '';
                        for (const opt of Array.from(select.options)) {
                            if (hint && opt.text.includes(hint)) return opt.value;
                        }
                        return '';
                    }, dialCode, countryHint);

                    // 用真实鼠标点击目标 option
                    const optBox = await this.page.evaluate((iso) => {
                        const option = document.querySelector(`[data-key="${iso}"]`);
                        if (option && option.offsetParent !== null) {
                            const rect = option.getBoundingClientRect();
                            return { x: rect.x, y: rect.y, w: rect.width, h: rect.height };
                        }
                        return null;
                    }, targetIso);

                    if (optBox) {
                        await this.page.mouse.click(optBox.x + optBox.w / 2, optBox.y + optBox.h / 2);
                        await SLEEP(1000);
                        console.log(`[Browser] 已选择 (React Aria 滚动点击) +${dialCode}`);
                        return;
                    }
                }

                // 如果滚动点击也失败，关闭下拉
                await this.page.keyboard.press('Escape');
                await SLEEP(500);
            }

            console.log(`[Browser] React Aria 选择器: 所有方法均失败`);
            return;
        }

        // ===== 标准 <select> 元素（chatgpt.com 注册弹窗）=====
        if (pageType === 'native-select') {
            const selectResult = await this.page.evaluate((code, hint) => {
                const select = document.querySelector('select');
                if (!select) return null;
                const options = Array.from(select.options);
                // 优先按国家名称 + 代码匹配
                if (hint) {
                    for (const opt of options) {
                        if (opt.text.includes(hint) && opt.text.includes(`(${code})`)) {
                            select.value = opt.value;
                            select.dispatchEvent(new Event('change', { bubbles: true }));
                            return opt.text;
                        }
                    }
                }
                // 按代码匹配
                for (const opt of options) {
                    if (opt.text.includes(`+(${code})`) || opt.text.includes(`+${code}`)) {
                        select.value = opt.value;
                        select.dispatchEvent(new Event('change', { bubbles: true }));
                        return opt.text;
                    }
                }
                return null;
            }, dialCode, countryHint);

            if (selectResult) {
                console.log(`[Browser] 已选择 (标准 select): ${selectResult}`);
                await SLEEP(1000);
                return;
            }
        }

        console.log(`[Browser] 未找到国家选择器，跳过`);
    }

    /**
     * 输入手机号并点击继续
     * @param {string} localNumber - 不含国家代码的本地号码
     */
    async enterPhone(localNumber) {
        console.log(`[Browser] 输入手机号: ${localNumber}`);
        const input = await this.page.$('input[name="phoneNumberInput"]');
        await input.click({ clickCount: 3 }); // 全选已有内容
        await input.type(localNumber, { delay: 50 });
        await SLEEP(500);

        // 点击手机号表单的提交按钮（精确匹配，避免误点「继续使用 Google 登录」）
        console.log('[Browser] 点击提交按钮...');
        await this.page.evaluate(() => {
            // 优先找 type=submit 且文字恰好是"继续"的按钮
            for (const b of document.querySelectorAll('button[type="submit"]')) {
                const text = b.innerText.trim();
                if (text === '继续' || text === 'Continue') {
                    ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                        b.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                    });
                    return;
                }
            }
        });
        await SLEEP(3000);

        // 提交手机号后可能跳转到 auth.openai.com 并触发新一轮 Cloudflare
        console.log('[Browser] 检查是否需要再次通过 Cloudflare...');
        await this.waitForCloudflare(60000);
        await SLEEP(5000);

        await this.screenshot('after-phone-submit.png');
        console.log('[Browser] 已提交手机号（截图: /tmp/after-phone-submit.png）');
    }

    /**
     * 检测提交手机号后的页面状态
     * @returns {'sms'|'password'|'unknown'} - sms=需要验证码, password=直接创建密码
     */
    async detectPageAfterPhone() {
        console.log('[Browser] 检测页面状态...');
        for (let i = 0; i < 10; i++) {
            try {
                const state = await this.page.evaluate(() => {
                    const text = document.body?.innerText || '';
                    if (text.includes('创建密码') || text.includes('Create password') || text.includes('密码'))
                        return 'password';
                    if (text.includes('验证码') || text.includes('code') || text.includes('verification'))
                        return 'sms';
                    return 'loading';
                });
                if (state !== 'loading') {
                    console.log(`[Browser] 页面状态: ${state}`);
                    return state;
                }
            } catch (e) { /* context destroyed */ }
            await SLEEP(2000);
        }
        console.log('[Browser] 页面状态不确定，默认为 password');
        return 'password';
    }

    /**
     * 输入短信验证码
     * @param {string} code - 6位验证码
     */
    async enterSmsCode(code) {
        console.log(`[Browser] 输入验证码: ${code}`);
        await SLEEP(2000);

        // 用 Puppeteer 原生方法找到输入框并点击聚焦
        const inputs = await this.page.$$('input:not([type="hidden"]):not([type="password"])');
        let targetInput = null;
        for (const inp of inputs) {
            const info = await inp.evaluate(el => ({
                name: el.name, visible: el.offsetParent !== null, type: el.type,
            }));
            if (info.visible && info.name !== 'phoneNumberInput') {
                targetInput = inp;
                break;
            }
        }

        if (targetInput) {
            // 用 Puppeteer 原生 click 聚焦，再用 type 输入（确保键盘事件发到正确元素）
            await targetInput.click({ clickCount: 3 });
            await SLEEP(300);
            await targetInput.type(code, { delay: 80 });
            console.log('[Browser] 验证码已输入');
        } else {
            // 兜底：直接键盘输入
            console.log('[Browser] 未找到输入框，尝试 Tab + 键盘输入...');
            await this.page.keyboard.press('Tab');
            await SLEEP(300);
            await this.page.keyboard.type(code, { delay: 80 });
        }

        await SLEEP(1000);

        // 点击提交
        await this.clickSubmitButton();
        await SLEEP(3000);
    }

    /**
     * 完成注册资料填写（密码、姓名、生日、验证码等）
     * @param {object} userData - 用户数据
     * @param {function} onSmsNeeded - 当需要 SMS 验证码时的回调，应返回验证码字符串
     */
    async completeProfile(userData, onSmsNeeded) {
        console.log('[Browser] 开始填写注册资料...');
        let lastHandledUrl = '';

        for (let round = 0; round < 20; round++) {
            await SLEEP(3000);

            let pageState;
            try {
                pageState = await this.page.evaluate(() => {
                    const inputs = Array.from(document.querySelectorAll('input:not([type="hidden"])'));
                    return {
                        inputs: inputs.map(i => ({ type: i.type, name: i.name, placeholder: i.placeholder, id: i.id })),
                        text: (document.body.innerText || '').substring(0, 800),
                        url: location.href,
                    };
                });
            } catch (e) {
                console.log(`[Browser] Round ${round}: 页面上下文变化，等待...`);
                lastHandledUrl = '';
                continue;
            }

            const url = pageState.url;

            // 如果页面没变化，跳过（防止重复操作）
            if (url === lastHandledUrl) {
                console.log(`[Browser] Round ${round}: 页面未变化，等待...`);
                continue;
            }

            console.log(`[Browser] Round ${round}: ${url.substring(0, 70)}, inputs=${pageState.inputs.length}`);

            // 完成：到达 ChatGPT 主页 或 about-you 后续页面
            if (url.includes('chatgpt.com') && !url.includes('auth.openai.com')) {
                console.log('[Browser] 注册完成，已到达 ChatGPT！');
                return true;
            }

            // about-you 页面：全名 + 年龄/生日
            
            if (url.includes('about-you') || url.includes('about_you')) {
                console.log('[Browser] 到达 about-you 页面...');
                await this.fillAboutYouAndSubmit(userData.fullName, userData.age, userData.birthDate, '[Phase1]');
                await this.screenshot('about-you-filled.png');
                lastHandledUrl = url;
                continue;
            }

            // 密码页
            if (url.includes('password') || pageState.inputs.some(i => i.type === 'password')) {
                console.log('[Browser] 填写密码...');
                await this.page.type('input[type="password"]', userData.password, { delay: 30 });
                await SLEEP(500);
                await this.clickSubmitButton();
                lastHandledUrl = url;
                continue;
            }

            // SMS 验证码页
            if (url.includes('contact-verification') || url.includes('verify')) {
                console.log('[Browser] 检测到验证码页面');
                if (onSmsNeeded) {
                    const code = await onSmsNeeded();
                    if (code) {
                        await this.enterSmsCode(code);
                        lastHandledUrl = url;
                        continue;
                    }
                }
            }

            // 姓名输入
            const nameInput = pageState.inputs.find(i =>
                i.name.toLowerCase().includes('name') ||
                i.placeholder.includes('姓名') || i.placeholder.includes('全名') ||
                i.placeholder.includes('name') || i.id.includes('name')
            );
            if (nameInput) {
                console.log('[Browser] 填写姓名...');
                const sel = nameInput.id ? `#${nameInput.id}` : `input[name="${nameInput.name}"]`;
                await this.page.type(sel, userData.fullName, { delay: 30 });
                await SLEEP(500);
                await this.clickSubmitButton();
                continue;
            }

            // 生日输入
            const dateInput = pageState.inputs.find(i =>
                i.type === 'date' || i.name.includes('birth') || i.name.includes('date') ||
                i.placeholder.includes('生日') || i.placeholder.includes('出生')
            );
            if (dateInput) {
                console.log('[Browser] 填写出生日期...');
                const sel = dateInput.id ? `#${dateInput.id}` : `input[name="${dateInput.name}"]`;
                await this.page.type(sel, userData.birthDate, { delay: 30 });
                await SLEEP(500);
                await this.clickSubmitButton();
                continue;
            }

            // 同意/接受/开始按钮
            for (const btnText of ['同意', '接受', 'Agree', 'Accept', "I'm okay", '好的', '确定', '开始', '继续']) {
                try {
                    await this.clickButtonByText(btnText, 1500);
                    console.log(`[Browser] 点击了「${btnText}」`);
                    break;
                } catch (e) {}
            }
        }

        return false;
    }

    /**
     * 点击页面上的提交按钮（type=submit 的"继续"按钮）
     */
    async clickSubmitButton() {
        await this.page.evaluate(() => {
            for (const b of document.querySelectorAll('button[type="submit"], button')) {
                const text = b.innerText.trim();
                if (text === '继续' || text === 'Continue' || text === '下一步' || text === 'Next') {
                    ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                        b.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                    });
                    return;
                }
            }
        });
        await SLEEP(3000);
    }

    // ================================================================
    // Phase 1.5: 首次登录 chatgpt.com 完成 about-you
    // ================================================================

    /**
     * 登录 chatgpt.com 并完成 about-you 个人资料
     * Phase 1 注册后，首次登录需要填写全名+生日才能使用
     * @param {object} opts
     * @param {string} opts.phone - 手机号 (+44...)
     * @param {string} opts.password - 密码
     * @param {string} opts.fullName - 全名
     * @param {string} opts.birthDate - 生日 (YYYY-MM-DD)
     */
    async loginAndCompleteProfile(opts) {
        const { phone, password, fullName, birthDate } = opts;

        // 1. 导航到 chatgpt.com
        console.log('[Phase1.5] 导航到 chatgpt.com...');
        await this.page.goto('https://chatgpt.com', {
            waitUntil: 'domcontentloaded',
            timeout: 60000,
        });
        await this.waitForCloudflare();

        // 2. 等待页面渲染，检查是否已登录
        console.log('[Phase1.5] 等待页面渲染...');
        await SLEEP(5000);

        // 检查是否已登录（没有「登录」按钮说明已登录）
        const hasLoginBtn = await this.page.evaluate(() => {
            for (const b of document.querySelectorAll('button, a')) {
                const text = b.innerText.trim();
                if (text === '登录' || text === 'Log in') return true;
            }
            return false;
        });

        if (!hasLoginBtn) {
            console.log('[Phase1.5] 已处于登录状态，跳过');
            return true;
        }

        console.log('[Phase1.5] 点击「登录」...');
        await this.clickButtonByText('登录');

        // 3. 等待登录弹窗 → 选手机登录
        await this.waitForTextOnPage('登录或注册', 15000);
        await SLEEP(1000);
        console.log('[Phase1.5] 点击「继续使用手机登录」...');
        await this.clickButtonByText('手机登录', 10000);

        // 4. 输入手机号
        await this.waitFor('input[name="phoneNumberInput"]', 15000);
        await this.selectCountry('44', '英国', 'GB');
        const localNumber = phone.replace(/^\+44/, '');
        await this.enterPhone(localNumber);

        // 5. 循环处理后续页面（密码、about-you、验证等）
        console.log('[Phase1.5] 开始处理登录后续步骤...');
        let lastHandledUrl = '';

        for (let round = 0; round < 20; round++) {
            await SLEEP(3000);

            let pageState;
            try {
                pageState = await this.page.evaluate(() => ({
                    inputs: Array.from(document.querySelectorAll('input:not([type="hidden"])')).map(i => ({
                        type: i.type, name: i.name, placeholder: i.placeholder,
                    })),
                    text: (document.body.innerText || '').substring(0, 800),
                    url: location.href,
                    btns: Array.from(document.querySelectorAll('button')).map(b => b.innerText.trim()).filter(t => t),
                }));
            } catch (e) {
                console.log(`[Phase1.5] Round ${round}: 页面上下文变化，等待...`);
                lastHandledUrl = '';
                continue;
            }

            const url = pageState.url;
            console.log(`[Phase1.5] Round ${round}: ${url.substring(0, 70)}`);

            // 完成：到达 ChatGPT 主页
            if (url.includes('chatgpt.com') && !url.includes('auth.openai.com')) {
                // 排除错误页面和弹窗中的情况
                if (url.includes('auth/error')) {
                    console.log(`[Phase1.5] 检测到错误页面: ${url}`);
                    // 尝试点重试或回到首页
                    try { await this.clickButtonByText('重试', 3000); } catch (e) {}
                    await SLEEP(3000);
                    lastHandledUrl = url;
                    continue;
                }
                const isMainPage = !pageState.text.includes('登录或注册')
                    && !pageState.text.includes('确认一下你的年龄')
                    && !pageState.text.includes('about-you');
                if (isMainPage) {
                    console.log('[Phase1.5] 已到达 ChatGPT 主页，登录完成！');
                    return true;
                }
            }

            if (url === lastHandledUrl) continue;

            // 密码页
            if (url.includes('password') || pageState.inputs.some(i => i.type === 'password')) {
                console.log('[Phase1.5] 填写密码...');
                await this.page.type('input[type="password"]', password, { delay: 30 });
                await SLEEP(500);
                await this.clickSubmitButton();
                await SLEEP(3000);
                await this.waitForCloudflare(60000);
                await SLEEP(3000);
                lastHandledUrl = url;
                continue;
            }

            // about-you 页面：全名 + 生日
            if (url.includes('about-you') || url.includes('about_you')
                || pageState.text.includes('确认一下你的年龄') || pageState.text.includes('你的年龄是多少')) {
                console.log('[Phase1.5] 检测到 about-you 页面...');
                const age = new Date().getFullYear() - parseInt(birthDate);
                await this.fillAboutYouAndSubmit(fullName, age, birthDate, '[Phase1.5]');
                await this.screenshot('phase1.5-about-you.png');
                lastHandledUrl = url;
                continue;
            }

            // 同意/接受/开始按钮
            for (const btnText of ['同意', '接受', 'Agree', 'Accept', "I'm okay", '好的', '确定', '开始', '继续']) {
                try {
                    await this.clickButtonByText(btnText, 1500);
                    console.log(`[Phase1.5] 点击了「${btnText}」`);
                    break;
                } catch (e) {}
            }
        }

        console.log('[Phase1.5] 登录流程完成（可能未到达主页）');
        return false;
    }

    // ================================================================
    // Phase 2: OAuth 授权
    // ================================================================

    /**
     * 导航到 OAuth 授权页面
     */
    async navigateToOAuth(authUrl) {
        console.log('[Browser] 导航到 OAuth URL...');
        await this.page.goto(authUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 60000,
        });

        await this.waitForCloudflare();
        await SLEEP(5000);
        console.log('[Browser] OAuth 页面已加载');
    }

    /**
     * OAuth 登录 + 授权完整流程（循环检测页面状态）
     * @param {object} opts
     * @param {'phone'|'email'} [opts.loginMethod] - 登录方式（默认 phone）
     * @param {boolean} [opts.stopAfterEmailBound] - 仅执行到邮箱绑定完成即返回
     * @param {string} opts.phone - 手机号（+44...）
     * @param {string} opts.email - 邮箱
     * @param {string} opts.password - 密码
     * @param {string} opts.redirectUri - OAuth 回调 URI
     * @param {function} opts.onSmsNeeded - SMS 验证码回调
     * @param {function} opts.onEmailCodeNeeded - 邮箱验证码回调
     * @returns {string} 回调 URL；当 stopAfterEmailBound=true 时，返回 'EMAIL_BOUND'
     */
    async oauthLoginAndAuthorize(opts) {
        console.log('[Browser] 开始 OAuth 登录+授权...');
        const {
            phone,
            email,
            password,
            redirectUri,
            onSmsNeeded,
            onEmailCodeNeeded,
            loginMethod = 'phone',
            preferEmailOtp = false,
            useOneTimeCodeLogin = false,
            stopAfterEmailBound = false,
        } = opts;
        const shouldPreferEmailOtp = !!(preferEmailOtp || useOneTimeCodeLogin);
        const redirectBase = new URL(redirectUri);
        let lastHandledUrl = '';
        let emailBound = false;

        // 监听 request 事件，捕获 localhost 回调 URL
        let capturedCallbackUrl = null;
        this.page.on('request', (req) => {
            const reqUrl = req.url();
            try {
                const u = new URL(reqUrl);
                if (u.hostname === redirectBase.hostname && u.port === redirectBase.port
                    && u.pathname === redirectBase.pathname
                    && (u.searchParams.has('code') || u.searchParams.has('error'))) {
                    capturedCallbackUrl = reqUrl;
                    console.log(`[OAuth] 捕获到回调 URL: ${reqUrl.substring(0, 80)}...`);
                }
            } catch (e) {}
        });

        // 先等页面渲染
        await SLEEP(5000);

        for (let round = 0; round < 30; round++) {
            await SLEEP(3000);

            let url, pageInfo;
            try {
                url = this.page.url();
                pageInfo = await this.page.evaluate(() => ({
                    text: (document.body?.innerText || '').substring(0, 500),
                    btns: Array.from(document.querySelectorAll('button')).map(b => b.innerText.trim()).filter(t => t),
                    inputs: Array.from(document.querySelectorAll('input:not([type="hidden"])')).map(i => ({
                        type: i.type, name: i.name, placeholder: i.placeholder,
                    })),
                    url: location.href,
                }));
                url = pageInfo.url;
            } catch (e) {
                console.log(`[OAuth] Round ${round}: 页面上下文变化...`);
                lastHandledUrl = '';
                continue;
            }

            // 检查通过 request 事件捕获的回调 URL
            if (capturedCallbackUrl) {
                console.log('[OAuth] 检测到 localhost 回调！');
                return capturedCallbackUrl;
            }

            // 也检查当前 URL（备用）
            try {
                const current = new URL(url);
                if (current.hostname === redirectBase.hostname
                    && current.port === redirectBase.port
                    && current.pathname === redirectBase.pathname
                    && (current.searchParams.has('code') || current.searchParams.has('error'))) {
                    console.log('[OAuth] 检测到 localhost 回调（URL 匹配）！');
                    return url;
                }
            } catch (e) {}

            // chrome-error 页面说明跳转到了 localhost 但连接失败，回调已在 request 事件中捕获
            if (url.includes('chrome-error')) {
                if (capturedCallbackUrl) return capturedCallbackUrl;
                // 等一下可能 request 事件还没触发
                await SLEEP(2000);
                if (capturedCallbackUrl) return capturedCallbackUrl;
            }

            // 0. 错误页面检测（「糟糕，出错了！」/ 「重试」）— URL 可能不变，需优先检测
            if (pageInfo.text.includes('出错了') || pageInfo.text.includes('went wrong')
                || pageInfo.text.includes('missing_email') || pageInfo.text.includes('error')) {
                const hasRetry = pageInfo.btns.some(b => b.includes('重试') || b.includes('Retry') || b.includes('Try again'));
                console.log(`[OAuth] Round ${round}: 检测到错误页面: ${pageInfo.text.substring(0, 150)}`);
                if (hasRetry) {
                    console.log('[OAuth] 点击「重试」...');
                    try { await this.clickButtonByText('重试', 5000); } catch (e) {
                        try { await this.clickButtonByText('Retry', 3000); } catch (e2) {}
                    }
                    await SLEEP(5000);
                    await this.waitForCloudflare(30000);
                    await SLEEP(3000);
                    lastHandledUrl = ''; // 重置，允许重新匹配
                    continue;
                }
            }

            if (url === lastHandledUrl) {
                console.log(`[OAuth] Round ${round}: 页面未变化...`);
                continue;
            }

            console.log(`[OAuth] Round ${round}: ${url.substring(0, 70)}`);
            console.log(`[OAuth]   按钮: ${pageInfo.btns.slice(0, 8).join(', ')}`);

            // 1. 登录/注册选择页 - 根据配置选择登录方式
            const hasPhoneLogin = pageInfo.btns.some(b => b.includes('手机登录'));
            const hasEmailLogin = pageInfo.btns.some(b => b.includes('电子邮件地址登录') || b.includes('邮箱登录') || b.includes('email'));
            if (loginMethod === 'email' && hasEmailLogin) {
                console.log('[OAuth] 点击「继续使用电子邮件地址登录」...');
                try {
                    await this.clickButtonByText('电子邮件地址登录');
                } catch (e) {
                    try { await this.clickButtonByText('邮箱登录', 3000); } catch (e2) {
                        await this.clickButtonByText('email');
                    }
                }
                await SLEEP(3000);
                lastHandledUrl = url;
                continue;
            }
            if (loginMethod !== 'email' && hasPhoneLogin) {
                console.log('[OAuth] 点击「继续使用手机登录」...');
                await this.clickButtonByText('手机登录');
                await SLEEP(3000);
                lastHandledUrl = url;
                continue;
            }

            // 1.5 邮箱输入页
            const hasEmailForm = pageInfo.inputs.some(i =>
                i.type === 'email' || i.name === 'email' || i.name === 'username' || i.name === 'identifier'
            );
            if (loginMethod === 'email' && hasEmailForm) {
                console.log(`[OAuth] 检测到邮箱输入页，输入: ${email}`);
                const emailInput = await this.page.$('input[type="email"]')
                    || await this.page.$('input[name="email"]')
                    || await this.page.$('input[name="username"]')
                    || await this.page.$('input[name="identifier"]')
                    || await this.page.$('input[type="text"]');

                if (emailInput) {
                    await emailInput.click({ clickCount: 3 });
                    await this.page.keyboard.type(email, { delay: 30 });
                }
                await SLEEP(500);
                await this.clickSubmitButton();
                await SLEEP(3000);
                await this.waitForCloudflare(30000);
                await SLEEP(3000);
                lastHandledUrl = url;
                continue;
            }

            // 2. 手机号输入页（检测方式：有国家选择器按钮 或 phoneNumberInput）
            const hasPhoneForm = pageInfo.inputs.some(i => i.name === 'phoneNumberInput' || i.type === 'tel')
                || pageInfo.btns.some(b => /\+\(\d+\)|\+\d+/.test(b));

            if (hasPhoneForm) {
                console.log('[OAuth] 检测到手机号输入页...');

                // 尝试选国家（方法1: select，方法2: 按钮）
                try {
                    await this.selectCountry('44', '英国', 'GB');
                } catch (e) {}

                // 找到手机号输入框
                const input = await this.page.$('input[name="phoneNumberInput"]')
                    || await this.page.$('input[type="tel"]');

                if (input) {
                    // 检查当前国家代码是否正确
                    const currentCountry = await this.page.evaluate(() => {
                        for (const b of document.querySelectorAll('button, select')) {
                            const t = b.textContent || b.innerText || '';
                            const match = t.match(/\+(\d+)/);
                            if (match) return match[1];
                        }
                        return '';
                    });

                    await input.click({ clickCount: 3 });

                    if (currentCountry === '44') {
                        // 国家正确，只输入本地号码
                        const localNumber = phone.replace(/^\+44/, '');
                        await input.type(localNumber, { delay: 50 });
                        console.log(`[OAuth] 输入本地号码: ${localNumber} (国家 +44)`);
                    } else {
                        // 国家不对，输入完整号码（去掉 + 号）
                        const fullNumber = phone.replace(/^\+/, '');
                        await input.type(fullNumber, { delay: 50 });
                        console.log(`[OAuth] 输入完整号码: ${fullNumber} (国家显示 +${currentCountry})`);
                    }
                }
                await SLEEP(500);
                await this.screenshot('oauth-phone.png');

                // 精确点击 type=submit 的「继续」按钮（避免匹配 Google 等按钮）
                await this.page.evaluate(() => {
                    for (const b of document.querySelectorAll('button[type="submit"]')) {
                        const text = b.innerText.trim();
                        if (text === '继续' || text === 'Continue') {
                            ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                                b.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                            });
                            return;
                        }
                    }
                });
                await SLEEP(3000);
                await this.waitForCloudflare(30000);
                await SLEEP(5000);
                lastHandledUrl = url; // 标记已处理，避免重复
                continue;
            }

            // 3. 密码页
            
            if (pageInfo.inputs.some(i => i.type === 'password') || url.includes('password')) {
                if (loginMethod === 'email' && shouldPreferEmailOtp) {
                    const switchedToOtp = await this.page.evaluate(() => {
                        const candidates = [
                            '使用一次性验证码登录',
                            '一次性验证码登录',
                            '一次性验证码',
                            'one-time code',
                            'one time code',
                            'email code',
                            'send code',
                            'use code',
                            'magic code',
                            'try another way',
                            'verification code',
                        ];
                        const nodes = document.querySelectorAll('button, a, [role="button"]');
                        for (const node of nodes) {
                            const text = (node.innerText || node.textContent || '').trim().toLowerCase();
                            if (!text) continue;
                            if (candidates.some(c => text.includes(c))) {
                                ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                                    node.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                                });
                                return true;
                            }
                        }
                        return false;
                    });

                    if (switchedToOtp) {
                        console.log('[OAuth] switched to one-time code login');
                        await SLEEP(4000);
                        await this.waitForCloudflare(30000);
                        await SLEEP(2000);
                        lastHandledUrl = url;
                        continue;
                    }

                    // 已要求走一次性验证码登录时，不再回退输入密码
                    throw new Error('已启用一次性验证码登录，但当前页面未找到「使用一次性验证码登录」入口');
                }

                if (!password) {
                    throw new Error('password page shown but password is empty');
                }

                console.log('[OAuth] 检测到密码页，准备输入密码并继续...');
                const pwdInput = await this.page.$('input[type="password"]');
                if (pwdInput) {
                    await pwdInput.click({ clickCount: 3 });
                    await this.page.keyboard.press('Backspace');
                    await this.page.keyboard.type(password, { delay: 30 });
                }
                await SLEEP(500);
                // 先尝试回车提交（OpenAI 登录页通常支持）
                await this.page.keyboard.press('Enter').catch(() => {});
                await SLEEP(1000);

                // 再用真实鼠标点击可见的提交按钮（避免仅 dispatchEvent 未触发）
                const submitBtnPos = await this.page.evaluate(() => {
                    const preferredTexts = ['继续', 'Continue', 'Next', 'Verify', 'Submit'];
                    const submitButtons = Array.from(document.querySelectorAll('button[type="submit"], button'));

                    for (const b of submitButtons) {
                        const text = (b.innerText || '').trim();
                        if (!preferredTexts.some(t => text === t || text.includes(t))) continue;
                        if (b.disabled) continue;
                        const rect = b.getBoundingClientRect();
                        if (rect.width <= 0 || rect.height <= 0) continue;
                        return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2, text };
                    }

                    for (const b of submitButtons) {
                        if (b.disabled) continue;
                        const rect = b.getBoundingClientRect();
                        if (rect.width <= 0 || rect.height <= 0) continue;
                        return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2, text: (b.innerText || '').trim() || 'submit' };
                    }

                    return null;
                });

                if (submitBtnPos) {
                    console.log(`[OAuth] 点击密码页按钮: ${submitBtnPos.text}`);
                    await this.page.mouse.click(submitBtnPos.x, submitBtnPos.y);
                } else {
                    await this.clickSubmitButton();
                }
                await SLEEP(5000);
                await this.waitForCloudflare(30000);
                await SLEEP(3000);
                lastHandledUrl = url;
                continue;
            }

            // 3.5 about-you 页面：填写个人信息并继续
            if (url.includes('about-you') || url.includes('about_you')) {
                console.log('[OAuth] 检测到 about-you 页面...');
                await this.fillAboutYouAndSubmit(
                    opts.fullName || opts.phone,
                    opts.age || 30,
                    opts.birthDate,
                    '[OAuth]'
                );
                await this.screenshot('oauth-about-you-filled.png');
                lastHandledUrl = url;
                continue;
            }

            // 3.6 添加邮箱页 (add-email)
            if (url.includes('add-email') || url.includes('add_email')) {
                console.log(`[OAuth] 检测到邮箱绑定页面，输入: ${email}`);
                const emailInput = await this.page.$('input[type="email"]')
                    || await this.page.$('input[name="email"]')
                    || await this.page.$('input[type="text"]');
                if (emailInput) {
                    await emailInput.click({ clickCount: 3 });
                    await this.page.keyboard.type(email, { delay: 30 });
                }
                await SLEEP(500);
                await this.clickSubmitButton();
                await SLEEP(5000);
                await this.waitForCloudflare(30000);
                await SLEEP(3000);
                emailBound = true;
                lastHandledUrl = url;
                continue;
            }

            // 4a. 邮箱验证码页（email-verification）
            
            if (url.includes('email-verification')
                || (loginMethod === 'email'
                    && /code|verification/i.test(pageInfo.text)
                    && pageInfo.inputs.some(i => i.name !== 'phoneNumberInput' && (i.type === 'text' || i.type === 'tel' || i.type === 'number')))) {
                console.log('[OAuth] 检测到邮箱验证码页面，准备读取并填写验证码...');
                if (onEmailCodeNeeded) {
                    const code = await onEmailCodeNeeded();
                    if (code) {
                        await this.enterSmsCode(code);
                        await this.screenshot('after-email-code.png');
                        emailBound = true;
                        lastHandledUrl = url;
                        continue;
                    }
                }
            }

            // 4c. 当已完成邮箱绑定且配置要求提前结束时，直接返回
            if (stopAfterEmailBound && emailBound) {
                const atConsentPage = url.includes('/consent') || pageInfo.btns.some(b => b === '继续' || b === 'Continue');
                const leftEmailBindingPage = !url.includes('add-email') && !url.includes('add_email') && !url.includes('email-verification');
                if (atConsentPage || leftEmailBindingPage) {
                    console.log('[OAuth] 邮箱绑定流程已完成，按配置提前返回');
                    return 'EMAIL_BOUND';
                }
            }

            // 4b. SMS 验证码页（contact-verification）
            
            if (url.includes('contact-verification')) {
                console.log('[OAuth] 需要 SMS 验证码...');
                if (onSmsNeeded) {
                    const code = await onSmsNeeded();
                    if (code) {
                        await this.enterSmsCode(code);
                        lastHandledUrl = url;
                        continue;
                    }
                }
            }

            // 5. 授权确认页 - 点击授权/允许按钮（精确匹配，避免 Google/Apple 等）
            const safeClick = await this.page.evaluate(() => {
                const skipWords = ['Google', 'Apple', 'Microsoft', '邮件', '邮箱', '手机', 'email', 'phone'];
                for (const b of document.querySelectorAll('button')) {
                    const text = b.innerText.trim();
                    if (!text) continue;
                    // 只点击短文本按钮（授权/允许/继续），排除包含第三方登录关键词的
                    if (text.length <= 10 && !skipWords.some(w => text.includes(w))) {
                        if (['Allow', '授权', '允许', '同意', 'Continue', '继续'].some(t => text.includes(t))) {
                            ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(type => {
                                b.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
                            });
                            return text;
                        }
                    }
                }
                return null;
            });
            if (safeClick) {
                console.log(`[OAuth] 点击了「${safeClick}」`);
                lastHandledUrl = url;
            }

            // 每5轮截图诊断
            if (round % 5 === 4) {
                await this.screenshot(`oauth-round${round}.png`);
                // 打印页面文字帮助诊断
                console.log(`[OAuth] 页面文字: ${pageInfo.text.substring(0, 150)}`);
            }
        }

        throw new Error('OAuth 登录+授权超时');
    }
}

module.exports = { BrowserService };
