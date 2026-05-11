import { App, Plugin, PluginSettingTab, Setting, SecretComponent, Notice, TFile, setIcon, arrayBufferToBase64, base64ToArrayBuffer } from 'obsidian';
import { argon2id } from 'hash-wasm';
import { i18n } from './i18n/helpers';

/**
 * PhantomCipher (幻影加密)
 * 核心设计：基于 Argon2id + AES-GCM 的高性能透明加解密方案。
 * 1. 算法：使用 Argon2id 派生密钥 + AES-GCM 认证加密。
 * 2. 压缩：内置 Deflate 压缩流，用于抵消 Base64 编码带来的体积膨胀。
 * 3. 透明：拦截 Vault Adapter 底层接口，实现用户无感知的加解密。
 * 4. 缓存：引入 Session Salt (会话盐) 机制，极大提升高频写入时的响应速度。
 */

interface PhantomCipherSettings {
	mode: 'encrypt' | 'decrypt' | 'none';
	secretName: string;
}

const DEFAULT_SETTINGS: PhantomCipherSettings = {
	mode: 'none',
	secretName: 'vault-master-key'
};

const MAGIC_HEADER = "ENC_V1:";
const SALT_SIZE = 16;
const IV_SIZE = 12;

// 预设不进行二次压缩的文件类型列表
const NON_COMPRESSIBLE = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'pdf']);

class CryptoHelper {
	// 缓存密钥：使用过的密钥自动缓存
	private keyMapCache: Map<string, CryptoKey> = new Map();
	// 运行时盐值：在插件生命周期内保持一致
	private sessionSalt: Uint8Array | null = null;
	// 计算锁：防止多文件同时解密时 Argon2id 撑爆内存
	private derivationPromise: Promise<CryptoKey> | null = null;

	/**
	 * 辅助工具：提取 Uint8Array 的 ArrayBuffer 副本，确保类型兼容性
	 */
	private toBuffer(arr: Uint8Array): ArrayBuffer {
		return arr.buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength) as ArrayBuffer;
	}

	/**
	 * 压缩逻辑：使用原生 CompressionStream 对数据进行 deflate 压缩
	 */
	private async compress(data: Uint8Array): Promise<Uint8Array> {
		const cleanBuffer = this.toBuffer(data);
		const stream = new Blob([cleanBuffer]).stream().pipeThrough(new CompressionStream('deflate'));
		return new Uint8Array(await new Response(stream).arrayBuffer());
	}

	/**
	 * 解压逻辑：使用原生 DecompressionStream 还原数据
	 */
	private async decompress(data: Uint8Array): Promise<Uint8Array> {
		const cleanBuffer = this.toBuffer(data);
		const stream = new Blob([cleanBuffer]).stream().pipeThrough(new DecompressionStream('deflate'));
		return new Uint8Array(await new Response(stream).arrayBuffer());
	}

	/**
	 * 派生密钥：利用 Argon2id 派生计算 256 位密钥
	 * 包含缓存机制，避免同一盐值重复计算
	 */
	async getEffectiveKey(password: string, saltArr: Uint8Array): Promise<CryptoKey> {
		const saltBase64 = arrayBufferToBase64(this.toBuffer(saltArr));
		const cacheKey = password + "_" + saltBase64;
		if (this.keyMapCache.has(cacheKey)) return this.keyMapCache.get(cacheKey)!;

		// 队列化派生请求
		if (this.derivationPromise) return await this.derivationPromise;

		this.derivationPromise = (async () => {
			const result = await argon2id({
				password, salt: saltArr, iterations: 3, memorySize: 65536, parallelism: 4, hashLength: 32, outputType: 'binary'
			});
			const derivedKey = await crypto.subtle.importKey("raw", this.toBuffer(result as Uint8Array), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
			this.keyMapCache.set(cacheKey, derivedKey);
			return derivedKey;
		})();

		try {
			return await this.derivationPromise;
		} finally {
			this.derivationPromise = null;
		}
	}


	/**
	 * 加密执行逻辑：处理压缩 -> 加密 -> 拼接 Base64
	 */
	async encrypt(data: Uint8Array, password: string, shouldCompress: boolean): Promise<string> {
		let payload = data;
		let compressionFlag = 0;
		if (shouldCompress) {
			payload = await this.compress(data);
			compressionFlag = 1;
		}
		// 运行时保持盐值一致，确保同一密码下的所有文件共用一个 CryptoKey 缓存
		if (!this.sessionSalt) {
			this.sessionSalt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
		}
		const salt = this.sessionSalt;
		const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
		const key = await this.getEffectiveKey(password, salt);
		const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: this.toBuffer(iv) }, key, this.toBuffer(payload));

		// 存储结构：Salt(16) + IV(12) + CompressionFlag(1) + Ciphertext(n)
		const combined = new Uint8Array(SALT_SIZE + IV_SIZE + 1 + ciphertext.byteLength);
		combined.set(salt, 0);
		combined.set(iv, SALT_SIZE);
		combined.set([compressionFlag], SALT_SIZE + IV_SIZE);
		combined.set(new Uint8Array(ciphertext), SALT_SIZE + IV_SIZE + 1);

		return MAGIC_HEADER + arrayBufferToBase64(this.toBuffer(combined));
	}

	/**
	 * 解密执行逻辑：拆包 Base64 -> 解密 -> 处理解压
	 */
	async decrypt(armoredText: string, password: string): Promise<Uint8Array | null> {
		if (!this.isEncrypted(armoredText)) return null;
		const combined = new Uint8Array(base64ToArrayBuffer(armoredText.substring(MAGIC_HEADER.length)));
		if (combined.length < SALT_SIZE + IV_SIZE + 1) return null;

		const salt = combined.subarray(0, SALT_SIZE);
		const iv = combined.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
		const compressionFlag = combined[SALT_SIZE + IV_SIZE];
		const ciphertext = combined.subarray(SALT_SIZE + IV_SIZE + 1);

		const key = await this.getEffectiveKey(password, salt);
		try {
			const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.toBuffer(iv) }, key, this.toBuffer(ciphertext));
			let finalData: any = new Uint8Array(decrypted);
			if (compressionFlag === 1) finalData = await this.decompress(finalData);
			return finalData as Uint8Array;
		} catch (e) { return null; }
	}

	/**
	 * 特征检测：识别字符串或二进制数据是否包含加密头
	 */
	isEncrypted(data: string | ArrayBuffer | null): boolean {
		if (!data) return false;
		if (typeof data === 'string') return data.startsWith(MAGIC_HEADER);
		if (data.byteLength < MAGIC_HEADER.length) return false;

		const bytes = new Uint8Array(data, 0, MAGIC_HEADER.length);
		let header = "";
		for (let i = 0; i < MAGIC_HEADER.length; i++) header += String.fromCharCode(bytes[i]!);
		return header === MAGIC_HEADER;
	}

	clearCache() {
		this.keyMapCache.clear();
		this.sessionSalt = null; // 密码更改或清除时重置盐
	}
}

export default class PhantomCipherPlugin extends Plugin {
	settings!: PhantomCipherSettings;
	crypto: CryptoHelper = new CryptoHelper();
	rawPassword: string | null = null;

	private originalRead: any;
	private originalWrite: any;
	private originalReadBinary: any;
	private originalWriteBinary: any;
	private statusBarItem!: HTMLElement;

	private errorThrottler: Map<string, number> = new Map();

	async onload() {
		await this.loadSettings();

		// 状态栏初始化
		this.statusBarItem = this.addStatusBarItem();
		this.statusBarItem.style.display = "none";

		// 功能区图标：手动转换按钮
		this.addRibbonIcon('lock', i18n.t('RIBBON_TEXT'), async () => {
			const file = this.app.workspace.getActiveFile();
			if (file) await this.manuallyToggleFile(file);
		});

		// 绑定右键菜单项
		this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
			if (!(file instanceof TFile)) return;
			menu.addItem((item) => {
				item.setTitle(i18n.t('MENU_TEXT')).setIcon("key").onClick(() => this.manuallyToggleFile(file));
			});
		}));

		// 拦截并备份原生的 Adapter 方法
		const adapter = this.app.vault.adapter;
		this.originalRead = adapter.read.bind(adapter);
		this.originalWrite = adapter.write.bind(adapter);
		this.originalReadBinary = adapter.readBinary.bind(adapter);
		this.originalWriteBinary = adapter.writeBinary.bind(adapter);

		this.hookAdapter();
		this.addSettingTab(new CryptoSettingTab(this.app, this));

		// 注册文件打开与修改的状态栏更新事件
		this.registerEvent(this.app.workspace.on('file-open', (file) => this.updateStatusBar(file)));
		this.registerEvent(this.app.vault.on('modify', (file) => {
			if (file instanceof TFile && file === this.app.workspace.getActiveFile()) this.updateStatusBar(file);
		}));

		this.app.workspace.onLayoutReady(() => {
			this.fetchPassword();
			this.updateStatusBar(this.app.workspace.getActiveFile());
		});
	}

	onunload() {
		// 插件卸载时还原底层 Adapter 引用
		const adapter = this.app.vault.adapter;
		adapter.read = this.originalRead;
		adapter.write = this.originalWrite;
		adapter.readBinary = this.originalReadBinary;
		adapter.writeBinary = this.originalWriteBinary;
		this.crypto.clearCache();
	}

	/**
	 * 从钥匙串中加载主密码
	 */
	async fetchPassword() {
		const storage = (this.app as any).secretStorage;
		if (!storage) return;
		this.rawPassword = typeof storage.get === 'function' ? await storage.get(this.settings.secretName) : storage.secrets?.[this.settings.secretName];
		if (this.rawPassword) {
			this.crypto.clearCache();
			this.updateStatusBar(this.app.workspace.getActiveFile());
		}
	}

	/**
	 * 旁路判定：识别是否为同步插件调用的核心
	 */
	private isSyncCaller(): boolean {
		const stack = new Error().stack || "";
		const lowStack = stack.toLowerCase();

		// 已知同步类插件的 ID 或核心关键词
		const syncBlacklist = [
			"remotely-save", 
			"livesync", 
		];

		// 1. 直接关键词匹配（通用）
		if (syncBlacklist.some(k => lowStack.includes(k))) return true;

		// 2. 移动端路径指纹匹配：匹配类似 .../plugins/插件ID/main.js 的结构
		const pluginMatch = stack.match(/plugins\/([a-z0-9\-]+)\/main\.js/i);
		if (pluginMatch) {
			const callingPluginId = pluginMatch[1]!.toLowerCase();
			return syncBlacklist.includes(callingPluginId);
		}

		return false;
	}

	/**
	 * 核心 Hook 逻辑：接管读取与写入流程
	 */
	private hookAdapter() {
		const self = this;
		const adapter = this.app.vault.adapter;

		// 统一处理解密异常
		const handleCryptoError = (path: string) => {
			const fileName = path.split('/').pop() || path;
			const errorMsg = i18n.t('ERROR_DECRYPT', { name: fileName });
			const now = Date.now();
			const lastTime = self.errorThrottler.get(path) || 0;

			if (now - lastTime > 2000) {
				new Notice(errorMsg);
				self.errorThrottler.set(path, now);
			}
			// 必须抛出异常，防止流程继续执行并返回加密乱码
			throw new Error(errorMsg);
		};

		// 处理文本读取：如果是加密文件则自动解密
		adapter.read = async (path: string): Promise<string> => {
			const content = await self.originalRead(path);
			if (path.includes(".obsidian") || !self.crypto.isEncrypted(content) || self.isSyncCaller()) return content;
			if (!self.rawPassword) await self.fetchPassword();
			try {
				const decrypted = await self.crypto.decrypt(content, self.rawPassword || "");
				return decrypted ? new TextDecoder().decode(decrypted) : content;
			} catch (e) { return handleCryptoError(path); }
		};

		// 处理二进制读取：支持附件透明解密
		adapter.readBinary = async (path: string): Promise<ArrayBuffer> => {
			const data = await self.originalReadBinary(path);
			if (path.includes(".obsidian") || !self.crypto.isEncrypted(data) || self.isSyncCaller()) return data;

			if (!self.rawPassword) await self.fetchPassword();
			try {
				const armoredText = new TextDecoder().decode(data);
				const decrypted = await self.crypto.decrypt(armoredText, self.rawPassword || "");
				return decrypted ? self.crypto["toBuffer"](decrypted) : data;
			} catch (e) { return handleCryptoError(path); }
		};

		/**
		 * 写入逻辑处理器：根据插件模式决定是否加密落地数据
		 */
		const handleWrite = async (path: string, data: Uint8Array): Promise<string | Uint8Array | null> => {
            if (path.includes(".obsidian") || self.isSyncCaller()) return data; // 同步插件写入时直接透传密文，不触发二次加密
            if (!self.rawPassword) await self.fetchPassword();

			// 性能优化：头部预检。仅读取前 10 字节判断文件是否原本就是加密状态。
			let isCurrentlyEncrypted = false;
			try {
				const head = await self.originalReadBinary(path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				isCurrentlyEncrypted = self.crypto.isEncrypted(head);
			} catch (e) {}

			const ext = path.split('.').pop()?.toLowerCase() || '';
			const shouldCompress = !NON_COMPRESSIBLE.has(ext);

			// 模式判定逻辑
			if (self.settings.mode === 'encrypt' && self.rawPassword) {
				return await self.crypto.encrypt(data, self.rawPassword, shouldCompress);
			}
			if (self.settings.mode === 'decrypt') return data;

			// 如果是非强制模式，根据头部的探测结果决定是否加密
			if (isCurrentlyEncrypted && self.rawPassword) {
				return await self.crypto.encrypt(data, self.rawPassword, shouldCompress);
			}
			return data;
		};

		adapter.write = async (path, data, options) => {
			const result = await handleWrite(path, new TextEncoder().encode(data));
			return typeof result === 'string' ? await self.originalWrite(path, result, options) : await self.originalWrite(path, data, options);
		};

		adapter.writeBinary = async (path, data, options) => {
			const result = await handleWrite(path, new Uint8Array(data));
			return typeof result === 'string' ? await self.originalWrite(path, result, options) : await self.originalWriteBinary(path, data, options);
		};
	}

	/**
	 * 更新状态栏 UI 展示文件的加密状态
	 */
	private async updateStatusBar(file: TFile | null) {
		if (!file) { this.statusBarItem.style.display = "none"; return; }
		try {
			// 仅读取前几个字节检查状态
			const head = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
			const isEnc = this.crypto.isEncrypted(head);
			this.statusBarItem.empty();
			if (isEnc) {
				this.statusBarItem.style.display = "inline-block";
				const span = this.statusBarItem.createSpan();
				setIcon(span, "lock");
				span.createSpan({ text: this.rawPassword ? i18n.t('STATUS_TRANSPARENT') : i18n.t('STATUS_LOCKED') });
				this.statusBarItem.style.color = this.rawPassword ? "var(--text-success)" : "var(--text-error)";
			} else {
				this.statusBarItem.style.display = "none";
			}
		} catch (e) { this.statusBarItem.style.display = "none"; }
	}

	/**
	 * 手动切换单文件的加解密物理状态
	 */
	private async manuallyToggleFile(file: TFile) {
		if (!this.rawPassword) { new Notice(i18n.t('NOTICE_SET_PASSWORD')); return; }
		const raw = await this.originalRead(file.path);
		const isEnc = this.crypto.isEncrypted(raw);
		const data = new Uint8Array(await this.originalReadBinary(file.path));

		try {
			if (isEnc) {
				const plain = await this.app.vault.readBinary(file);
				await this.originalWriteBinary(file.path, plain);
				new Notice(i18n.t('NOTICE_RESTORED', { name: file.name }));
			} else {
				const ext = file.extension.toLowerCase();
				const armored = await this.crypto.encrypt(data, this.rawPassword, !NON_COMPRESSIBLE.has(ext));
				await this.originalWrite(file.path, armored);
				new Notice(i18n.t('NOTICE_ENCRYPTED', { name: file.name }));
			}
		} catch (e) {
			new Notice(i18n.t('NOTICE_FAILED', { name: file.name }));
		}
		await this.updateStatusBar(file);
	}

	async loadSettings() { this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData()); }
	async saveSettings() { await this.saveData(this.settings); }
}

class CryptoSettingTab extends PluginSettingTab {
	plugin: PhantomCipherPlugin;
	constructor(app: App, plugin: PhantomCipherPlugin) { super(app, plugin); this.plugin = plugin; }

	display(): void {
		const { containerEl } = this;
		containerEl.empty();
		containerEl.createEl('h2', { text: 'PhantomCipher' });

		new Setting(containerEl)
			.setName(i18n.t('MODE'))
			.setDesc(i18n.t('MODE_DESC'))
			.addDropdown(d => d
				.addOption('none', i18n.t('MODE_NONE'))
				.addOption('encrypt', i18n.t('MODE_ENCRYPT'))
				.addOption('decrypt', i18n.t('MODE_DECRYPT'))
				.setValue(this.plugin.settings.mode)
				.onChange(async v => {
					this.plugin.settings.mode = v as any;
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName(i18n.t('SECRET_NAME'))
			.setDesc(i18n.t('SECRET_NAME_DESC'))
			.addText(t => t
				.setValue(this.plugin.settings.secretName)
				.onChange(async v => {
					this.plugin.settings.secretName = v;
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName(i18n.t('MASTER_KEY'))
			.setDesc(i18n.t('MASTER_KEY_DESC'))
			.addComponent(el => {
				const component = new (SecretComponent as any)(this.app, el);
				component.setValue(this.plugin.settings.secretName)
					.onChange(async (v: string) => {
						this.plugin.settings.secretName = v;
						await this.plugin.saveSettings();
						await this.plugin.fetchPassword();
					});
				return component;
			});
	}
}
