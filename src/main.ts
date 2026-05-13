import { App, Plugin, PluginSettingTab, Setting, SecretComponent, Notice, TFile, TFolder, setIcon, arrayBufferToBase64, base64ToArrayBuffer, DataWriteOptions, Stat, Platform, normalizePath } from 'obsidian';
import { argon2id } from 'hash-wasm';
import { i18n } from './i18n/helpers';

/**
 * PhantomCipher (幻影加密)
 * 核心设计：基于 Argon2id + AES-GCM 的高性能透明加解密方案。
 * 1. 算法：使用 Argon2id 派生密钥 + AES-GCM 认证加密。
 * 2. 压缩：内置 Deflate 压缩流，用于抵消 Base64 编码带来的体积膨胀。
 * 3. 透明：拦截 Vault Adapter 底层接口，实现用户无感知的加解密。
 * 4. 缓存：引入 Session Salt (会话盐) 机制，极大提升高频写入时的响应速度。
 * 5. 内存保护：采用 XOR 内存混淆，防止密码明文在内存中长期驻留导致 Dump 泄露。
 */

interface PhantomCipherSettings {
	mode: 'encrypt' | 'none';
	secretName: string;
}

const DEFAULT_SETTINGS: PhantomCipherSettings = {
	mode: 'none',
	secretName: ''
};

const MAGIC_HEADER = "ENC_V1:";
const SALT_SIZE = 16;
const IV_SIZE = 12;

// 预设不进行二次压缩的文件类型列表
const NON_COMPRESSIBLE = new Set([
	'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', // 图片
	'pdf', // 文档
	'mp3', 'ogg', 'opus', 'm4a', 'flac', 'aac', // 音频
	'mp4', 'webm', 'ogv', 'mov', 'mkv' // 视频
]);

// 支持预览的文件类型列表
const PREVIEW_SUPPORTED = new Set([
	'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'avif', // 图片
	'pdf', // 文档
	'mp3', 'ogg', 'opus', 'm4a', 'flac', 'aac', 'wav', // 音频
	'mp4', 'webm', 'ogv', 'mov', 'mkv' // 视频
]);

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
			const derivedKey = await crypto.subtle.importKey("raw", this.toBuffer(result as Uint8Array), { name: "AES-GCM" }, false,["encrypt", "decrypt"]);
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
	isEncrypted(data: string | ArrayBuffer | Uint8Array | null): boolean {
		if (!data) return false;
		if (typeof data === 'string') return data.startsWith(MAGIC_HEADER);
		
		let bytes: Uint8Array;
		if (data instanceof Uint8Array) {
			bytes = data;
		} else {
			bytes = new Uint8Array(data);
		}

		if (bytes.length < MAGIC_HEADER.length) return false;

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
	
	// 内存混淆安全凭证
	private memoryKey: Uint8Array | null = null;
	private obfuscatedPassword: Uint8Array | null = null;

	private originalRead: any;
	private originalWrite: any;
	private originalReadBinary: any;
	private originalWriteBinary: any;
	private originalProcess: any;
	private originalStat: any;
	private originalGetResourcePath: any;
	private originalCachedRead: any;
	private statusBarItem!: HTMLElement;

	private errorThrottler: Map<string, number> = new Map();
	private decryptedPaths: Set<string> = new Set(); // 追踪真正解密成功的路径
	// 缓存已解密文件的大小 (Size) 和 Blob URL，确保编辑器和媒体加载正常
	private decryptedSizeCache: Map<string, number> = new Map();
	private blobUrlCache: Map<string, string> = new Map();

	/**
	 * 设置密码时，立刻使用随机数进行 XOR 混淆存储
	 */
	private setPassword(pwd: string | null) {
		// 先擦除旧密码内存
		if (this.obfuscatedPassword) this.obfuscatedPassword.fill(0);
		if (this.memoryKey) this.memoryKey.fill(0);

		if (!pwd) {
			this.memoryKey = null;
			this.obfuscatedPassword = null;
			return;
		}

		const pwdBytes = new TextEncoder().encode(pwd);
		const memKey = crypto.getRandomValues(new Uint8Array(pwdBytes.length));
		const obfPwd = new Uint8Array(pwdBytes.length);
		
		for (let i = 0; i < pwdBytes.length; i++) {
			obfPwd[i] = pwdBytes[i]! ^ memKey[i]!;
		}
		
		this.memoryKey = memKey;
		this.obfuscatedPassword = obfPwd;
		// 敏感数据用完立刻清零
		pwdBytes.fill(0);
	}

	/**
	 * 获取密码时即时还原
	 */
	private getPassword(): string | null {
		const memKey = this.memoryKey;
		const obfPwd = this.obfuscatedPassword;
		
		if (!memKey || !obfPwd) return null;
		
		const pwdBytes = new Uint8Array(obfPwd.length);
		for (let i = 0; i < obfPwd.length; i++) {
			pwdBytes[i] = obfPwd[i]! ^ memKey[i]!;
		}
		const pwd = new TextDecoder().decode(pwdBytes);
		pwdBytes.fill(0);
		return pwd;
	}

	/**
	 * 密钥缺失提示（针对未设置密码的情况）
	 */
	private notifyPasswordMissing() {
		const now = Date.now();
		const lastTime = this.errorThrottler.get("__PWD_MISSING") || 0;
		if (now - lastTime > 5000) { // 5 秒只提醒一次
			new Notice(i18n.t('NOTICE_SET_PASSWORD'));
			this.errorThrottler.set("__PWD_MISSING", now);
		}
	}

	/**
	 * 解密失败提示（针对密码错误或损坏的情况）
	 */
	private notifyDecryptFailed(path: string) {
		const fileName = path.split('/').pop() || path;
		const now = Date.now();
		const lastTime = this.errorThrottler.get("__DECRYPT_FAIL_" + path) || 0;
		if (now - lastTime > 5000) {
			new Notice(i18n.t('ERROR_DECRYPT', { name: fileName }));
			this.errorThrottler.set("__DECRYPT_FAIL_" + path, now);
		}
	}

	async onload() {
		await this.loadSettings();

		// 状态栏初始化
		this.statusBarItem = this.addStatusBarItem();
		this.statusBarItem.addClass("phantom-cipher-status-bar");

		// 功能区图标：手动转换按钮
		this.addRibbonIcon('lock', i18n.t('RIBBON_TEXT'), async () => {
			const file = this.app.workspace.getActiveFile();
			if (file) await this.manuallyToggleFile(file);
		});

		// 绑定右键菜单项
		this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
			if (file instanceof TFile) {
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_TEXT')).setIcon("key").onClick(() => this.manuallyToggleFile(file));
				});
			} else if (file instanceof TFolder) {
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_BATCH_ENCRYPT')).setIcon("lock").onClick(() => this.batchProcessFolder(file, 'encrypt'));
				});
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_BATCH_DECRYPT')).setIcon("unlock").onClick(() => this.batchProcessFolder(file, 'decrypt'));
				});
			}
		}));

		// 拦截并备份原生的 Adapter 方法
		const adapter = this.app.vault.adapter;
		this.originalRead = adapter.read.bind(adapter);
		this.originalWrite = adapter.write.bind(adapter);
		this.originalReadBinary = adapter.readBinary.bind(adapter);
		this.originalWriteBinary = adapter.writeBinary.bind(adapter);
		this.originalProcess = adapter.process.bind(adapter);
		this.originalStat = adapter.stat.bind(adapter);
		this.originalGetResourcePath = adapter.getResourcePath.bind(adapter);
		this.originalCachedRead = this.app.vault.cachedRead.bind(this.app.vault);

		this.hookAdapter();
		this.addSettingTab(new CryptoSettingTab(this.app, this));

		// 监听文件打开、修改、以及元数据更新（处理启动时的索引延迟）
		this.registerEvent(this.app.workspace.on('file-open', (file) => this.updateStatusBar(file)));
		this.registerEvent(this.app.vault.on('modify', (file) => {
			if (file instanceof TFile && file === this.app.workspace.getActiveFile()) this.updateStatusBar(file);
		}));
        this.registerEvent(this.app.metadataCache.on('changed', (file) => {
            if (file === this.app.workspace.getActiveFile()) this.updateStatusBar(file);
        }));

		this.app.workspace.onLayoutReady(async () => {
			await this.fetchPassword();
            // 延迟 500ms 待视图稳定后执行初次预热
            setTimeout(() => {
                const activeFile = this.app.workspace.getActiveFile();
                if (activeFile) this.updateStatusBar(activeFile);
            }, 500);
		});
	}

	onunload() {
		// 插件卸载时还原底层 Adapter 引用
		const adapter = this.app.vault.adapter;
		adapter.read = this.originalRead;
		adapter.write = this.originalWrite;
		adapter.readBinary = this.originalReadBinary;
		adapter.writeBinary = this.originalWriteBinary;
		adapter.stat = this.originalStat;
		adapter.process = this.originalProcess;
		adapter.getResourcePath = this.originalGetResourcePath;
		this.app.vault.cachedRead = this.originalCachedRead;
		this.blobUrlCache.forEach(url => URL.revokeObjectURL(url));
		this.blobUrlCache.clear();
		this.decryptedSizeCache.clear();
		this.crypto.clearCache();
		this.setPassword(null); // 显式擦除混淆内存
	}

	/**
	 * 从钥匙串中加载主密码
	 */
	async fetchPassword() {
		const storage = (this.app as any).secretStorage;
		if (!storage) return;
		const raw = typeof storage.get === 'function' ? await storage.get(this.settings.secretName) : storage.secrets?.[this.settings.secretName];
		if (raw) {
			this.setPassword(raw); // 使用混淆存储
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
		const syncBlacklist =[
			"remotely-save", 
			"obsidian-livesync", 
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
	 * 根据扩展名获取精确的 MIME 类型，用于 Blob URL 预览
	 */
	private getMimeType(ext: string): string {
		const map: Record<string, string> = {
			'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
			'pdf': 'application/pdf',
			'mp4': 'video/mp4', 'mkv': 'video/x-matroska',
			'mov': 'video/quicktime', 'm4a': 'audio/mp4',
			'mp3': 'audio/mpeg', 'svg': 'image/svg+xml'
		};
		if (map[ext]) return map[ext];
		if (['png', 'gif', 'webp', 'avif', 'bmp'].includes(ext)) return `image/${ext}`;
		if (['webm', 'wav', 'ogg', 'opus', 'flac'].includes(ext)) return `audio/${ext}`;
		return 'application/octet-stream';
	}

	/**
	 * 核心 Hook 逻辑：接管读取与写入流程
	 */
	private hookAdapter() {
		const self = this;
		const adapter = this.app.vault.adapter;

		// 拦截资源路径。如果是加密媒体文件，返回解密后的 Blob URL。
		adapter.getResourcePath = (path: string): string => {
			if (self.blobUrlCache.has(path)) return self.blobUrlCache.get(path)!;
			return self.originalGetResourcePath(path);
		};

		// 拦截 Stat 接口。编辑器会根据 Stat 返回的 size 校验 changeset。
		// 如果检测到是加密文件且由非同步插件访问，返回已记录的解密后大小。
		adapter.stat = async (path: string): Promise<Stat | null> => {
			const stat = await self.originalStat(path);
			if (!stat || path.includes(".obsidian") || self.isSyncCaller()) return stat;
            
            // 如果内存缓存中有，直接返回解密后的尺寸
			if (self.decryptedSizeCache.has(path)) {
				stat.size = self.decryptedSizeCache.get(path)!;
				return stat;
			} 

            if (self.decryptedPaths.has(path)) {
                try {
                    // 仅对已知解密成功的文件进行一次读取以更新缓存
                    const data = await self.originalReadBinary(path);
                    const armoredText = new TextDecoder().decode(data);
                    const decrypted = await self.crypto.decrypt(armoredText, self.getPassword() || "");
                    if (decrypted) {
                        const size = decrypted.byteLength;
                        self.decryptedSizeCache.set(path, size);
                        stat.size = size;
                    }
                } catch (e) {
                    // 忽略探测错误，返回原始 stat
                }
            }
            
			return stat;
		};

		// 拦截 CachedRead，确保 Obsidian 内部缓存系统拿到的是解密后的明文
		this.app.vault.cachedRead = async (file: TFile): Promise<string> => {
			const content = await self.originalRead(file.path);
			if (file.path.includes(".obsidian") || !self.crypto.isEncrypted(content) || self.isSyncCaller()) return content;

			if (!self.getPassword()) await self.fetchPassword();
			const pwd = self.getPassword();
			
			if (!pwd) {
				self.decryptedPaths.delete(file.path); // 未解密
				self.notifyPasswordMissing(); // 提示设置密码
				return content; // 返回密文原始内容
			}
			
			const decrypted = await self.crypto.decrypt(content, pwd);
			if (decrypted) {
				self.decryptedPaths.add(file.path); // 解密成功
				return new TextDecoder().decode(decrypted);
			}
			
			self.decryptedPaths.delete(file.path); // 解密失败
			self.notifyDecryptFailed(file.path);
			return content; 
		};

		// 处理文本读取：如果是加密文件则自动解密
		adapter.read = async (path: string): Promise<string> => {
			const content = await self.originalRead(path);
			if (path.includes(".obsidian") || !self.crypto.isEncrypted(content) || self.isSyncCaller()) return content;
			
			if (!self.getPassword()) await self.fetchPassword();
			const pwd = self.getPassword();
			
			if (!pwd) {
				self.decryptedPaths.delete(path);
				self.notifyPasswordMissing();
				return content;
			}
			
			const decrypted = await self.crypto.decrypt(content, pwd);
			if (decrypted) {
				self.decryptedPaths.add(path);
				const text = new TextDecoder().decode(decrypted);
				self.decryptedSizeCache.set(path, text.length); // 记录文本长度
				return text;
			}
			
			self.decryptedPaths.delete(path);
			self.notifyDecryptFailed(path);
			return content;
		};

		// 处理二进制读取：支持附件透明解密
		adapter.readBinary = async (path: string): Promise<ArrayBuffer> => {
			const data = await self.originalReadBinary(path);
			if (path.includes(".obsidian") || !self.crypto.isEncrypted(data.slice(0, MAGIC_HEADER.length)) || self.isSyncCaller()) return data;

			if (!self.getPassword()) await self.fetchPassword();
			const pwd = self.getPassword();

			if (!pwd) {
				self.decryptedPaths.delete(path);
				self.notifyPasswordMissing();
				return data;
			}

			const armoredText = new TextDecoder().decode(data);
			const decrypted = await self.crypto.decrypt(armoredText, pwd);
			if (decrypted) {
				self.decryptedPaths.add(path);
				self.decryptedSizeCache.set(path, decrypted.byteLength);
				// 针对媒体文件生成 Blob URL，让 app:// 协议能显示加密图片
				const ext = path.split('.').pop()?.toLowerCase() || '';
				if (PREVIEW_SUPPORTED.has(ext)) {
					if (self.blobUrlCache.has(path)) URL.revokeObjectURL(self.blobUrlCache.get(path)!);
					// 生成 Blob URL 并映射，支持所有媒体格式预览
					const blob = new Blob([decrypted as any], { type: self.getMimeType(ext) });
					self.blobUrlCache.set(path, URL.createObjectURL(blob));
				}
				return self.crypto["toBuffer"](decrypted);
			}
			
			self.decryptedPaths.delete(path);
			self.notifyDecryptFailed(path);
			return data;
		};

		/**
		 * 写入逻辑处理器：根据插件模式决定是否加密落地数据
		 */
		const handleWrite = async (path: string, data: Uint8Array): Promise<string | Uint8Array | null> => {
            if (path.includes(".obsidian") || self.isSyncCaller()) {
                self.decryptedPaths.delete(path);
                self.decryptedSizeCache.delete(path);
                return data; 
            } // 同步插件写入时直接透传密文，不触发二次加密
            if (!self.getPassword()) await self.fetchPassword();
			const pwd = self.getPassword();

			// 仅读取前 10 字节判断文件是否原本直接就是加密状态
			let isCurrentlyEncrypted = false;
			try {
				const head = await self.originalReadBinary(path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				isCurrentlyEncrypted = self.crypto.isEncrypted(head);
			} catch (e) {}

			// 如果磁盘上的文件是加密的，但内存集合中没有该路径（说明未成功解密过）
			// 此时绝对禁止任何写入。哪怕用户删掉了编辑器里的加密头，也知道它是加密文件。
			if (isCurrentlyEncrypted && !self.decryptedPaths.has(path)) {
				return null; // 静默拦截物理写入
			}

			if (self.crypto.isEncrypted(data)) {
				return data;
			}

			// 模式判定逻辑
			if (self.crypto.isEncrypted(data)) return data;

			const ext = path.split('.').pop()?.toLowerCase() || '';
			const shouldCompress = !NON_COMPRESSIBLE.has(ext);

			// 仅在明确开启加密模式，或该文件原本就是加密状态时，才执行加密写入
			if ((self.settings.mode === 'encrypt' || isCurrentlyEncrypted) && pwd) {
				const encrypted = await self.crypto.encrypt(data, pwd, shouldCompress);
				self.decryptedSizeCache.set(path, data.byteLength);
				return encrypted;
			}
			self.decryptedSizeCache.set(path, data.byteLength);
			return data;
		};

		adapter.write = async (path, data, options) => {
			const result = await handleWrite(path, new TextEncoder().encode(data));
			if (result === null) return;
			return typeof result === 'string' ? await self.originalWrite(path, result, options) : await self.originalWrite(path, data, options);
		};

		adapter.writeBinary = async (path, data, options) => {
			const result = await handleWrite(path, new Uint8Array(data));
			if (result === null) return;
			return typeof result === 'string' ? await self.originalWrite(path, result, options) : await self.originalWriteBinary(path, data, options);
		};

		adapter.process = async (path: string, fn: (data: string) => string, options?: DataWriteOptions): Promise<string> => {
			const content = await adapter.read(path);
			const processed = fn(content);
			await adapter.write(path, processed, options);
			return processed;
		};
	}

	/**
	 * 预热逻辑：解密文件并存入 Blob 缓存。
	 */
	private async warmupFile(file: TFile): Promise<boolean> {
		const path = file.path;
		if (this.blobUrlCache.has(path)) return true;
		try {
			const rawHead = await this.originalReadBinary(path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
			if (this.crypto.isEncrypted(rawHead) && this.getPassword()) {
				// 调用 readBinary 触发 Hook，生成并记录 Blob URL
				await this.app.vault.readBinary(file);
				return true;
			}
		} catch (e) {}
		return false;
	}

	/**
	 * 视图更新逻辑
	 */
	private fixMediaDOM() {
		// 查找所有受支持的媒体节点
		const mediaElements = document.querySelectorAll('img, video, audio, source');
		if (mediaElements.length === 0) return;

		this.blobUrlCache.forEach((blobUrl, path) => {
			// 获取由 Obsidian 原生生成的原始 URL
			const originalUrlBase = this.originalGetResourcePath(path).split('?')[0];
			// 回退匹配：处理可能出现的标准 URL 编码格式
			const encodedPath = encodeURIComponent(path).replace(/%2F/g, '/');

			mediaElements.forEach((el) => {
				const src = el.getAttribute('src');
				// 如果标签还没挂载或者已经是 blob 了，跳过
				if (!src || src.startsWith('blob:')) return;

				// Obsidian 会追加 ? 参数缓存修饰，只对比基础路径
				const srcBase = src.split('?')[0];
				
				// 匹配上了残留的本地物理路径，说明浏览器之前请求失败了，直接通过 DOM 更新替换为 Blob
				if (srcBase && (srcBase === originalUrlBase || srcBase.endsWith(path) || srcBase.endsWith(encodedPath))) {
					el.setAttribute('src', blobUrl);
					// 对于视频或音频播放器，需要调起重新加载流
					if (el instanceof HTMLMediaElement) {
						el.load();
					}
				}
			});
		});
	}

	/**
	 * 更新状态栏 UI 展示文件的加密状态
	 */
	private async updateStatusBar(file: TFile | null) {
		if (!file) { 
			this.statusBarItem.hide();
			return; 
		}
		try {
			// 1. 物理状态检查（仅用于状态标展示）
			const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
			const isEnc = this.crypto.isEncrypted(rawHead);
			// 物理上是加密文件，且必须在“成功解密列表”中，才算“透明”
			const isTransparent = this.decryptedPaths.has(file.path);
			
			this.statusBarItem.empty();
			if (isEnc) {
				this.statusBarItem.show();
				
				// 解密成功绿色，未成功（只读）红色
				this.statusBarItem.toggleClass("is-transparent", isTransparent);
				this.statusBarItem.toggleClass("is-locked", !isTransparent);

				const span = this.statusBarItem.createSpan();
				setIcon(span, "lock");
				
				// 移动端仅显示图标，非移动端根据解密实况显示文字
				if (!Platform.isMobile) {
					span.createSpan({ text: isTransparent ? i18n.t('STATUS_TRANSPARENT') : i18n.t('STATUS_LOCKED') });
				}
			} else {
				this.statusBarItem.hide();
			}

			// 2. 预热任务队列：不论笔记本身是否加密，都要预热其中的媒体
			const warmupTasks: Promise<boolean>[] =[];
			
			// 如果当前文件本身就是可预览的媒体（如直接打开图片/PDF），先预热它
			if (PREVIEW_SUPPORTED.has(file.extension.toLowerCase())) {
				warmupTasks.push(this.warmupFile(file));
			}

			// 扫描 Markdown 中的所有双链嵌入附件 (Images/PDFs/Videos)
			const cache = this.app.metadataCache.getFileCache(file);
			if (cache?.embeds) {
				for (const embed of cache.embeds) {
					const embedFile = this.app.metadataCache.getFirstLinkpathDest(embed.link, file.path);
					if (embedFile instanceof TFile) {
						warmupTasks.push(this.warmupFile(embedFile));
					}
				}
			}

			// 3. 阻塞等待：确保所有相关的加密附件都已解密并生成 Blob URL
			if (warmupTasks.length > 0) {
				const results = await Promise.all(warmupTasks);
				// 如果产生了任何一个新解密的映射，触发 DOM 重载以修复媒体错位。
				if (results.some(r => r)) {
					this.fixMediaDOM();
				}
			}

		} catch (e) { this.statusBarItem.hide(); }
	}

	/**
	 * 安全转换机制
	 * 逻辑：写入副本 -> 校验副本 -> 替换原件
	 */
	private async safeConvertProcess(path: string, extension: string, action: 'encrypt' | 'decrypt', pwd: string): Promise<boolean> {
		const tempPath = normalizePath(path + ".phantom_tmp");
		try {
			let targetData: Uint8Array | string;
			let originalDataLength = 0;

			// 1. 内存转换
			if (action === 'encrypt') {
				const data = new Uint8Array(await this.originalReadBinary(path));
				originalDataLength = data.byteLength;
				targetData = await this.crypto.encrypt(data, pwd, !NON_COMPRESSIBLE.has(extension));
			} else {
				const rawText = await this.originalRead(path);
				const decrypted = await this.crypto.decrypt(rawText, pwd);
				if (!decrypted) throw new Error(i18n.t('ERR_MEM_DECRYPT'));
				targetData = decrypted;
				originalDataLength = decrypted.byteLength;
			}

			// 2. 写入副本
			if (typeof targetData === 'string') {
				await this.originalWrite(tempPath, targetData);
			} else {
				await this.originalWriteBinary(tempPath, targetData);
			}

			// 3. 副本校验
			const tempRead = await this.originalReadBinary(tempPath);
			if (action === 'encrypt') {
				const tempArmored = new TextDecoder().decode(tempRead);
				const testPlain = await this.crypto.decrypt(tempArmored, pwd);
				if (!testPlain || testPlain.byteLength !== originalDataLength) {
					throw new Error(i18n.t('ERR_VAL_ENC_CORRUPT'));
				}
			} else {
				if (tempRead.byteLength !== (targetData as Uint8Array).byteLength) {
					throw new Error(i18n.t('ERR_VAL_DEC_MISMATCH'));
				}
			}

			// 4. 原子替换：删除原件并重命名副本
			// 在某些情况 rename 可能会失败，先 remove 再 rename
			const oldAbstractFile = this.app.vault.getAbstractFileByPath(path);
			if (oldAbstractFile) {
				await this.app.vault.delete(oldAbstractFile);
			}
            
            // 获取临时文件的抽象引用并重命名
            const tempAbstractFile = this.app.vault.getAbstractFileByPath(tempPath);
            if (tempAbstractFile) {
                await this.app.vault.rename(tempAbstractFile, path);
            } else {
                // 如果 Vault API 没能即时识别临时文件，回退到 Adapter API 重命名
                await this.app.vault.adapter.rename(tempPath, path);
            }
			
			return true;

		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			// 失败时尝试清理副本，如果清理失败说明是系统问题，保留副本给用户手动抢救
			console.error(i18n.t('LOG_ERR_CONVERSION', { path }), message);
			try { await this.app.vault.adapter.remove(tempPath); } catch (ce) {}
			return false;
		}
	}

	/**
	 * 手动切换单文件的加解密物理状态
	 */
	private async manuallyToggleFile(file: TFile) {
		const pwd = this.getPassword();
		if (!pwd) { new Notice(i18n.t('NOTICE_SET_PASSWORD')); return; }
		
		const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
		const isEnc = this.crypto.isEncrypted(rawHead);

		const action = isEnc ? 'decrypt' : 'encrypt';
		
		// 接入带有校验恢复机制的安全转换流
		const success = await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action, pwd);
		
		if (success) {
			new Notice(isEnc ? i18n.t('NOTICE_RESTORED', { name: file.name }) : i18n.t('NOTICE_ENCRYPTED', { name: file.name }));
		} else {
			new Notice(i18n.t('NOTICE_FAILED', { name: file.name }));
		}
		
		await this.updateStatusBar(file);
	}

	/**
	 * 批量处理文件夹下的加解密逻辑
	 * 采用底层安全旁路执行，通过读取/写入底层原生的 adapter API 绕开 Hook，防止死循环。
	 */
	private async batchProcessFolder(folder: TFolder, action: 'encrypt' | 'decrypt') {
		const pwd = this.getPassword();
		if (!pwd) { new Notice(i18n.t('NOTICE_SET_PASSWORD')); return; }
		
		let successCount = 0;
		const isEncryptAction = action === 'encrypt';
        
        // 递归遍历目标文件夹的 children 树
        const targetFiles: TFile[] = [];
        const recursiveCollect = (curr: TFolder) => {
            for (const child of curr.children) {
                if (child instanceof TFile) {
                    // 只收集符合处理条件的文件类型
                    if (child.extension === 'md' || PREVIEW_SUPPORTED.has(child.extension.toLowerCase()) || NON_COMPRESSIBLE.has(child.extension.toLowerCase())) {
                        targetFiles.push(child);
                    }
                } else if (child instanceof TFolder) {
                    recursiveCollect(child);
                }
            }
        };

        recursiveCollect(folder);
		
		new Notice(i18n.t('NOTICE_BATCH_START', { count: targetFiles.length }));

		for (const file of targetFiles) {
            try {
                // 直接通过底层 Adapter 探查头信息判断状态
                const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
                const isEnc = this.crypto.isEncrypted(rawHead);

                if ((isEncryptAction && !isEnc) || (!isEncryptAction && isEnc)) {
                    // 接入带有校验恢复机制的安全转换流
                    const success = await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action, pwd);
                    if (success) successCount++;
                }
            } catch (e) {
                const actionName = isEncryptAction ? i18n.t('MODE_ENCRYPT') : i18n.t('MODE_DECRYPT');
                console.error(i18n.t('LOG_BATCH_ERROR', { action: actionName, path: file.path }), e);
            }
		}

		new Notice(i18n.t('NOTICE_BATCH_FINISH', { count: successCount }));
		// 操作完成后强制刷新一次当前激活窗口的状态标
		this.updateStatusBar(this.app.workspace.getActiveFile());
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

		new Setting(containerEl)
			.setName(i18n.t('MODE'))
			.setDesc(i18n.t('MODE_DESC'))
			.addDropdown(d => d
				.addOption('none', i18n.t('MODE_NONE'))
				.addOption('encrypt', i18n.t('MODE_ENCRYPT'))
				.setValue(this.plugin.settings.mode)
				.onChange(async v => {
					this.plugin.settings.mode = v as any;
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
