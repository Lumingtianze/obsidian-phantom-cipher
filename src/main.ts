import { App, Plugin, PluginSettingTab, Setting, SecretComponent, Notice, TFile, TFolder, setIcon, arrayBufferToBase64, base64ToArrayBuffer, DataWriteOptions, Platform, normalizePath } from 'obsidian';
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
 * 6. 结构化扩展：采用 ENC_V1:{ExtBlock}:{Payload}。ExtBlock 为基于 Key=Value&... 的紧凑元数据区，具有独立 Checksum 签名校验，支持受损隔离与降级回退。
 * 
 * 架构：基于官方 API 规范的逻辑层与物理层分离。
 * - Adapter (物理层)：放开 read/stat，拦截 write 以保证加密落盘。兼容同步插件，同步插件可直接拿取底层密文，防止冲突。
 * - Vault (逻辑层)：拦截 read/cachedRead/process，为编辑器 UI 动态提供明文。
 */

interface PhantomCipherSettings {
	mode: 'encrypt' | 'none';
	secretName: string;
	encryptMedia: boolean;
}

// 由于当前架构无需读取元数据，暂时将 ExtBlock 相关定义与处理函数注释保留
// 文件头部结构精简为 ENC_V1::Payload。等未来有需要再开启。
/*
// 独立的扩展数据结构，使用 2字母 短键规范避免冲突，预留同步插件联动的可能性
interface PhantomExtensionData {
	sz?: number; // sz (size): 原始解密后的大小 (Base36 编码)

	// --- 以下为未来预留设计的标准词汇空间，当前版本暂不装载 ---
	// mt?: number; // mtime: 原始修改时间 Unix 时间戳 (Base36 编码，供同步插件判断真伪修改)
	// ct?: number; // ctime: 原始创建时间 Unix 时间戳 (Base36 编码)
	// ex?: string; // ext: 原始扩展名 (为后续方案预留，免解密即可获知 MimeType)

	// cx?: string; // checksum: 扩展区自身的完整性签名校验（代码内动态生成并校验，不在此定义）

	[key: string]: string | number | undefined; // 处理未来可能引入的其他未知扩展键
}
*/

const DEFAULT_SETTINGS: PhantomCipherSettings = {
	mode: 'none',
	secretName: '',
	encryptMedia: false
};

const MAGIC_HEADER = "ENC_V1:";
const SALT_SIZE = 16;
const IV_SIZE = 12;

// 限制内存中同时存在的解密媒体文件数量
const BLOB_CACHE_LIMIT = Platform.isMobile ? 100 : 200;

// 压缩阈值：2048 字节 (2KB)
// 低于此大小的数据不进行压缩，以避免 CompressionStream 的异步调度开销超过加密本身的收益
const COMPRESSION_THRESHOLD = 2048;

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
	'mp3', 'ogg', 'opus', 'm4a', 'flac', 'aac', 'wav', //音频
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
	public toBuffer(arr: Uint8Array): ArrayBuffer {
		const buf = arr.buffer;
		if (buf instanceof ArrayBuffer) {
			return buf.slice(arr.byteOffset, arr.byteOffset + arr.byteLength);
		}

		const fixed = new ArrayBuffer(arr.byteLength);
		new Uint8Array(fixed).set(arr);
		return fixed;
	}

	// /**
	//  * MurmurHash3 32-bit 实现
	//  * 优于 FNV-1a，具有更好的雪崩效应和更低的碰撞率
	//  * 扩展扩展数据块的数据块的快速校验
	//  */
	// private calculateChecksum(str: string, seed: number = 0x12345678): string {
	// 	const data = new TextEncoder().encode(str);
	// 	const nblocks = Math.floor(data.length / 4);
	// 	let h1 = seed;
	//
	// 	const c1 = 0xcc9e2d51;
	// 	const c2 = 0x1b873593;
	//
	// 	// 块处理 (每 4 字节一组)
	// 	for (let i = 0; i < nblocks; i++) {
	// 		const index = i * 4;
	// 		// 模拟小端序读取 32 位整数
	// 		let k1 = (data[index]!) |
	// 			(data[index + 1]! << 8) |
	// 			(data[index + 2]! << 16) |
	// 			(data[index + 3]! << 24);
	//
	// 		k1 = Math.imul(k1, c1);
	// 		k1 = (k1 << 15) | (k1 >>> 17);
	// 		k1 = Math.imul(k1, c2);
	//
	// 		h1 ^= k1;
	// 		h1 = (h1 << 13) | (h1 >>> 19);
	// 		h1 = Math.imul(h1, 5) + 0xe6546b64;
	// 	}
	//
	// 	// 尾部处理
	// 	let k2 = 0;
	// 	const tailIndex = nblocks * 4;
	// 	const remaining = data.length % 4;
	//
	// 	if (remaining >= 3) {
	// 		k2 ^= data[tailIndex + 2]! << 16;
	// 	}
	// 	if (remaining >= 2) {
	// 		k2 ^= data[tailIndex + 1]! << 8;
	// 	}
	// 	if (remaining >= 1) {
	// 		k2 ^= data[tailIndex]!;
	// 		k2 = Math.imul(k2, c1);
	// 		k2 = (k2 << 15) | (k2 >>> 17);
	// 		k2 = Math.imul(k2, c2);
	// 		h1 ^= k2;
	// 	}
	//
	// 	// 最终混淆
	// 	h1 ^= data.length;
	// 	h1 ^= h1 >>> 16;
	// 	h1 = Math.imul(h1, 0x85ebca6b);
	// 	h1 ^= h1 >>> 13;
	// 	h1 = Math.imul(h1, 0xc2b2ae35);
	// 	h1 ^= h1 >>> 16;
	//
	// 	// 使用 Base36 编码返回
	// 	return (h1 >>> 0).toString(36);
	// }

	// /**
	//  * 序列化扩展结构：转为 sz=v&k2=v2&cx=HASH 的紧凑且防篡改格式
	//  */
	// private stringifyExt(ext: PhantomExtensionData): string {
	// 	const parts: string[] = [];
	// 	if (ext.sz !== undefined) parts.push(`sz=${ext.sz.toString(36)}`);
	//
	// 	const payload = parts.join('&');
	// 	if (!payload) return ""; // 空扩展
	//
	// 	const cx = this.calculateChecksum(payload);
	// 	return `${payload}&cx=${cx}`;
	// }

	// /**
	//  * 反序列化扩展结构：剥离签名进行散列比对，验证失败触发拦截降级
	//  */
	// private parseExt(extStr: string): PhantomExtensionData | null {
	// 	if (!extStr) return {};
	//
	// 	// 拆离散列签名区
	// 	const cxMatch = extStr.match(/&cx=([^&]+)$/);
	// 	let payload = extStr;
	// 	let expectedCx = '';
	//
	// 	if (cxMatch) {
	// 		expectedCx = cxMatch[1]!;
	// 		payload = extStr.substring(0, cxMatch.index);
	// 	} else {
	// 		// 找不到签名，意味着数据结构受损或非标准篡改，抛弃元数据
	// 		return null;
	// 	}
	//
	// 	// 验证内容完整性
	// 	if (this.calculateChecksum(payload) !== expectedCx) {
	// 		return null; // 散列不匹配，元数据被污染，触发返回 null 以供上层降级
	// 	}
	//
	// 	const data: PhantomExtensionData = {};
	// 	const parts = payload.split('&');
	// 	for (const part of parts) {
	// 		const [k, v] = part.split('=');
	// 		if (k === 'sz' && v) {
	// 			const parsedSize = parseInt(v, 36);
	// 			if (!isNaN(parsedSize)) data.sz = parsedSize;
	// 		} else if (k && v) {
	// 			data[k] = v; // 将未知/未来的扩展字段兜底保存
	// 		}
	// 	}
	// 	return data;
	// }

	// /**
	//  * 提取外置的结构化扩展数据
	//  */
	// getExtensionData(headerText: string): PhantomExtensionData | null {
	// 	if (!headerText.startsWith(MAGIC_HEADER)) return null;
	//
	// 	const body = headerText.substring(MAGIC_HEADER.length);
	// 	const colonIndex = body.indexOf(':');
	//
	// 	// 只有在存在次级分隔符冒号时，才证明是完全符合结构的新版数据
	// 	if (colonIndex > -1) {
	// 		const extStr = body.substring(0, colonIndex);
	// 		return this.parseExt(extStr);
	// 	}
	// 	return null;
	// }

	/**
	 * 获取纯净的 Base64 Payload
	 * 此处逻辑与元数据提取严格隔离，确保只要冒号后面的载荷完整就能返回，不受元数据损毁影响
	 */
	private getBase64Payload(armoredText: string): string | null {
		const body = armoredText.substring(MAGIC_HEADER.length);
		const colonIndex = body.indexOf(':');

		// 冒号后方即为密文载荷，支持形如 ENC_V1::Payload (空扩展段) 的情况
		if (colonIndex > -1) {
			return body.substring(colonIndex + 1);
		}
		return null;
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
	async getEffectiveKey(passwordBytes: Uint8Array, saltArr: Uint8Array): Promise<CryptoKey> {
		const saltKey = arrayBufferToBase64(this.toBuffer(saltArr));
		if (this.keyMapCache.has(saltKey)) return this.keyMapCache.get(saltKey)!;

		// 队列化派生请求
		if (this.derivationPromise) return await this.derivationPromise;

		this.derivationPromise = (async () => {
			const result = await argon2id({
				password: passwordBytes, salt: saltArr, iterations: 3, memorySize: 65536, parallelism: 4, hashLength: 32, outputType: 'binary'
			});
			const derivedKey = await crypto.subtle.importKey("raw", this.toBuffer(result), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
			this.keyMapCache.set(saltKey, derivedKey);

			// 派生完成后立刻抹零
			result.fill(0);
			return derivedKey;
		})();

		try {
			return await this.derivationPromise;
		} finally {
			this.derivationPromise = null;
		}
	}

	/**
	 * 加密执行逻辑：处理压缩 -> 加密 -> 组合完整的带元数据的加装体
	 */
	async encrypt(data: Uint8Array, passwordBytes: Uint8Array, shouldCompress: boolean): Promise<string> {
		let payload = data;
		let compressionFlag = 0;

		// 扩展名允许且数据大小超过阈值进行压缩
		if (shouldCompress && data.byteLength > COMPRESSION_THRESHOLD) {
			try {
				payload = await this.compress(data);
				compressionFlag = 1;
			} catch {
				// 如果压缩失败，降级回不压缩模式，确保数据不丢失
				payload = data;
				compressionFlag = 0;
			}
		}
		// 运行时保持盐值一致，确保同一密码下的所有文件共用一个 CryptoKey 缓存
		if (!this.sessionSalt) {
			this.sessionSalt = crypto.getRandomValues(new Uint8Array(SALT_SIZE));
		}
		const salt = this.sessionSalt;
		const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
		const key = await this.getEffectiveKey(passwordBytes, salt);
		const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: this.toBuffer(iv) }, key, this.toBuffer(payload));

		// 存储结构：Salt(16) + IV(12) + CompressionFlag(1) + Ciphertext(n)
		const combined = new Uint8Array(SALT_SIZE + IV_SIZE + 1 + ciphertext.byteLength);
		combined.set(salt, 0);
		combined.set(iv, SALT_SIZE);
		combined.set([compressionFlag], SALT_SIZE + IV_SIZE);
		combined.set(new Uint8Array(ciphertext), SALT_SIZE + IV_SIZE + 1);

		// 精简后的结构直接为 ENC_V1::Payload，跳过 ExtBlock 处理
		// const extData: PhantomExtensionData = { sz: data.byteLength };
		// const extBlock = this.stringifyExt(extData);
		// return MAGIC_HEADER + extBlock + ":" + arrayBufferToBase64(this.toBuffer(combined));

		return MAGIC_HEADER + ":" + arrayBufferToBase64(this.toBuffer(combined));
	}

	/**
	 * 解密执行逻辑：拆包提取基础 Base64 -> 解密 -> 处理解压
	 */
	async decrypt(armoredText: string, passwordBytes: Uint8Array): Promise<Uint8Array | null> {
		if (!this.isEncrypted(armoredText)) return null;

		// 解密获取 Payload 时自动隔离元数据区
		// 因此即使元数据因为外部篡改受损，只要后面的 Base64 完好，解密就不会崩溃
		const base64Payload = this.getBase64Payload(armoredText);
		if (!base64Payload) return null; // 完全找不到载荷分隔符才判定格式报废

		const combined = new Uint8Array(base64ToArrayBuffer(base64Payload));
		if (combined.length < SALT_SIZE + IV_SIZE + 1) return null;

		const salt = combined.subarray(0, SALT_SIZE);
		const iv = combined.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE);
		const compressionFlag = combined[SALT_SIZE + IV_SIZE];
		const ciphertext = combined.subarray(SALT_SIZE + IV_SIZE + 1);

		const key = await this.getEffectiveKey(passwordBytes, salt);
		try {
			const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.toBuffer(iv) }, key, this.toBuffer(ciphertext));
			let finalData: Uint8Array = new Uint8Array(decrypted);
			if (compressionFlag === 1) finalData = await this.decompress(finalData);
			return finalData;
		} catch {
			return null; // 载荷自身 GCM 校验失败才会返回 null
		}
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
		if (this.sessionSalt) {
			this.sessionSalt.fill(0); // 盐值清除时同步擦除内存
			this.sessionSalt = null;
		}
	}
}

export default class PhantomCipherPlugin extends Plugin {
	settings!: PhantomCipherSettings;
	crypto: CryptoHelper = new CryptoHelper();

	// 内存混淆安全凭证
	private memoryKey: Uint8Array | null = null;
	private obfuscatedPassword: Uint8Array | null = null;

	private originalRead!: (path: string) => Promise<string>;
	private originalWrite!: (path: string, data: string, options?: DataWriteOptions) => Promise<void>;
	private originalReadBinary!: (path: string) => Promise<ArrayBuffer>;
	private originalWriteBinary!: (path: string, data: ArrayBuffer, options?: DataWriteOptions) => Promise<void>;
	private originalProcess!: (path: string, fn: (data: string) => string, options?: DataWriteOptions) => Promise<string>;
	private originalGetResourcePath!: (path: string) => string;

	// 备份 Vault 层原生方法。解密操作移交逻辑层，以遵循官方安全分层规范
	private originalVaultRead!: (file: TFile) => Promise<string>;
	private originalVaultReadBinary!: (file: TFile) => Promise<ArrayBuffer>;
	private originalVaultCachedRead!: (file: TFile) => Promise<string>;

	private statusBarItem!: HTMLElement;
	private errorThrottler: Map<string, number> = new Map();

	private decryptedPaths: Set<string> = new Set(); // 追踪真正解密成功的路径
	private blobUrlCache: Map<string, string> = new Map(); // 缓存已解密文件的 Blob URL，确保编辑器和媒体加载正常

	private visibilityTimeout: number | null = null; // 后台清理定时器引用

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
	 * 判断当前是否存在主密码缓存
	 */
	private hasPassword(): boolean {
		return this.memoryKey !== null && this.obfuscatedPassword !== null;
	}

	/**
	 * 获取密码时即时还原
	 */
	private async withPassword<T>(callback: (pwd: Uint8Array) => Promise<T>): Promise<T | null> {
		const memKey = this.memoryKey;
		const obfPwd = this.obfuscatedPassword;

		if (!memKey || !obfPwd) return null;

		const pwdBytes = new Uint8Array(obfPwd.length);
		for (let i = 0; i < obfPwd.length; i++) {
			pwdBytes[i] = obfPwd[i]! ^ memKey[i]!;
		}

		try {
			return await callback(pwdBytes);
		} finally {
			// 主动清理明文密码所在的临时字节数组
			pwdBytes.fill(0);
		}
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

	/**
	 * 视口失焦事件处理器。负责在挂起到后台且闲置 10 分钟后主动擦除驻留的派生密钥
	 */
	private onVisibilityChange = () => {
		if (activeDocument.hidden) {
			this.visibilityTimeout = window.setTimeout(() => {
				this.crypto.clearCache(); // 清除派生凭据
			}, 10 * 60 * 1000); // 10 minutes
		} else {
			if (this.visibilityTimeout !== null) {
				window.clearTimeout(this.visibilityTimeout);
				this.visibilityTimeout = null;
			}
		}
	};

	/**
	 * 当密码重置或者生命周期更迭时，必须立即无差别摧毁之前密码派生出的所有成果。
	 * 避免由于更换密码导致的旧图像/文本在内存中持续暴露。
	 */
	public clearInternalState() {
		this.crypto.clearCache();
		this.decryptedPaths.clear();

		// 显式回收掉浏览器缓存的内存 Blob 映射
		this.blobUrlCache.forEach(url => URL.revokeObjectURL(url));
		this.blobUrlCache.clear();
	}

	async onload() {
		await this.loadSettings();

		// 状态栏初始化
		this.statusBarItem = this.addStatusBarItem();
		this.statusBarItem.addClass("phantom-cipher-status-bar");

		// 功能区图标：手动转换按钮
		this.addRibbonIcon('lock', i18n.t('RIBBON_TEXT'), () => {
			const file = this.app.workspace.getActiveFile();
			if (file) void this.manuallyToggleFile(file);
		});

		// 绑定右键菜单项
		this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
			if (file instanceof TFile) {
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_TEXT')).setIcon("key").onClick(() => { void this.manuallyToggleFile(file); });
				});
			} else if (file instanceof TFolder) {
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_BATCH_ENCRYPT')).setIcon("lock").onClick(() => { void this.batchProcessFolder(file, 'encrypt'); });
				});
				menu.addItem((item) => {
					item.setTitle(i18n.t('MENU_BATCH_DECRYPT')).setIcon("unlock").onClick(() => { void this.batchProcessFolder(file, 'decrypt'); });
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
		this.originalGetResourcePath = adapter.getResourcePath.bind(adapter);

		// 备份 Vault 层方法用于挂载解密逻辑，实现物理/逻辑读写分层
		const vault = this.app.vault;
		this.originalVaultRead = vault.read.bind(vault);
		this.originalVaultReadBinary = vault.readBinary.bind(vault);
		this.originalVaultCachedRead = vault.cachedRead.bind(vault);

		this.hookAdapter();
		this.addSettingTab(new CryptoSettingTab(this.app, this));

		// 监听文件打开、修改、以及元数据更新（处理启动时的索引延迟）
		this.registerEvent(this.app.workspace.on('file-open', (file) => { void this.updateStatusBar(file); }));
		this.registerEvent(this.app.vault.on('modify', (file) => {
			if (file instanceof TFile && file === this.app.workspace.getActiveFile()) void this.updateStatusBar(file);
		}));
		this.registerEvent(this.app.metadataCache.on('changed', (file) => {
			if (file === this.app.workspace.getActiveFile()) void this.updateStatusBar(file);
		}));

		this.registerDomEvent(activeDocument, 'visibilitychange', this.onVisibilityChange);
		this.registerEvent(this.app.workspace.on('window-open', (workspaceWindow) => {
			// 为新弹出的每一个独立笔记窗口绑定安全焦点追踪
			this.registerDomEvent(workspaceWindow.doc, 'visibilitychange', this.onVisibilityChange);
		}));

		this.app.workspace.onLayoutReady(() => {
			void this.fetchPassword().then(() => {
				// 延迟 500ms 待视图稳定后执行初次预热
				window.setTimeout(() => {
					const activeFile = this.app.workspace.getActiveFile();
					if (activeFile) void this.updateStatusBar(activeFile);
				}, 500);
			});
		});
	}

	onunload() {
		// 插件卸载时还原底层 Adapter 引用
		const adapter = this.app.vault.adapter;
		adapter.read = this.originalRead;
		adapter.write = this.originalWrite;
		adapter.readBinary = this.originalReadBinary;
		adapter.writeBinary = this.originalWriteBinary;
		adapter.process = this.originalProcess;
		adapter.getResourcePath = this.originalGetResourcePath;

		// 还原逻辑层的方法
		const vault = this.app.vault;
		vault.read = this.originalVaultRead;
		vault.readBinary = this.originalVaultReadBinary;
		vault.cachedRead = this.originalVaultCachedRead;

		// 取代原本单独清理内存的代码，统一使用强制清理逻辑
		this.clearInternalState();

		if (this.visibilityTimeout !== null) window.clearTimeout(this.visibilityTimeout);

		this.setPassword(null); // 显式擦除混淆内存
	}

	/**
	 * 从钥匙串中加载主密码
	 */
	async fetchPassword() {
		const storage = this.app.secretStorage;
		if (!storage) return;

		const raw = storage.getSecret(this.settings.secretName);

		// 密码重置或获取时，立刻清洗缓存
		this.clearInternalState();

		if (raw) {
			this.setPassword(raw); // 使用混淆存储
			void this.updateStatusBar(this.app.workspace.getActiveFile());
		} else {
			this.setPassword(null);
		}
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
	 * LRU 缓存管理
	 */
	private addToBlobCache(path: string, url: string) {
		if (this.blobUrlCache.has(path)) {
			URL.revokeObjectURL(this.blobUrlCache.get(path)!);
			this.blobUrlCache.delete(path);
		}
		this.blobUrlCache.set(path, url);

		if (this.blobUrlCache.size > BLOB_CACHE_LIMIT) {
			for (const [oldPath, oldUrl] of this.blobUrlCache) {
				URL.revokeObjectURL(oldUrl);
				this.blobUrlCache.delete(oldPath);
				break; // Map 迭代严格保证插入顺序，直接 break 以准确淘汰最老的条目
			}
		}
	}

	/**
	 * 核心 Hook 逻辑：接管读取与写入流程
	 */
	private hookAdapter() {
		const adapter = this.app.vault.adapter;
		const vault = this.app.vault;
		const configDir = this.app.vault.configDir;

		// 拦截资源路径。如果是加密媒体文件，返回解密后的 Blob URL。
		adapter.getResourcePath = (path: string): string => {
			if (this.blobUrlCache.has(path)) {
				const url = this.blobUrlCache.get(path)!;
				this.blobUrlCache.delete(path);
				this.blobUrlCache.set(path, url);
				return url;
			}
			return this.originalGetResourcePath(path);
		};

		// 拦截 CachedRead，确保 Obsidian 内部缓存系统拿到的是解密后的明文
		vault.cachedRead = async (file: TFile): Promise<string> => {
			const content = await this.originalVaultCachedRead(file);

			if (file.path.startsWith(configDir) || !this.crypto.isEncrypted(content)) return content;

			if (!this.hasPassword()) await this.fetchPassword();

			if (!this.hasPassword()) {
				this.decryptedPaths.delete(file.path); // 未解密
				this.notifyPasswordMissing(); // 提示设置密码
				return content; // 返回密文原始内容
			}

			const decryptedText = await this.withPassword(async (pwdBytes) => {
				const decrypted = await this.crypto.decrypt(content, pwdBytes);
				if (decrypted) {
					this.decryptedPaths.add(file.path); // 解密成功
					const text = new TextDecoder().decode(decrypted);

					decrypted.fill(0);
					return text;
				}
				return null;
			});

			if (decryptedText !== null) return decryptedText;

			this.decryptedPaths.delete(file.path); // 解密失败
			this.notifyDecryptFailed(file.path);
			return content;
		};

		// 处理文本读取：如果是加密文件则自动解密
		vault.read = async (file: TFile): Promise<string> => {
			const content = await this.originalVaultRead(file);
			if (file.path.startsWith(configDir) || !this.crypto.isEncrypted(content)) return content;

			if (!this.hasPassword()) await this.fetchPassword();

			if (!this.hasPassword()) {
				this.decryptedPaths.delete(file.path);
				this.notifyPasswordMissing();
				return content;
			}

			const decryptedText = await this.withPassword(async (pwdBytes) => {
				const decrypted = await this.crypto.decrypt(content, pwdBytes);
				if (decrypted) {
					this.decryptedPaths.add(file.path);
					const text = new TextDecoder().decode(decrypted);

					decrypted.fill(0);
					return text;
				}
				return null;
			});

			if (decryptedText !== null) return decryptedText;

			this.decryptedPaths.delete(file.path);
			this.notifyDecryptFailed(file.path);
			return content;
		};

		// 处理二进制读取：支持附件透明解密
		vault.readBinary = async (file: TFile): Promise<ArrayBuffer> => {
			const data = await this.originalVaultReadBinary(file);
			if (file.path.startsWith(configDir) || !this.crypto.isEncrypted(data.slice(0, MAGIC_HEADER.length))) return data;

			if (!this.hasPassword()) await this.fetchPassword();

			if (!this.hasPassword()) {
				this.decryptedPaths.delete(file.path);
				this.notifyPasswordMissing();
				return data;
			}

			const decryptedData = await this.withPassword(async (pwdBytes) => {
				const armoredText = new TextDecoder().decode(data);
				const decrypted = await this.crypto.decrypt(armoredText, pwdBytes);
				if (decrypted) {
					this.decryptedPaths.add(file.path);
					// 针对媒体文件生成 Blob URL，让 app:// 协议能显示加密图片
					const ext = file.path.split('.').pop()?.toLowerCase() || '';
					if (PREVIEW_SUPPORTED.has(ext)) {
						const blob = new Blob([this.crypto.toBuffer(decrypted)], { type: this.getMimeType(ext) });
						const url = URL.createObjectURL(blob);
						// 使用 LRU 方式存储缓存
						this.addToBlobCache(file.path, url);
					}
					return this.crypto.toBuffer(decrypted);
				}
				return null;
			});

			if (decryptedData !== null) return decryptedData;

			this.decryptedPaths.delete(file.path);
			this.notifyDecryptFailed(file.path);
			return data;
		};

		/**
		 * 写入逻辑处理器：根据插件模式决定是否加密落地数据
		 */
		const handleWrite = async (path: string, data: Uint8Array): Promise<string | Uint8Array | null> => {
			if (path.startsWith(configDir)) {
				return data;
			}

			if (!this.hasPassword()) await this.fetchPassword();
			const hasPwd = this.hasPassword();
			const ext = path.split('.').pop()?.toLowerCase() || '';

			// 仅读取前 10 字节判断文件是否原本直接就是加密状态
			let isCurrentlyEncrypted = false;
			try {
				const head = await this.originalReadBinary(path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				isCurrentlyEncrypted = this.crypto.isEncrypted(head);
			} catch {
				// 合规地忽略文件无法探测的初始化情况
			}

			// 判断即将写入的内容本身是否带有加密头标识
			const isIncomingEncrypted = this.crypto.isEncrypted(data);

			// 零信任安全校验：严防中间人与脏密文注入
			// 一旦检测到试图写入系统的密文，在此处就地执行强制中转验证。
			// 绝不允许单纯依赖特征头而放行落盘，一切非经验证合法的密文皆视为攻击或损坏。
			if (isIncomingEncrypted) {
				if (!hasPwd) {
					// 若当前设备未解锁，则无法验证密文的真伪
					// 为防止垃圾数据覆写破坏本地文件，在此刻无条件拒绝写入并利用通知提醒用户。
					this.notifyPasswordMissing();
					return null;
				}

				// 强制试解密即将落盘的载荷
				const isValid = await this.withPassword(async (pwdBytes) => {
					const armoredText = new TextDecoder().decode(data);
					const decrypted = await this.crypto.decrypt(armoredText, pwdBytes);
					if (decrypted) {
						decrypted.fill(0); // 验证通过即刻销毁明文内存
						return true;
					}
					return false;
				});

				if (isValid) {
					// 验证通过：确认为当前密码下合法的密文（如同步插件写入）
					// 立刻将此文件路径加入已信任名单，并将中转的 data 原路返回给底层完成物理落盘。
					this.decryptedPaths.add(path);
					return data;
				} else {
					// 验证失败：载荷损坏、不同密码或蓄意伪造
					// 向用户抛出具有具体文件名的警告，并拒绝写入保护本地文件。
					this.notifyDecryptFailed(path);
					return null;
				}
			}

			// 以下为即将写入明文数据时的处理

			// 如果磁盘上的文件是加密的，但内存集合中没有该路径（说明本次会话中从未成功解密验证过）
			// 此时绝对禁止任何覆盖写入。防止其他插件不知情地把空白或错误明文覆写到未解锁的加密文件上。
			if (isCurrentlyEncrypted && !this.decryptedPaths.has(path)) {
				return null; // 静默拦截物理写入
			}

			const isMedia = PREVIEW_SUPPORTED.has(ext);

			// 只有当满足以下任一条件时，才执行明文加密并落地：
			// - 该文件当前在磁盘上已经是加密状态（维持一致性）
			// - 处于自动加密模式，且（不是媒体文件 或 开启了媒体加密开关）
			const shouldEncrypt = hasPwd && (
				isCurrentlyEncrypted ||
				(this.settings.mode === 'encrypt' && (!isMedia || this.settings.encryptMedia))
			);

			if (shouldEncrypt) {
				const encryptedResult = await this.withPassword(async (pwdBytes) => {
					return await this.crypto.encrypt(data, pwdBytes, !NON_COMPRESSIBLE.has(ext));
				});
				if (encryptedResult) {
					// 自身完成加密落盘后同步录入信任名单
					this.decryptedPaths.add(path);
					return encryptedResult;
				}
			}

			// 不满足加密条件，执行正常的明文放行
			return data;
		};

		adapter.write = async (path: string, data: string, options?: DataWriteOptions): Promise<void> => {
			const result = await handleWrite(path, new TextEncoder().encode(data));
			if (result === null) return;
			if (typeof result === 'string') {
				await this.originalWrite(path, result, options);
			} else {
				await this.originalWriteBinary(path, this.crypto.toBuffer(result), options);
			}
		};

		adapter.writeBinary = async (path: string, data: ArrayBuffer, options?: DataWriteOptions): Promise<void> => {
			const result = await handleWrite(path, new Uint8Array(data));
			if (result === null) return;
			if (typeof result === 'string') {
				await this.originalWrite(path, result, options);
			} else {
				await this.originalWriteBinary(path, this.crypto.toBuffer(result), options);
			}
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
			if (this.crypto.isEncrypted(rawHead) && this.hasPassword()) {
				// 调用被接管为解密流的 Vault API 强制缓存生成 Blob URL
				await this.app.vault.readBinary(file);
				return true;
			}
		} catch {
			// 静默跳过探测不到的媒体文件
		}
		return false;
	}

	/**
	 * 视图更新逻辑
	 */
	private fixMediaDOM() {
		// 查找所有受支持的媒体节点
		const mediaElements = activeDocument.querySelectorAll('img, video, audio, source');
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
					if (el.tagName === 'VIDEO' || el.tagName === 'AUDIO') {
						(el as HTMLMediaElement).load();
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
			const warmupTasks: Promise<boolean>[] = [];

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

		} catch {
			this.statusBarItem.hide();
		}
	}

	/**
	 * 安全转换机制
	 * 逻辑：写入副本 -> 校验副本 -> 替换原件
	 */
	private async safeConvertProcess(path: string, extension: string, action: 'encrypt' | 'decrypt'): Promise<boolean> {
		const tempPath = normalizePath(path + ".phantom_tmp");
		try {
			let originalDataLength = 0;

			const convertResult = await this.withPassword(async (pwdBytes) => {
				let targetData: Uint8Array | string;

				// 1. 内存转换
				if (action === 'encrypt') {
					// 物理层获取原本的数据执行加密
					const data = new Uint8Array(await this.originalReadBinary(path));
					originalDataLength = data.byteLength;
					targetData = await this.crypto.encrypt(data, pwdBytes, !NON_COMPRESSIBLE.has(extension));
				} else {
					// 物理层提取原密文用于解密
					const rawText = await this.originalRead(path);
					const decrypted = await this.crypto.decrypt(rawText, pwdBytes);
					if (!decrypted) throw new Error(i18n.t('ERR_MEM_DECRYPT'));
					targetData = decrypted;
					originalDataLength = decrypted.byteLength;
				}

				// 2. 写入副本
				if (typeof targetData === 'string') {
					await this.originalWrite(tempPath, targetData);
				} else {
					await this.originalWriteBinary(tempPath, this.crypto.toBuffer(targetData));
				}

				// 3. 副本校验
				const tempRead = await this.originalReadBinary(tempPath);
				if (action === 'encrypt') {
					const tempArmored = new TextDecoder().decode(tempRead);
					const testPlain = await this.crypto.decrypt(tempArmored, pwdBytes);
					if (!testPlain || testPlain.byteLength !== originalDataLength) {
						if (testPlain) testPlain.fill(0);
						throw new Error(i18n.t('ERR_VAL_ENC_CORRUPT'));
					}
					testPlain.fill(0);
				} else {
					if (tempRead.byteLength !== (targetData as Uint8Array).byteLength) {
						if (targetData instanceof Uint8Array) targetData.fill(0);
						throw new Error(i18n.t('ERR_VAL_DEC_MISMATCH'));
					}
				}

				if (targetData instanceof Uint8Array) targetData.fill(0);

				return true;
			});

			if (!convertResult) return false;

			// 4. 原子替换：删除原件并重命名副本
			// 在某些情况 rename 可能会失败，先 remove 再 rename
			try {
				await this.app.vault.adapter.remove(path);
			} catch {
				/* 文件如果被强行抢占或不存在，忽略错误，让下面继续执行覆盖尝试 */
			}

			// 获取临时文件的抽象引用并重命名
			const tempAbstractFile = this.app.vault.getAbstractFileByPath(tempPath);
			if (tempAbstractFile) {
				await this.app.vault.rename(tempAbstractFile, path);
			} else {
				// 如果 Vault API 没能即时识别临时文件，回退到 Adapter API 重命名
				await this.app.vault.adapter.rename(tempPath, path);
			}

			// 转换成功后，强制 Obsidian 重新读取并建立索引
			const file = this.app.vault.getAbstractFileByPath(path);
			if (file instanceof TFile) {
				this.app.metadataCache.trigger("changed", file);
			}
			return true;

		} catch (e) {
			const message = e instanceof Error ? e.message : String(e);
			// 失败时尝试清理副本，如果清理失败说明是系统问题，保留副本给用户手动抢救
			console.error(i18n.t('LOG_ERR_CONVERSION', { path }), message);
			try { await this.app.vault.adapter.remove(tempPath); } catch { /* 忽略清理失败 */ }
			return false;
		}
	}

	/**
	 * 手动切换单文件的加解密物理状态
	 */
	private async manuallyToggleFile(file: TFile) {
		if (!this.hasPassword()) { new Notice(i18n.t('NOTICE_SET_PASSWORD')); return; }

		const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
		const isEnc = this.crypto.isEncrypted(rawHead);
		const ext = file.extension.toLowerCase();

		// 如果是手动加密媒体文件但开关没开，进行提醒
		if (!isEnc && PREVIEW_SUPPORTED.has(ext) && !this.settings.encryptMedia) {
			new Notice(i18n.t('NOTICE_MEDIA_IGNORE'));
			return;
		}

		const action = isEnc ? 'decrypt' : 'encrypt';

		// 接入带有校验恢复机制的安全转换流
		const success = await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action);

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
		if (!this.hasPassword()) { new Notice(i18n.t('NOTICE_SET_PASSWORD')); return; }

		let successCount = 0;
		const isEncryptAction = action === 'encrypt';

		// 递归遍历目标文件夹的 children 树
		const targetFiles: TFile[] = [];
		const recursiveCollect = (curr: TFolder) => {
			for (const child of curr.children) {
				if (child instanceof TFile) {
					const ext = child.extension.toLowerCase();
					// 只收集符合处理条件的文件类型
					if (ext === 'md' || (this.settings.encryptMedia && PREVIEW_SUPPORTED.has(ext))) {
						targetFiles.push(child);
					}
				} else if (child instanceof TFolder) recursiveCollect(child);
			}
		};

		recursiveCollect(folder);

		// 使用动态 Notice 显示进度
		const progressNotice = new Notice(i18n.t('NOTICE_BATCH_START', { count: targetFiles.length }), 0);

		for (let i = 0; i < targetFiles.length; i++) {
			const file = targetFiles[i]!;
			// 更新进度条文字
			progressNotice.setMessage(`🚀 ${i18n.t(isEncryptAction ? 'MODE_ENCRYPT' : 'MODE_DECRYPT')}... (${i + 1}/${targetFiles.length})`);

			try {
				// 直接通过底层 Adapter 探查头信息判断状态
				const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				const isEnc = this.crypto.isEncrypted(rawHead);

				if ((isEncryptAction && !isEnc) || (!isEncryptAction && isEnc)) {
					// 接入带有校验恢复机制的安全转换流
					const success = await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action);
					if (success) successCount++;
				}
			} catch (e) {
				const actionName = isEncryptAction ? i18n.t('MODE_ENCRYPT') : i18n.t('MODE_DECRYPT');
				console.error(i18n.t('LOG_BATCH_ERROR', { action: actionName, path: file.path }), e);
			}
		}

		progressNotice.hide(); // 处理完后关闭进度条
		new Notice(i18n.t('NOTICE_BATCH_FINISH', { count: successCount }));
		void this.updateStatusBar(this.app.workspace.getActiveFile());
	}

	async loadSettings() {
		const loadedData = (await this.loadData()) as unknown;
		this.settings = Object.assign({}, DEFAULT_SETTINGS, loadedData as Partial<PhantomCipherSettings>);
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}
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
					this.plugin.settings.mode = v as 'encrypt' | 'none';
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName(i18n.t('ENCRYPT_MEDIA'))
			.setDesc(i18n.t('ENCRYPT_MEDIA_DESC'))
			.addToggle(t => t
				.setValue(this.plugin.settings.encryptMedia)
				.onChange(async v => {
					this.plugin.settings.encryptMedia = v;
					await this.plugin.saveSettings();
				}));

		new Setting(containerEl)
			.setName(i18n.t('MASTER_KEY'))
			.setDesc(i18n.t('MASTER_KEY_DESC'))
			.addComponent(el => {
				return new SecretComponent(this.app, el)
					.setValue(this.plugin.settings.secretName)
					.onChange(async (v: string) => {
						this.plugin.settings.secretName = v;
						await this.plugin.saveSettings();
						await this.plugin.fetchPassword();
					});
			});
	}
}
