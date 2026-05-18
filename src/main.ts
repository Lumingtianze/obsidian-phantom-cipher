import { App, Plugin, PluginSettingTab, Setting, Modal, Notice, TFile, TFolder, setIcon, arrayBufferToBase64, base64ToArrayBuffer, DataWriteOptions, Platform, normalizePath } from 'obsidian';
import { argon2id } from 'hash-wasm';
import { i18n } from './i18n/helpers';

/**
 * PhantomCipher (幻影加密)
 * 核心设计：基于 Argon2id + AES-GCM 的高性能透明加解密方案。
 * 
 * 1. 架构：引入 KEK (密钥加密密钥) 与 DEK (数据加密密钥) 的信封加密架构。
 *    - 用户密码 -> Argon2id -> KEK。
 *    - 随机生成库全局 DEK。KEK 加密 DEK 得到 EDEK。
 *    - 文件载荷一律使用 DEK 加密。文件头存储 EDEK 以实现独立自愈。
 * 2. 存储：不再存储明文密码。SecretStorage (钥匙串) 仅安全存储 KEK (Base64) 与 EDEK (Base64)。
 * 3. 隔离：增加 KID (Key ID) 标识。提取 KEK Base64 的前 6 位，用于快速识别跨端文件的密钥归属，防止破坏。
 * 4. 压缩：内置 Deflate 压缩流，用于抵消 Base64 编码带来的体积膨胀。
 * 5. 透明：拦截 Vault Adapter 底层接口，实现用户无感知的加解密。
 * 6. 内存保护：采用 XOR 内存混淆，防止 KEK/DEK 明文在内存中长期驻留导致 Dump 泄露。
 * 7. 结构化扩展：采用 ENC_V2:{ExtBlock}:{Payload}。ExtBlock 为基于 Key=Value&... 的紧凑元数据区。
 */

interface PhantomCipherSettings {
	mode: 'encrypt' | 'none';
	encryptMedia: boolean;
	kekId: string;
	dekId: string;
}

// 独立的扩展数据结构，使用 2字母 短键规范避免冲突，预留同步插件联动的可能性
interface PhantomExtensionData {
	sz?: number; // sz (size): 原始解密后的大小 (Base36 编码)
	ph?: string; // ph (plaintext hash): 加密前明文的 MurmurHash3 校验和，用于解密安全转换校验
	cp?: number; // cp (compression): V2 压缩标识，1 为启用，0 为未压缩
	kid?: string; // kid (Key ID): 当前 KEK 的前 6 位截断标识符，用于阻断未知密钥覆写
	ek?: string; // ek (EDEK): 被 KEK 加密的专属 DEK 数据包
	bf?: number; // bf (binary format): 1 代表当前密文载荷为纯二进制原生拼合，0 代表 Base64 字符串
	_isValid?: boolean; // 内部标记：元数据校验和是否通过
	[key: string]: string | number | boolean | undefined;  // 处理未来可能引入的其他未知扩展键
}

const DEFAULT_SETTINGS: PhantomCipherSettings = {
	mode: 'none',
	encryptMedia: false,
	kekId: '',
	dekId: ''
};

const MAGIC_HEADER = "ENC_V2:";
const MAGIC_HEADER_V1 = "ENC_V1:"; // 用于检测旧版降级
const IV_SIZE = 12;
const TAG_SIZE = 16;
const KEK_SALT = new TextEncoder().encode("Phantom_Cipher_KEK_Salt_V2_2026");

// V8 引擎的内存限制
const MAX_FILE_SIZE = 2000 * 1024 * 1024;

// 分块加密阈值：4MB
const CHUNK_SIZE = 4 * 1024 * 1024;

// 限制内存中同时存在的解密媒体文件数量
const BLOB_CACHE_LIMIT = Platform.isMobile ? 100 : 200;

// 压缩阈值：2048 字节 (2KB)
// 低于此大小的数据不进行压缩，以避免 CompressionStream 的异步调度开销超过加密本身的收益
const COMPRESSION_THRESHOLD = 2048;

// 预设不进行二次压缩的文件类型列表
const NON_COMPRESSIBLE = new Set([
	'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', // 图片
	'pdf', // 文档
	'mp3', 'ogg', 'opus', 'm4a', 'flac', 'aac', 'wav', // 音频
	'mp4', 'webm', 'ogv', 'mov', 'mkv' // 视频
]);

// 支持预览的文件类型列表
const PREVIEW_SUPPORTED = new Set([
	'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'avif', // 图片
	'pdf', // 文档
	'mp3', 'ogg', 'opus', 'm4a', 'flac', 'aac', 'wav', //音频
	'mp4', 'webm', 'ogv', 'mov', 'mkv' // 视频
]);


// 供 PDF 原生渲染器劫持使用的类型声明
interface PDFOpenArgs {
	url?: string;
	data?: Uint8Array;
	[key: string]: unknown;
}

interface ObsidianPDFApp {
	__phantomHooked?: boolean;
	open: (args: PDFOpenArgs) => Promise<unknown>;
}

interface PDFViewerCreator {
	__phantomHooked?: boolean;
	(this: unknown, ...args: unknown[]): ObsidianPDFApp;
}

interface PDFjsViewer {
	createObsidianPDFViewer?: PDFViewerCreator;
}

interface ObsidianWindow extends Window {
	pdfjsViewer?: PDFjsViewer;
}


/**
 * 安全内存凭证容器 (XOR 混淆)
 * 用于将 KEK 和 DEK 的原始字节在内存中打散，防止直接扫描内存提取。
 */
class SecureKey {
	private memoryKey: Uint8Array;
	private obfuscatedData: Uint8Array;

	constructor(data: Uint8Array) {
		this.memoryKey = crypto.getRandomValues(new Uint8Array(data.length));
		this.obfuscatedData = new Uint8Array(data.length);
		for (let i = 0; i < data.length; i++) {
			this.obfuscatedData[i] = data[i]! ^ this.memoryKey[i]!;
		}
	}

	/** 
	 * 提取时即时解混淆，返回的视图必须在使用后立即由调用者 fill(0)
	 */
	public get(): Uint8Array {
		const data = new Uint8Array(this.obfuscatedData.length);
		for (let i = 0; i < this.obfuscatedData.length; i++) {
			data[i] = this.obfuscatedData[i]! ^ this.memoryKey[i]!;
		}
		return data;
	}

	/** 彻底擦除内存 */
	public clear() {
		this.memoryKey.fill(0);
		this.obfuscatedData.fill(0);
	}
}

class CryptoHelper {
	/**
	 * 安全的 Base64 编码机制
	 */
	public safeBase64Encode(arr: Uint8Array): string {
		let result: string;
		if (arr.byteOffset === 0 && arr.byteLength === arr.buffer.byteLength) {
			result = arrayBufferToBase64(arr.buffer as ArrayBuffer);
		} else {
			const copy = new Uint8Array(arr);
			result = arrayBufferToBase64(copy.buffer);
			copy.fill(0); // 销毁防止逃逸的副本
		}
		return result;
	}

	/**
	 * 安全提取纯净的 ArrayBuffer (供 Obsidian 底层 Adapter 使用)
	 * 此方法只能用于最终向 Obsidian 提交需要落盘的文件数据块（明文或密文结果）
	 * 绝不允许在处理任何密钥、密码凭证时调用此方法
	 */
	public getCleanBuffer(arr: Uint8Array): ArrayBuffer {
		if (arr.byteOffset === 0 && arr.byteLength === arr.buffer.byteLength) {
			return arr.buffer as ArrayBuffer;
		}
		const result = new ArrayBuffer(arr.byteLength);
		new Uint8Array(result).set(arr);
		return result;
	}

	/**
	 * 恒定时间比较，防止针对密钥或散列的计时攻击
	 */
	public compareBytes(a: Uint8Array, b: Uint8Array): boolean {
		if (a.length !== b.length) return false;
		let result = 0;
		for (let i = 0; i < a.length; i++) result |= a[i]! ^ b[i]!;
		return result === 0;
	}


	/**
	 * MurmurHash3 32-bit 实现
	 * 优于 FNV-1a，具有更好的雪崩效应和更低的碰撞率
	 */
	public calculateChecksum(input: string | Uint8Array, seed: number = 0x12345678): string {
		const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;

		// 拦截 0 字节内容，给定独立标识
		if (data.length === 0) return "empty_hash";

		const nblocks = Math.floor(data.length / 4);
		let h1 = seed;

		const c1 = 0xcc9e2d51;
		const c2 = 0x1b873593;

		// 块处理 (每 4 字节一组)
		for (let i = 0; i < nblocks; i++) {
			const index = i * 4;
			// 模拟小端序读取 32 位整数
			let k1 = (data[index]! & 0xff) |
				((data[index + 1]! & 0xff) << 8) |
				((data[index + 2]! & 0xff) << 16) |
				((data[index + 3]! & 0xff) << 24);

			k1 = Math.imul(k1, c1);
			k1 = (k1 << 15) | (k1 >>> 17);
			k1 = Math.imul(k1, c2);

			h1 ^= k1;
			h1 = (h1 << 13) | (h1 >>> 19);
			h1 = Math.imul(h1, 5) + 0xe6546b64;
		}

		// 尾部处理
		let k2 = 0;
		const tailIndex = nblocks * 4;
		const remaining = data.length % 4;

		if (remaining >= 3) {
			k2 ^= (data[tailIndex + 2]! & 0xff) << 16;
		}
		if (remaining >= 2) {
			k2 ^= (data[tailIndex + 1]! & 0xff) << 8;
		}
		if (remaining >= 1) {
			k2 ^= (data[tailIndex]! & 0xff);
			k2 = Math.imul(k2, c1);
			k2 = (k2 << 15) | (k2 >>> 17);
			k2 = Math.imul(k2, c2);
			h1 ^= k2;
		}

		// 最终混淆
		h1 ^= data.length;
		h1 ^= h1 >>> 16;
		h1 = Math.imul(h1, 0x85ebca6b);
		h1 ^= h1 >>> 13;
		h1 = Math.imul(h1, 0xc2b2ae35);
		h1 ^= h1 >>> 16;

		// 使用 Base36 编码返回
		return (h1 >>> 0).toString(36);
	}

	/**
	 * 序列化扩展结构：转为 sz=v&kid=v&ek=v 的紧凑且防篡改格式
	 */
	private stringifyExt(ext: PhantomExtensionData): string {
		const parts: string[] = [];
		if (ext.sz !== undefined) parts.push(`sz=${ext.sz.toString(36)}`);
		if (ext.ph !== undefined) parts.push(`ph=${ext.ph}`);
		if (ext.cp !== undefined) parts.push(`cp=${ext.cp}`);
		if (ext.kid !== undefined) parts.push(`kid=${ext.kid}`);
		if (ext.ek !== undefined) parts.push(`ek=${ext.ek}`);
		if (ext.bf !== undefined) parts.push(`bf=${ext.bf}`);

		const payload = parts.join('&');
		if (!payload) return ""; // 空扩展

		const cx = this.calculateChecksum(payload);
		return `${payload}&cx=${cx}`;
	}

	/**
	 * 反序列化扩展结构：剥离签名进行散列比对，验证失败触发拦截降级
	 */
	private parseExt(extStr: string): PhantomExtensionData {
		const data: PhantomExtensionData = {};
		if (!extStr) return data;

		// 分解键值对，不再在解析阶段验证 CX
		const parts = extStr.split('&');
		for (const part of parts) {
			const idx = part.indexOf('=');
			if (idx > 0) {
				const k = part.substring(0, idx);
				const v = part.substring(idx + 1);
				if (k === 'sz') { const p = parseInt(v, 36); if (!isNaN(p)) data.sz = p; }
				else if (k === 'cp') { const p = parseInt(v, 10); if (!isNaN(p)) data.cp = p; }
				else if (k === 'bf') { const p = parseInt(v, 10); if (!isNaN(p)) data.bf = p; }
				else if (k === 'ph') { data.ph = v; }
				else if (k === 'kid') { data.kid = v; }
				else if (k === 'ek') { data.ek = v; }
				else if (k === 'cx') { data.cx = v; } // 将 cx 作为一个普通字段提取
				else { data[k] = v; } // 将未知/未来的扩展字段兜底保存
			}
		}
		return data;
	}

	/**
	 * 提取外置的结构化扩展数据
	 */
	public getExtensionData(headerText: string): PhantomExtensionData | null {
		if (!headerText.startsWith(MAGIC_HEADER)) return null;

		const body = headerText.substring(MAGIC_HEADER.length);
		const colonIndex = body.indexOf(':');

		if (colonIndex > -1) {
			const extStr = body.substring(0, colonIndex);
			const data = this.parseExt(extStr);

			// 校验元数据块的完整性
			const cxMatch = extStr.match(/&cx=([^&]+)$/);
			if (cxMatch) {
				const expectedCx = cxMatch[1];
				const payload = extStr.substring(0, cxMatch.index);
				// 记录验证状态，但不拦截。如果 cx 匹配，则 metadata 为真
				data._isValid = this.calculateChecksum(payload) === expectedCx;
			} else {
				data._isValid = false;
			}
			return data;
		}
		return null;
	}

	/**
	 * 获取纯净的 Base64 Payload (仅限文本文件)
	 */
	private getBase64Payload(armoredText: string): string | null {
		const body = armoredText.substring(MAGIC_HEADER.length);
		const colonIndex = body.indexOf(':');

		// 冒号后方即为密文载荷
		if (colonIndex > -1) {
			return body.substring(colonIndex + 1);
		}
		return null;
	}

	/**
	 * 压缩逻辑：使用原生 CompressionStream 对数据进行 deflate 压缩
	 */
	private async compress(data: Uint8Array): Promise<Uint8Array> {
		if (data.byteLength === 0) return data;
		const stream = new Blob([data as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('deflate'));
		const buffer = await new Response(stream).arrayBuffer();
		return new Uint8Array(buffer);
	}

	/**
	 * 解压逻辑：使用原生 DecompressionStream 还原数据
	 */
	private async decompress(data: Uint8Array): Promise<Uint8Array> {
		if (data.byteLength === 0) return data;
		const stream = new Blob([data as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate'));
		const buffer = await new Response(stream).arrayBuffer();
		return new Uint8Array(buffer);
	}

	/** WebCrypto API 凭证包装 */
	async importGCMKey(raw: Uint8Array): Promise<CryptoKey> {
		return await crypto.subtle.importKey("raw", raw as unknown as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
	}

	/** 派生主密钥 (KEK) - 仅在设置密码时调度 */
	async deriveKEK(password: string): Promise<Uint8Array> {
		const pwdBytes = new TextEncoder().encode(password);
		try {
			const raw = await argon2id({
				password: pwdBytes, salt: KEK_SALT, iterations: 3, memorySize: 65536, parallelism: 4, hashLength: 32, outputType: 'binary'
			});
			return raw;
		} finally {
			pwdBytes.fill(0);
		}
	}

	/** 加密数据密钥 -> 生成 EDEK */
	async encryptDEK(dekRaw: Uint8Array, kek: CryptoKey): Promise<string> {
		const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
		const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, kek, dekRaw as unknown as BufferSource);
		const combined = new Uint8Array(IV_SIZE + cipher.byteLength);
		combined.set(iv, 0);
		combined.set(new Uint8Array(cipher), IV_SIZE);
		// 安全转换为 Base64
		return this.safeBase64Encode(combined);
	}

	/** 解密 EDEK -> 还原底层数据密钥 DEK */
	async decryptDEK(edekStr: string, kek: CryptoKey): Promise<Uint8Array | null> {
		try {
			const combined = new Uint8Array(base64ToArrayBuffer(edekStr));
			if (combined.length < IV_SIZE) return null;
			const iv = combined.subarray(0, IV_SIZE);
			const cipher = combined.subarray(IV_SIZE);
			const dekRaw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, kek, cipher);
			return new Uint8Array(dekRaw);
		} catch (_e) {
			void _e;
			return null;
		}
	}

	/**
	 * 加密执行逻辑：压缩 -> DEK加密 -> 组合完整的带 KID 的元数据体
	 */
	async encryptFile(data: Uint8Array, dek: CryptoKey, edekStr: string, kid: string, shouldCompress: boolean, asBinary: boolean = false): Promise<string | Uint8Array> {
		let payload = data;
		let compressionFlag = 0;
		let isPayloadCompressed = false;

		// 扩展名允许且数据大小超过阈值进行压缩
		if (shouldCompress && data.byteLength > COMPRESSION_THRESHOLD) {
			try {
				payload = await this.compress(data);
				compressionFlag = 1;
				isPayloadCompressed = true;
			} catch (_e) {
				void _e;
				// 如果压缩失败，降级回不压缩模式，确保数据不丢失
				payload = data;
				compressionFlag = 0;
			}
		}

		// 生成原始明文的校验和，用于在转换时保证内容一致
		const ph = this.calculateChecksum(data);

		// 计算精确的总切割数，若空白则强制分出1个空片用于产出 Tag 签名
		const numChunks = Math.max(1, Math.ceil(payload.byteLength / CHUNK_SIZE));
		const totalCipherLength = payload.byteLength + numChunks * (IV_SIZE + TAG_SIZE);

		let finalPayload: Uint8Array | null = null;
		let base64Combined: Uint8Array | null = null;
		let writeBuffer: Uint8Array;
		let writeOffsetBase = 0;
		let headerStr = "";

		if (asBinary) {
			const extBlock = this.stringifyExt({ sz: data.byteLength, ph: ph, ek: edekStr, cp: compressionFlag, kid: kid, bf: 1 });
			headerStr = MAGIC_HEADER + extBlock + ":";
			const headerBytes = new TextEncoder().encode(headerStr);

			finalPayload = new Uint8Array(headerBytes.length + totalCipherLength);
			finalPayload.set(headerBytes, 0);

			writeBuffer = finalPayload;
			writeOffsetBase = headerBytes.length;
		} else {
			const extBlock = this.stringifyExt({ sz: data.byteLength, ph: ph, ek: edekStr, cp: compressionFlag, kid: kid });
			headerStr = MAGIC_HEADER + extBlock + ":";

			base64Combined = new Uint8Array(totalCipherLength);
			writeBuffer = base64Combined;
			writeOffsetBase = 0;
		}

		// 分块加密
		for (let i = 0; i < numChunks; i++) {
			const start = i * CHUNK_SIZE;
			const chunk = payload.subarray(start, start + CHUNK_SIZE);
			const targetOffset = writeOffsetBase + i * (CHUNK_SIZE + IV_SIZE + TAG_SIZE);

			const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
			const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, dek, chunk as unknown as BufferSource);

			writeBuffer.set(iv, targetOffset);
			writeBuffer.set(new Uint8Array(cipherBuf), targetOffset + IV_SIZE);

			// 每处理 16 个分块 (约 64MB)，强制使用 setTimeout 让出主线程
			if (i > 0 && i % 16 === 0) {
				await new Promise(r => window.setTimeout(r, 0));
			}
		}

		if (isPayloadCompressed && payload instanceof Uint8Array) {
			payload.fill(0);
		}

		if (asBinary) return writeBuffer;
		return headerStr + this.safeBase64Encode(writeBuffer);
	}
	/**
	 * 解密执行逻辑：KID识别 -> DEK解密 -> 回退解密 -> 解压
	 */
	async decryptFile(armoredData: string | Uint8Array, currentDek: CryptoKey | null, currentKek: CryptoKey | null, currentKid: string | null): Promise<{ data: Uint8Array, usedFallback: boolean, ph?: string } | null> {

		let combined: Uint8Array;
		let extData: PhantomExtensionData | null = null;

		if (typeof armoredData === 'string') {
			if (armoredData.startsWith(MAGIC_HEADER_V1)) throw new Error("UNSUPPORTED_V1");
			if (!this.isEncrypted(armoredData)) return null;

			extData = this.getExtensionData(armoredData);
			if (extData?.bf === 1) {
				throw new Error("ERR_BINARY_READ_AS_TEXT");
			}

			const base64Payload = this.getBase64Payload(armoredData);
			if (!base64Payload) return null;

			combined = new Uint8Array(base64ToArrayBuffer(base64Payload));
		} else {
			let headerEndIndex = -1;
			for (let i = MAGIC_HEADER.length; i < Math.min(armoredData.length, 2048); i++) {
				if (armoredData[i] === 58) {
					headerEndIndex = i;
					break;
				}
			}
			if (headerEndIndex === -1) return null;

			const headerBytes = armoredData.subarray(0, headerEndIndex);
			const headerStr = new TextDecoder().decode(headerBytes);
			if (headerStr.startsWith(MAGIC_HEADER_V1)) throw new Error("UNSUPPORTED_V1");

			extData = this.getExtensionData(headerStr + ":");
			if (extData?.bf === 1) {
				combined = armoredData.subarray(headerEndIndex + 1);
			} else {
				const b64Bytes = armoredData.subarray(headerEndIndex + 1);
				const b64Str = new TextDecoder().decode(b64Bytes);
				combined = new Uint8Array(base64ToArrayBuffer(b64Str.trim()));
			}
		}

		if (combined.length < IV_SIZE) return null;

		const compressionFlag = extData?.cp || 0;

		// 无论 cx 校验是否通过，只要解析出了 KID 且不匹配，立即抛出 KID 错误
		if (extData?.kid && currentKid && extData.kid !== currentKid) {
			throw new Error(`KID_MISMATCH:${extData.kid}`);
		}

		// 分块解密
		const attemptDecryption = async (dek: CryptoKey): Promise<Uint8Array> => {
			const numChunks = Math.max(1, Math.ceil(combined.byteLength / (CHUNK_SIZE + IV_SIZE + TAG_SIZE)));
			const plainTotalLength = combined.byteLength - (numChunks * (IV_SIZE + TAG_SIZE));
			const resultBuffer = new Uint8Array(plainTotalLength);

			for (let i = 0; i < numChunks; i++) {
				const cipherOffset = i * (CHUNK_SIZE + IV_SIZE + TAG_SIZE);
				const plainOffset = i * CHUNK_SIZE;
				const currentChunkSize = Math.min(combined.byteLength - cipherOffset, CHUNK_SIZE + IV_SIZE + TAG_SIZE);

				const iv = combined.subarray(cipherOffset, cipherOffset + IV_SIZE);
				const ciphertext = combined.subarray(cipherOffset + IV_SIZE, cipherOffset + currentChunkSize);

				const decChunk = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, dek, ciphertext as unknown as BufferSource);
				const decArray = new Uint8Array(decChunk);
				resultBuffer.set(decArray, plainOffset);

				// 每处理 16 个分块 (约 64MB)，强制使用 setTimeout 让出主线程
				if (i > 0 && i % 16 === 0) {
					await new Promise(r => window.setTimeout(r, 0));
				}
			}
			return resultBuffer;
		};

		let finalPlaintext: Uint8Array | null = null;
		let usedFallback = false;

		// 路径 A: 尝试使用当前库的 DEK 解密
		if (currentDek) {
			try {
				finalPlaintext = await attemptDecryption(currentDek);
			} catch (_e) {
				void _e; // 失败说明库 DEK 可能已变更，进入自愈路径
			}
		}

		// 路径 B: 库 DEK 不通时，尝试用主 KEK 解开文件自带的 EDEK
		if (!finalPlaintext && currentKek && extData?.ek) {
			const fallbackDekRaw = await this.decryptDEK(extData.ek, currentKek);
			if (fallbackDekRaw) {
				try {
					const fallbackDek = await this.importGCMKey(fallbackDekRaw);
					finalPlaintext = await attemptDecryption(fallbackDek);
					usedFallback = true;
				} catch (_e) {
					void _e;
				} finally {
					fallbackDekRaw.fill(0);
				}
			}
		}

		if (!finalPlaintext) throw new Error(i18n.t('ERR_DECRYPT_FAIL'));

		if (compressionFlag === 1) {
			const compressedBuffer = finalPlaintext; // 暂存压缩态明文
			try {
				finalPlaintext = await this.decompress(compressedBuffer);
			} finally {
				// 在获得解压数据后，立即物理擦除掉旧的压缩态明文
				compressedBuffer.fill(0);
			}
		}

		return { data: finalPlaintext, usedFallback, ph: extData?.ph };
	}

	/**
	 * 特征检测：识别字符串或二进制数据是否包含加密头
	 */
	isEncrypted(data: string | ArrayBuffer | Uint8Array | null): boolean {
		if (!data) return false;

		// 字符串特征检测
		if (typeof data === 'string') {
			return data.startsWith(MAGIC_HEADER) || data.startsWith(MAGIC_HEADER_V1);
		}

		// 二进制特征检测
		let bytes: Uint8Array;
		if (data instanceof Uint8Array) {
			bytes = data;
		} else {
			bytes = new Uint8Array(data);
		}

		// 长度不足以包含特征头
		if (bytes.length < MAGIC_HEADER.length) return false;

		// 提取前 7 位字符进行比对
		let header = "";
		for (let i = 0; i < MAGIC_HEADER.length; i++) {
			header += String.fromCharCode(bytes[i]!);
		}

		return header === MAGIC_HEADER || header === MAGIC_HEADER_V1;
	}
}

export default class PhantomCipherPlugin extends Plugin {
	settings!: PhantomCipherSettings;
	crypto: CryptoHelper = new CryptoHelper();

	// 内存混淆安全凭证 (保护驻留的 KEK 与 DEK 原始字节流)
	private secureKEK: SecureKey | null = null;
	private secureDEK: SecureKey | null = null;

	public vaultEDEK: string | null = null; // 供高频写入拼接使用
	public vaultKID: string | null = null; // 截取自 KEK 的前 6 位用于快速识别

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
	private blobUrlCache: Map<string, string> = new Map(); // 缓存已解密文件的 Blob URL
	private blobMtimeCache: Map<string, number> = new Map(); // 资源生命周期管理：通过 mtime 锚定 Blob 状态

	// 记录 app:// 内部路径与原始物理 vault 路径的反向映射供 PDF 拦截器使用
	private resourcePathToVaultPath: Map<string, string> = new Map();

	private visibilityTimeout: number | null = null; // 后台清理定时器引用

	/** 判断当前设备是否已装载混淆容器 */
	public hasPassword(): boolean {
		return this.secureKEK !== null;
	}

	/** 
	 * 临时提取密钥：
	 * 1. 从 XOR 容器提取字节 -> 2. 导入 CryptoKey -> 3. 立即物理擦除解混淆的字节 
	 */
	private async getTmpKEK(): Promise<CryptoKey | null> {
		if (!this.secureKEK) return null;
		const raw = this.secureKEK.get();
		try { return await this.crypto.importGCMKey(raw); }
		finally { raw.fill(0); }
	}

	private async getTmpDEK(): Promise<CryptoKey | null> {
		if (!this.secureDEK) return null;
		const raw = this.secureDEK.get();
		try { return await this.crypto.importGCMKey(raw); }
		finally { raw.fill(0); }
	}

	/** 密钥缺失提示 */
	private notifyPasswordMissing() {
		const now = Date.now();
		const lastTime = this.errorThrottler.get("__PWD_MISSING") || 0;
		if (now - lastTime > 5000) {
			new Notice(i18n.t('ERR_PWD_MISSING'));
			this.errorThrottler.set("__PWD_MISSING", now);
		}
	}

	/** KID 不匹配提示 */
	private notifyKidMismatch(path: string, kid: string) {
		const name = path.split('/').pop() || path;
		const now = Date.now();
		const throttleKey = "__KID_FAIL_" + path;
		if (now - (this.errorThrottler.get(throttleKey) || 0) > 5000) {
			new Notice(i18n.t('ERR_KID_MISMATCH', { name, kid }));
			this.errorThrottler.set(throttleKey, now);
		}
	}

	/** 损坏或底层解密失败提示 */
	private notifyDecryptFailed(path: string) {
		const name = path.split('/').pop() || path;
		const now = Date.now();
		const throttleKey = "__DECRYPT_FAIL_" + path;
		if (now - (this.errorThrottler.get(throttleKey) || 0) > 5000) {
			new Notice(i18n.t('ERR_DECRYPT', { name }));
			this.errorThrottler.set(throttleKey, now);
		}
	}

	/**
	 * V1 降级提醒
	 */
	private notifyV1Unsupported() {
		const now = Date.now();
		const lastTime = this.errorThrottler.get("__V1_WARN") || 0;
		if (now - lastTime > 10000) { // 10秒防抖区间
			new Notice("UNSUPPORTED_V1: Legacy ENC_V1 format detected. Decryption is no longer supported in V2. Please downgrade to v1.0.8 to decrypt and migrate your files.");
			this.errorThrottler.set("__V1_WARN", now);
		}
	}

	/**
	 * 视口失焦事件处理器。负责在挂起到后台且闲置 10 分钟后主动擦除驻留的密钥对象
	 */
	private onVisibilityChange = () => {
		if (activeDocument.hidden) {
			this.visibilityTimeout = window.setTimeout(() => {
				// 擦除内存中的所有加密原材料
				if (this.secureKEK) { this.secureKEK.clear(); this.secureKEK = null; }
				if (this.secureDEK) { this.secureDEK.clear(); this.secureDEK = null; }
			}, 10 * 60 * 1000);
			if (this.visibilityTimeout !== null) {
				window.clearTimeout(this.visibilityTimeout);
				this.visibilityTimeout = null;
			}
			// 重新回到前台时，尝试从 SecretStorage 重新验证与加载
			if (!this.secureKEK) {
				void this.fetchKeys();
			}
		}
	};

	/**
	 * 更换密码/彻底擦除时的强制内清理
	 */
	public clearInternalState() {
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
		
		this.hookPDFViewer(); // 启动挂载针对 PDF 渲染器原生的底层加载劫持拦截器
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
			this.registerDomEvent(workspaceWindow.doc, 'visibilitychange', this.onVisibilityChange);
		}));

		this.app.workspace.onLayoutReady(() => {
			void this.fetchKeys().then(() => {
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

		this.clearInternalState();

		if (this.visibilityTimeout !== null) window.clearTimeout(this.visibilityTimeout);

		// 彻底摧毁混淆内存
		if (this.secureKEK) { this.secureKEK.clear(); this.secureKEK = null; }
		if (this.secureDEK) { this.secureDEK.clear(); this.secureDEK = null; }
		this.vaultEDEK = null; this.vaultKID = null;
	}

	/**
	 * 从钥匙串中加载 KEK 与 EDEK
	 */
	async fetchKeys() {
		this.clearInternalState();
		const storage = this.app.secretStorage;
		if (!storage) return;
		const kekB64 = storage.getSecret(this.settings.kekId);
		const edekB64 = storage.getSecret(this.settings.dekId);

		if (kekB64) {
			// KID：用于对外宣称的唯一标识
			this.vaultKID = kekB64.substring(0, 6);

			// 临时解密 DEK 存入 XOR
			const kekRaw = new Uint8Array(base64ToArrayBuffer(kekB64));
			try {
				this.secureKEK = new SecureKey(kekRaw);
				const tKek = await this.crypto.importGCMKey(kekRaw);

				if (edekB64) {
					this.vaultEDEK = edekB64;
					const dekRaw = await this.crypto.decryptDEK(edekB64, tKek);
					if (dekRaw) {
						try {
							this.secureDEK = new SecureKey(dekRaw);
						} finally {
							dekRaw.fill(0); // 确保临时解出的 DEK 原始字节被立即擦除
						}
					}
				}
			} finally {
				// 无论初始化过程是否报错，kekRaw 必须在逻辑跳出前被物理摧毁。
				kekRaw.fill(0);
			}
		} else {
			if (this.secureKEK) this.secureKEK.clear(); this.secureKEK = null;
			if (this.secureDEK) this.secureDEK.clear(); this.secureDEK = null;
			this.vaultEDEK = null; this.vaultKID = null;
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
	private addToBlobCache(path: string, url: string, mtime: number) {
		// 检查路径是否存在，如果存在且 mtime 没变，直接返回
		if (this.blobUrlCache.has(path) && this.blobMtimeCache.get(path) === mtime) return;

		// 只有在文件确实修改过的情况下，才执行 Revoke
		if (this.blobUrlCache.has(path)) {
			URL.revokeObjectURL(this.blobUrlCache.get(path)!);
			this.blobUrlCache.delete(path);
		}

		this.blobUrlCache.set(path, url);
		this.blobMtimeCache.set(path, mtime);

		if (this.blobUrlCache.size > BLOB_CACHE_LIMIT) {
			for (const [oldPath, oldUrl] of this.blobUrlCache) {
				URL.revokeObjectURL(oldUrl);
				this.blobUrlCache.delete(oldPath);
				this.blobMtimeCache.delete(oldPath);
				if (this.blobUrlCache.size <= BLOB_CACHE_LIMIT)
					break; // Map 迭代严格保证插入顺序，直接 break 以准确淘汰最老的条目
			}
		}
	}

	/**
	 * PDF 渲染器原生劫持处理
	 * 处理在初次打开或刷新时因为异步的 `blobUrlCache` 处于未挂载状态，导致 PDF.js 退回到默认原生的 app:// 请求
	 * 从而绕过安全底层钩子抓取到加密明文数据引发的 Invalid PDF structure 报错崩溃死机不刷新问题。
	 */
	private hookPDFViewer() {
		const hookApp = (app: ObsidianPDFApp) => {
			if (app.__phantomHooked) return;
			const originalOpen = app.open.bind(app);
			
			app.open = async (args: PDFOpenArgs) => {
				if (args && args.url && typeof args.url === 'string') {
					try {
						// 1. 剥离 Obsidian 每次加载生成的类似 ?123456 的随机查询缓存参数
						const urlWithoutQuery = args.url.split('?')[0];

						// 2. 利用前置映射字典查找真实的 Vault 文件物理路径
						if (urlWithoutQuery) {
							const vaultPath = this.resourcePathToVaultPath.get(urlWithoutQuery);

							if (vaultPath) {
								// 3. 读取头部签名校验是否为加密文件
								const rawHead = await this.originalReadBinary(vaultPath).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
								
								if (this.crypto.isEncrypted(rawHead)) {
									if (!this.hasPassword()) await this.fetchKeys();
									if (!this.hasPassword()) {
										this.notifyPasswordMissing();
										throw new Error(i18n.t('ERR_PWD_MISSING') || "Password missing");
									}

									// 4. 将原生加载行为在此处强制改为读取完整二进制流解密
									const rawBuffer = await this.originalReadBinary(vaultPath);
									const tKek = await this.getTmpKEK();
									const tDek = await this.getTmpDEK();
									const result = await this.crypto.decryptFile(new Uint8Array(rawBuffer), tDek, tKek, this.vaultKID);
									
									if (result && result.data) {
										// 5. 将原生入参偷偷替换为解密完的 Uint8Array，然后抛弃 URL
										// 使 PDF.js 完全打消使用网络 Fetch 跨钩子加载本地文件的企图
										args.data = result.data;
										delete args.url;
									}
								}
							}
						}
					} catch (e) {
						// 此处截获错误不向上传导阻断，让 PDF.js 自行崩溃按原生流程抛出正确的本地损坏错误
						console.error("PhantomCipher PDF Intercept Error:", e);
					}
				}
				return originalOpen(args);
			};
			app.__phantomHooked = true;
		};

		const targetWindow = window as unknown as ObsidianWindow;
		let _pdfjsViewer = targetWindow.pdfjsViewer;
		
		Object.defineProperty(targetWindow, 'pdfjsViewer', {
			get: () => _pdfjsViewer,
			set: (val: PDFjsViewer | undefined) => {
				_pdfjsViewer = val;
				if (_pdfjsViewer && _pdfjsViewer.createObsidianPDFViewer) {
					const originalCreate = _pdfjsViewer.createObsidianPDFViewer;
					if (!originalCreate.__phantomHooked) {
						_pdfjsViewer.createObsidianPDFViewer = function(this: unknown, ...args: unknown[]) {
							const app = originalCreate.call(this, ...args);
							hookApp(app); // 针对每一个新的 PDF 标签实例做 Hook 绑定
							return app;
						};
						_pdfjsViewer.createObsidianPDFViewer.__phantomHooked = true;
					}
				}
			},
			configurable: true
		});

		// 避免出现热重载插件/懒加载导致 PDF 组件已经被初始化过了，没有命中监听赋值操作的情况
		if (_pdfjsViewer && _pdfjsViewer.createObsidianPDFViewer) {
			const originalCreate = _pdfjsViewer.createObsidianPDFViewer;
			if (!originalCreate.__phantomHooked) {
				_pdfjsViewer.createObsidianPDFViewer = function(this: unknown, ...args: unknown[]) {
					const app = originalCreate.call(this, ...args);
					hookApp(app);
					return app;
				};
				_pdfjsViewer.createObsidianPDFViewer.__phantomHooked = true;
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
			// 无论是否从 Blob 吐出结果，率先通过 Obsidian 底层拿到真实关联协议路径
			// 并在内部维护一套映射关系字典，供上层 PDF 拦截器回推映射时使用
			const originalUrl = this.originalGetResourcePath(path);
			const urlWithoutQuery = originalUrl.split('?')[0];
			if (urlWithoutQuery) {
				this.resourcePathToVaultPath.set(urlWithoutQuery, path);
			}

			if (this.blobUrlCache.has(path)) {
				const url = this.blobUrlCache.get(path)!;
				return url;
			}
			return originalUrl;
		};

		// 通用的读取解密中间件
		const processRead = async (path: string, content: string | ArrayBuffer): Promise<{ text?: string, buffer?: ArrayBuffer } | null> => {
			const isString = typeof content === 'string';

			const probeData = isString ? content : new Uint8Array(content).subarray(0, MAGIC_HEADER.length);
			if (path.startsWith(configDir) || !this.crypto.isEncrypted(probeData)) return isString ? { text: content } : { buffer: content };

			// 如果初次读取时钥匙串还未装载完成，强制阻塞等待
			if (!this.hasPassword()) await this.fetchKeys();

			if (!this.hasPassword()) {
				this.decryptedPaths.delete(path);
				this.notifyPasswordMissing();
				// 未解锁密码时，对于试图请求二进制附件的操作强行返回长度为 0 的空白 Buffer
				return isString ? { text: content } : { buffer: new ArrayBuffer(0) };
			}

			const armoredData = isString ? content : new Uint8Array(content);

			// 动态 XOR 还原 Key 用于解密
			const tKek = await this.getTmpKEK();
			const tDek = await this.getTmpDEK();

			try {
				const result = await this.crypto.decryptFile(armoredData, tDek, tKek, this.vaultKID);
				if (result) {
					// 使用文件自身附带的 EDEK 解开，下次保存时将自动迁移至当前库 DEK
					this.decryptedPaths.add(path);
					// 读取出的明文流在交付给 Obsidian 时提取为其底层的 CleanBuffer 以防部分底层插件挂载报错
					return isString ? { text: new TextDecoder().decode(result.data) } : { buffer: this.crypto.getCleanBuffer(result.data) };
				}
			} catch (err: unknown) {
				const msg = err instanceof Error ? err.message : String(err);
				// 不支持 V1 加密格式
				if (msg === 'UNSUPPORTED_V1') {
					this.notifyV1Unsupported();
				} else if (msg.startsWith('KID_MISMATCH:')) {
					this.notifyKidMismatch(path, msg.split(':')[1]!);
				} else {
					this.notifyDecryptFailed(path);
				}
			}

			this.decryptedPaths.delete(path);
			return isString ? { text: content } : { buffer: new ArrayBuffer(0) };
		};

		// 拦截 CachedRead，确保 Obsidian 内部缓存系统拿到的是解密后的明文
		vault.cachedRead = async (file: TFile): Promise<string> => {
			const content = await this.originalVaultCachedRead(file);
			const res = await processRead(file.path, content);
			return res ? (res.text !== undefined ? res.text : content) : content;
		};

		// 处理文本读取：如果是加密文件则自动解密
		vault.read = async (file: TFile): Promise<string> => {
			const content = await this.originalVaultRead(file);
			const res = await processRead(file.path, content);
			return res ? (res.text !== undefined ? res.text : content) : content;
		};

		// 处理二进制读取：支持附件透明解密
		vault.readBinary = async (file: TFile): Promise<ArrayBuffer> => {

			// 在读取二进制前，如果缓存已有且没过期，直接返回已处理的 Buffer 模拟
			if (this.blobUrlCache.has(file.path) && this.blobMtimeCache.get(file.path) === file.stat.mtime) {
				// 缓存命中策略由内部预处理实现
			}

			const d = await this.originalVaultReadBinary(file);
			const r = await processRead(file.path, d);
			if (r && r.buffer && this.decryptedPaths.has(file.path)) {
				// 针对媒体文件生成 Blob URL，让 app:// 协议能显示加密图片
				const ext = file.extension.toLowerCase();
				if (PREVIEW_SUPPORTED.has(ext)) {
					const blob = new Blob([r.buffer], { type: this.getMimeType(ext) });
					// 使用 LRU 方式存储缓存
					this.addToBlobCache(file.path, URL.createObjectURL(blob), file.stat.mtime);
				}
			}
			return r?.buffer !== undefined ? r.buffer : d;
		};

		/**
		 * 写入逻辑处理器：零信任校验与动态落地
		 */
		const handleWrite = async (path: string, data: Uint8Array, isText: boolean): Promise<string | Uint8Array | null> => {
			if (path.startsWith(configDir)) return data;

			// 内存限制
			if (data.byteLength > MAX_FILE_SIZE) {
				new Notice(i18n.t('ERR_2GB_LIMIT'));
				return null;
			}

			// 写入前检查，防止钥匙串脱机
			if (!this.hasPassword()) await this.fetchKeys();
			const hasPwd = this.hasPassword();
			const ext = path.split('.').pop()?.toLowerCase() || '';

			// 仅读取前 7 字节判断文件是否原本直接就是加密状态
			let isCurrentlyEncrypted = false;
			try {
				const head = await this.originalReadBinary(path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				isCurrentlyEncrypted = this.crypto.isEncrypted(head);
			} catch (_e) {
				void _e;
			}

			// 判断即将写入的内容本身是否带有加密头标识
			const isIncomingEncrypted = this.crypto.isEncrypted(data);

			// 零信任安全校验：严防中间人与脏密文注入
			// 一旦检测到试图写入系统的密文，在此处就地执行强制中转验证。
			// 绝不允许单纯依赖特征头而放行落盘，一切非经验证合法的密文皆视为攻击或损坏。
			if (isIncomingEncrypted) {
				if (!hasPwd) {
					// 若当前设备未解锁，则无法验证密文的真伪
					// 为防止垃圾数据覆写破坏本地文件，在此刻无条件拒绝写入并利用通知提醒用户
					this.notifyPasswordMissing();
					return null;
				}

				// 强制试解密即将落盘的载荷
				const payloadToVerify = isText ? new TextDecoder().decode(data) : data;
				try {
					const tKek = await this.getTmpKEK();
					const tDek = await this.getTmpDEK();
					const isValid = await this.crypto.decryptFile(payloadToVerify, tDek, tKek, this.vaultKID);
					if (isValid) {
						// 验证通过：确认为当前密码下合法的密文（如同步插件写入）
						// 立刻将此文件路径加入已信任名单，并将中转的 data 原路返回给底层完成物理落盘。
						this.decryptedPaths.add(path);
						return data;
					}
				} catch (_e) {
					void _e;
				}
				// 验证失败：载荷损坏、不同密码或蓄意伪造
				// 向用户抛出具有具体文件名的警告，并拒绝写入保护本地文件。
				this.notifyDecryptFailed(path);
				return null;
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
				const tDek = await this.getTmpDEK();

				// 写入时，如果由于某种极端情况空缺核心凭据，拒绝加密
				if (!tDek || !this.vaultEDEK || !this.vaultKID) return null;

				// 无论此文件之前是用什么分裂的附属 EDEK 读出来的，此时一律使用当前的 vaultDEK 进行被动统一写回。
				const encryptedResult = await this.crypto.encryptFile(
					data,
					tDek,
					this.vaultEDEK,
					this.vaultKID,
					!NON_COMPRESSIBLE.has(ext),
					!isText // 如果源不是 Text，则打包为纯二进制落地
				);

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
			const result = await handleWrite(path, new TextEncoder().encode(data), true);
			if (result === null) return;
			// 如果底层文件以二进制落地写入，调用安全的 getCleanBuffer 向底层交付提取物
			if (typeof result === 'string') await this.originalWrite(path, result, options);
			else await this.originalWriteBinary(path, this.crypto.getCleanBuffer(result), options);
		};

		adapter.writeBinary = async (path: string, data: ArrayBuffer, options?: DataWriteOptions): Promise<void> => {
			const result = await handleWrite(path, new Uint8Array(data), false);
			if (result === null) return;
			// 同上应用 getCleanBuffer 提取交付
			if (typeof result === 'string') await this.originalWrite(path, result, options);
			else await this.originalWriteBinary(path, this.crypto.getCleanBuffer(result), options);
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
		} catch (_e) {
			void _e;
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
				this.statusBarItem.removeClass("is-transparent", "is-locked");

				const span = this.statusBarItem.createSpan();

				// 解密成功绿色，锁定只读红色
				if (isTransparent) {
					this.statusBarItem.addClass("is-transparent");
					setIcon(span, "unlock");
				} else {
					this.statusBarItem.addClass("is-locked");
					setIcon(span, "lock");
				}

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
				let anySuccess = false;
				for (const task of warmupTasks) {
					const isGenerated = await task;
					if (isGenerated) anySuccess = true;
				}

				// 如果产生了任何一个新解密的映射，触发 DOM 重载以修复媒体错位。
				if (anySuccess) {
					this.fixMediaDOM();
				}
			}

		} catch (_e) {
			void _e;
			this.statusBarItem.hide();
		}
	}


	/**
	 * 安全转换机制
	 * 逻辑：读取 -> 写入副本 -> 校验副本 -> 替换原件
	 */
	private async safeConvertProcess(path: string, extension: string, action: 'encrypt' | 'decrypt'): Promise<boolean> {
		const tempPath = normalizePath(path + ".phantom_tmp");
		try {
			let originalDataHash = "";
			let expectedHashFromExt = "";

			const isText = ["md", "canvas", "txt", "json", "css"].includes(extension);

			const tKek = await this.getTmpKEK();
			const tDek = await this.getTmpDEK();

			// 强制确保安全转化时 KEK 和 DEK 就位
			if (!tDek || !this.vaultEDEK || !this.vaultKID) throw new Error(i18n.t('ERR_MISSING_CREDENTIALS'));

			// 1. 读取文件
			if (action === 'encrypt') {
				let rawRead: ArrayBuffer | null = await this.originalReadBinary(path);
				if (rawRead.byteLength > MAX_FILE_SIZE) throw new Error(i18n.t('ERR_2GB_LIMIT'));

				let data: Uint8Array | null = new Uint8Array(rawRead);
				rawRead = null;

				originalDataHash = this.crypto.calculateChecksum(data);
				let targetData: Uint8Array | string | null = await this.crypto.encryptFile(data, tDek, this.vaultEDEK, this.vaultKID, !NON_COMPRESSIBLE.has(extension), !isText);

				data.fill(0);
				data = null; // 完成加密后立即丢弃原件的明文驻留

				if (typeof targetData === 'string') {
					await this.originalWrite(tempPath, targetData);
				} else {
					await this.originalWriteBinary(tempPath, this.crypto.getCleanBuffer(targetData));
					// 完成加密提取后，应当立刻擦除读入的源文件明文，防止留在内存
					targetData.fill(0);
				}
				targetData = null; // 写入磁盘后立即释放产出缓冲
			} else {
				let rawBuffer: ArrayBuffer | null = await this.originalReadBinary(path);
				if (rawBuffer.byteLength > MAX_FILE_SIZE) throw new Error(i18n.t('ERR_2GB_LIMIT'));

				let rawBytes: Uint8Array | null = new Uint8Array(rawBuffer);
				rawBuffer = null;

				const res = await this.crypto.decryptFile(rawBytes, tDek, tKek, this.vaultKID);
				rawBytes = null; // 切断加密源文件引用

				if (!res) throw new Error(i18n.t('ERR_MEM_DECRYPT'));

				let targetData: Uint8Array | string | null;
				if (isText) {
					targetData = new TextDecoder().decode(res.data);
				} else {
					targetData = res.data;
				}

				originalDataHash = this.crypto.calculateChecksum(res.data);
				expectedHashFromExt = res.ph || "";

				// 如果加密头中含有正确的 ph 记录，执行校验保证解密数据未在逻辑上受损
				if (expectedHashFromExt && expectedHashFromExt !== originalDataHash) {
					if (targetData instanceof Uint8Array) targetData.fill(0);
					res.data.fill(0);
					throw new Error(i18n.t('ERR_VAL_DEC_MISMATCH'));
				}

				// 2. 写入副本
				if (typeof targetData === 'string') {
					await this.originalWrite(tempPath, targetData);
				} else {
					await this.originalWriteBinary(tempPath, this.crypto.getCleanBuffer(targetData));
					targetData.fill(0);
				}
				targetData = null;
				res.data.fill(0);
			}

			// 3. 副本校验
			let tempRead: ArrayBuffer | null = await this.originalReadBinary(tempPath);
			if (action === 'encrypt') {
				let tempBytes: Uint8Array | null = new Uint8Array(tempRead);
				tempRead = null;
				const testResult = await this.crypto.decryptFile(tempBytes, tDek, tKek, this.vaultKID);
				tempBytes = null;

				// 解密临时密文副本，对其进行重新 Hash 并比对
				if (!testResult || this.crypto.calculateChecksum(testResult.data) !== originalDataHash) {
					if (testResult && testResult.data) testResult.data.fill(0);
					throw new Error(i18n.t('ERR_VAL_ENC_CORRUPT'));
				}
				testResult.data.fill(0);
			} else {
				let tempBytes: Uint8Array | null = new Uint8Array(tempRead);
				tempRead = null;
				const tempReadHash = this.crypto.calculateChecksum(tempBytes);
				tempBytes = null;
				// 解密输出的副本校验
				if (tempReadHash !== originalDataHash) {
					throw new Error(i18n.t('ERR_VAL_DEC_MISMATCH'));
				}
			}

			// 4. 原子替换：删除原件并重命名副本
			// 在某些情况 rename 可能会失败，先 remove 再 rename
			try {
				await this.app.vault.adapter.remove(path);
			} catch (_e) {
				void _e;
			}

			// 获取临时文件的抽象引用并重命名
			const tempAbstractFile = this.app.vault.getAbstractFileByPath(tempPath);
			if (tempAbstractFile) {
				await this.app.vault.rename(tempAbstractFile, path);
			} else {
				await this.app.vault.adapter.rename(tempPath, path);
			}

			// 转换成功后，强制 Obsidian 重新读取并建立索引
			const file = this.app.vault.getAbstractFileByPath(path);
			if (file instanceof TFile) {
				this.app.metadataCache.trigger("changed", file);
			}
			return true;

		} catch (e) {
			// 转换失败时清理副本
			try {
				await this.app.vault.adapter.remove(tempPath);
			} catch (_e) {
				void _e;
			}
			// 将错误向上抛出，由 UI 层负责具体的 Notice 逻辑
			throw e;
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
		
		// 创建占位 Notice
		const progressNotice = new Notice(`${i18n.t('NOTICE_CONVERTING')}: ${file.name}...`, 0);

		try {
			// 接入带有校验恢复机制的安全转换流
			await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action);

			progressNotice.hide();

			// 转换成功后，直接替换原占位 Notice 内容
			new Notice(isEnc 
				? i18n.t('NOTICE_RESTORED', { name: file.name }) 
				: i18n.t('NOTICE_ENCRYPTED', { name: file.name }), 5000);
		} catch (e) {
			progressNotice.hide();
			const message = e instanceof Error ? e.message : String(e);

			if (message.startsWith('KID_MISMATCH:')) {
				const kid = message.split(':')[1] ?? '';
				new Notice(i18n.t('ERR_KID_MISMATCH', { name: file.name, kid: kid }), 8000);
				this.notifyKidMismatch(file.path, kid);
			} else if (isEnc) {
				new Notice(i18n.t('NOTICE_CONVERT_FAIL_LOCKED', { name: file.name }), 8000);
			} else {
				new Notice(i18n.t('NOTICE_FAILED', { name: file.name }), 8000);
			}

			// 同时在控制台打印原始错误方便排查
			console.error(i18n.t('LOG_ERR_CONVERSION') + " " + file.path, e);
		}

		await this.updateStatusBar(file);
	}

	/**
	 * 批量处理文件夹下的加解密逻辑
	 */
	private async batchProcessFolder(folder: TFolder, action: 'encrypt' | 'decrypt') {
		if (!this.hasPassword()) { this.notifyPasswordMissing(); return; }

		let successCount = 0;
		let failCount = 0;      // 物理性转换失败（如写入冲突、损坏）
		let mismatchCount = 0;  // 逻辑性跳过（KID 不匹配）
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

		new Notice(i18n.t('NOTICE_BATCH_START', { count: targetFiles.length }), 3000);

		// 使用动态 Notice 显示进度
		const progressNotice = new Notice('', 0);

		for (let i = 0; i < targetFiles.length; i++) {
			const file = targetFiles[i]!;
			const actionName = i18n.t(isEncryptAction ? 'ACTION_ENCRYPT' : 'ACTION_DECRYPT');

			// 更新进度条文字
			progressNotice.setMessage(i18n.t('NOTICE_BATCH_PROGRESS', {
				current: i + 1,
				total: targetFiles.length,
				action: actionName,
				name: file.name
			}));
			try {
				// 直接通过底层 Adapter 探查头信息判断状态
				const rawHead = await this.originalReadBinary(file.path).then((b: ArrayBuffer) => b.slice(0, MAGIC_HEADER.length));
				const isEnc = this.crypto.isEncrypted(rawHead);

				// 只有状态不符合目标状态时才执行转换
				if ((isEncryptAction && !isEnc) || (!isEncryptAction && isEnc)) {
					// 接入带有校验恢复机制的安全转换流
					await this.safeConvertProcess(file.path, file.extension.toLowerCase(), action);
					successCount++;
				}
			} catch (e) {
				const message = e instanceof Error ? e.message : String(e);
				const actionName = i18n.t(isEncryptAction ? 'ACTION_ENCRYPT' : 'ACTION_DECRYPT');

				// 错误分流记录
				if (message.startsWith('KID_MISMATCH:')) {
					// 密钥不匹配引起的跳过
					mismatchCount++;
					this.notifyKidMismatch(file.path, message.split(':')[1]!);
				} else if (message === 'UNSUPPORTED_V1') {
					// V1 格式不支持
					failCount++;
					this.notifyV1Unsupported();
				} else {
					// 其他未知失败
					failCount++;
					console.error(i18n.t('LOG_BATCH_ERROR', { action: actionName, path: file.path }), e);
				}
				// 批处理中单个文件失败不中断循环，继续处理后续文件
			}
		}

		progressNotice.hide(); // 处理完后关闭进度条

		// 最终汇总通知：展示成功、失败、以及因密钥不匹配跳过的数量
		new Notice(i18n.t('NOTICE_BATCH_FINISH', {
			count: successCount,
			failed: failCount,
			mismatch: mismatchCount
		}), 5000); // 增加停留时间方便用户看清数据

		void this.updateStatusBar(this.app.workspace.getActiveFile());
	}

	async loadSettings() {
		const loadedData = (await this.loadData()) as unknown;
		this.settings = Object.assign({}, DEFAULT_SETTINGS, loadedData as Partial<PhantomCipherSettings>);

		let dirty = false;
		if (!this.settings.kekId) { this.settings.kekId = "phantom-kek-" + Math.random().toString(36).substring(2, 7); dirty = true; }
		if (!this.settings.dekId) { this.settings.dekId = "phantom-dek-" + Math.random().toString(36).substring(2, 7); dirty = true; }
		if (dirty) await this.saveSettings();
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	/** 暴露提供给 Modal 验证旧密码的辅助接口 */
	public async getTestKEKRaw(pwd: string): Promise<Uint8Array> {
		return await this.crypto.deriveKEK(pwd);
	}

	/** 暴露提供给 Modal 跨界拉取内存凭据的方式*/
	public getVaultKEKRaw(): Uint8Array | null {
		return this.secureKEK ? this.secureKEK.get() : null;
	}

	public getVaultDEKRaw(): Uint8Array | null {
		return this.secureDEK ? this.secureDEK.get() : null;
	}
}

/**
 * 密码变更面板
 */
class PasswordModal extends Modal {
	plugin: PhantomCipherPlugin;
	onCloseCallback: () => void;
	oldPwd = "";
	newPwd = "";

	constructor(app: App, plugin: PhantomCipherPlugin, onCloseCallback: () => void) {
		super(app);
		this.plugin = plugin;
		this.onCloseCallback = onCloseCallback;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.createEl("h2", { text: i18n.t('MODAL_PWD_TITLE') });

		if (this.plugin.hasPassword()) {
			new Setting(contentEl)
				.setName(i18n.t('MODAL_OLD_PWD'))
				.addText(t => { t.inputEl.type = 'password'; t.onChange(v => this.oldPwd = v); });

			new Setting(contentEl)
				.setName(i18n.t('MODAL_NEW_PWD'))
				.setDesc(i18n.t('MODAL_NEW_PWD_DESC'))
				.addText(t => { t.inputEl.type = 'password'; t.onChange(v => this.newPwd = v); });
		} else {
			new Setting(contentEl)
				.setName(i18n.t('MODAL_NEW_PWD'))
				.addText(t => { t.inputEl.type = 'password'; t.onChange(v => this.newPwd = v); });
		}

		new Setting(contentEl)
			.addButton(b => b.setButtonText(i18n.t('BTN_CONFIRM'))
				.setCta()
				.onClick(async () => {
					b.setButtonText(i18n.t('BTN_DERIVING')).setDisabled(true);
					await this.handleConfirm();
					b.setButtonText(i18n.t('BTN_CONFIRM')).setDisabled(false);
				}))
			.addButton(b => b.setButtonText(i18n.t('BTN_CANCEL')).onClick(() => this.close()));
	}

	async handleConfirm() {
		try {
			if (!this.plugin.app.secretStorage) {
				throw new Error(i18n.t('ERR_NO_SECRET_STORAGE'));
			}

			// 如果已存在密码，强制拦截并校验旧密码
			if (this.plugin.hasPassword()) {
				const testKekRaw = await this.plugin.getTestKEKRaw(this.oldPwd);
				const vaultKekRaw = this.plugin.getVaultKEKRaw();
				let isMatch = false;

				try {
					isMatch = vaultKekRaw ? this.plugin.crypto.compareBytes(testKekRaw, vaultKekRaw) : false;
				} finally {
					testKekRaw.fill(0);
					if (vaultKekRaw) vaultKekRaw.fill(0);
				}

				if (!isMatch) {
					new Notice(i18n.t('ERR_PWD_WRONG'));
					return;
				}

				// 清除模式
				if (this.newPwd === "") {
					this.plugin.app.secretStorage.setSecret(this.plugin.settings.kekId, "");
					this.plugin.app.secretStorage.setSecret(this.plugin.settings.dekId, "");

					this.plugin.clearInternalState();
					new Notice(i18n.t('NOTICE_PWD_CLEARED'));
					void this.plugin.fetchKeys();
					this.close();
					return;
				}
			}

			// 全新派生与替换流
			const newKekRaw = await this.plugin.crypto.deriveKEK(this.newPwd);
			try {
				const newKek = await this.plugin.crypto.importGCMKey(newKekRaw);

				let newEdek = "";

				// 如果系统内原先存在 DEK 原材料，尝试提取并使用新 KEK 重新包裹它 (信封更换)
				const currentDekRaw = this.plugin.getVaultDEKRaw();

				if (currentDekRaw) {
					try {
						newEdek = await this.plugin.crypto.encryptDEK(currentDekRaw, newKek);
					} finally {
						currentDekRaw.fill(0);
					}
				} else {
					// 这是一个纯净初始化的库，直接生成全新的全局 DEK 体系
					const freshDekRaw = crypto.getRandomValues(new Uint8Array(32));
					try {
						newEdek = await this.plugin.crypto.encryptDEK(freshDekRaw, newKek);
					} finally {
						freshDekRaw.fill(0);
					}
				}

				const kekBase64 = this.plugin.crypto.safeBase64Encode(newKekRaw);

				this.plugin.app.secretStorage.setSecret(this.plugin.settings.kekId, kekBase64);
				this.plugin.app.secretStorage.setSecret(this.plugin.settings.dekId, newEdek);

				if (this.plugin.hasPassword()) {
					new Notice(i18n.t('NOTICE_PWD_CHANGED'));
				} else {
					new Notice(i18n.t('NOTICE_PWD_SET'));
				}

				void this.plugin.fetchKeys();
				this.close();
			} finally {
				newKekRaw.fill(0);
				// 清除明文字符串变量引用
				this.oldPwd = "";
				this.newPwd = "";
			}
		} catch (error) {
			console.error(i18n.t('LOG_PWD_SETUP_ERROR'), error);
			const msg = error instanceof Error ? error.message : String(error);
			new Notice(msg);
		}
	}

	onClose() {
		this.oldPwd = "";
		this.newPwd = "";
		this.contentEl.empty();
		this.onCloseCallback();
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
			.addButton(btn => btn
				.setButtonText(this.plugin.hasPassword() ? i18n.t('BTN_CHANGE_PWD') : i18n.t('BTN_SET_PWD'))
				.onClick(() => {
					// 激活独立的派生弹窗保护流程
					new PasswordModal(this.app, this.plugin, () => this.display()).open();
				})
			);
	}
}
