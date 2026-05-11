import { moment } from "obsidian";
import { LANGS } from "./langs";

export type LangType = keyof typeof LANGS;
export type LangTypeAndAuto = LangType | "auto";
export type TransItemType = keyof (typeof LANGS)["en"];

export class I18n {
  lang: LangTypeAndAuto;

  constructor(lang: LangTypeAndAuto = "auto") {
    this.lang = lang;
  }

  _get(key: TransItemType): string {
    let realLang: string = this.lang;
    
    if (this.lang === "auto") {
      // 对齐 Obsidian 的 locale 格式 (如 zh-cn -> zh_cn)
      const locale = moment.locale().replace("-", "_");
      realLang = (locale in LANGS) ? locale : "en";
    }

    const langDict = (LANGS[realLang as LangType] || LANGS["en"]) as Record<string, string>;
    return langDict[key] || LANGS["en"][key] || (key as string);
  }

  /**
   * 翻译函数：支持 {{var}} 变量替换
   */
  t(key: TransItemType, vars?: Record<string, any>): string {
    const rawStr = this._get(key);
    if (!vars) return rawStr;

    return rawStr.replace(/{{(\w+)}}/g, (match, p1) => {
      return vars[p1] !== undefined ? String(vars[p1]) : match;
    });
  }
}

export const i18n = new I18n();
