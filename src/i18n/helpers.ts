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

  private _get(key: TransItemType): string {
    let realLang: LangType = "en";
    
    if (this.lang === "auto") {
      const locale = moment.locale().replace("-", "_");
      if (locale in LANGS) {
        realLang = locale as LangType; 
      }
    } else {
      realLang = this.lang;
    }

    const langDict = LANGS[realLang];
    return langDict[key] || LANGS["en"][key] || key;
  }

  t(key: TransItemType, vars?: Record<string, string | number>): string {
    const rawStr = this._get(key);
    if (!vars) return rawStr;

    return rawStr.replace(/{{(\w+)}}/g, (match: string, p1: string) => {
      const value = vars[p1];
      return value !== undefined ? String(value) : match;
    });
  }
}

export const i18n = new I18n();
