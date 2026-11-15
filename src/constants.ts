export const invalidProtocolRegex = /^([^\w]*)(javascript|data|vbscript)/im;
export const htmlEntitiesRegex = /&#(\w+)(^\w|;)?/g;
export const htmlCtrlEntityRegex = /&(newline|tab);/gi;
export const ctrlCharactersRegex =
  /[\u0000-\u001F\u007F-\u009F\u2000-\u200D\uFEFF]/gim;
export const urlSchemeRegex = /^.+(:|&colon;)/gim;
// Stateless variants: the `g` flag makes the exported regexes stateful
// (lastIndex leaks across calls), which can skip the scheme on the next
// URL. Keep the stateful exports for backwards compatibility but use these
// internally.
export const urlSchemeMatchRegex = /^.+(:|&colon;)/im;
export const strictUrlSchemeRegex = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
export const invalidProtocolMatchRegex =
  /^([^\w]*)(javascript|data|vbscript)/im;
export const whitespaceEscapeCharsRegex =
  /(\\|%5[cC])((%(6[eE]|72|74))|[nrt])/g;
export const relativeFirstCharacters = [".", "/"];
export const BLANK_URL = "about:blank";
export const MAX_DECODE_ITERATIONS = 10;
export const DEFAULT_ALLOWED_SCHEMES = ["http:", "https:", "mailto:"];
