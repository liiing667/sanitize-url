import {
  DEFAULT_ALLOWED_SCHEMES,
  BLANK_URL,
  ctrlCharactersRegex,
  htmlCtrlEntityRegex,
  htmlEntitiesRegex,
  invalidProtocolMatchRegex,
  MAX_DECODE_ITERATIONS,
  relativeFirstCharacters,
  strictUrlSchemeRegex,
  urlSchemeMatchRegex,
  whitespaceEscapeCharsRegex,
} from "./constants";

export interface SanitizeUrlOptions {
  /**
   * Explicitly registered schemes (with or without a trailing colon) that
   * are permitted in addition to the default allowlist when the allowlist
   * mode is enabled. Passing this opts the sanitizer into default-deny
   * mode: any scheme not on the allowlist is replaced with about:blank.
   */
  allowedSchemes?: string[];
}

function isRelativeUrlWithoutProtocol(url: string): boolean {
  return relativeFirstCharacters.indexOf(url[0]) > -1;
}

function decodeHtmlCharacters(str: string) {
  const removedNullByte = str.replace(ctrlCharactersRegex, "");
  return removedNullByte.replace(htmlEntitiesRegex, (match, dec) => {
    return String.fromCharCode(dec);
  });
}

function isValidUrl(url: string): boolean {
  return URL.canParse(url);
}

function decodeURI(uri: string): string {
  try {
    return decodeURIComponent(uri);
  } catch (e: unknown) {
    // Ignoring error
    // It is possible that the URI contains a `%` not associated
    // with URI/URL-encoding.
    return uri;
  }
}

function normalizeRegisteredScheme(scheme: string): string {
  return scheme.trim().toLowerCase().replace(/:+$/, "");
}

function extractScheme(url: string): string | null {
  const strictSchemeMatch = url.match(strictUrlSchemeRegex);

  if (strictSchemeMatch) {
    return strictSchemeMatch[0].toLowerCase();
  }

  // The loose regex also recognizes "&colon;" based scheme smuggling
  // variants such as "javascript&colon;alert(1)", which the strict RFC
  // grammar cannot express.
  const looseSchemeMatch = url.match(urlSchemeMatchRegex);

  if (looseSchemeMatch) {
    return looseSchemeMatch[0].toLowerCase().trim();
  }

  return null;
}

function hasRemainingEncodedCharacters(url: string): RegExpMatchArray | null {
  return (
    url.match(ctrlCharactersRegex) ||
    url.match(htmlEntitiesRegex) ||
    url.match(htmlCtrlEntityRegex) ||
    url.match(whitespaceEscapeCharsRegex)
  );
}

function normalizeDecodedUrl(url: string): string {
  let charsToDecode;
  let iteration = 0;
  let decodedUrl = decodeURI(url.trim());

  do {
    decodedUrl = decodeHtmlCharacters(decodedUrl)
      .replace(htmlCtrlEntityRegex, "")
      .replace(ctrlCharactersRegex, "")
      .replace(whitespaceEscapeCharsRegex, "")
      .trim();

    decodedUrl = decodeURI(decodedUrl);

    charsToDecode = hasRemainingEncodedCharacters(decodedUrl);

    iteration += 1;
  } while (
    charsToDecode &&
    charsToDecode.length > 0 &&
    iteration < MAX_DECODE_ITERATIONS
  );

  // Decode depth exhausted while obfuscated characters remain; treat the
  // input as an evasion attempt rather than continuing unbounded.
  if (charsToDecode && charsToDecode.length > 0) {
    return BLANK_URL;
  }

  return decodedUrl;
}

function buildAllowedSchemes(registeredSchemes: string[] = []): Set<string> {
  const allowedSchemes = new Set(
    registeredSchemes.map(normalizeRegisteredScheme),
  );
  DEFAULT_ALLOWED_SCHEMES.forEach((scheme) => {
    allowedSchemes.add(normalizeRegisteredScheme(scheme));
  });

  return allowedSchemes;
}

function isAllowlistedScheme(
  url: string,
  allowedSchemes: Set<string>,
): boolean {
  const strictSchemeMatch = url.match(strictUrlSchemeRegex);

  if (!strictSchemeMatch) {
    return false;
  }

  const strictScheme = strictSchemeMatch[0].slice(0, -1).toLowerCase();

  return allowedSchemes.has(strictScheme);
}

function normalizeWebUrl(url: string): string {
  if (!isValidUrl(url)) {
    return BLANK_URL;
  }

  const parsedUrl = new URL(url);
  parsedUrl.protocol = parsedUrl.protocol.toLowerCase();
  parsedUrl.hostname = parsedUrl.hostname.toLowerCase();

  return parsedUrl.toString();
}

export function sanitizeUrl(
  url?: string | null,
  options?: SanitizeUrlOptions,
): string {
  if (!url) {
    return BLANK_URL;
  }

  const allowlistMode = typeof options === "object" && options !== null;
  const allowedSchemes = buildAllowedSchemes(options?.allowedSchemes);
  const decodedUrl = normalizeDecodedUrl(url);

  if (decodedUrl === BLANK_URL) {
    return BLANK_URL;
  }

  // Normalize backslashes before any scheme inspection so that backslash
  // variants cannot smuggle a scheme past the checks.
  const sanitizedUrl = decodedUrl.replace(/\\/g, "/");

  if (!sanitizedUrl) {
    return BLANK_URL;
  }

  if (isRelativeUrlWithoutProtocol(sanitizedUrl)) {
    return sanitizedUrl;
  }

  const urlScheme = extractScheme(sanitizedUrl);

  if (urlScheme === null) {
    return sanitizedUrl;
  }

  if (invalidProtocolMatchRegex.test(urlScheme)) {
    return BLANK_URL;
  }

  if (allowlistMode && !isAllowlistedScheme(sanitizedUrl, allowedSchemes)) {
    return BLANK_URL;
  }

  const lowerCaseScheme = urlScheme.toLowerCase();

  // Handle special case for mailto, which has no // authority
  if (lowerCaseScheme === "mailto:") {
    return sanitizedUrl;
  }

  // For http and https URLs, perform additional validation
  if (lowerCaseScheme === "http:" || lowerCaseScheme === "https:") {
    return normalizeWebUrl(sanitizedUrl);
  }

  return sanitizedUrl;
}
