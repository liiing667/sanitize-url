# sanitize-url

## Installation

```sh
npm install -S @braintree/sanitize-url
```

## Usage

```js
var sanitizeUrl = require("@braintree/sanitize-url").sanitizeUrl;

sanitizeUrl("https://example.com"); // 'https://example.com'
sanitizeUrl("http://example.com"); // 'http://example.com'
sanitizeUrl("www.example.com"); // 'www.example.com'
sanitizeUrl("mailto:hello@example.com"); // 'mailto:hello@example.com'
sanitizeUrl(
  "&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;",
); // https://example.com

sanitizeUrl("javascript:alert(document.domain)"); // 'about:blank'
sanitizeUrl("jAvasCrIPT:alert(document.domain)"); // 'about:blank'
sanitizeUrl(decodeURIComponent("JaVaScRiP%0at:alert(document.domain)")); // 'about:blank'
// HTML encoded javascript:alert('XSS')
sanitizeUrl(
  "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
); // 'about:blank'
```

## Allowlist mode

By default `sanitizeUrl` keeps its historical, backwards-compatible
blacklist behavior: only `javascript:`, `data:` and `vbscript:` are blocked,
while any other scheme is passed through.

Pass an options object as the second argument to opt into default-deny
(allowlist) mode instead. In this mode every scheme must be explicitly
allowed:

- `http:`, `https:` and `mailto:` are always allowed.
- Relative references (`./path`, `/path`, `//host/path`) and scheme-less
  strings (for example `www.example.com`) are always allowed.
- Any other scheme is replaced with `about:blank` unless it is registered
  through `allowedSchemes`. Scheme names are case-insensitive and the
  trailing colon is optional.

```js
// Unknown schemes and unregistered deep links are rejected.
sanitizeUrl("com.example.app://deep/link", {}); // 'about:blank'

// Register the deep-link schemes your application trusts.
sanitizeUrl("com.example.app://deep/link", {
  allowedSchemes: ["com.example.app"],
}); // 'com.example.app://deep/link'

// The built-in blacklist still applies, even to registered schemes.
sanitizeUrl("javascript:alert(1)", {
  allowedSchemes: ["javascript"],
}); // 'about:blank'
```

The input is repeatedly decoded (HTML entities and percent encoding), has
control and whitespace-escape characters stripped, and has backslashes
normalized to forward slashes before the scheme is inspected. Repeated
decoding is bounded; input that is still obfuscated after the decode limit
is reached is replaced with `about:blank`.

## Testing

This library uses [Vitest](https://vitest.dev/). All testing dependencies
will be installed upon `npm install` and the test suite can be executed with
`npm test`. Running the test suite will also run lint checks upon exiting.

    npm test

To generate a coverage report, use `npm run coverage`.
