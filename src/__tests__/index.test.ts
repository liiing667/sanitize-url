/* eslint-disable no-script-url */
import { sanitizeUrl } from "..";
import { BLANK_URL, MAX_DECODE_ITERATIONS } from "../constants";

describe("sanitizeUrl", () => {
  it("does not alter http URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("http://example.com/path/to:something")).toBe(
      "http://example.com/path/to:something",
    );
  });

  it("does not alter http URLs with ports with alphanumeric characters", () => {
    expect(sanitizeUrl("http://example.com:4567/path/to:something")).toBe(
      "http://example.com:4567/path/to:something",
    );
  });

  it("does not alter https URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("https://example.com")).toBe("https://example.com/");
  });

  it("does not alter https URLs with ports with alphanumeric characters", () => {
    expect(sanitizeUrl("https://example.com:4567/path/to:something")).toBe(
      "https://example.com:4567/path/to:something",
    );
  });

  it("does not alter relative-path reference URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("./path/to/my.json")).toBe("./path/to/my.json");
  });

  it("does not alter absolute-path reference URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("/path/to/my.json")).toBe("/path/to/my.json");
  });

  it("does not alter protocol-less network-path URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("//google.com/robots.txt")).toBe(
      "//google.com/robots.txt",
    );
  });

  it("does not alter protocol-less URLs with alphanumeric characters", () => {
    expect(sanitizeUrl("www.example.com")).toBe("www.example.com");
  });

  it("does not alter deep-link urls with alphanumeric characters", () => {
    expect(sanitizeUrl("com.braintreepayments.demo://example")).toBe(
      "com.braintreepayments.demo://example",
    );
  });

  it("does not alter mailto urls with alphanumeric characters", () => {
    expect(sanitizeUrl("mailto:test@example.com?subject=hello+world")).toBe(
      "mailto:test@example.com?subject=hello+world",
    );
  });

  it("does not alter urls with accented characters", () => {
    expect(sanitizeUrl("www.example.com/with-áccêntš")).toBe(
      "www.example.com/with-áccêntš",
    );
  });

  it("does not strip harmless unicode characters", () => {
    expect(sanitizeUrl("www.example.com/лот.рфшишкиü–")).toBe(
      "www.example.com/лот.рфшишкиü–",
    );
  });

  it("strips out ctrl chars", () => {
    expect(
      sanitizeUrl("www.example.com/\u200D\u0000\u001F\x00\x1F\uFEFFfoo"),
    ).toBe("www.example.com/foo");
  });

  it(`replaces blank urls with ${BLANK_URL}`, () => {
    expect(sanitizeUrl("")).toBe(BLANK_URL);
  });

  it(`replaces null values with ${BLANK_URL}`, () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    expect(sanitizeUrl(null)).toBe(BLANK_URL);
  });

  it(`replaces undefined values with ${BLANK_URL}`, () => {
    expect(sanitizeUrl()).toBe(BLANK_URL);
  });

  it("removes whitespace from urls", () => {
    expect(sanitizeUrl("   http://example.com/path/to:something    ")).toBe(
      "http://example.com/path/to:something",
    );
  });

  it("removes newline entities from urls", () => {
    expect(sanitizeUrl("https://example.com&NewLine;&NewLine;/something")).toBe(
      "https://example.com/something",
    );
  });

  it("decodes html entities", () => {
    // all these decode to javascript:alert('xss');
    const attackVectors = [
      "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
      "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;",
      "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
      "jav&#x09;ascript:alert('XSS');",
      " &#14; javascript:alert('XSS');",
      "javasc&Tab;ript: alert('XSS');",
      "javasc&#\u0000x09;ript:alert(1)",
      "java&#38;&#38;&#35;78&#59;ewLine&#38;newline&#59;&#59;script&#58;alert&#40;&#39;XSS&#39;&#41;",
      "java&&#78;ewLine&newline;;script:alert('XSS')",
    ];

    attackVectors.forEach((vector) => {
      expect(sanitizeUrl(vector)).toBe(BLANK_URL);
    });

    // https://example.com/javascript:alert('XSS')
    // since the javascript is the url path, and not the protocol,
    // this url is technically sanitized
    expect(
      sanitizeUrl(
        "&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
      ),
    ).toBe("https://example.com/javascript:alert('XSS')");
  });

  it("removes whitespace escape sequences", () => {
    const attackVectors = [
      "javascri\npt:alert('xss')",
      "javascri\rpt:alert('xss')",
      "javascri\tpt:alert('xss')",
      "javascrip\\%74t:alert('XSS')",
      "javascrip%5c%72t:alert()",
      "javascrip%5Ctt:alert()",
      "javascrip%255Ctt:alert()",
      "javascrip%25%35Ctt:alert()",
      "javascrip%25%35%43tt:alert()",
      "javascrip%25%32%35%25%33%35%25%34%33rt:alert()",
      "javascrip%255Crt:alert('%25xss')",
    ];

    attackVectors.forEach((vector) => {
      expect(sanitizeUrl(vector)).toBe(BLANK_URL);
    });
  });

  it("backslash prefixed attack vectors", () => {
    const attackVectors = [
      "\fjavascript:alert()",
      "\vjavascript:alert()",
      "\tjavascript:alert()",
      "\njavascript:alert()",
      "\rjavascript:alert()",
      "\u0000javascript:alert()",
      "\u0001javascript:alert()",
    ];

    attackVectors.forEach((vector) => {
      expect(sanitizeUrl(vector)).toBe(BLANK_URL);
    });
  });

  it("reverses backslashes", () => {
    const attack = "\\j\\av\\a\\s\\cript:alert()";

    expect(sanitizeUrl(attack)).toBe("/j/av/a/s/cript:alert()");
  });

  describe("invalid protocols", () => {
    describe.each(["javascript", "data", "vbscript"])("%s", (protocol) => {
      it(`replaces ${protocol} urls with ${BLANK_URL}`, () => {
        expect(sanitizeUrl(`${protocol}:alert(document.domain)`)).toBe(
          BLANK_URL,
        );
      });

      it(`allows ${protocol} urls that start with a letter prefix`, () => {
        expect(sanitizeUrl(`not_${protocol}:alert(document.domain)`)).toBe(
          `not_${protocol}:alert(document.domain)`,
        );
      });

      it(`disallows ${protocol} urls that start with non-\w characters as a suffix for the protocol`, () => {
        expect(sanitizeUrl(`&!*${protocol}:alert(document.domain)`)).toBe(
          BLANK_URL,
        );
      });

      it(`disallows ${protocol} urls that use &colon; for the colon portion of the url`, () => {
        expect(sanitizeUrl(`${protocol}&colon;alert(document.domain)`)).toBe(
          BLANK_URL,
        );
        expect(sanitizeUrl(`${protocol}&COLON;alert(document.domain)`)).toBe(
          BLANK_URL,
        );
      });

      it(`disregards capitalization for ${protocol} urls`, () => {
        // upper case every other letter in protocol name
        const mixedCapitalizationProtocol = protocol
          .split("")
          .map((character, index) => {
            if (index % 2 === 0) {
              return character.toUpperCase();
            }
            return character;
          })
          .join("");

        expect(
          sanitizeUrl(`${mixedCapitalizationProtocol}:alert(document.domain)`),
        ).toBe(BLANK_URL);
      });

      it(`ignores invisible ctrl characters in ${protocol} urls`, () => {
        const protocolWithControlCharacters = protocol
          .split("")
          .map((character, index) => {
            if (index === 1) {
              return character + "%EF%BB%BF%EF%BB%BF";
            } else if (index === 2) {
              return character + "%e2%80%8b";
            }
            return character;
          })
          .join("");

        expect(
          sanitizeUrl(
            decodeURIComponent(
              `${protocolWithControlCharacters}:alert(document.domain)`,
            ),
          ),
        ).toBe(BLANK_URL);
      });

      it(`replaces ${protocol} urls with ${BLANK_URL} when url begins with %20`, () => {
        expect(
          sanitizeUrl(
            decodeURIComponent(
              `%20%20%20%20${protocol}:alert(document.domain)`,
            ),
          ),
        ).toBe(BLANK_URL);
      });

      it(`replaces ${protocol} urls with ${BLANK_URL} when ${protocol} url begins with spaces`, () => {
        expect(sanitizeUrl(`    ${protocol}:alert(document.domain)`)).toBe(
          BLANK_URL,
        );
      });

      it(`does not replace ${protocol}: if it is not in the scheme of the URL`, () => {
        expect(sanitizeUrl(`http://example.com#${protocol}:foo`)).toBe(
          `http://example.com/#${protocol}:foo`,
        );
      });
    });
  });

  describe("legacy blacklist behavior without options", () => {
    it("still allows unknown deep-link schemes when no options are passed", () => {
      expect(sanitizeUrl("com.braintreepayments.demo://example")).toBe(
        "com.braintreepayments.demo://example",
      );
    });

    it("still allows unknown schemes without an authority when no options are passed", () => {
      expect(sanitizeUrl("customthing:whatever")).toBe("customthing:whatever");
    });

    it("normalizes backslashes before scheme detection in legacy mode", () => {
      expect(sanitizeUrl("https:\\\\example.com")).toBe("https://example.com/");
    });

    it("treats a backslash-prefixed javascript string as a relative path", () => {
      expect(sanitizeUrl("\\javascript:alert()")).toBe("/javascript:alert()");
    });
  });

  describe("allowlist mode", () => {
    it("allows http and https by default", () => {
      expect(sanitizeUrl("http://example.com", {})).toBe("http://example.com/");
      expect(sanitizeUrl("https://example.com", {})).toBe(
        "https://example.com/",
      );
    });

    it("allows mailto by default", () => {
      expect(sanitizeUrl("mailto:test@example.com?subject=hello", {})).toBe(
        "mailto:test@example.com?subject=hello",
      );
    });

    it("allows relative urls without a scheme", () => {
      expect(sanitizeUrl("./path/to/my.json", {})).toBe("./path/to/my.json");
      expect(sanitizeUrl("/path/to/my.json", {})).toBe("/path/to/my.json");
      expect(sanitizeUrl("//example.com/robots.txt", {})).toBe(
        "//example.com/robots.txt",
      );
      expect(sanitizeUrl("www.example.com", {})).toBe("www.example.com");
    });

    it("replaces unknown deep-link schemes with about:blank", () => {
      expect(sanitizeUrl("com.braintreepayments.demo://example", {})).toBe(
        BLANK_URL,
      );
      expect(sanitizeUrl("my-app://deep/link", {})).toBe(BLANK_URL);
      expect(sanitizeUrl("customthing:whatever", {})).toBe(BLANK_URL);
    });

    it("allows explicitly registered deep-link schemes", () => {
      expect(
        sanitizeUrl("com.braintreepayments.demo://example", {
          allowedSchemes: ["com.braintreepayments.demo"],
        }),
      ).toBe("com.braintreepayments.demo://example");

      expect(
        sanitizeUrl("my-app://deep/link", {
          allowedSchemes: ["my-app:"],
        }),
      ).toBe("my-app://deep/link");
    });

    it("accepts registered schemes case-insensitively and with surrounding whitespace", () => {
      expect(
        sanitizeUrl("MY-APP://deep/link", {
          allowedSchemes: ["  My-App:: "],
        }),
      ).toBe("MY-APP://deep/link");
    });

    it("still blocks javascript, data and vbscript when registered", () => {
      expect(
        sanitizeUrl("javascript:alert(1)", {
          allowedSchemes: ["javascript"],
        }),
      ).toBe(BLANK_URL);
      expect(
        sanitizeUrl("data:text/html,hi", { allowedSchemes: ["data"] }),
      ).toBe(BLANK_URL);
      expect(
        sanitizeUrl("vbscript:msgbox(1)", {
          allowedSchemes: ["vbscript"],
        }),
      ).toBe(BLANK_URL);
    });

    it("rejects obfuscated schemes that do not match a strict scheme grammar", () => {
      expect(sanitizeUrl("java&colon;script:alert(1)", {})).toBe(BLANK_URL);
      expect(sanitizeUrl("&!*my-app://evil", {})).toBe(BLANK_URL);
    });

    it("normalizes backslashes before the allowlist scheme check", () => {
      expect(
        sanitizeUrl("my-app:\\\\deep\\link", {
          allowedSchemes: ["my-app"],
        }),
      ).toBe("my-app://deep/link");

      expect(
        sanitizeUrl("evil-scheme:\\\\deep", {
          allowedSchemes: ["my-app"],
        }),
      ).toBe(BLANK_URL);
    });

    it("keeps http/https url normalization in allowlist mode", () => {
      expect(sanitizeUrl("https://EXAMPLE.com:4567/path", {})).toBe(
        "https://example.com:4567/path",
      );

      expect(
        sanitizeUrl("https://example.com", {
          allowedSchemes: ["my-app"],
        }),
      ).toBe("https://example.com/");
    });

    it("rejects malformed http and https urls", () => {
      expect(sanitizeUrl("https://", {})).toBe(BLANK_URL);
    });
  });

  describe("decode depth", () => {
    const wrapHtmlEntity = (value: string): string =>
      value
        .split("")
        .map((char) => `&#${char.charCodeAt(0)};`)
        .join("");

    it("still decodes shallowly nested html entities", () => {
      const shallow = wrapHtmlEntity(wrapHtmlEntity("https://example.com"));

      expect(sanitizeUrl(shallow)).toBe("https://example.com/");
    });

    it("replaces urls whose encoding exceeds the repeated decode depth", () => {
      // Every full-entity wrap needs its own decode pass, so a chain one
      // layer deeper than MAX_DECODE_ITERATIONS cannot finish decoding and
      // is treated as an evasion attempt. A chain at exactly the limit
      // still decodes normally.
      let overLimit = "A";
      for (let index = 0; index < MAX_DECODE_ITERATIONS + 1; index += 1) {
        overLimit = wrapHtmlEntity(overLimit);
      }

      expect(sanitizeUrl(overLimit)).toBe(BLANK_URL);
      expect(sanitizeUrl(overLimit, {})).toBe(BLANK_URL);
    }, 30000);
  });
});
