import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";
import { parse as parseYaml } from "yaml";

/** @type {Record<string, unknown> | null} */
let rsigmaVars = null;
/** @type {Map<string, string> | null} */
let releases = null;
/** @type {string | null} */
let repoRoot = null;
/** Published site origin and base path, from the resolved docmd config. */
let siteUrl = "https://rsigma.io/";
let siteBase = "/";

/**
 * Walk up from a starting directory until we find the workspace `Cargo.toml`
 * (the repository root). The docmd project lives under `docs/`, so the repo
 * root is a parent of the current working directory.
 *
 * @param {string} startDir
 * @returns {string}
 */
function findRepoRoot(startDir) {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, "Cargo.toml"))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return path.resolve(startDir);
    }
    dir = parent;
  }
}

/**
 * @param {string} root Repository root (directory containing Cargo.toml).
 * @returns {Record<string, unknown>}
 */
function loadRsigmaVars(root) {
  const cargoPath = path.join(root, "Cargo.toml");
  const varsPath = path.join(root, "docs", "_data", "vars.yml");
  const cargoText = fs.readFileSync(cargoPath, "utf8");
  const staticVars = parseYaml(fs.readFileSync(varsPath, "utf8"));

  const pkg = {};
  const inWorkspacePackage = cargoText.match(
    /\[workspace\.package\]([\s\S]*?)(?:\n\[|\n*$)/,
  );
  if (inWorkspacePackage) {
    for (const line of inWorkspacePackage[1].split("\n")) {
      const m = line.match(/^(\w[\w-]*) = "(.*)"\s*$/);
      if (m) {
        pkg[m[1]] = m[2];
      }
    }
  }

  const members = cargoText.match(/^members = \[([\s\S]*?)\]/m);
  const crateCount = members ? [...members[1].matchAll(/"[^"]+"/g)].length : undefined;

  const rsigma = {
    ...(staticVars.rsigma ?? {}),
    version: pkg.version,
    edition: pkg.edition,
    msrv: pkg["rust-version"],
    license: pkg.license,
    crate_count: crateCount,
  };

  return { rsigma };
}

/**
 * @param {Record<string, unknown>} vars
 * @param {string} dottedPath
 * @returns {unknown}
 */
function getVar(vars, dottedPath) {
  return dottedPath.split(".").reduce((obj, key) => {
    if (obj && typeof obj === "object" && key in obj) {
      return /** @type {Record<string, unknown>} */ (obj)[key];
    }
    return undefined;
  }, /** @type {unknown} */ (vars));
}

/**
 * @param {unknown} value
 * @param {string | undefined} search
 * @param {string | undefined} replaceWith
 * @returns {string}
 */
function applyReplaceFilter(value, search, replaceWith) {
  const text = String(value ?? "");
  if (search === undefined || replaceWith === undefined) {
    return text;
  }
  return text.split(search).join(replaceWith);
}

/**
 * @param {string} src
 * @param {Record<string, unknown>} vars
 * @returns {string}
 */
function substituteRsigmaMacros(src, vars) {
  return src.replace(
    /\{\{\s*rsigma\.([\w.]+)\s*(?:\|\s*replace\("([^"]*)",\s*"([^"]*)"\))?\s*\}\}/g,
    (_match, dottedPath, search, replaceWith) =>
      applyReplaceFilter(getVar(vars, `rsigma.${dottedPath}`), search, replaceWith),
  );
}

/**
 * Read the released versions from `CHANGELOG.md` headings
 * (`## [X.Y.Z] - YYYY-MM-DD`), keyed by version with the release date.
 *
 * @param {string} root Repository root.
 * @returns {Map<string, string>}
 */
function loadReleases(root) {
  const text = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  const releases = new Map();
  for (const m of text.matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})\s*$/gm)) {
    releases.set(m[1], m[2]);
  }
  return releases;
}

/**
 * Heading id docmd assigns to a version section on the release-notes page,
 * which inlines the changelog under its `# Changelog` title.
 *
 * @param {string} version `X.Y.Z` or `unreleased`
 * @param {Map<string, string>} releases
 * @returns {string}
 */
function releaseAnchor(version, releases) {
  if (version === "unreleased") {
    return "changelog-unreleased";
  }
  return `changelog-${version.replaceAll(".", "")}-${releases.get(version)}`;
}

/** Anchors emitted by version tags, checked against the built release notes. */
const emittedReleaseAnchors = new Set();

/**
 * Expand `{{ added "X.Y.Z" }}` and `{{ added "unreleased" }}` into docmd
 * inline tags linking to the matching release-notes section. Fenced code
 * blocks and inline code spans are left alone so the syntax can be quoted.
 *
 * docmd does not rebase tag URLs for its pretty-URL output the way it does
 * Markdown links, and it calls `onBeforeParse` for the home page without a
 * file path, so the link is rooted at the site base rather than page-relative.
 *
 * Each tag is closed with `:::` so text after it on the same line stays
 * outside the tag. docmd only honors that terminator when whitespace or the end
 * of the line follows it, so a tag directly followed by punctuation is an error.
 * A tag inside a heading is also an error, since docmd would fold the tag's
 * text into the heading anchor.
 *
 * @param {string} src
 * @param {string} page Page path for error messages.
 * @param {Map<string, string>} releases
 * @returns {string}
 */
function expandVersionTags(src, page, releases) {
  if (!/\{\{\s*added\s/.test(src)) {
    return src;
  }
  const tagRe = /\{\{\s*added\s+"([^"]+)"\s*\}\}/g;
  const notes = `${siteBase.endsWith("/") ? siteBase : `${siteBase}/`}release-notes/`;
  const render = (match, version, offset, text) => {
    const next = text.charAt(offset + match.length);
    if (next && !/\s/.test(next)) {
      throw new Error(
        `docmd-plugin-rsigma: ${page} has "${next}" directly after {{ added "${version}" }}; put whitespace or a line end after the tag`,
      );
    }
    if (version !== "unreleased" && !releases.has(version)) {
      throw new Error(
        `docmd-plugin-rsigma: ${page} tags unknown version "${version}"; use a released X.Y.Z from CHANGELOG.md or "unreleased"`,
      );
    }
    const anchor = releaseAnchor(version, releases);
    emittedReleaseAnchors.add(anchor);
    return version === "unreleased"
      ? `::: tag "Unreleased" icon:flask-conical color:#d97706 url:"${notes}#${anchor}" :::`
      : `::: tag "Added in v${version}" icon:tag url:"${notes}#${anchor}" :::`;
  };
  const skipRe = /(`+[^`]*`+)/;
  let inFence = false;
  return src
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (t.startsWith("```") || t.startsWith("~~~")) {
        inFence = !inFence;
        return line;
      }
      if (inFence) {
        return line;
      }
      const segs = line.split(skipRe);
      if (
        /^ {0,3}#{1,6}\s/.test(line) &&
        segs.some((seg) => !seg.startsWith("`") && /\{\{\s*added\s/.test(seg))
      ) {
        throw new Error(
          `docmd-plugin-rsigma: ${page} has a version tag in the heading "${line.trim()}"; put the tag on its own line below the heading so the anchor stays stable`,
        );
      }
      return segs
        .map((seg) => (seg.startsWith("`") ? seg : seg.replace(tagRe, render)))
        .join("");
    })
    .join("\n");
}

const INCLUDE_MARKDOWN_RE = /\{%\s*include-markdown\s+"([^"]+)"\s*%\}/g;

/**
 * @param {string} src
 * @param {string} filePath
 * @param {string} projectRoot
 * @returns {string}
 */
function inlineIncludeMarkdown(src, filePath, projectRoot) {
  return src.replace(INCLUDE_MARKDOWN_RE, (_match, relPath) => {
    const baseDir = path.dirname(filePath);
    const target = path.resolve(baseDir, relPath);
    const relToRoot = path.relative(projectRoot, target);
    if (relToRoot.startsWith("..") || path.isAbsolute(relToRoot)) {
      throw new Error(
        `include-markdown target escapes project root: ${relPath} from ${filePath}`,
      );
    }
    return fs.readFileSync(target, "utf8").trimEnd();
  });
}

/**
 * Turn GitHub issue/PR shorthand (`#123`) into links, matching the old
 * MkDocs `pymdownx.magiclink` behaviour. Skips fenced code blocks and inline
 * code spans, and leaves already-linked references (`[#123](...)`) untouched.
 * `/issues/N` redirects to `/pull/N` for pull requests, so it resolves for both.
 *
 * @param {string} md
 * @param {string} repoUrl e.g. https://github.com/timescale/rsigma
 * @returns {string}
 */
function linkifyIssueRefs(md, repoUrl) {
  const base = `${repoUrl.replace(/\/$/, "")}/issues/`;
  // Not preceded by a word char, `[` (existing link text), `#`, `&`, or `/`
  // (URL path/entity); followed by digits ending on a word boundary.
  const issueRe = /(?<![\w[#&/])#(\d+)\b/g;
  // `#N` tokens whose immediately preceding word marks an external reference
  // (a newsletter issue or a SigmaHQ spec proposal), not an rsigma issue/PR.
  const excludeBefore = [
    /\bweekly\s*$/i, // Detection Engineering Weekly #N
    /\bdew\s*$/i, // DEW #N
    /\bsec\s*$/i, // tl;dr sec #N
    /\bnewsletter\s*$/i,
    /\bblacknoise\s*$/i,
    /\bsep\s*$/i, // Sigma Enhancement Proposal #N
    /\bdiscussion\s*$/i, // SigmaHQ spec Discussion #N
    /\bspecification\s*$/i, // (sigma-)specification #N
  ];
  // Split out inline code spans and existing markdown links so `#N` inside
  // them (e.g. `[issue #158](...)`, `[SEP #212](...)`) is never rewritten.
  const skipRe = /(`+[^`]*`+|\[[^\]]*\]\([^)]*\))/;
  const linkInline = (text) =>
    text
      .split(skipRe)
      .map((seg) => {
        if (!seg || seg.startsWith("`") || seg.startsWith("[")) return seg;
        return seg.replace(issueRe, (m, n, offset, str) =>
          excludeBefore.some((re) => re.test(str.slice(0, offset)))
            ? m
            : `[#${n}](${base}${n})`,
        );
      })
      .join("");
  let inFence = false;
  return md
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (t.startsWith("```") || t.startsWith("~~~")) {
        inFence = !inFence;
        return line;
      }
      return inFence ? line : linkInline(line);
    })
    .join("\n");
}

/**
 * Render inline-code spans (`` `code` ``) in an already-HTML-escaped string as
 * `<code>` elements. Used where HTML renders (the visible header title).
 *
 * @param {string} escaped
 * @returns {string}
 */
function inlineCodeToHtml(escaped) {
  return escaped.replace(/`([^`]+)`/g, "<code>$1</code>");
}

/**
 * Drop inline-code backticks, keeping the inner text. Used in plain-text
 * contexts (`<title>`, Open Graph / Twitter meta) where HTML does not render.
 *
 * @param {string} text
 * @returns {string}
 */
function stripInlineCode(text) {
  return text.replace(/`([^`]+)`/g, "$1");
}

/**
 * docmd derives the page title from the first Markdown H1 but keeps the raw
 * text, so a heading like `` # `rsigma engine discover-schemas` `` leaves
 * literal backticks in the header bar, the focus-mode title, the `<title>`, and
 * the social meta. Fix that after render: the visible titles render the code
 * span as `<code>` (matching the in-body H1), and the plain-text `<title>` / meta strip the
 * markers. Pages whose title has no backticks are left untouched.
 *
 * @param {string} html
 * @returns {string}
 */
function renderMarkdownTitles(html) {
  let out = html.replace(
    /(<span class="header-title">)([\s\S]*?)(<\/span>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${inlineCodeToHtml(inner.trim())}${close}` : match,
  );
  out = out.replace(
    /(<h1 class="docmd-focus-title">)([\s\S]*?)(<\/h1>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${inlineCodeToHtml(inner.trim())}${close}` : match,
  );
  out = out.replace(
    /(<title>)([\s\S]*?)(<\/title>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${stripInlineCode(inner)}${close}` : match,
  );
  out = out.replace(
    /(<meta (?:property="og:title"|name="twitter:title") content=")([^"]*)(">)/g,
    (match, open, content, close) =>
      content.includes("`") ? `${open}${stripInlineCode(content)}${close}` : match,
  );
  return out;
}

/**
 * Set Google Consent Mode before docmd's GA4 script runs, then connect it to
 * docmd's cookie-consent event. Advertising consent remains denied because the
 * site only uses analytics.
 *
 * @param {string} html
 * @returns {string}
 */
function injectAnalyticsConsentMode(html) {
  const ga4Marker = "    <!-- GA4 -->";
  let out = html.replace(
    /(<script async src="https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=)"(G-[A-Z0-9]{6,12})"("><\/script>)/,
    "$1$2$3",
  );
  if (!out.includes(ga4Marker) || out.includes("RSigma GA4 consent mode")) {
    return out;
  }
  const consentScript = `    <!-- RSigma GA4 consent mode -->
    <script>
      window.dataLayer = window.dataLayer || [];
      window.gtag = window.gtag || function(){dataLayer.push(arguments);};
      (function() {
        var analyticsConsent = 'denied';
        try {
          var raw = localStorage.getItem('docmd-cookie-consent');
          var choice = raw ? JSON.parse(raw) : null;
          if (choice && choice.value === 'accept' && choice.expires > Date.now()) {
            analyticsConsent = 'granted';
          }
        } catch (_) {}
        gtag('consent', 'default', {
          ad_storage: 'denied',
          ad_user_data: 'denied',
          ad_personalization: 'denied',
          analytics_storage: analyticsConsent
        });
        window.addEventListener('docmd:cookie-consent', function(event) {
          gtag('consent', 'update', {
            ad_storage: 'denied',
            ad_user_data: 'denied',
            ad_personalization: 'denied',
            analytics_storage: event.detail.value === 'accept' ? 'granted' : 'denied'
          });
        });
      })();
    </script>
`;
  return out.replace(ga4Marker, `${consentScript}${ga4Marker}`);
}

/** Legacy generated/copied brand files to remove when refreshing assets. */
const STALE_BRAND_FILES = [
  "sidebar-logo.svg",
  "logo.png",
  "logo-dark.png",
  "favicon.png",
  "favicon-dark.png",
  "rsigma-logotype.svg",
  "rsigma-logo.svg",
  "rsigma-logotype.png",
];

/** Repo-root `assets/` brand files published under a fixed site name. */
const BRAND_COPIES = {
  "logo.svg": "rsigma-logotype-horizontal.svg",
  "logo-dark.svg": "rsigma-logotype-horizontal-dark.svg",
  "favicon.svg": "rsigma-icon.svg",
  "social-banner.png": "social-banner.png",
};

/** Sizes packed into `favicon.ico` for browsers without SVG favicon support. */
const ICO_SIZES = [16, 32, 48];

/**
 * Link preview banner referenced by `plugins.seo.openGraph.defaultImage`,
 * copied from the repo-root `assets/`. The size must match the PNG.
 */
const SOCIAL_BANNER = {
  name: "social-banner.png",
  alt: "RSigma: a complete Sigma detection engineering toolkit",
  width: 1200,
  height: 627,
};

/** Repo-root `assets/` files copied into the site so pages can embed them. */
const COPIED_ASSETS = ["detection-loop.svg", "architecture.svg", "internal_architecture.svg"];

/**
 * The repo copy of an SVG links to the published site with absolute URLs so
 * it still works when opened on its own (GitHub "Raw", a local file). Inside
 * the docs those links must follow the host serving the build instead, so the
 * site origin is rewritten to the configured base path.
 *
 * @param {Buffer} data
 * @returns {Buffer}
 */
function relinkToSiteBase(data) {
  const origin = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
  const base = siteBase.endsWith("/") ? siteBase : `${siteBase}/`;
  return Buffer.from(data.toString("utf8").replaceAll(`href="${origin}`, `href="${base}`), "utf8");
}

/** @type {{ key: string, images: Record<string, Buffer> } | null} */
let brandImageCache = null;

/**
 * Pack PNG images into an ICO container. Every browser that still asks for
 * `favicon.ico` reads PNG-encoded entries.
 *
 * @param {{ size: number, png: Buffer }[]} entries
 * @returns {Buffer}
 */
function packIco(entries) {
  const header = Buffer.alloc(6 + 16 * entries.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  let offset = header.length;
  entries.forEach(({ size, png }, i) => {
    const at = 6 + 16 * i;
    header.writeUInt8(size >= 256 ? 0 : size, at);
    header.writeUInt8(size >= 256 ? 0 : size, at + 1);
    header.writeUInt16LE(1, at + 4);
    header.writeUInt16LE(32, at + 6);
    header.writeUInt32LE(png.length, at + 8);
    header.writeUInt32LE(offset, at + 12);
    offset += png.length;
  });
  return Buffer.concat([header, ...entries.map((e) => e.png)]);
}

/**
 * Build the brand image set from the repo-root `assets/`: the light and dark
 * sidebar lockups, the SVG favicon, and the link preview banner are copied
 * as-is; `favicon.ico` (from the small mark) and `apple-touch-icon.png` (the
 * full mark on white, since iOS fills transparency with black) are
 * rasterised. Memoised on the
 * sources so repeated builds in one `docmd dev` session rasterise once.
 *
 * @param {string} assetsDir
 * @returns {Promise<Record<string, Buffer>>}
 */
async function renderBrandImages(assetsDir) {
  const read = (name) => {
    const file = path.join(assetsDir, name);
    if (!fs.existsSync(file)) {
      throw new Error(`docmd-plugin-rsigma: missing brand asset ${file}`);
    }
    return fs.readFileSync(file);
  };
  const mark = read("rsigma-logo.svg");
  const copies = Object.fromEntries(
    Object.entries(BRAND_COPIES).map(([dest, src]) => [dest, read(src)]),
  );
  const key = [mark, ...Object.values(copies)].map((b) => b.toString("utf8")).join("\0");
  if (brandImageCache && brandImageCache.key === key) {
    return brandImageCache.images;
  }

  const icon = copies["favicon.svg"];
  const icoEntries = await Promise.all(
    ICO_SIZES.map(async (size) => ({
      size,
      png: await sharp(icon, { density: 300 }).resize(size, size).png().toBuffer(),
    })),
  );

  const touchSize = 180;
  const touchPad = 16;
  const touchMark = await sharp(mark, { density: 300 })
    .resize(touchSize - 2 * touchPad, touchSize - 2 * touchPad, {
      fit: "contain",
      background: { r: 255, g: 255, b: 255, alpha: 0 },
    })
    .png()
    .toBuffer();
  const touchIcon = await sharp(touchMark)
    .extend({
      top: touchPad,
      bottom: touchPad,
      left: touchPad,
      right: touchPad,
      background: { r: 255, g: 255, b: 255, alpha: 0 },
    })
    .flatten({ background: "#ffffff" })
    .png()
    .toBuffer();

  const images = {
    ...copies,
    "favicon.ico": packIco(icoEntries),
    "apple-touch-icon.png": touchIcon,
  };
  brandImageCache = { key, images };
  return images;
}

/**
 * docmd emits a single `<link rel="icon">` for `config.favicon`. Keep it as
 * the SVG icon and add the ICO fallback (for browsers without SVG favicons)
 * and the Apple touch icon beside it, reusing its page-relative prefix and
 * cache-busting query.
 *
 * @param {string} html
 * @returns {string}
 */
function injectIconLinks(html) {
  return html.replace(
    /<link id="site-favicon" rel="icon" href="([^"]*)favicon\.svg(\?[^"]*)?">/,
    (_tag, prefix, query = "") =>
      `<link rel="icon" href="${prefix}favicon.ico${query}" sizes="32x32">` +
      `<link id="site-favicon" rel="icon" href="${prefix}favicon.svg${query}" type="image/svg+xml">` +
      `<link rel="apple-touch-icon" href="${prefix}apple-touch-icon.png${query}">`,
  );
}

/**
 * Write a file only when its bytes differ from what is already on disk.
 * `docmd dev` watches `docs/assets/` and keys its change detection on
 * mtime, so an unconditional rewrite of an identical file starts a build
 * loop that never settles.
 *
 * @param {string} filePath
 * @param {Buffer} data
 */
function writeIfChanged(filePath, data) {
  try {
    if (fs.readFileSync(filePath).equals(data)) {
      return;
    }
  } catch {
    // Missing or unreadable: fall through and write.
  }
  fs.writeFileSync(filePath, data);
}

/**
 * @param {string} destDir
 * @param {string} assetsDir
 */
async function writeBrandImages(destDir, assetsDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const images = await renderBrandImages(assetsDir);
  for (const [name, data] of Object.entries(images)) {
    writeIfChanged(path.join(destDir, name), data);
  }

  for (const name of COPIED_ASSETS) {
    const src = path.join(assetsDir, name);
    if (!fs.existsSync(src)) {
      throw new Error(`docmd-plugin-rsigma: missing asset ${src}`);
    }
    writeIfChanged(path.join(destDir, name), relinkToSiteBase(fs.readFileSync(src)));
  }

  for (const stale of STALE_BRAND_FILES) {
    const stalePath = path.join(destDir, stale);
    if (fs.existsSync(stalePath)) {
      fs.unlinkSync(stalePath);
    }
  }
}

/**
 * Generate brand images from the canonical SVGs in the repo-root `assets/`
 * into `{docsRoot}/assets/images/`. Keeps a single source of truth at the
 * repo root without git symlinks (which break on many Windows clones and are
 * unreliable on static hosts).
 *
 * @param {string} repoRoot
 * @param {string} docsRoot
 */
async function syncBrandAssets(repoRoot, docsRoot) {
  await writeBrandImages(path.join(docsRoot, "assets", "images"), path.join(repoRoot, "assets"));
}

/**
 * Read the `viewBox` of each copied diagram so its `<object>` embed can carry
 * the matching aspect ratio.
 *
 * @param {string} assetsDir
 * @returns {Map<string, string>} file name to a CSS `aspect-ratio` value
 */
function diagramAspectRatios(assetsDir) {
  const ratios = new Map();
  for (const name of COPIED_ASSETS) {
    const svg = fs.readFileSync(path.join(assetsDir, name), "utf8");
    const viewBox = svg.match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
    if (!viewBox) {
      throw new Error(`docmd-plugin-rsigma: ${name} has no "0 0 W H" viewBox`);
    }
    ratios.set(name, `${viewBox[1]} / ${viewBox[2]}`);
  }
  return ratios;
}

/**
 * Wrap images of the copied diagrams in an `<object>` so their links and
 * hover styles work; SVG loaded through `<img>` is inert. docmd escapes raw
 * HTML in Markdown, so the page keeps a plain image and the swap happens here.
 * The original `<img>` stays inside as the fallback content.
 *
 * @param {string} html
 * @param {Map<string, string>} ratios
 */
function embedInteractiveDiagrams(html, ratios) {
  return html.replace(
    /(?<!<object[^>]*>)<img src="([^"]*\/assets\/images\/([\w-]+\.svg))" alt="([^"]*)">/g,
    (img, src, name, alt) => {
      const ratio = ratios.get(name);
      if (!ratio) {
        return img;
      }
      return `<object class="diagram" data="${src}" type="image/svg+xml" aria-label="${alt}" style="aspect-ratio: ${ratio}">${img}</object>`;
    },
  );
}

/**
 * Recursively collect every .html file under a directory.
 *
 * @param {string} dir
 * @returns {string[]}
 */
function collectHtmlFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectHtmlFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".html")) {
      out.push(full);
    }
  }
  return out;
}

/** Fence languages that mean "no highlighting". */
const PLAIN_FENCE_LANGUAGES = new Set(["text", "txt", "plaintext", "plain"]);

/**
 * docmd's highlighter (lite-hl) ignores the fence language and runs one
 * heuristic tokenizer over every block, so plain-text blocks get colored as
 * code: an apostrophe opens a "string" that runs to the next one. Render those
 * blocks escaped and unhighlighted instead, keeping the same wrapper markup.
 *
 * @param {any} md markdown-it instance
 */
function plainTextFences(md) {
  const highlight = md.options.highlight;
  md.options.highlight = (str, lang, attrs) => {
    if (PLAIN_FENCE_LANGUAGES.has(lang)) {
      return `<pre class="hljs"><code class="language-${lang}">${md.utils.escapeHtml(str)}</code></pre>`;
    }
    return highlight ? highlight(str, lang, attrs) : "";
  };
}

/** Search engines cut meta descriptions off at about this many characters. */
const MAX_DESCRIPTION_LENGTH = 160;

/**
 * docmd's SEO plugin writes an empty `<meta name="description">` for a page
 * without a `description:` in its frontmatter, so search results and link
 * previews fall back to whatever text the crawler picks. Fail the build
 * instead.
 *
 * @param {any[]} pages
 * @param {string} docsRoot
 */
function checkDescriptions(pages, docsRoot) {
  const problems = [];
  for (const page of pages) {
    const where = page.sourcePath ? path.relative(docsRoot, page.sourcePath) : page.outputPath;
    const description = page.frontmatter?.description;
    if (typeof description !== "string" || !description.trim()) {
      problems.push(`${where}: no description`);
    } else if (description.length > MAX_DESCRIPTION_LENGTH) {
      problems.push(
        `${where}: description is ${description.length} characters, over ${MAX_DESCRIPTION_LENGTH}`,
      );
    }
  }
  if (problems.length > 0) {
    throw new Error(
      `docmd-plugin-rsigma: every page needs a frontmatter description of at most ${MAX_DESCRIPTION_LENGTH} characters:\n  ${problems.join("\n  ")}`,
    );
  }
}

/**
 * Add the size and alt text of the link preview banner after the `og:image` and
 * `twitter:image` tags docmd emits, so previews render without fetching the
 * image first, plus `og:site_name` after `og:type`.
 *
 * @param {string} html
 * @returns {string}
 */
function injectSocialMeta(html) {
  const card = new RegExp(`(<meta property="og:image" content="[^"]*/${SOCIAL_BANNER.name}">\\n?)`);
  const twitterCard = new RegExp(`(<meta name="twitter:image" content="[^"]*/${SOCIAL_BANNER.name}">\\n?)`);
  if (html.includes('property="og:site_name"')) {
    return html;
  }
  return html
    .replace(/(<meta property="og:type" content="[^"]*">\n?)/, '$1<meta property="og:site_name" content="RSigma">\n')
    .replace(
      card,
      `$1<meta property="og:image:width" content="${SOCIAL_BANNER.width}">\n` +
        `<meta property="og:image:height" content="${SOCIAL_BANNER.height}">\n` +
        `<meta property="og:image:alt" content="${SOCIAL_BANNER.alt}">\n`,
    )
    .replace(twitterCard, `$1<meta name="twitter:image:alt" content="${SOCIAL_BANNER.alt}">\n`);
}

/**
 * docmd builds the `BreadcrumbList` structured data from the sidebar, so a
 * navigation group without a page of its own (`Reference`, `rule`, `Deploy and
 * Detect`) becomes a list item with a name and no `item` URL. Google rejects
 * the whole trail when any item but the last lacks one, so drop those items
 * and renumber the rest.
 *
 * @param {string} html
 * @returns {string}
 */
function linkBreadcrumbStructuredData(html) {
  return html.replace(
    /(<script type="application\/ld\+json">\n)(\{"@context":"https:\/\/schema\.org","@type":"BreadcrumbList".*\})(\n<\/script>)/,
    (match, open, json, close) => {
      const data = JSON.parse(json);
      const items = data.itemListElement;
      const linked = items.filter((item, i) => item.item || i === items.length - 1);
      if (linked.length === items.length) {
        return match;
      }
      data.itemListElement = linked.map((item, i) => ({ ...item, position: i + 1 }));
      return `${open}${JSON.stringify(data).replaceAll("<", "\\u003c")}${close}`;
    },
  );
}

/**
 * Describe RSigma itself on the home page with schema.org `SoftwareApplication`
 * data, using the version and license from `Cargo.toml`.
 *
 * @param {string} html
 * @param {string} description
 * @returns {string}
 */
function injectSoftwareStructuredData(html, description) {
  if (html.includes('"SoftwareApplication"')) {
    return html;
  }
  const rsigma = /** @type {any} */ (rsigmaVars)?.rsigma ?? {};
  const origin = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
  const data = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "RSigma",
    description,
    url: origin,
    image: `${origin}assets/images/${SOCIAL_BANNER.name}`,
    applicationCategory: "SecurityApplication",
    operatingSystem: "Linux, macOS, Windows",
    softwareVersion: rsigma.version,
    license: `https://spdx.org/licenses/${rsigma.license}.html`,
    sameAs: [rsigma.repo_url, "https://crates.io/crates/rsigma"],
    offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  };
  const json = JSON.stringify(data, null, 2).replaceAll("<", "\\u003c");
  return html.replace("</head>", `<script type="application/ld+json">\n${json}\n</script>\n</head>`);
}

/**
 * Commit time of the last change to a file, as an ISO 8601 string, or null
 * outside a git checkout or for an uncommitted file.
 *
 * @param {string} file
 * @param {string} root Repository root.
 * @returns {string | null}
 */
function gitLastCommitDate(file, root) {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%ct", "--", path.relative(root, file)], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out ? new Date(Number(out) * 1000).toISOString() : null;
  } catch {
    return null;
  }
}

/**
 * docmd's sitemap has no `<lastmod>`, which crawlers use to decide what to
 * recrawl. Add the last commit time of each page's source, from the git
 * plugin's metadata, or of the root file a page inlines (release notes,
 * contributing, benchmarks, security policy) when that is newer.
 *
 * @param {string} sitemapPath
 * @param {any[]} pages
 * @param {string} root Repository root.
 * @returns {number} entries dated
 */
function addSitemapLastmod(sitemapPath, pages, root) {
  if (!fs.existsSync(sitemapPath)) {
    return 0;
  }
  const origin = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
  const lastmod = new Map();
  for (const page of pages) {
    const dates = [page.frontmatter?._git?.lastUpdated];
    if (page.sourcePath && typeof page.rawMarkdown === "string") {
      for (const m of page.rawMarkdown.matchAll(INCLUDE_MARKDOWN_RE)) {
        dates.push(gitLastCommitDate(path.resolve(path.dirname(page.sourcePath), m[1]), root));
      }
    }
    const newest = dates.filter(Boolean).sort().at(-1);
    if (newest) {
      lastmod.set(`${origin}${page.outputPath.replace(/index\.html$/, "")}`, newest);
    }
  }
  let dated = 0;
  const xml = fs
    .readFileSync(sitemapPath, "utf8")
    .replace(/(<loc>([^<]+)<\/loc>\n)(?!\s*<lastmod>)/g, (match, locLine, url) => {
      const date = lastmod.get(url);
      if (!date) {
        return match;
      }
      dated += 1;
      return `${locLine}    <lastmod>${date}</lastmod>\n`;
    });
  fs.writeFileSync(sitemapPath, xml);
  return dated;
}

export default {
  plugin: {
    name: "docmd-plugin-rsigma",
    version: "1.0.0",
    capabilities: ["init", "markdown", "build", "post-build"],
  },

  markdownSetup(md) {
    plainTextFences(md);
  },

  async onConfigResolved(config) {
    if (typeof config?.url === "string" && config.url) {
      siteUrl = config.url;
    }
    if (typeof config?.base === "string" && config.base) {
      siteBase = config.base;
    }
    const docsRoot = process.cwd();
    repoRoot = findRepoRoot(docsRoot);
    rsigmaVars = loadRsigmaVars(repoRoot);
    releases = loadReleases(repoRoot);
    await syncBrandAssets(repoRoot, docsRoot);
  },

  onBeforeParse(src, _frontmatter, filePath) {
    if (!repoRoot) {
      repoRoot = findRepoRoot(process.cwd());
    }
    if (!rsigmaVars) {
      rsigmaVars = loadRsigmaVars(repoRoot);
    }
    if (!releases) {
      releases = loadReleases(repoRoot);
    }
    let out = inlineIncludeMarkdown(src, filePath ?? repoRoot, repoRoot);
    out = substituteRsigmaMacros(out, rsigmaVars);
    out = expandVersionTags(out, filePath ?? "a page", releases);
    // Linkify `#123` issue/PR shorthand on the release-notes page (the inlined
    // CHANGELOG), replacing the old MkDocs magiclink behaviour.
    if (typeof filePath === "string" && /release-notes\.md$/.test(filePath)) {
      const repoUrl =
        /** @type {any} */ (rsigmaVars)?.rsigma?.repo_url ||
        "https://github.com/timescale/rsigma";
      out = linkifyIssueRefs(out, repoUrl);
    }
    return out;
  },

  // docmd emits page-relative asset/link URLs (e.g. `../../assets/...`) together
  // with a `<base href="{siteRoot}">` tag. The base tag re-roots those relative
  // URLs at the site root, which breaks deep pages when combined with how the
  // client resolves paths. The client JS reads `window.DOCMD_BASE`, not the tag,
  // so removing the tag lets relative URLs resolve against the real document URL.
  async onPostBuild(ctx) {
    const outputDir = ctx?.outputDir ?? path.join(process.cwd(), "site");
    const log = typeof ctx?.log === "function" ? ctx.log : () => {};
    const docsRoot = process.cwd();
    const pages = ctx?.pages ?? [];
    checkDescriptions(pages, docsRoot);
    const root = repoRoot ?? findRepoRoot(docsRoot);
    const assetsDir = path.join(root, "assets");
    await writeBrandImages(path.join(outputDir, "assets", "images"), assetsDir);
    await writeBrandImages(path.join(docsRoot, "assets", "images"), assetsDir);
    // Browsers request /favicon.ico on their own for pages without icon links
    // (raw files, feeds), so the site root carries a copy too.
    writeIfChanged(path.join(outputDir, "favicon.ico"), (await renderBrandImages(assetsDir))["favicon.ico"]);
    // The config template and deployment units point yaml-language-server at
    // https://rsigma.io/rsigma.schema.json. Docs CI does not build the Rust
    // binary, so the schema is a committed artifact copied to the site root.
    writeIfChanged(
      path.join(outputDir, "rsigma.schema.json"),
      fs.readFileSync(path.join(docsRoot, "rsigma.schema.json")),
    );
    const ratios = diagramAspectRatios(assetsDir);
    const homeHtml = path.join(outputDir, "index.html");
    const homePage = pages.find((page) => page.outputPath === "index.html");
    let stripped = 0;
    let titlesRendered = 0;
    for (const file of collectHtmlFiles(outputDir)) {
      const html = fs.readFileSync(file, "utf8");
      let next = html.replace(/[ \t]*<base\b[^>]*>\n?/i, "");
      if (next !== html) {
        stripped += 1;
      }
      next = injectAnalyticsConsentMode(next);
      next = injectIconLinks(next);
      next = injectSocialMeta(next);
      next = linkBreadcrumbStructuredData(next);
      if (file === homeHtml) {
        next = injectSoftwareStructuredData(next, homePage?.frontmatter?.description ?? "");
      }
      next = embedInteractiveDiagrams(next, ratios);
      const withTitles = renderMarkdownTitles(next);
      if (withTitles !== next) {
        titlesRendered += 1;
        next = withTitles;
      }
      if (next !== html) {
        fs.writeFileSync(file, next);
      }
    }
    const dated = addSitemapLastmod(path.join(outputDir, "sitemap.xml"), pages, root);
    const notesHtml = path.join(outputDir, "release-notes", "index.html");
    if (emittedReleaseAnchors.size > 0 && fs.existsSync(notesHtml)) {
      const notes = fs.readFileSync(notesHtml, "utf8");
      const broken = [];
      for (const file of collectHtmlFiles(outputDir)) {
        const html = fs.readFileSync(file, "utf8");
        for (const m of html.matchAll(/<a href="([^"]*)" class="docmd-tag-link"/g)) {
          const [target, anchor = ""] = m[1].split("#");
          const resolved = path.resolve(path.dirname(file), target, "index.html");
          if (resolved !== notesHtml || !notes.includes(`id="${anchor}"`)) {
            broken.push(`${path.relative(outputDir, file)} -> ${m[1]}`);
          }
        }
      }
      if (broken.length > 0) {
        throw new Error(
          `docmd-plugin-rsigma: version tags do not resolve to a release-notes heading:\n  ${broken.join("\n  ")}`,
        );
      }
    }
    log(
      `docmd-plugin-rsigma: stripped <base> tag from ${stripped} pages, rendered Markdown in ${titlesRendered} page titles, checked ${emittedReleaseAnchors.size} version-tag anchors, dated ${dated} sitemap entries`,
    );
  },
};
