// Best-effort credential redaction for text that ends up in the model's context (device consoles,
// logs). Covers the common shapes: URL userinfo, rtsp stream paths, auth headers, and
// keyword-anchored values like `token=...` or `"password": "..."`.
//
// Every pass stays linear on adversarial input: value runs after a fixed anchor (a keyword, or
// rtsp://host/) are unbounded, but each match starts at the anchor and a global replace resumes
// after it, so a long secret is redacted whole. The only bounded parts are those where a match
// could start at many places.

// Value after a keyword separator: a double- or single-quoted string (backslash escapes allowed,
// closing quote optional so an unterminated value is redacted to the end of the line instead of
// failing the match and rescanning), or an unquoted run.
const QUOTED_OR_BARE = String.raw`"(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|[^\s"'&,;}]+`;

const SECRET_PATTERNS: Array<[RegExp, (m: string, ...groups: string[]) => string]> = [
    // rtsp(s)://host/<path>: stream paths often are the credential (UniFi Protect's
    // rtsps://host:7441/<token>), so keep the host for debugging and drop the path.
    [/\b(rtsps?:\/\/[^\s/'"]{1,255}\/)[^\s'"]+/gi, (_m, prefix) => `${prefix}[REDACTED]`],
    // Authorization: Bearer xyz / Basic xyz
    [
        /\b(authorization\s{0,8}[:=]\s{0,8}["']?)(?:bearer|basic|digest)?\s{0,8}[^\s"',]+/gi,
        (_m, prefix) => `${prefix}[REDACTED]`,
    ],
    // bare bearer tokens
    [/\b(bearer\s{1,8})[a-z0-9._~+/-]+=*/gi, (_m, prefix) => `${prefix}[REDACTED]`],
    // token=..., password: '...', "api_key": "...", X-Api-Key: ..., secret_key=..., client_secret=...
    [
        new RegExp(
            String.raw`\b((?:access_|refresh_|id_|api_|auth_|session_)?token|password|passwd|pwd|client_secret|secret(?:[_-]?key)?|api[_-]?key)` +
                String.raw`(["']?\s{0,8}[:=]\s{0,8})(${QUOTED_OR_BARE})`,
            'gi',
        ),
        (_m, key, sep, value) => {
            const q = value[0];
            if (q !== '"' && q !== "'") return `${key}${sep}[REDACTED]`;
            return `${key}${sep}${q}[REDACTED]${value.length > 1 && value.endsWith(q) ? q : ''}`;
        },
    ],
];

// scheme:// at the start of a run (never mid-run, so each run is tried once).
const URL_SCHEME = /(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}:\/\//gi;

const isAuthorityEnd = (c: string) => c === '/' || c === "'" || c === '"' || /\s/.test(c);
const isRunEnd = (c: string) => c === "'" || c === '"' || /\s/.test(c);

// scheme://user:password@host -> scheme://[REDACTED]@host. Done as a scan rather than a regex so
// credentials of any length are caught: the authority ends at the first '/', whitespace or quote,
// and any '@' inside it means userinfo is present.
//
// Hand-typed camera URLs sometimes carry an unencoded '/' in the password
// (rtsp://admin:pa/ss@cam/...). When the authority has no '@' but looks like `user:<not a port>`,
// we keep scanning to the end of the run for an '@'. Requiring a non-numeric value after the ':'
// keeps host:port URLs whose path contains '@' (npm's /package/@scope/name) intact.
function redactUrlCredentials(text: string): string {
    let out = '';
    let last = 0;
    // End of the furthest extended scan that found no '@'. A later run starting before it would
    // hit the same end without an '@', so skipping it keeps the scan linear.
    let noAtUntil = -1;
    for (const m of text.matchAll(URL_SCHEME)) {
        const start = m.index! + m[0].length;
        if (start < last) continue;
        // Walk the authority once, remembering the last '@'. (Searching backwards from its end
        // with lastIndexOf would scan the whole text whenever there's no '@'.)
        let at = -1;
        let i = start;
        for (; i < text.length && !isAuthorityEnd(text[i]); i++) if (text[i] === '@') at = i;
        if (at < 0 && text[i] === '/' && start >= noAtUntil && looksLikeUserPassword(text.slice(start, i))) {
            let j = i;
            for (; j < text.length && !isRunEnd(text[j]); j++) {
                if (text[j] === '@') {
                    at = j;
                    break;
                }
            }
            if (at < 0) noAtUntil = j;
        }
        if (at >= start) {
            out += text.slice(last, start) + '[REDACTED]';
            last = at;
        }
    }
    return out + text.slice(last);
}

// `user:something` where `something` isn't a port number. IPv6 literals start with '['.
function looksLikeUserPassword(authority: string): boolean {
    if (authority.startsWith('[')) return false;
    const colon = authority.indexOf(':');
    return colon > 0 && !/^\d*$/.test(authority.slice(colon + 1));
}

export function redactSecrets(text: string): string {
    text = redactUrlCredentials(text);
    for (const [pattern, replacement] of SECRET_PATTERNS) text = text.replace(pattern, replacement);
    return text;
}
