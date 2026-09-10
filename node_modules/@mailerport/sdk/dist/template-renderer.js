function valueAsString(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

export function renderTemplate(template, variables = {}) {
  return template.replace(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g, (_, key) =>
    valueAsString(variables[key])
  );
}

function tokenize(text) {
  const tokens = [];
  let current = "";
  for (const ch of text) {
    const isWhitespace = ch === " " || ch === "\n" || ch === "\t" || ch === "\r";
    if (isWhitespace) {
      if (current) tokens.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

function trimPunctuation(value) {
  let result = value;
  while (result.length > 0) {
    const last = result[result.length - 1];
    if (last === ")" || last === "," || last === "." || last === ";") {
      result = result.slice(0, -1);
      continue;
    }
    break;
  }
  return result;
}

function addLinkIfPresent(set, token) {
  const cleaned = trimPunctuation(token.replaceAll('"', "").replaceAll("'", ""));
  if (!cleaned) return;
  if (
    cleaned.startsWith("http://") ||
    cleaned.startsWith("https://") ||
    cleaned.startsWith("/")
  ) {
    set.add(cleaned);
  }
}

function extractHrefLinks(html, set) {
  const lower = html.toLowerCase();
  let cursor = 0;
  while (cursor < lower.length) {
    const hrefIndex = lower.indexOf("href", cursor);
    if (hrefIndex === -1) break;
    let valueStart = hrefIndex + 4;
    while (valueStart < html.length && /\s/.test(html[valueStart])) valueStart += 1;
    if (html[valueStart] !== "=") {
      cursor = valueStart + 1;
      continue;
    }
    valueStart += 1;
    while (valueStart < html.length && /\s/.test(html[valueStart])) valueStart += 1;
    const quote = html[valueStart];
    if (quote !== '"' && quote !== "'") {
      cursor = valueStart + 1;
      continue;
    }
    const valueEnd = html.indexOf(quote, valueStart + 1);
    if (valueEnd === -1) break;
    addLinkIfPresent(set, html.slice(valueStart + 1, valueEnd));
    cursor = valueEnd + 1;
  }
}

export function extractLinks({ html = "", text = "" }) {
  const links = new Set();
  extractHrefLinks(html, links);
  for (const token of tokenize(`${html} ${text}`)) {
    addLinkIfPresent(links, token);
  }
  return [...links];
}
