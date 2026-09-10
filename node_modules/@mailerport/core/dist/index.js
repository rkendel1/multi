import { MailPortError, ERROR_CODES } from "./errors.js";
export { MailPortError, ERROR_CODES };

export const mailCapability = Object.freeze({
  name: "mail", version: "1",
  parse(source) {
    if (!/\buse\s+mail\b/.test(source)) throw new MailPortError(ERROR_CODES.MAIL_NOT_CONFIGURED, "Missing `use mail` declaration");
    const block = (text, name) => { const match = new RegExp(`\\b${name}\\s*\\{`).exec(text); if (!match) return "";
      let depth = 1, index = match.index + match[0].length, end = index;
      for (; end < text.length && depth; end += 1) { if (text[end] === "{") depth += 1; if (text[end] === "}") depth -= 1; }
      return text.slice(index, end - 1); };
    const entries = (text) => Object.fromEntries([...text.matchAll(/([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/g)].map((item) => [item[1], item[2]]));
    const mail = block(source, "mail");
    return { capability: "mail", identities: entries(block(mail, "identities")), templates: entries(block(mail, "templates")) };
  },
  snapshot(contract) { return { capability: "mail", version: "1", identities: Object.keys(contract.identities), templates: Object.keys(contract.templates) }; },
});

export function defineMailCapability() { return mailCapability; }
export function registerMailCapability(registry) { registry.register(mailCapability); return registry; }
export function defineTemplate(template) { return Object.freeze({ ...template }); }
export const parseMailDsl = (source) => mailCapability.parse(source);
export const generateMailContractSnapshot = (contract) => mailCapability.snapshot(contract);
