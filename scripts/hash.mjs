// Генерирует хэш ответа для app.js.
// Использование: node scripts/hash.mjs <номер флага> "CTF{ответ}" [--list]
//   --list — ответ-список через запятую: порядок, регистр и пробелы не важны
//            (у этого флага в app.js должно стоять list: true).
import { createHash } from "node:crypto";

const SALT = "ctf-path-v3";

const args = process.argv.slice(2);
const list = args.includes("--list");
const [id, answer] = args.filter((a) => a !== "--list");
if (!id || answer === undefined) {
  console.error('Usage: node scripts/hash.mjs <id> "CTF{answer}" [--list]');
  process.exit(1);
}

// та же нормализация, что normalize() в app.js
function normalize(value, isList) {
  value = value.trim();
  if (!isList) return value;
  const m = value.match(/^([A-Za-z]+)\{([\s\S]*)\}$/);
  if (!m) return value.replace(/\s+/g, "").toLowerCase();
  const items = m[2].split(",").map((s) => s.trim().toLowerCase()).filter(Boolean).sort();
  return m[1].toUpperCase() + "{" + items.join(",") + "}";
}

const hash = createHash("sha256")
  .update(`${SALT}:${id}:${normalize(answer, list)}`)
  .digest("hex");

console.log(hash);
