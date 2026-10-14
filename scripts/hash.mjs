// Генерирует хэш ответа для app.js.
// Использование: node scripts/hash.mjs <номер флага 1-3> "flag{ответ}"
import { createHash } from "node:crypto";

const SALT = "glug-path-v1";

const [id, answer] = process.argv.slice(2);
if (!id || answer === undefined) {
  console.error('Usage: node scripts/hash.mjs <1|2|3> "flag{answer}"');
  process.exit(1);
}

const hash = createHash("sha256")
  .update(`${SALT}:${id}:${answer.trim()}`)
  .digest("hex");

console.log(hash);
