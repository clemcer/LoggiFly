// docs/guide/config/schema.data.js
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default {
  load() {
    const raw = fs.readFileSync(path.resolve(__dirname, 'v2_schema.json'), 'utf-8')
    return JSON.parse(raw)
  }
}
