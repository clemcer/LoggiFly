<!-- docs/.vitepress/components/ModelTable.vue -->
<template>
  <div class="model-table-wrap">
    <!-- Own fields table -->
    <table v-if="ownFields.length">
      <thead>
        <tr>
          <th>Field</th>
          <th>Type</th>
          <th>Default</th>
          <th>Required</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="[name, field] in ownFields" :key="name">
          <td><code>{{ name }}</code></td>
          <td>
            <template v-if="getOneOfRefs(field).length">
              <template v-for="(rn, i) in getOneOfRefs(field)" :key="rn">
                <a :href="'#' + rn.toLowerCase()"><code>{{ rn }}[]</code></a>
                <span v-if="i < getOneOfRefs(field).length - 1"> | </span>
              </template>
            </template>
            <template v-else>
              <template v-for="(part, i) in resolveTypeParts(field)" :key="i">
                <a v-if="part.href" :href="part.href"><code>{{ part.text }}</code></a>
                <code v-else>{{ part.text }}</code>
                <span v-if="i < resolveTypeParts(field).length - 1"> | </span>
              </template>
            </template>
          </td>
          <td>
            <code v-if="defaultCellData(field).kind === 'simple'">{{ defaultCellData(field).value }}</code>
            <a v-else-if="defaultCellData(field).kind === 'link'" :href="defaultCellData(field).href"><code>{{ defaultCellData(field).name }}</code></a>
            <span v-else>–</span>
          </td>
          <td>{{ required?.includes(name) ? '✅' : '–' }}</td>
          <td>{{ field.description ?? field.title ?? '–' }}</td>
        </tr>
      </tbody>
    </table>

    <!-- Collapsed inherited fields notice -->
    <details v-if="inheritedFields && inheritedFieldsList.length" class="inherited-notice">
      <summary>
        + {{ inheritedFieldsList.length }} overridable fields inherited from
        <a :href="modularDefName ? '#' + modularDefName.toLowerCase() : '#appendix'">Shared Overridable Fields</a>
      </summary>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="[name, field] in inheritedFieldsList" :key="name">
            <td><code>{{ name }}</code></td>
            <td>
              <template v-if="getOneOfRefs(field).length">
                <template v-for="(rn, i) in getOneOfRefs(field)" :key="rn">
                  <a :href="'#' + rn.toLowerCase()"><code>{{ rn }}[]</code></a>
                  <span v-if="i < getOneOfRefs(field).length - 1"> | </span>
                </template>
              </template>
              <template v-else>
                <template v-for="(part, i) in resolveTypeParts(field)" :key="i">
                  <a v-if="part.href" :href="part.href"><code>{{ part.text }}</code></a>
                  <code v-else>{{ part.text }}</code>
                  <span v-if="i < resolveTypeParts(field).length - 1"> | </span>
                </template>
              </template>
            </td>
            <td>
              <code v-if="defaultCellData(field).kind === 'simple'">{{ defaultCellData(field).value }}</code>
              <a v-else-if="defaultCellData(field).kind === 'link'" :href="defaultCellData(field).href"><code>{{ defaultCellData(field).name }}</code></a>
              <span v-else>–</span>
            </td>
            <td>{{ field.description ?? field.title ?? '–' }}</td>
          </tr>
        </tbody>
      </table>
    </details>
  </div>
</template>

<script setup>
import { computed, inject } from 'vue'
import { getOneOfRefs } from './schemaHelpers.js'

const ctx = inject('schemaCtx', null)
const modularDefName = ctx?.modularDefName ?? null

const props = defineProps({
  model: Object,
  defs: Object,
  // Set of field names that are "inherited" and should be collapsed
  inheritedFields: { type: Set, default: null },
  // Suppress complex object defaults (e.g. top-level $ref defaults)
  hideComplexDefaults: { type: Boolean, default: false },
})

const required = computed(() => props.model?.required ?? [])
const allProperties = computed(() => Object.entries(props.model?.properties ?? {}))

const ownFields = computed(() =>
  props.inheritedFields
    ? allProperties.value.filter(([name]) => !props.inheritedFields.has(name))
    : allProperties.value
)

const inheritedFieldsList = computed(() =>
  props.inheritedFields
    ? allProperties.value.filter(([name]) => props.inheritedFields.has(name))
    : []
)

function refName(ref) {
  return ref?.split('/').at(-1) ?? '?'
}


// Resolves a field to a single $ref, returning { baseName, isArr } or null.
// Handles direct $ref, anyOf with a single non-null $ref, and anyOf with a single array<$ref>.
// Guards on the raw ref name to avoid false-positive matches on primitive type names.
function resolveSingleRef(field) {
  if (field.$ref) return { baseName: refName(field.$ref), isArr: false }
  if (field.anyOf) {
    const nonNull = field.anyOf.filter(s => s.type !== 'null')
    if (nonNull.length === 1) {
      const s = nonNull[0]
      if (s.$ref) return { baseName: refName(s.$ref), isArr: false }
      if (s.type === 'array' && s.items?.$ref) return { baseName: refName(s.items.$ref), isArr: true }
    }
  }
  return null
}

// Returns an array of { text, href? } parts for the Type cell.
// $ref branches that exist in defs get a link; primitives and unknown refs are plain text.
function resolveTypeParts(field) {
  const defs = props.defs ?? {}
  function partFor(s) {
    if (s.$ref) {
      const name = refName(s.$ref)
      return name in defs ? { text: name, href: `#${name.toLowerCase()}` } : { text: name }
    }
    if (s.type === 'array' && s.items) {
      const itemType = s.items.$ref ? refName(s.items.$ref) : s.items.type ?? '?'
      const text = `${itemType}[]`
      if (s.items.$ref && itemType in defs)
        return { text, href: `#${itemType.toLowerCase()}` }
      return { text }
    }
    return { text: s.type ?? '?' }
  }

  if (field.type && field.type !== 'null') {
    if (field.type === 'array' && field.items) return [partFor(field)]
    return [{ text: field.type }]
  }
  if (field.$ref) {
    const name = refName(field.$ref)
    return [name in defs ? { text: name, href: `#${name.toLowerCase()}` } : { text: name }]
  }
  if (field.const !== undefined) return [{ text: JSON.stringify(field.const) }]
  if (field.anyOf) {
    const parts = field.anyOf.filter(s => s.type !== 'null').map(partFor)
    return parts.length ? parts : [{ text: 'null' }]
  }
  if (field.allOf) return [{ text: field.allOf.map(s => s.$ref ? refName(s.$ref) : s.type ?? '?').join(' & ') }]
  return [{ text: '–' }]
}


function formatDefault(value) {
  if (value === undefined) return '–'
  if (value === null) return 'null'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

// Returns { kind: 'simple'|'link'|'none', value?, name?, href? } for the Default cell.
// 'simple' — show the value as plain text.
// 'link'   — show a linked ref name (only when hideComplexDefaults is true and default is a ref).
// 'none'   — show a dash.
// Like resolveSingleRef but also matches the first $ref in a multi-option anyOf
// when the default is a complex object (we want to link to the model, not dump JSON).
function resolveObjectRef(field) {
  const r = resolveSingleRef(field)
  if (r) return r
  if (field.anyOf) {
    const refBranch = field.anyOf.find(s => s.$ref)
    if (refBranch) {
      const name = refName(refBranch.$ref)
      if (name in (props.defs ?? {})) return { baseName: name, isArr: false }
    }
  }
  return null
}

function defaultCellData(field) {
  const hasDefault = field.default !== undefined
  const isSimple = hasDefault && (field.default === null || typeof field.default !== 'object')
  if (isSimple) return { kind: 'simple', value: formatDefault(field.default) }
  // Complex object default: prefer a ref link if any anyOf branch is a known def
  if (hasDefault) {
    const r = resolveObjectRef(field)
    if (r) return { kind: 'link', name: r.baseName, href: `#${r.baseName.toLowerCase()}` }
  }
  if (hasDefault && !props.hideComplexDefaults)
    return { kind: 'simple', value: formatDefault(field.default) }
  return { kind: 'none' }
}
</script>

<style scoped>
.model-table-wrap {
  margin-bottom: 1rem;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
th, td {
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--vp-c-divider);
  text-align: left;
  vertical-align: top;
}
th {
  background: var(--vp-c-bg-soft);
  font-weight: 600;
}
.inherited-notice {
  margin-top: 0.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  padding: 0.4rem 0.75rem;
  font-size: 0.88rem;
  color: var(--vp-c-text-2);
}
.inherited-notice summary {
  cursor: pointer;
  list-style: none;
  padding: 0.2rem 0;
}
.inherited-notice summary::-webkit-details-marker { display: none; }
.inherited-notice table {
  margin-top: 0.5rem;
}
</style>
