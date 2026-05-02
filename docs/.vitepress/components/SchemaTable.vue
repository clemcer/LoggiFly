<!-- docs/.vitepress/components/SchemaTable.vue -->
<template>
  <div class="schema-page">

    <!-- ── Top-level config ────────────────────────────── -->
    <h2>Top-level Config</h2>
    <ModelTable :model="rootModel" :defs="defs" :hideComplexDefaults="true" />

    <!-- ── Recursive tree rooted at each top-level $ref field ── -->
    <SchemaNode
      v-for="node in renderTree"
      :key="node.fieldKey + '-' + node.defName"
      :fieldKey="node.fieldKey"
      :defName="node.defName"
      :isArray="node.isArray"
      :depth="node.depth"
      :childNodes="node.children"
    />

    <!-- ── Appendix ─────────────────────────────────────── -->
    <h2 id="appendix">Appendix</h2>

    <!-- Shared overridable fields -->
    <h3 v-if="modularDefName" :id="modularDefName.toLowerCase()">Shared Overridable Fields</h3>
    <p v-if="modularDefName" class="section-desc">
      These fields can be set at multiple levels: under <code>defaults</code>, per rule, and per keyword/regex item.
      A value set at a deeper level overrides the parent.
    </p>
    <ModelTable v-if="modularDefName" :model="defs[modularDefName]" :defs="defs" />

    <!-- Discriminated-union item types -->
    <h3 id="union-types">Union Types</h3>
    <p class="section-desc">
      These types appear as list items in discriminated-union array fields throughout the config. They are documented here separately because they may appear in multiple places.
    </p>
    <template v-for="name in appendixDefs" :key="name">
      <h4 :id="name.toLowerCase()">{{ name }}</h4>
      <ModelTable
        :model="defs[name]"
        :defs="defs"
        :inheritedFields="modularInheritors.has(name) ? modularFields : null"
      />
    </template>

  </div>
</template>

<script setup>
import { provide } from 'vue'
import ModelTable from './ModelTable.vue'
import SchemaNode from './SchemaNode.vue'
import { getFollowableRef, isArrayRef, collectOneOfRefs } from './schemaHelpers.js'

const props = defineProps(['schema'])

const defs = props.schema.$defs ?? {}
const rootModel = {
  properties: props.schema.properties ?? {},
  required: props.schema.required,
}

// ── Hardcoded model names for the shared overridable fields ───────────────
// ModularDefaultsConfig defines all overridable fields with Optional/None defaults.
// Models that inherit from it (ContainerRule, KeywordItem, etc.) get those fields
// flattened into their own properties by Pydantic — the JSON schema has no inheritance
// info, so we detect inheritors structurally: any def that contains ALL of
// ModularDefaultsConfig's fields is treated as an inheritor.
// RootDefaultsConfig has the same fields but with concrete defaults (used under `defaults:`).
// Both must be excluded from the inheritor check to avoid them being flagged as
// inheritors of themselves.
const modularDefName = 'ModularDefaultsConfig'
const rootDefaultsDefName = 'RootDefaultsConfig'

// ── Derive modular fields and inheritors from the schema ───────────────────
const modularFields = new Set(Object.keys(defs[modularDefName]?.properties ?? {}))

const modularInheritors = new Set(
  Object.entries(defs)
    .filter(([name, def]) => {
      if (name === modularDefName) return false
      if (name === rootDefaultsDefName) return false
      const defProps = new Set(Object.keys(def.properties ?? {}))
      return [...modularFields].every(f => defProps.has(f))
    })
    .map(([name]) => name)
)

// ── Defs excluded from the tree; rendered exclusively in the appendix ──────
if (!(modularDefName in defs)) console.warn(`[SchemaTable] '${modularDefName}' not found in schema.$defs`)
if (!(rootDefaultsDefName in defs)) console.warn(`[SchemaTable] '${rootDefaultsDefName}' not found in schema.$defs`)
const treeExcluded = new Set([modularDefName])

// ── Root-level fields that reference a def ────────────────────────────────
const rootChildren = Object.entries(props.schema.properties ?? {})
  .flatMap(([fieldKey, field]) => {
    const defName = getFollowableRef(field)
    return defName ? [{ fieldKey, defName, isArray: isArrayRef(field) }] : []
  })

// ── Precompute the full DFS render tree ───────────────────────────────────
// Returns a flat list of nodes with their children pre-resolved,
// avoiding any mutable shared state during Vue's render phase.
function computeRenderTree(startNodes) {
  const visited = new Set()

  function walk(nodes, depth) {
    const result = []
    for (const node of nodes) {
      if (visited.has(node.defName) || treeExcluded.has(node.defName)) continue
      visited.add(node.defName)

      const m = defs[node.defName] ?? {}
      const isInheritor = modularInheritors.has(node.defName)
      const grandChildren = []
      for (const [fname, field] of Object.entries(m.properties ?? {})) {
        if (isInheritor && modularFields.has(fname)) continue
        const ref = getFollowableRef(field)
        if (ref && !visited.has(ref) && !treeExcluded.has(ref)) {
          grandChildren.push({ fieldKey: fname, defName: ref, isArray: isArrayRef(field) })
        }
      }

      result.push({
        ...node,
        depth,
        children: walk(grandChildren, depth + 1),
      })
    }
    return result
  }

  return walk(startNodes, 1)
}

const renderTree = computeRenderTree(rootChildren)

// ── Appendix: defs only reachable via oneOf, not in the tree ──────────────
const treeReachable = new Set()
function markReachable(nodes) {
  for (const node of nodes) {
    treeReachable.add(node.defName)
    markReachable(node.children)
  }
}
markReachable(renderTree)

const oneOfRefs = collectOneOfRefs(props.schema)
const appendixDefs = [...oneOfRefs].filter(name => name in defs && !treeReachable.has(name))

// ── Provide read-only context to all SchemaNode descendants ───────────────
provide('schemaCtx', {
  defs,
  modularFields,
  modularInheritors,
  modularDefName,
})
</script>

<style scoped>
.schema-page h2 {
  margin-top: 2.5rem;
  border-bottom: 1px solid var(--vp-c-divider);
  padding-bottom: 0.3rem;
}
.schema-page h3 {
  margin-top: 1.5rem;
}
.schema-page h4 {
  margin-top: 1.2rem;
}
.schema-page :deep(h4) {
  margin-top: 1.2rem;
}
.schema-page :deep(h5) {
  margin-top: 1rem;
}
.schema-page :deep(.schema-section) {
  margin-top: 2.5rem;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 0 1rem 1rem;
}
.schema-page :deep(.schema-section > summary) {
  cursor: pointer;
  list-style: none;
  font-size: 1.35rem;
  font-weight: 600;
  padding: 0.6rem 0;
  border-bottom: 1px solid var(--vp-c-divider);
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.schema-page :deep(.schema-section > summary::-webkit-details-marker) {
  display: none;
}
.schema-page :deep(.schema-section > summary::before) {
  content: '▶';
  font-size: 0.65em;
  color: var(--vp-c-text-3);
  transition: transform 0.15s;
  flex-shrink: 0;
}
.schema-page :deep(.schema-section[open] > summary::before) {
  transform: rotate(90deg);
}
.section-desc {
  color: var(--vp-c-text-2);
  margin: 0.25rem 0 0.75rem;
  font-size: 0.93rem;
}
</style>
