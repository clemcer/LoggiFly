<!-- docs/.vitepress/components/SchemaNode.vue -->
<template>
  <!-- Depth-1 nodes are collapsible top-level sections, deeper nodes are always open -->
  <details v-if="depth === 1" class="schema-section" :id="defName.toLowerCase()">
    <summary>
      {{ label }}
      <span class="def-badge">{{ defName }}</span>
    </summary>
    <ModelTable
      :model="model"
      :defs="ctx.defs"
      :inheritedFields="isModularInheritor ? ctx.modularFields : null"
    />
    <SchemaNode
      v-for="child in childNodes"
      :key="child.fieldKey + '-' + child.defName"
      :fieldKey="child.fieldKey"
      :defName="child.defName"
      :isArray="child.isArray"
      :depth="child.depth"
      :childNodes="child.children"
    />
  </details>

  <template v-else>
    <component :is="headingTag" :id="defName.toLowerCase()">{{ label }}</component>
    <span class="def-badge">{{ defName }}</span>
    <ModelTable
      :model="model"
      :defs="ctx.defs"
      :inheritedFields="isModularInheritor ? ctx.modularFields : null"
    />
    <SchemaNode
      v-for="child in childNodes"
      :key="child.fieldKey + '-' + child.defName"
      :fieldKey="child.fieldKey"
      :defName="child.defName"
      :isArray="child.isArray"
      :depth="child.depth"
      :childNodes="child.children"
    />
  </template>
</template>

<script setup>
import { inject } from 'vue'
import ModelTable from './ModelTable.vue'
import SchemaNode from './SchemaNode.vue'

const props = defineProps({
  fieldKey:  { type: String, required: true },
  defName:   { type: String, required: true },
  isArray:   { type: Boolean, default: false },
  depth:     { type: Number, default: 1 },
  childNodes: { type: Array, default: () => [] },
})

const ctx = inject('schemaCtx')

const label           = props.fieldKey + (props.isArray ? '[]' : '')
const headingTag      = `h${Math.min(props.depth + 1, 6)}`
const model           = ctx.defs[props.defName] ?? {}
const isModularInheritor = ctx.modularInheritors.has(props.defName)
</script>

<style scoped>
.def-badge {
  font-size: 0.78em;
  background: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  border-radius: 4px;
  padding: 0.1rem 0.35rem;
  color: var(--vp-c-text-2);
  font-family: var(--vp-font-family-mono);
  margin-left: 0.4rem;
  vertical-align: middle;
}
</style>
