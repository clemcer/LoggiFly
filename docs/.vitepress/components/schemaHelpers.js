// Shared schema-traversal helpers used by SchemaTable.vue and SchemaNode.vue

/**
 * Returns the def name that a field "follows into" (i.e. is renderable as a child section),
 * or null if the field is not followable.
 * Followable: direct $ref, or anyOf with a single non-null option that is a $ref or array<$ref>.
 * NOT followable: oneOf (discriminated union), multi-option anyOf.
 */
export function getFollowableRef(field) {
  if (field.$ref) return field.$ref.split('/').at(-1)
  if (field.anyOf) {
    const nonNull = field.anyOf.filter(s => s.type !== 'null')
    if (nonNull.length === 1) {
      const s = nonNull[0]
      if (s.$ref) return s.$ref.split('/').at(-1)
      // Array with a single direct $ref item type — followable
      if (s.type === 'array' && s.items?.$ref) return s.items.$ref.split('/').at(-1)
      // Array with oneOf items (discriminated union) — NOT followable
    }
    // Multi-option anyOf: followable if at least one branch is a $ref (others are primitives)
    const refBranches = nonNull.filter(s => s.$ref)
    if (refBranches.length >= 1) return refBranches[0].$ref.split('/').at(-1)
  }
  return null
}

/**
 * Returns true if the field is an optional array whose items are a single $ref
 * (as opposed to a oneOf discriminated union).
 */
export function isArrayRef(field) {
  if (field.anyOf) {
    const nonNull = field.anyOf.filter(s => s.type !== 'null')
    if (nonNull.length === 1) {
      const s = nonNull[0]
      return s.type === 'array' && !!s.items?.$ref
    }
  }
  return false
}

/**
 * Returns an array of def names for discriminated-union array fields (anyOf/array with oneOf items).
 * Used in the Type cell to render each union branch as a separate linked type.
 */
export function getOneOfRefs(field) {
  if (field.anyOf) {
    const nonNull = field.anyOf.filter(s => s.type !== 'null')
    if (nonNull.length === 1) {
      const s = nonNull[0]
      if (s.type === 'array' && s.items?.oneOf)
        return s.items.oneOf.filter(o => o.$ref).map(o => o.$ref.split('/').at(-1))
    }
  }
  if (field.type === 'array' && field.items?.oneOf)
    return field.items.oneOf.filter(o => o.$ref).map(o => o.$ref.split('/').at(-1))
  return []
}

/**
 * Recursively collects all def names that appear exclusively as oneOf branch $refs.
 * These are discriminated-union types that should go in the appendix rather than the tree.
 */
export function collectOneOfRefs(obj, result = new Set()) {
  if (Array.isArray(obj)) {
    obj.forEach(v => collectOneOfRefs(v, result))
  } else if (obj && typeof obj === 'object') {
    if (obj.oneOf) {
      obj.oneOf.forEach(s => { if (s.$ref) result.add(s.$ref.split('/').at(-1)) })
    }
    Object.values(obj).forEach(v => collectOneOfRefs(v, result))
  }
  return result
}
