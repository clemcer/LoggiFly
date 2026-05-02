# Config Schema

This page contains the full config schema for LoggiFly.

The content of this page is dynamically generatated from the pydantic models that make up the config.yaml structure.

<script setup>
import { data } from './schema.data.js'
import SchemaTable from '../../.vitepress/components/SchemaTable.vue'
</script>

<SchemaTable :schema="data" />
