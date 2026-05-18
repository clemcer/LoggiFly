<script setup lang="ts">
import { computed, ref } from 'vue';
import { useData, useRouter } from 'vitepress';
import VPFlyout from 'vitepress/dist/client/theme-default/components/VPFlyout.vue';
import VPMenuLink from 'vitepress/dist/client/theme-default/components/VPMenuLink.vue';

const props = defineProps<{
    screenMenu?: boolean | ''
}>();

const isScreenMenu = computed(() => props.screenMenu === true || props.screenMenu === '');

const VERSIONS = ['v1.8']
const CURRENT_VERSION = 'v2'

interface VersionMenuItem {
    text: string;
    link: string;
}

const router = useRouter();
const { site } = useData();
const isOpen = ref(false);

const versionSet = new Set(VERSIONS)

const pathSegments = computed(() => {
    const base = site.value.base.replace(/\/$/, '')
    return router.route.path
        .replace(/\.html$/, '')
        .replace(/\/$/, '')
        .replace(base, '')
        .split('/')
        .filter(Boolean)
});

const activeVersion = computed(() => {
    const candidate = pathSegments.value[0]
    return versionSet.has(candidate) ? candidate : CURRENT_VERSION
});

const availableVersions = computed(() =>
    [CURRENT_VERSION, ...VERSIONS].filter(v => v !== activeVersion.value)
);

function removeVersionSegments(segments: string[]): string[] {
    return segments.filter(seg => !versionSet.has(seg));
}

function buildVersionPath(version: string): string {
    const baseSegments = removeVersionSegments(pathSegments.value);
    const newSegments = version === CURRENT_VERSION
        ? baseSegments
        : [version, ...baseSegments];
    return `/${newSegments.join('/')}`;
}

function createVersionMenuItem(version: string): VersionMenuItem {
    return { text: version, link: buildVersionPath(version) };
}

function toggle(): void {
    isOpen.value = !isOpen.value;
}
</script>

<template>
    <!-- Desktop flyout -->
    <VPFlyout
        v-if="!isScreenMenu"
        class="VPVersionSwitcher"
        icon="vpi-versioning"
        :button="activeVersion"
        label="Switch Version"
    >
        <div class="items">
            <VPMenuLink
                v-for="version in availableVersions"
                :key="version"
                :item="createVersionMenuItem(version)"
            />
        </div>
    </VPFlyout>

    <!-- Mobile screen menu -->
    <div v-else class="VPScreenVersionSwitcher" :class="{ open: isOpen }">
        <button
            class="button"
            type="button"
            aria-controls="navbar-group-version"
            :aria-expanded="isOpen"
            @click="toggle"
        >
            <span class="button-text">
                <span class="vpi-versioning icon" />
                {{ activeVersion }}
            </span>
            <span class="vpi-plus button-icon" />
        </button>
        <div id="navbar-group-version" class="items">
            <VPMenuLink
                v-for="version in availableVersions"
                :key="version"
                :item="createVersionMenuItem(version)"
            />
        </div>
    </div>
</template>

<style>
.vpi-versioning.option-icon {
    margin-right: 2px !important;
}

.vpi-versioning {
    --icon: url("data:image/svg+xml;charset=utf-8;base64,PHN2ZyB3aWR0aD0iNjRweCIgaGVpZ2h0PSI2NHB4IiB2aWV3Qm94PSIwIDAgMjQgMjQiIHN0cm9rZS13aWR0aD0iMi4yIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGNvbG9yPSIjMDAwMDAwIj48cGF0aCBkPSJNMTcgN0MxOC4xMDQ2IDcgMTkgNi4xMDQ1NyAxOSA1QzE5IDMuODk1NDMgMTguMTA0NiAzIDE3IDNDMTUuODk1NCAzIDE1IDMuODk1NDMgMTUgNUMxNSA2LjEwNDU3IDE1Ljg5NTQgNyAxNyA3WiIgc3Ryb2tlPSIjMDAwMDAwIiBzdHJva2Utd2lkdGg9IjIuMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48L3BhdGg+PHBhdGggZD0iTTcgN0M4LjEwNDU3IDcgOSA2LjEwNDU3IDkgNUM5IDMuODk1NDMgOC4xMDQ1NyAzIDcgM0M1Ljg5NTQzIDMgNSAzLjg5NTQzIDUgNUM1IDYuMTA0NTcgNS44OTU0MyA3IDcgN1oiIHN0cm9rZT0iIzAwMDAwMCIgc3Ryb2tlLXdpZHRoPSIyLjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PC9wYXRoPjxwYXRoIGQ9Ik03IDIxQzguMTA0NTcgMjEgOSAyMC4xMDQ2IDkgMTlDOSAxNy44OTU0IDguMTA0NTcgMTcgNyAxN0M1Ljg5NTQzIDE3IDUgMTcuODk1NCA1IDE5QzUgMjAuMTA0NiA1Ljg5NTQzIDIxIDcgMjFaIiBzdHJva2U9IiMwMDAwMDAiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjwvcGF0aD48cGF0aCBkPSJNNyA3VjE3IiBzdHJva2U9IiMwMDAwMDAiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjwvcGF0aD48cGF0aCBkPSJNMTcgN1Y4QzE3IDEwLjUgMTUgMTEgMTUgMTFMOSAxM0M5IDEzIDcgMTMuNSA3IDE2VjE3IiBzdHJva2U9IiMwMDAwMDAiIHN0cm9rZS13aWR0aD0iMi4yIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjwvcGF0aD48L3N2Zz4=");
}
</style>

<style scoped>
.VPVersionSwitcher {
    display: flex;
    align-items: center;
}

.icon {
    padding: 8px;
}

.VPScreenVersionSwitcher {
    border-bottom: 1px solid var(--vp-c-divider);
    height: 48px;
    overflow: hidden;
    transition: border-color 0.5s;
}

.VPScreenVersionSwitcher .items {
    visibility: hidden;
}

.VPScreenVersionSwitcher.open {
    padding-bottom: 10px;
    height: auto;
}

.VPScreenVersionSwitcher.open .items {
    visibility: visible;
}

.VPScreenVersionSwitcher.open .button {
    padding-bottom: 6px;
    color: var(--vp-c-brand-1);
}

.VPScreenVersionSwitcher.open .button-icon {
    transform: rotate(45deg);
}

.VPScreenVersionSwitcher button .icon {
    margin-right: 8px;
}

.button {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 4px 11px 0;
    width: 100%;
    line-height: 24px;
    font-size: 14px;
    font-weight: 500;
    color: var(--vp-c-text-1);
    transition: color 0.25s;
}

.button:hover {
    color: var(--vp-c-brand-1);
}

.button-icon {
    transition: transform 0.25s;
}

.group:first-child {
    padding-top: 0;
}

.group + .group,
.group + .item {
    padding-top: 4px;
}
</style>
