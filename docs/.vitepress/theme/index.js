import DefaultTheme from 'vitepress/theme'
import { h, onMounted, watch } from 'vue'
import { useRoute } from 'vitepress'
import './custom.css'

// Open any <details> ancestors of the element targeted by the current URL hash
function openDetailsForHash(hash) {
  if (!hash) return
  const target = document.getElementById(hash.slice(1))
  if (!target) return
  let el = target.closest('details') ?? target.parentElement?.closest('details')
  while (el) {
    el.open = true
    el = el.parentElement?.closest('details')
  }
}

// export default DefaultTheme

export default {
  extends: DefaultTheme,
  setup() {
    const route = useRoute()
    onMounted(() => {
      openDetailsForHash(window.location.hash)
      // Native hashchange covers cases Vue Router misses (e.g. clicking a link
      // to the already-active hash), ensuring collapsed sections always open.
      window.addEventListener('hashchange', () => openDetailsForHash(window.location.hash))
    })
    watch(() => route.hash, hash => openDetailsForHash(hash))
  },
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'sidebar-nav-after': () =>
        h('div', { style: 'padding: 16px; text-align: left; display: flex; flex-direction: column; gap: 12px;' }, [
          h(
            'a',
            {
              href: 'https://ko-fi.com/clemcer',
              target: '_blank',
              rel: 'noopener',
            },
            h('img', {
              src: 'https://ko-fi.com/img/githubbutton_sm.svg',
              alt: 'Support on Ko-fi',
              style: 'max-width: 75%; height: auto;',
            }),
          ),
          h(
            'a',
            {
              href: 'https://www.buymeacoffee.com/clemcer',
              target: '_blank',
              rel: 'noopener',
            },
            h('img', {
              src: 'https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png',
              alt: 'Buy Me a Coffee',
              style: 'max-width: 75%; height: auto;',
            }),
          ),
        ]),
    })
  }
}