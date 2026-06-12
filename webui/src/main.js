import { createApp } from 'vue'
import App from './App.vue'
import router from './router/index.js'
import { startReminderCheck } from './services/reminder.js'
import './theme.css'

function applySavedTheme() {
  try {
    const saved = localStorage.getItem('theme_hsl')
    if (saved) {
      const { h, s, l } = JSON.parse(saved)
      const root = document.documentElement
      root.style.setProperty('--brand-hue', h + 'deg')
      root.style.setProperty('--brand-sat', s + '%')
      root.style.setProperty('--brand-lit', l + '%')
    }
  } catch(e) {}
}
applySavedTheme()

createApp(App).use(router).mount('#app')

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
  })
}

startReminderCheck()
