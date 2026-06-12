import { createApp } from 'vue'
import App from './App.vue'
import router from './router/index.js'
import { startReminderCheck } from './services/reminder.js'
import './theme.css'

createApp(App).use(router).mount('#app')

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
  })
}

startReminderCheck()
