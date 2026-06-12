import { createRouter, createWebHashHistory } from 'vue-router'
import Login from '../views/Login.vue'
import AppLayout from '../components/AppLayout.vue'
import Dashboard from '../views/Dashboard.vue'
import ContactsList from '../views/ContactsList.vue'
import ContactEdit from '../views/ContactEdit.vue'
import Calendar from '../views/Calendar.vue'
import Schedule from '../views/Schedule.vue'
import CalendarEventEdit from '../views/CalendarEventEdit.vue'
import Files from '../views/Files.vue'
import Settings from '../views/Settings.vue'

const routes = [
  { path: '/login', component: Login },
  {
    path: '/',
    component: AppLayout,
    children: [
      { path: '', component: Dashboard, meta: { title: '概览' } },
      { path: 'contacts', component: ContactsList, meta: { title: '联系人' } },
      { path: 'contacts/new', component: ContactEdit, meta: { title: '新建联系人' } },
      { path: 'contacts/:uid/edit', component: ContactEdit, meta: { title: '编辑联系人' } },
      { path: 'calendar', component: Calendar, meta: { title: '月视图' } },
      { path: 'calendar/schedule', component: Schedule, meta: { title: '日程视图' } },
      { path: 'calendar/new', component: CalendarEventEdit, meta: { title: '新建事件' } },
      { path: 'calendar/:uid/edit', component: CalendarEventEdit, meta: { title: '编辑事件' } },
      { path: 'files', component: Files, meta: { title: '文件' } },
      { path: 'settings', component: Settings, meta: { title: '设置' } },
    ],
  },
]

const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  if (to.path !== '/login' && !token) next('/login')
  else next()
})

export default router
