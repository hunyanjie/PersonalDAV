<template>
  <div class="layout">
    <!-- Sidebar / Drawer -->
    <aside class="sidebar glass" :class="{ collapsed: sidebarCollapsed, 'mobile-open': mobileMenuOpen }">
      <div class="sidebar-header">
        <div class="logo" v-show="!sidebarCollapsed || mobileMenuOpen">
          <div class="logo-icon">P</div>
          <span>PersonalDAV</span>
        </div>
        <button class="toggle-btn" @click="toggleSidebar" :title="sidebarCollapsed ? '展开侧栏' : '收缩侧栏'">
          <Menu v-if="sidebarCollapsed && !mobileMenuOpen" :size="20" />
          <ChevronLeft v-else :size="20" />
        </button>
      </div>
      <nav @click="onNavClick">
        <router-link to="/" exact-active-class="active" :title="sidebarCollapsed ? '概览' : ''">
          <LayoutDashboard :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">概览</span>
        </router-link>
        <router-link to="/contacts" active-class="active" :title="sidebarCollapsed ? '联系人' : ''">
          <Users :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">联系人</span>
        </router-link>
        <router-link to="/calendar" active-class="active" :title="sidebarCollapsed ? '月视图' : ''">
          <Calendar :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">月视图</span>
        </router-link>
        <router-link to="/calendar/schedule" active-class="active" :title="sidebarCollapsed ? '日程视图' : ''">
          <ListTodo :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">日程视图</span>
        </router-link>
        <router-link to="/files" active-class="active" :title="sidebarCollapsed ? '文件' : ''">
          <Folder :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">文件</span>
        </router-link>
        <router-link to="/settings" active-class="active" :title="sidebarCollapsed ? '设置' : ''">
          <Settings :size="20" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">设置</span>
        </router-link>
      </nav>
      <div class="sidebar-footer">
        <a href="#" @click.prevent="logout" :title="sidebarCollapsed ? '退出登录' : ''">
          <LogOut :size="18" />
          <span v-show="!sidebarCollapsed || mobileMenuOpen">退出登录</span>
        </a>
      </div>
    </aside>

    <!-- Mobile Overlay -->
    <div v-if="mobileMenuOpen" class="mobile-overlay" @click="mobileMenuOpen = false"></div>

    <main class="main">
      <header class="header">
        <div class="header-inner glass">
          <button class="mobile-menu-btn" @click="mobileMenuOpen = true">
            <Menu :size="24" />
          </button>
          <h2>{{ $route.meta.title || '' }}</h2>
        </div>
      </header>
      <div class="content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </main>
  </div>
</template>

<script>
import { 
  LayoutDashboard, Users, Calendar, ListTodo, Folder, 
  Settings, LogOut, Menu, ChevronLeft 
} from 'lucide-vue-next'
import api from '../api.js'

export default {
  components: { 
    LayoutDashboard, Users, Calendar, ListTodo, Folder, 
    Settings, LogOut, Menu, ChevronLeft 
  },
  data: () => ({
    sidebarCollapsed: localStorage.getItem('sidebar_collapsed') === 'true',
    mobileMenuOpen: false,
  }),
  async mounted() {
    await this.syncServerTheme()
  },
  methods: {
    async syncServerTheme() {
      try {
        const res = await api.getSetting('theme_hsl')
        if (res && res.value) {
          const { h, s, l } = JSON.parse(res.value)
          const root = document.documentElement
          root.style.setProperty('--brand-hue', h + 'deg')
          root.style.setProperty('--brand-sat', s + '%')
          root.style.setProperty('--brand-lit', l + '%')
          localStorage.setItem('theme_hsl', JSON.stringify({ h, s, l }))
        }
      } catch (e) { /* 服务器无主题色设置时保持本地值 */ }
    },
    toggleSidebar() {
      if (window.innerWidth <= 768) {
        this.mobileMenuOpen = !this.mobileMenuOpen
      } else {
        this.sidebarCollapsed = !this.sidebarCollapsed
        localStorage.setItem('sidebar_collapsed', this.sidebarCollapsed)
      }
    },
    onNavClick() {
      if (window.innerWidth <= 768) {
        this.mobileMenuOpen = false
      }
    },
    logout() {
      localStorage.removeItem('token')
      this.$router.push('/login')
    },
  },
}
</script>

<style scoped>
.layout { display: flex; height: 100vh; background-color: var(--bg-page); position: relative; }

.sidebar { 
  width: 240px; 
  background: #001529; 
  color: var(--text-inverse); 
  display: flex; 
  flex-direction: column; 
  flex-shrink: 0; 
  transition: all .3s cubic-bezier(0.4, 0, 0.2, 1); 
  overflow: hidden; 
  margin: 12px 0 12px 12px;
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  border: none;
  z-index: 1000;
}
.sidebar.collapsed { width: 72px; }

.sidebar-header { 
  display: flex; 
  align-items: center; 
  justify-content: space-between; 
  padding: 24px 16px; 
  min-height: 80px;
}
.logo { 
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 16px; 
  font-weight: 700; 
  white-space: nowrap; 
  color: var(--text-inverse);
}
.logo-icon {
  width: 32px;
  height: 32px;
  background: var(--brand);
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
}

.toggle-btn { 
  border: none; 
  background: rgba(255,255,255,0.05); 
  color: rgba(255,255,255,.65); 
  cursor: pointer; 
  width: 32px;
  height: 32px;
  border-radius: var(--radius-sm); 
  display: flex;
  align-items: center;
  justify-content: center;
  transition: .2s;
}
.toggle-btn:hover { color: var(--text-inverse); background: rgba(255,255,255,.12); }
.sidebar.collapsed .toggle-btn { margin: 0 auto; }

.sidebar nav { flex: 1; padding: 12px 8px; }
.sidebar nav a { 
  display: flex; 
  align-items: center; 
  gap: 12px; 
  padding: 12px 16px; 
  color: rgba(255,255,255,.65); 
  text-decoration: none; 
  font-size: 14px; 
  font-weight: 500;
  transition: all .2s; 
  white-space: nowrap; 
  border-radius: var(--radius-md);
  margin-bottom: 4px;
}
.sidebar.collapsed nav a { justify-content: center; padding: 12px 0; margin: 0 8px 4px; }
.sidebar nav a:hover { 
  color: var(--text-inverse); 
  background: rgba(255,255,255,.08); 
}
.sidebar nav a.active { 
  color: var(--text-inverse); 
  background: var(--brand); 
  box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.3);
}

.sidebar-footer { padding: 16px; border-top: 1px solid rgba(255,255,255,.08); }
.sidebar.collapsed .sidebar-footer { text-align: center; }
.sidebar-footer a { 
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  color: rgba(255,255,255,.45); 
  text-decoration: none; 
  font-size: 13px; 
  border-radius: var(--radius-md);
  transition: .2s;
}
.sidebar-footer a:hover { color: var(--danger); background: rgba(255,77,79,0.1); }
.sidebar.collapsed .sidebar-footer a { justify-content: center; }

.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; padding: 12px; }
.header { padding: 0 12px 12px; }
.header-inner { 
  padding: 16px 24px;
  background: var(--bg-card); 
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  display: flex;
  align-items: center;
  min-height: 64px;
  gap: 16px;
}
.header h2 { margin: 0; font-size: 24px; font-weight: 600; color: var(--text-primary); }

.mobile-menu-btn {
  display: none;
  background: transparent;
  border: 1px solid var(--border-base);
  padding: 6px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-secondary);
}

.content { 
  flex: 1; 
  padding: 12px; 
  overflow-y: auto; 
  background: transparent; 
  position: relative; 
}

/* Mobile Overlay */
.mobile-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  backdrop-filter: blur(4px);
  z-index: 990;
}

/* Transitions */
.fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease, transform 0.2s ease; }
.fade-enter-from { opacity: 0; transform: translateY(8px); }
.fade-leave-to { opacity: 0; transform: translateY(-8px); }

@media (max-width: 768px) {
  .sidebar { 
    position: fixed; 
    left: 0; 
    top: 0; 
    bottom: 0; 
    margin: 0; 
    border-radius: 0; 
    transform: translateX(-100%); 
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .sidebar.mobile-open { transform: translateX(0); width: 240px !important; }
  .mobile-menu-btn { display: block; }
  .header-inner { padding: 12px 20px; }
  .main { padding: 0; }
}
</style>
