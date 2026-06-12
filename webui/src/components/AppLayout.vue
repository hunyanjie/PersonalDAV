<template>
  <div class="layout">
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="sidebar-header">
        <div class="logo" v-show="!sidebarCollapsed">PersonalDAV</div>
        <button class="toggle-btn" @click="toggleSidebar" :title="sidebarCollapsed ? '展开侧栏' : '收缩侧栏'">
          {{ sidebarCollapsed ? '☰' : '◀' }}
        </button>
      </div>
      <nav>
        <router-link to="/" exact-active-class="active" :title="sidebarCollapsed ? '概览' : ''">📊 <span v-show="!sidebarCollapsed">概览</span></router-link>
        <router-link to="/contacts" active-class="active" :title="sidebarCollapsed ? '联系人' : ''">👤 <span v-show="!sidebarCollapsed">联系人</span></router-link>
        <router-link to="/calendar" active-class="active" :title="sidebarCollapsed ? '月视图' : ''">📅 <span v-show="!sidebarCollapsed">月视图</span></router-link>
        <router-link to="/calendar/schedule" active-class="active" :title="sidebarCollapsed ? '日程视图' : ''">📋 <span v-show="!sidebarCollapsed">日程视图</span></router-link>
        <router-link to="/files" active-class="active" :title="sidebarCollapsed ? '文件' : ''">📁 <span v-show="!sidebarCollapsed">文件</span></router-link>
        <router-link to="/settings" active-class="active" :title="sidebarCollapsed ? '设置' : ''">⚙️ <span v-show="!sidebarCollapsed">设置</span></router-link>
      </nav>
      <div class="sidebar-footer">
        <a href="#" @click.prevent="logout" :title="sidebarCollapsed ? '退出登录' : ''">
          <span v-show="!sidebarCollapsed">退出登录</span>
          <span v-show="sidebarCollapsed">🚪</span>
        </a>
      </div>
    </aside>
    <main class="main">
      <header class="header">
        <h2>{{ $route.meta.title || '' }}</h2>
      </header>
      <div class="content">
        <router-view />
      </div>
    </main>
  </div>
</template>

<script>
export default {
  data: () => ({
    sidebarCollapsed: localStorage.getItem('sidebar_collapsed') === 'true',
  }),
  methods: {
    toggleSidebar() {
      this.sidebarCollapsed = !this.sidebarCollapsed
      localStorage.setItem('sidebar_collapsed', this.sidebarCollapsed)
    },
    logout() {
      localStorage.removeItem('token')
      this.$router.push('/login')
    },
  },
}
</script>

<style scoped>
.layout { display: flex; height: 100vh; }
.sidebar { width: 200px; background: #001529; color: var(--text-inverse); display: flex; flex-direction: column; flex-shrink: 0; transition: width .25s; overflow: hidden; }
.sidebar.collapsed { width: 60px; }
.sidebar-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 12px; border-bottom: 1px solid rgba(255,255,255,.1); min-height: 56px; }
.logo { font-size: 15px; font-weight: bold; white-space: nowrap; }
.toggle-btn { border: none; background: transparent; color: rgba(255,255,255,.65); cursor: pointer; font-size: 16px; padding: 4px 8px; border-radius: 4px; transition: .2s; flex-shrink: 0; }
.toggle-btn:hover { color: var(--text-inverse); background: rgba(255,255,255,.08); }
.sidebar.collapsed .toggle-btn { margin: 0 auto; }
.sidebar.collapsed .sidebar-header { justify-content: center; }
.sidebar nav { flex: 1; padding: 8px 0; }
.sidebar nav a { display: flex; align-items: center; gap: 10px; padding: 12px 20px; color: rgba(255,255,255,.65); text-decoration: none; font-size: 14px; transition: .2s; white-space: nowrap; }
.sidebar.collapsed nav a { justify-content: center; padding: 14px 0; }
.sidebar nav a:hover { color: var(--text-inverse); background: rgba(255,255,255,.08); }
.sidebar nav a.active { color: var(--text-inverse); background: var(--brand); }
.sidebar-footer { padding: 12px 20px; border-top: 1px solid rgba(255,255,255,.1); }
.sidebar.collapsed .sidebar-footer { padding: 12px 0; text-align: center; }
.sidebar-footer a { color: rgba(255,255,255,.45); text-decoration: none; font-size: 13px; }
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.header { padding: 16px 24px; background: var(--bg-card); border-bottom: 1px solid var(--border-base); }
.header h2 { margin: 0; font-size: 20px; }
.content { flex: 1; padding: 24px; overflow-y: auto; background: var(--bg-page); position: relative; }
</style>
