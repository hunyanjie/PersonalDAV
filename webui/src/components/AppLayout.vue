<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="logo">PersonalDAV</div>
      <nav>
        <router-link to="/" exact-active-class="active">📊 概览</router-link>
        <router-link to="/contacts" active-class="active">👤 联系人</router-link>
        <router-link to="/calendar" active-class="active">📅 月视图</router-link>
        <router-link to="/calendar/schedule" active-class="active">📋 日程视图</router-link>
        <router-link to="/files" active-class="active">📁 文件</router-link>
        <router-link to="/settings" active-class="active">⚙️ 设置</router-link>
      </nav>
      <div class="sidebar-footer">
        <a href="#" @click.prevent="logout">退出登录</a>
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
  methods: {
    logout() {
      localStorage.removeItem('token')
      this.$router.push('/login')
    },
  },
}
</script>

<style scoped>
.layout { display: flex; height: 100vh; }
.sidebar { width: 200px; background: #001529; color: #fff; display: flex; flex-direction: column; flex-shrink: 0; }
.logo { padding: 20px 16px; font-size: 18px; font-weight: bold; border-bottom: 1px solid rgba(255,255,255,.1); }
.sidebar nav { flex: 1; padding: 8px 0; }
.sidebar nav a { display: flex; align-items: center; gap: 8px; padding: 12px 20px; color: rgba(255,255,255,.65); text-decoration: none; font-size: 14px; transition: .2s; }
.sidebar nav a:hover { color: #fff; background: rgba(255,255,255,.08); }
.sidebar nav a.active { color: #fff; background: #1677ff; }
.sidebar-footer { padding: 12px 20px; border-top: 1px solid rgba(255,255,255,.1); }
.sidebar-footer a { color: rgba(255,255,255,.45); text-decoration: none; font-size: 13px; }
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.header { padding: 16px 24px; background: #fff; border-bottom: 1px solid #f0f0f0; }
.header h2 { margin: 0; font-size: 20px; }
.content { flex: 1; padding: 24px; overflow-y: auto; background: #f5f5f5; }
</style>
