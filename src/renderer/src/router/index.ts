import { createRouter, createWebHashHistory } from 'vue-router'
import WelcomeView   from '@/views/WelcomeView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import SettingsView  from '@/views/SettingsView.vue'

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/',          name: 'welcome',   component: WelcomeView },
    { path: '/workspace', name: 'workspace', component: WorkspaceView },
    { path: '/settings',  name: 'settings',  component: SettingsView },
  ],
})
