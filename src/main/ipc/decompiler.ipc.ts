/**
 * Decompiler IPC — start decompilation, stream functions back to renderer.
 */

import { ipcMain, BrowserWindow } from 'electron'
import { DockerBridge } from '../bridge/docker'

export function registerDecompilerIPC(docker: DockerBridge): void {

  ipcMain.handle('decompile:start', async (event, relPath: string, projectId: string, backend = 'ghidra') => {
    const { streamId, backend: actualBackend } = await docker.startDecompile(relPath, projectId, backend)

    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) throw new Error('No window found')

    // Stream in background; push each event to renderer via webContents.send
    ;(async () => {
      try {
        for await (const item of docker.streamDecompile(streamId)) {
          if (win.isDestroyed()) break
          win.webContents.send('decompile:event', item)
        }
      } catch (err: unknown) {
        if (!win.isDestroyed()) {
          win.webContents.send('decompile:event', {
            type: 'error',
            message: (err as Error).message,
          })
        }
      }
    })()

    return { streamId, backend: actualBackend }
  })
}
