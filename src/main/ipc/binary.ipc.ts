/**
 * Binary IPC — file open dialog, staging, analysis, resources, strings.
 */

import { ipcMain, dialog } from 'electron'
import { DockerBridge } from '../bridge/docker'
import { randomUUID } from 'crypto'
import { basename } from 'path'

export function registerBinaryIPC(docker: DockerBridge): void {

  ipcMain.handle('binary:open-dialog', async () => {
    const result = await dialog.showOpenDialog({
      title: 'Open Binary',
      buttonLabel: 'Open',
      filters: [
        { name: 'Executables', extensions: ['exe', 'dll', 'so', 'dylib', 'elf', 'bin', 'out', 'wasm', 'class', 'dex', 'apk', 'fw'] },
        { name: 'All Files', extensions: ['*'] },
      ],
      properties: ['openFile'],
    })
    return result.canceled ? null : result.filePaths[0]
  })

  ipcMain.handle('binary:analyze', async (_event, localPath: string) => {
    const projectId = randomUUID()
    const name = basename(localPath)

    // Stage file into work volume
    const relPath = docker.stageFile(localPath, projectId)

    // Run analysis
    const meta = await docker.analyze(relPath)
    const quick = await docker.quickAnalysis(relPath).catch(() => ({ functions: [], imports: [], exports: [], sections: [], info: {} }))

    return { projectId, name, localPath, relPath, meta, quick }
  })

  ipcMain.handle('binary:get-strings', async (_event, relPath: string, minLen?: number) => {
    return docker.getStrings(relPath, minLen)
  })

  ipcMain.handle('binary:list-resources', async (_event, relPath: string) => {
    return docker.listResources(relPath)
  })

  ipcMain.handle('docker:status', async () => {
    const healthy = await docker.isHealthy()
    return { running: healthy }
  })

  ipcMain.handle('docker:start', async () => {
    try {
      await docker.ensureRunning()
      return { ok: true }
    } catch (err: unknown) {
      return { ok: false, error: (err as Error).message }
    }
  })
}
