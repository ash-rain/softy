import { ipcMain } from 'electron'
import { DockerBridge, CompileRequest, AssembleRequest } from '../bridge/docker'

export function registerCompilerIPC(docker: DockerBridge): void {

  ipcMain.handle('compile:code', async (_event, req: CompileRequest) => {
    return docker.compile(req)
  })

  ipcMain.handle('compile:assemble', async (_event, req: AssembleRequest) => {
    return docker.assemble(req)
  })
}
