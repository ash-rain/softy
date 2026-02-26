import { ipcMain } from 'electron'
import { DockerBridge, CompileRequest, AssembleRequest, PatchBinaryRequest } from '../bridge/docker'

export function registerCompilerIPC(docker: DockerBridge): void {

  ipcMain.handle('compile:code', async (_event, req: CompileRequest) => {
    return docker.compile(req)
  })

  ipcMain.handle('compile:assemble', async (_event, req: AssembleRequest) => {
    return docker.assemble(req)
  })

  // Returns { data: base64, filename: string } so the renderer can offer a download
  ipcMain.handle('compile:patch', async (_event, req: PatchBinaryRequest) => {
    const buf = await docker.patchBinary(req)
    return {
      data:     buf.toString('base64'),
      filename: req.filePath.split('/').pop()?.replace(/\.[^.]+$/, '') + '.patched',
    }
  })
}
