import { DockerBridge } from '../bridge/docker'
import { registerBinaryIPC } from './binary.ipc'
import { registerDecompilerIPC } from './decompiler.ipc'
import { registerCompilerIPC } from './compiler.ipc'
import { registerAIIPC } from './ai.ipc'

export function registerAllIPC(docker: DockerBridge): void {
  registerBinaryIPC(docker)
  registerDecompilerIPC(docker)
  registerCompilerIPC(docker)
  registerAIIPC(docker)
}
