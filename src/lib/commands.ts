import { invoke } from '@tauri-apps/api/core'

/**
 * Typed wrappers over the Rust command surface.
 *
 * Everything that touches a decrypted secret stays on the Rust side; nothing
 * here should ever return plaintext except the explicit reveal path (Phase 1).
 */

export function coreVersion(): Promise<string> {
  return invoke<string>('core_version')
}
