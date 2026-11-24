export type ClipboardClearOutcome = 'cleared' | 'replaced' | 'stale' | 'failed'

export interface ClipboardReaderWriter {
  readText(): Promise<string>
  writeText(value: string): Promise<void>
}

export interface ClipboardOperationQueue {
  run<T>(operation: () => Promise<T>): Promise<T>
}

/** Serialize app clipboard operations so an older async write cannot finish after a newer one. */
export function createClipboardOperationQueue(): ClipboardOperationQueue {
  let pending: Promise<unknown> = Promise.resolve()

  return {
    run<T>(operation: () => Promise<T>): Promise<T> {
      const result = pending.then(operation, operation)
      pending = result.then(() => undefined, () => undefined)
      return result
    },
  }
}

/** Clear only the value this app copied, and only while its scheduled generation is still current. */
export async function clearClipboardIfStillCurrent(
  clipboard: ClipboardReaderWriter,
  expectedValue: string,
  isCurrent: () => boolean,
): Promise<ClipboardClearOutcome> {
  if (!isCurrent()) return 'stale'
  let clipboardValue: string
  try {
    clipboardValue = await clipboard.readText()
  } catch {
    return 'failed'
  }
  if (!isCurrent()) return 'stale'
  if (clipboardValue !== expectedValue) return 'replaced'

  try {
    await clipboard.writeText('')
    return 'cleared'
  } catch {
    return 'failed'
  }
}
