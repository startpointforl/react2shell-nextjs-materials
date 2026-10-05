'use server'

export async function leakyAction(arg: unknown) {
  const message = `Processing request: ${String(arg)}`
  return message
}