'use server'

export async function greet(name: unknown) {
  // server-action-audit-ignore-next-line stringify-arg
  return `Hello ${name}`
}
