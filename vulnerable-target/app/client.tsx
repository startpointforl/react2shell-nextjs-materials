'use client'

type ServerAction = (...args: unknown[]) => Promise<string>

export default function Client({ action }: { action: ServerAction }) {
  async function trigger() {
    await action(action)
  }
  return <button onClick={trigger}>trigger</button>
}