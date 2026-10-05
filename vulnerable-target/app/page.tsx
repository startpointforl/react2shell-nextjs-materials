import { leakyAction } from './actions'
import Client from './client'

export default function Home() {
  return <Client action={leakyAction} />
}