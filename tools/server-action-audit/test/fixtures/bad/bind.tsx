import { updateUser } from './actions-for-bind'

const SIGNING_SECRET = process.env.SIGNING_SECRET!

export function Form({ id }: { id: string }) {
  // должно сработать: секрет уходит через .bind() (medium)
  const action = updateUser.bind(null, SIGNING_SECRET)
  return <form action={action} />
}
