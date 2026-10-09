'use server'

import { z } from 'zod'
import { db } from './db'
import { auth } from './auth'

// НЕ должно сработать: тип проверен до использования, в строку идёт уже string
export async function greet(name: unknown) {
  if (typeof name !== 'string') throw new Error('bad input')
  return `Hello ${name}`
}

// НЕ должно сработать: секрет из env, не литерал
export async function callApi() {
  const apiKey = process.env.STRIPE_SECRET_KEY
  return fetch('https://api.stripe.com', { headers: { Authorization: `Bearer ${apiKey}` } })
}

// НЕ должно сработать: есть auth + валидация + явные поля + select
const schema = z.object({ id: z.string(), title: z.string() })
export async function updatePost(raw: unknown) {
  await auth()
  const { id, title } = schema.parse(raw)
  const post = await db.post.update({ where: { id }, data: { title }, select: { id: true } })
  return post
}

// НЕ должно сработать: число приведено через Number() (валидация), редирект на статику
export async function paginate(pageRaw: unknown) {
  const page = Number(pageRaw)
  return db.post.findMany({ skip: page * 10, select: { id: true } })
}
