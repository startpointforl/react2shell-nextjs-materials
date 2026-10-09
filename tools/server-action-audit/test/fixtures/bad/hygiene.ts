'use server'

import { db } from './db'
import { redirect } from 'next/navigation'
import { exec } from 'node:child_process'

// missing-auth + missing-validation: мутация без auth и без валидации
export async function deletePost(id: string) {
  await db.post.delete({ where: { id } })
}

// mass-assignment: весь вход в data
export async function updateProfile(input: Record<string, unknown>) {
  await db.user.update({ where: { id: '1' }, data: input })
}

// dangerous-sink: open redirect
export async function goTo(url: string) {
  redirect(url)
}

// dangerous-sink: command injection (RCE)
export async function runTask(cmd: string) {
  exec(cmd)
}

// return-leak: сырая запись из БД
export async function getUser(id: string) {
  const user = await db.user.findUnique({ where: { id } })
  return user
}

// return-leak: детали ошибки
export async function risky(id: string) {
  try {
    await db.post.update({ where: { id }, data: { seen: true } })
    return { ok: true }
  } catch (e) {
    return { error: (e as Error).message }
  }
}
