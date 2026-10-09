// НЕ Server Action — нет 'use server'. Ничего не должно находиться здесь.

export async function greet(name: unknown) {
  return `Hello ${name}`
}

const apiKey = 'sk_live_51H9xQ2eZvKYlo2C8kR3nD4pXmT7wY6aB'
export function getKey() {
  return apiKey
}
