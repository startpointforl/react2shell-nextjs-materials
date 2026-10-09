'use server'

export async function callStripe(amount: number) {
  // должно сработать: имя + высокоэнтропийный литерал (high)
  const apiKey = 'sk_live_51H9xQ2eZvKYlo2C8kR3nD4pXmT7wY6aB'
  await fetch('https://api.stripe.com/v1/charges', {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  return amount
}

export async function signToken(payload: string) {
  // должно сработать: свойство token с литералом (high)
  const config = { token: 'ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY2z4' }
  return config.token + payload
}
