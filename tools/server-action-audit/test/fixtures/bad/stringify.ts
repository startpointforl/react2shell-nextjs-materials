'use server'

// должно сработать: шаблонный литерал с аргументом возвращается клиенту (high)
export async function greet(name: unknown) {
  return `Hello ${name}`
}

// должно сработать: String(arg) возвращается (high)
export async function echo(arg: unknown) {
  const msg = 'Processing: ' + String(arg)
  return msg
}

// должно сработать: .toString() через промежуточную переменную (high)
export async function stamp(input: unknown) {
  const s = input.toString()
  return { stamp: s }
}
