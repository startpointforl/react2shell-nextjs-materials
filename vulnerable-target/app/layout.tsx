export const metadata = {
  title: "vulnerable-target",
  description: "Намеренно уязвимое приложение для демонстрации React2Shell",
}

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
