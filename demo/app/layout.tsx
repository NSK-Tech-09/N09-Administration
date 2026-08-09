import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "N09 – Administration · Démonstrateur d’identité",
  description:
    "Démonstrateur local du contrôle central des identités NSK Tech 09.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
