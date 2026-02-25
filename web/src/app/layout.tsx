import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { Providers } from "@/components/providers";

export const metadata: Metadata = {
  title: "IronVeil Dashboard",
  description: "Control Plane for IronVeil Database Anonymization Proxy",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Providers>
          <div className="h-full relative">
            <div className="hidden h-full md:flex md:w-72 md:flex-col md:fixed md:inset-y-0 z-[80] bg-gray-900 dark:bg-gray-900">
              <Sidebar />
            </div>
            <main className="md:pl-72 h-full bg-background">
              {children}
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
