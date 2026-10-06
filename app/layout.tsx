import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title:'솜사탕의 작은 이야기',description:'솜사탕의 관심사와 경험, 패스키로 여는 나만의 메모함.',icons:{icon:'/favicon.svg'} };
export default function RootLayout({children}:Readonly<{children:React.ReactNode}>){return <html lang="ko"><body>{children}</body></html>}
