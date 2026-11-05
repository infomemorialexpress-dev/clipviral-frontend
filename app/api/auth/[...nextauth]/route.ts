import NextAuth from 'next-auth';
import { authOptions } from '@/lib/auth';
import { NextRequest } from 'next/server';

const handler = async (req: NextRequest, ctx: any) => {
  // Ensure NEXTAUTH_URL dynamically matches the production domain on Vercel
  const host = req.headers.get('x-forwarded-host') || req.headers.get('host');
  const proto = req.headers.get('x-forwarded-proto') || 'https';

  if (host && !host.includes('localhost')) {
    // If NEXTAUTH_URL is missing, defaulted to localhost, or set to placeholder, use the incoming host
    if (
      !process.env.NEXTAUTH_URL ||
      process.env.NEXTAUTH_URL.includes('localhost') ||
      process.env.NEXTAUTH_URL === 'https://clipviral.ai'
    ) {
      process.env.NEXTAUTH_URL = `${proto}://${host}`;
    }
  } else if (!process.env.NEXTAUTH_URL) {
    process.env.NEXTAUTH_URL = 'http://localhost:3000';
  }

  return NextAuth(req, ctx, authOptions);
};

export { handler as GET, handler as POST };


