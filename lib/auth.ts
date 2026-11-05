import type { NextAuthOptions } from 'next-auth';
import GoogleProvider from 'next-auth/providers/google';
import CredentialsProvider from 'next-auth/providers/credentials';
import { PrismaAdapter } from '@next-auth/prisma-adapter';
import prisma from '@/lib/prisma';
import bcrypt from 'bcryptjs';

// Ensure NEXTAUTH_URL is accurately set in production environments (e.g. Vercel)
if (typeof window === 'undefined') {
  if (
    !process.env.NEXTAUTH_URL ||
    process.env.NEXTAUTH_URL.includes('localhost') ||
    process.env.NEXTAUTH_URL === 'https://clipviral.ai'
  ) {
    if (process.env.VERCEL_ENV === 'production' || process.env.NODE_ENV === 'production') {
      process.env.NEXTAUTH_URL = 'https://clipviral-frontend.vercel.app';
    } else if (process.env.VERCEL_URL) {
      process.env.NEXTAUTH_URL = `https://${process.env.VERCEL_URL}`;
    }
  }
}

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    // Google OAuth Provider (Primary Authentication Method)
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      authorization: {
        params: {
          prompt: 'select_account',
          access_type: 'offline',
          response_type: 'code',
        },
      },
      allowDangerousEmailAccountLinking: true,
    }),
    // Strict Credentials Provider (Google & Email/Password Only)
    CredentialsProvider({
      id: 'credentials',
      name: 'Email & Password',
      credentials: {
        email: { label: 'Email', type: 'email', placeholder: 'creator@example.com' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email) {
          throw new Error('Please provide an email address.');
        }

        const email = credentials.email.toLowerCase().trim();

        // Strict Validation: Email MUST exist in database
        const user = await prisma.user.findUnique({
          where: { email },
        });

        if (!user) {
          throw new Error('No account found with this email. Please sign up first.');
        }

        // If password is provided, strictly verify with bcrypt
        const userPassword = (user as any).password;
        if (credentials.password) {
          if (!userPassword) {
            throw new Error('This account was registered with Google. Please continue with Google.');
          }

          const isPasswordValid = await bcrypt.compare(credentials.password, userPassword);
          if (!isPasswordValid) {
            throw new Error('Incorrect password. Please try again.');
          }
        } else {
          // Password not provided
          if (userPassword) {
            throw new Error('Please enter your password to sign in.');
          }
        }

        return user;
      },
    }),
  ],
  pages: {
    signIn: '/login',
    error: '/login',
  },
  session: {
    strategy: 'jwt',
  },
  callbacks: {
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith('/')) return `${baseUrl}${url}`;
      // Allows callback URLs on the same origin (including Vercel deployment URLs)
      try {
        if (new URL(url).origin === baseUrl) return url;
      } catch {
        return baseUrl;
      }
      return baseUrl;
    },
    async signIn({ user, account, profile }) {
      if (user.email) {
        try {
          await prisma.user.upsert({
            where: { email: user.email },
            update: {
              name: user.name || undefined,
              image: user.image || undefined,
            },
            create: {
              email: user.email,
              name: user.name || user.email.split('@')[0],
              image: user.image,
            },
          });
        } catch (e) {
          console.warn('[Prisma signIn sync warning]:', e);
        }
      }
      return true;
    },
    async jwt({ token, user, account }) {
      if (user) {
        token.id = user.id;
      }
      if (account) {
        token.provider = account.provider;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as any).id = token.id;

        // Fetch user's active Stripe subscription tier and connected social accounts
        try {
          if (token.id) {
            const [subscription, accounts] = await Promise.all([
              prisma.subscription.findFirst({
                where: {
                  userId: token.id as string,
                  status: 'active',
                },
              }),
              prisma.account.findMany({
                where: {
                  userId: token.id as string,
                },
                select: {
                  provider: true,
                },
              }),
            ]);

            const userTier = subscription?.tier || 'starter';
            (session.user as any).subscriptionTier = userTier;
            (session.user as any).plan = userTier.toUpperCase();
            (session.user as any).connectedAccounts = accounts.map((a) => a.provider);
          }
        } catch (e) {
          (session.user as any).subscriptionTier = 'starter';
          (session.user as any).plan = 'STARTER';
          (session.user as any).connectedAccounts = [];
        }
      }
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET || 'clipviral-ai-editor-super-secret-dev-key-2026',
};
