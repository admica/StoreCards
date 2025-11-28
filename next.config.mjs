/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,
    serverExternalPackages: ['@prisma/client'],  // For Prisma in server components
    output: 'standalone',  // Crucial for Vercel serverless (includes Prisma binaries)
    env: {
        // Expose env vars to browser if needed (e.g., NEXTAUTH_URL)
    },
};

export default nextConfig;