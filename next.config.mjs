/** @type {import('next').NextConfig} */
const nextConfig = {
    reactStrictMode: true,

    serverExternalPackages: ['@prisma/client'],
    output: 'standalone',  // Required for Docker/self-hosted deployment
    env: {
        // Expose env vars to browser if needed (e.g., NEXTAUTH_URL)
    },
};

export default nextConfig;