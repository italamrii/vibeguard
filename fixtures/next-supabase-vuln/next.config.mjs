/** @type {import('next').NextConfig} */
const nextConfig = {
  // vg-expect: secrets/client-exposed-env
  env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY },
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          // vg-expect: endpoints/cors-wildcard-credentials
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};

export default nextConfig;
