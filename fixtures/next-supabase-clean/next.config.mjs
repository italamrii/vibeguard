/** @type {import('next').NextConfig} */
const nextConfig = {
  env: { APP_VERSION: '1.4.0', NEXT_PUBLIC_SITE_URL: 'https://acme.example' },
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: 'https://app.acme.example' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};

export default nextConfig;
