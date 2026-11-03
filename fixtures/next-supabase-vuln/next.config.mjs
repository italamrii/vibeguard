/** @type {import('next').NextConfig} */
const nextConfig = {
  // vg-expect: secrets/client-exposed-env
  env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY },
};

export default nextConfig;
