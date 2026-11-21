/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: [
    '@dcmp/shared-types',
    '@dcmp/api-contracts',
    '@dcmp/validation-schemas',
    '@dcmp/design-tokens',
  ],
};

module.exports = nextConfig;
