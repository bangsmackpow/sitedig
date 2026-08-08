/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The UI does not serve optimized images, so disable the image optimizer.
  // This also lets the runtime image omit the heavy `sharp` dependency.
  images: { unoptimized: true },
  // The worker owns all scanner subprocess execution. The web service must
  // never execute scanner commands; it only talks to the worker over HTTP.
  serverExternalPackages: [],
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default nextConfig;
