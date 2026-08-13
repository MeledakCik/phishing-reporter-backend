# Pakai image Playwright versi 1.44 (sesuai package.json)
FROM mcr.microsoft.com/playwright:v1.44.0-focal

WORKDIR /app

# Copy file package.json dan package-lock.json
COPY package*.json ./

# Install dependency Node
RUN npm ci

# Copy semua source code
COPY . .

# Install browser Playwright (Chromium)
RUN npx playwright install

# Expose port 5000 (sesuai aplikasi kamu)
EXPOSE 5000

# Jalankan aplikasi
CMD ["node", "src/index.js"]