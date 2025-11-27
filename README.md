# StoreCards

StoreCards is a modern, mobile-first web application for storing and displaying loyalty cards. It allows you to keep all your rewards cards in one place, accessible from any device.

## Features

-   **📱 Mobile-First Design**: Optimized for phone screens to easily show barcodes at checkout.
-   **📷 Easy Scanning**: Add cards by scanning barcodes with your camera or uploading images.
-   **🏷️ Wide Format Support**: Supports codes like UPC, EAN, Code 128, QR Code, PDF417, and more.
-   **💡 Smart Display**: Full-screen barcode view for easy and reliable scanning.

## Tech Stack

-   **Framework**: [Next.js 14](https://nextjs.org/) (App Router)
-   **Language**: TypeScript
-   **Styling**: Tailwind CSS
-   **Database**: SQLite (Local) / PostgreSQL (Production)
-   **ORM**: Prisma
-   **Auth**: NextAuth.js v5

## Getting Started Locally

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/admica/storecards.git
    cd storecards
    ```

2.  **Install**:
    ```bash
    npm install --legacy-peer-deps
    npx prisma db push
    ```

4.  **Run the development server**:
    ```bash
    npm run dev
    ```

5.  **Open the app**:
    Visit [http://localhost:3000](http://localhost:3000) in your browser.

## Deployment

This app is optimized for deployment on [Vercel](https://vercel.com).
