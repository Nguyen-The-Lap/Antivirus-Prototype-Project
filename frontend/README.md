<div align="center">
  <img src="https://img.icons8.com/fluency/96/000000/shield.png" alt="Cool Logo" width="100" height="100">
  
  <h1>Cool Web Dashboard</h1>
  <h3>⚡ Modern Interface for Cool Antivirus</h3>
  
  <p align="center">
    <a href="https://nodejs.org/">
      <img src="https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node Version">
    </a>
    <a href="https://react.dev/">
      <img src="https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=white" alt="React Version">
    </a>
    <a href="https://www.typescriptlang.org/">
      <img src="https://img.shields.io/badge/TypeScript-5.0%2B-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript Version">
    </a>
    <a href="https://vitejs.dev/">
      <img src="https://img.shields.io/badge/Vite-4.0%2B-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite Version">
    </a>
  </p>
  
  <p>
    <a href="#-features">Features</a> •
    <a href="#-quick-start">Quick Start</a> •
    <a href="#-development">Development</a> •
    <a href="#-contributing">Contributing</a>
  </p>
  
  <hr>
</div>

## ✨ Features

### 📊 Real-time Dashboard
- System status at a glance
- Threat detection alerts
- Resource usage metrics

### 🛡️ Security Controls
- Quick scan options
- Real-time protection toggles
- Quarantine management

### 📱 Responsive Design
- Works on desktop and mobile
- Dark/light theme support
- Keyboard navigation

### 🔌 Integration
- REST API connectivity
- WebSocket for real-time updates
- Plugin system for extensions

## 🚀 Quick Start

### Prerequisites
- Node.js 18 or later
- npm 9 or later (or pnpm/yarn)
- Backend API server (see main project README)

### Installation

```bash
# Clone the repository
git clone https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project.git
cd Antivirus-Prototype-Project/frontend

# Install dependencies
npm install  # or pnpm install / yarn install

# Start development server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser to see the dashboard.

## 🛠 Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint
- `npm run type-check` - Check TypeScript types
- `npm test` - Run tests

### Project Structure

```
frontend/
├── public/          # Static files
├── src/
│   ├── assets/      # Images, fonts, etc.
│   ├── components/  # Reusable UI components
│   ├── hooks/       # Custom React hooks
│   ├── layouts/     # Page layouts
│   ├── pages/       # Page components
│   ├── services/    # API services
│   ├── store/       # State management
│   ├── styles/      # Global styles
│   ├── types/       # TypeScript type definitions
│   ├── utils/       # Utility functions
│   ├── App.tsx      # Main app component
│   └── main.tsx     # Entry point
└── ...
```

### Environment Variables

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:3000/api
VITE_WS_URL=ws://localhost:3001
VITE_APP_NAME="Cool Antivirus"
```

## 🤝 Contributing

We welcome contributions! Please see the main [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

<div align="center">
  <p>Made with ❤️ by Nguyen The Lap</p>
  <p>⭐ Star this project on <a href="https://github.com/Nguyen-The-Lap/Antivirus-Prototype-Project">GitHub</a></p>
</div>
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
