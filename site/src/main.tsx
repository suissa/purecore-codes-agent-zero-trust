import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'

// Aplicar classe dark no elemento raiz
document.documentElement.classList.add('dark');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <div className="bg-background text-foreground antialiased selection:bg-primary/30">
      <App />
    </div>
  </StrictMode>,
)
