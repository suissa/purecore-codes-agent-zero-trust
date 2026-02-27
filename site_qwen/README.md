# Site de Documentação - Agent Zero Trust

Site de documentação desenvolvido com Vite + React + Tailwind CSS + Shadcn UI.

## 🚀 Início Rápido

### Instalar dependências

```bash
cd site_qwen
npm install
# ou
bun install
```

### Rodar em desenvolvimento

```bash
npm run dev
# ou
bun dev
```

O site estará disponível em `http://localhost:5173`

### Build de produção

```bash
npm run build
npm run preview
```

## 📁 Estrutura de Diretórios

```
site_qwen/
├── src/
│   ├── components/
│   │   └── ui/          # Componentes Shadcn
│   ├── lib/             # Utilitários
│   ├── App.tsx          # App principal com rotas
│   ├── main.tsx         # Entry point
│   └── index.css        # Estilos globais + Tailwind
├── index.html
├── package.json
├── tailwind.config.js
├── tsconfig.json
└── vite.config.ts
```

## 🎨 Páginas

1. **Início** - Hero section, features, instalação, quick start
2. **Arquitetura** - Explicação da arquitetura tri-camada
3. **Tecnologias** - Detalhes de X3DH, Double Ratchet, JWK Thumbprint, Bloom Filter
4. **Diagramas** - Fluxos e diagramas ASCII
5. **API** - Referência completa da API

## 🧩 Componentes UI

- Button
- Card
- Tabs
- Accordion

Todos os componentes são baseados em Radix UI e estilizados com Tailwind CSS.

## 📦 Dependências Principais

- React 18
- React Router DOM
- Tailwind CSS
- Shadcn UI (Radix UI + Tailwind)
- Lucide React (ícones)
- Recharts (gráficos)

## 🎯 Recursos

- ✅ Responsivo (mobile-first)
- ✅ Dark mode ready
- ✅ Tipagem TypeScript
- ✅ Componentes acessíveis
- ✅ Performance otimizada

## 📝 Adicionando Conteúdo

Para adicionar novas páginas:

1. Crie o componente da página em `src/pages/`
2. Adicione a rota em `App.tsx`
3. Atualize a navegação em `Navigation`

Para adicionar componentes UI:

```bash
# Use o CLI do Shadcn (se configurado)
npx shadcn-ui@latest add button
```

Ou copie manualmente de https://ui.shadcn.com

## 🚀 Deploy

### Vercel

```bash
npm install -g vercel
vercel
```

### Netlify

```bash
npm run build
# Deploy da pasta dist/
```

### GitHub Pages

```bash
npm install -D gh-pages
npm run build
npx gh-pages -d dist
```

## 📄 Licença

Apache 2.0 - Mesmo license do pacote principal.
