# CyberPulse - Terminal de Inteligência de Ameaças 🛡️

![CyberPulse Banner](./docs/banner.png)

> Um agregador de inteligência de ameaças em tempo real construído com estética Hacker/Cyberpunk. Monitoramento global, pontuação de risco customizada e análise de vulnerabilidades alimentada por Inteligência Artificial (Gemini).

## ⚡ Recursos Principais

- **Feed de Notícias (INTEL):** Captura avisos de segurança de grandes fornecedores em tempo real.
- **Score Customizado (Risk Engine):** Esqueça a ordem cronológica. O CyberPulse calcula o risco real combinando a nota do NVD (CVSS), alertas da CISA (falhas ativamente exploradas) e a data de descobrimento.
- **Integração Real-Time NVD:** Pesquisou por um CVE que não está no banco? O sistema conecta ativamente com a base do governo americano, baixa e processa o dado na mesma hora.
- **Motor de Análise por IA:** Traduz descrições difíceis e ações da CISA para uma linguagem acessível e prática. Segue um padrão de segurança máxima (Zero-Trust para Tokens).
- **Estética Cyber-Dark:** Terminal retrô com fontes mono-espaçadas, CRT scanlines, e alto contraste neon.

### ⏱️ Nota sobre o Delay da CISA (KEV)
O catálogo de vulnerabilidades ativamente exploradas (KEV) da CISA possui um delay natural de propagação em sua API (JSON Oficial). Embora as ameaças apareçam imediatamente no [Site HTML da CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), o arquivo de dados consumido globalmente por sistemas de inteligência pode demorar de 4 a 24 horas para ser atualizado pelos servidores do governo americano.
**Como contornar:** Se você viu uma ameaça urgente no site da CISA que ainda não desceu para a nossa tabela, basta copiar o ID (ex: `CVE-2026-1234`), colar na barra de busca do CyberPulse e dar Enter. Nosso robô fará uma interceptação em tempo real no banco de dados do NVD, baixará a ameaça na hora e permitirá que você use a Inteligência Artificial para analisá-la sem esperar o cache do governo!

---

## 📸 Screenshots da Plataforma

![Tela Inicial](./docs/tela_inicial.png)

![Detalhes da Ameaça](./docs/modal_ameaca.png)

![Busca Real-Time](./docs/busca_cve.png)

---

## 🛠️ Arquitetura Técnica

* **Backend:** FastAPI (Python), SQLAlchemy, PostgreSQL, APScheduler (Background Jobs).
* **Frontend:** React, TypeScript, TailwindCSS.
* **Inteligência Artificial:** Google Gemini (`gemini-3.5-flash`).
* **Tradução:** Deep Translator (PT-BR).
* **Deploy:** Docker & Docker Compose.

---

## 🚀 Como Executar o Projeto

O projeto foi empacotado para rodar com o mínimo de esforço utilizando Docker.

### Pré-requisitos
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) ou Docker Engine instalado.
* Git.

### Passo 1: Clonar e Iniciar
```bash
# Clone o repositório
git clone https://github.com/SEU-USUARIO/cyberpulse.git
cd cyberpulse

# Suba todos os containers (Banco de Dados, Backend e Frontend)
docker compose up -d --build
```

### Passo 2: Acessar a Plataforma
Pronto! Com o comando acima os robôs de coleta já começaram a popular seu banco de dados local.
Abra seu navegador e acesse:
👉 **[http://localhost:5173](http://localhost:5173)**

---

## 🧠 Como Configurar a IA (Google Gemini)

Pensando em **Segurança Absoluta**, o CyberPulse não armazena chaves de API no servidor (evitando vazamentos e cobranças indevidas). 
Para usar a Inteligência Artificial:

1. Acesse o [Google AI Studio](https://aistudio.google.com/app/apikey) e gere uma **API Key Gratuita**.
2. Abra o painel do CyberPulse (`http://localhost:5173`).
3. Clique em uma vulnerabilidade (em Ameaças Ativas).
4. No quadro da Inteligência Artificial, cole seu Token e clique em **SALVAR**.
5. O Token ficará salvo localmente no seu próprio navegador e será usado com segurança a cada chamada de análise.

---

## ☁️ Deploy na Nuvem (Vercel + Render)

O CyberPulse já está preparado para rodar gratuitamente na nuvem, permitindo que qualquer pessoa acesse através de um link!

### 1. Backend + Robôs (Render)
O Render suporta Docker e mantém nossos coletores em segundo plano trabalhando.
1. Crie uma conta no [Render](https://render.com/) conectando com o seu GitHub.
2. Clique em `New` > `PostgreSQL` para criar seu Banco de Dados. Copie a `Internal Database URL`.
3. Clique em `New` > `Web Service`, escolha o seu repositório `cyberpulse`.
4. No ambiente, escolha **Docker**.
5. Em **Environment Variables**, crie uma variável chamada `DATABASE_URL` e cole a URL do banco que você copiou no passo 2.
6. Clique em Deploy. Ao final, o Render te dará um link (ex: `https://cyberpulse-back.onrender.com`). Copie-o!

### 2. Frontend (Vercel)
A Vercel hospedará a interface lindíssima em React.
1. Crie uma conta na [Vercel](https://vercel.com/) conectando com o seu GitHub.
2. Clique em `Add New` > `Project` e importe o repositório `cyberpulse`.
3. Abra a aba **Environment Variables**.
4. Crie uma chave chamada `VITE_API_URL` e cole o link do seu Backend gerado no Render no passo anterior (sem a barra `/` no final).
5. O _Framework Preset_ deve estar marcado como `Vite`.
6. Na configuração do "Root Directory", clique em "Edit" e selecione a pasta `frontend`. (IMPORTANTE!)
7. Clique em **Deploy**.

Em 1 minuto a Vercel vai te dar o link final do seu projeto! 🎉

---

## 🔐 Segurança e Boas Práticas (Devs)

- O arquivo `.env` está explicitamente no `.gitignore` para evitar vazamentos de configurações de banco de dados.
- O Token da IA trafega diretamente do cliente para o provedor, sem passar por armazenamento em banco de dados (`Zero-Trust`).

---
Desenvolvido como projeto de Inteligência de Segurança e Monitoramento Ativo.
