# CyberPulse - Terminal de Inteligência de Ameaças 🛡️

![CyberPulse Banner](./docs/banner.png)

> Um agregador de inteligência de ameaças em tempo real construído com estética Hacker/Cyberpunk. Monitoramento global, pontuação de risco customizada e análise de vulnerabilidades alimentada por Inteligência Artificial (Gemini).

---

## 🌐 Acesse a Plataforma ao Vivo (Live Demo)
O projeto já está hospedado e funcionando 24/7 na nuvem. Você pode testar todas as funcionalidades diretamente pelo navegador:

👉 **[ACESSAR CYBERPULSE AGORA](https://cyberpulse-git-main-bymail.vercel.app/)** *(Link de Produção)*

---

## 🚀 Como Utilizar e Testar a Plataforma

Para ter a experiência completa de um Analista de Cibersegurança, siga os passos abaixo no site ao vivo:

### 1. Configure a Inteligência Artificial (Gratuito e Seguro)
A IA do sistema traduz jargões técnicos para uma linguagem clara e diz como corrigir a falha. Por questões de segurança (Zero-Trust), o sistema não guarda a chave de ninguém.
- Acesse o [Google AI Studio](https://aistudio.google.com/app/apikey) e gere uma **API Key Gratuita**.
- No CyberPulse, clique em qualquer ameaça na tabela para abrir o Terminal de Detalhes.
- Cole sua chave no quadro da Inteligência Artificial e clique em **SALVAR**. Sua chave fica segura apenas no seu navegador e não vai para o nosso banco de dados.

### 2. Drible o "Delay" do Governo Americano (Busca Real-Time)
**Você sabia?** A base de dados oficial da CISA (governo americano) demora até 24 horas para atualizar seus arquivos de API por conta do gigantesco cache global dos servidores deles. 
- **O Teste:** Se você viu uma falha que saiu hoje no site oficial da CISA e ela ainda não apareceu na nossa tabela, não espere!
- **A Solução:** Copie o código da falha (ex: `CVE-2024-3094`), cole na barra de busca superior do CyberPulse e aperte `[ BUSCAR ]`.
- O nosso sistema fará uma interceptação *em tempo real* no banco de dados raiz (NVD), trará os dados brutos instantaneamente e permitirá que você mande a IA analisá-los antes mesmo do governo atualizar a lista pública!

### 3. Entenda o "Risk Score (CyberPulse)"
Ao contrário de sites comuns que apenas listam o score CVSS básico, o CyberPulse possui um **Motor de Risco Customizado**. Se a CISA emitir um alerta de que a falha está sendo explorada ativamente por hackers, nosso robô detecta, penaliza a vulnerabilidade e **multiplica a nota de risco (chegando a quase 10.0)**, jogando a ameaça para o topo da sua tabela de prioridades.

---

## 📸 Screenshots

![Tela Inicial](./docs/tela_inicial.png)
![Detalhes da Ameaça](./docs/modal_ameaca.png)
![Busca Real-Time](./docs/busca_cve.png)

---

## 🛠️ Arquitetura Técnica (Para Desenvolvedores)

- **Backend:** FastAPI (Python), SQLAlchemy, PostgreSQL, APScheduler (Rotinas Automáticas a cada 6h).
- **Frontend:** React, TypeScript, TailwindCSS.
- **Inteligência Artificial:** Google Gemini (`gemini-3.5-flash`).
- **Deploy Cloud:** Vercel (Frontend) e Render (Backend/Robôs).

### Rodando Localmente com Docker
Se você quiser clonar e rodar o projeto na sua máquina para estudar o código:
```bash
# Clone o repositório
git clone https://github.com/SEU-USUARIO/cyberpulse.git
cd cyberpulse

# Suba todos os containers (Banco de Dados, Backend e Frontend)
docker compose up -d --build
```
Após compilar, acesse `http://localhost:5173`. O backend já começará a varrer a internet populando seu banco de dados local através do agendador automático (APScheduler).
