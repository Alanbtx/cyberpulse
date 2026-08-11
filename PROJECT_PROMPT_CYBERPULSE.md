# CyberPulse — Plataforma Aberta de Inteligência em Segurança

## 1. Visão do projeto

Você é um agente de desenvolvimento responsável por construir, passo a passo, uma plataforma web gratuita e de código aberto para **Cyber Threat Intelligence (CTI)**.

O objetivo é coletar informações recentes e confiáveis sobre:

- vulnerabilidades (CVEs);
- vulnerabilidades exploradas ativamente;
- ameaças e campanhas;
- malware;
- incidentes relevantes;
- técnicas e táticas de ataque;
- atualizações de segurança;
- notícias relevantes de cibersegurança;
- recomendações de mitigação.

A plataforma deve transformar informações técnicas dispersas em conteúdo **claro, verificável e útil para empresas**, principalmente para profissionais que precisam entender rapidamente:

1. O que aconteceu?
2. Qual produto/tecnologia é afetado?
3. Qual é a gravidade?
4. Existe exploração ativa?
5. Quem pode ser impactado?
6. O que deve ser feito agora?
7. Qual é a fonte original?
8. Quando a informação foi atualizada?

O projeto será desenvolvido como um **projeto pessoal de portfólio**, mas a arquitetura deve permitir que futuramente ele seja disponibilizado publicamente para qualquer pessoa utilizar gratuitamente.

---

# 2. Regras fundamentais do projeto

Estas regras são obrigatórias durante todo o desenvolvimento.

### 2.1 Custo

O projeto deve utilizar exclusivamente:

- software open source;
- APIs públicas gratuitas;
- serviços com camada gratuita suficiente para o projeto;
- recursos locais no computador do desenvolvedor.

Não adicionar serviços pagos obrigatórios.

Se uma tecnologia possuir plano gratuito limitado, verificar primeiro se existe alternativa open source ou gratuita.

### 2.2 Transparência

A plataforma nunca deve apresentar uma análise gerada automaticamente como fato confirmado.

Todo conteúdo deve distinguir claramente:

- **Fato observado:** informação diretamente encontrada na fonte.
- **Análise:** interpretação produzida pelo sistema.
- **Recomendação:** possível ação de mitigação.
- **Fonte:** referência original utilizada.

Nunca inventar:

- CVEs;
- versões afetadas;
- produtos;
- indicadores de comprometimento;
- ataques;
- grupos criminosos;
- recomendações;
- datas;
- evidências.

### 2.3 Prioridade das fontes

Priorizar fontes primárias e oficiais.

Ordem preferencial:

1. CISA KEV
2. NVD
3. CVE / CNA
4. Microsoft Security Response Center
5. Apple Security Releases
6. Google / Android Security
7. Red Hat Security
8. Ubuntu Security
9. Debian Security
10. Cisco Security
11. Fortinet PSIRT
12. Palo Alto Networks Unit 42 / advisories
13. Cloudflare
14. AWS Security
15. Google Cloud Security
16. IBM Security
17. Outras fontes oficiais de fabricantes
18. CERTs e organizações nacionais/internacionais
19. Veículos especializados de segurança, somente como fonte complementar

Não substituir a fonte original por uma notícia quando existir um advisory oficial.

---

# 3. Objetivo do MVP

Antes de criar funcionalidades avançadas, construir um MVP funcional.

O MVP deverá:

### Coleta

- consultar fontes públicas;
- buscar informações recentes;
- armazenar os dados;
- evitar duplicações.

### Normalização

Transformar informações diferentes em um modelo comum.

### Classificação

Classificar cada item por:

- CVE;
- severidade;
- produto;
- fabricante;
- categoria;
- data;
- exploração ativa;
- fonte.

### Análise

Gerar uma análise em linguagem simples contendo:

- resumo;
- impacto;
- sistemas potencialmente afetados;
- nível de prioridade;
- recomendação de mitigação;
- indicação sobre exploração ativa;
- referências.

### Interface

Criar uma página web simples com:

- vulnerabilidades recentes;
- vulnerabilidades críticas;
- vulnerabilidades exploradas;
- notícias;
- pesquisa;
- filtros;
- página detalhada de cada vulnerabilidade.

### Alertas

Permitir futuramente cadastro de e-mail para receber:

- vulnerabilidades críticas;
- vulnerabilidades exploradas ativamente;
- alertas relacionados a produtos selecionados.

---

# 4. Stack tecnológica

Utilizar tecnologias populares, gratuitas e fáceis de aprender.

## Backend

Utilizar:

**Python + FastAPI**

Motivos:

- Python é amplamente utilizado em segurança;
- possui grande quantidade de bibliotecas;
- FastAPI é moderno;
- possui documentação clara;
- facilita criação de APIs REST.

## Banco de dados

Começar com:

**PostgreSQL**

Para desenvolvimento local:

**Docker + PostgreSQL**

O projeto deve ser estruturado para funcionar também com SQLite durante os primeiros testes, caso isso simplifique o desenvolvimento.

## Frontend

Utilizar:

**React + TypeScript + Vite**

Motivos:

- muito utilizado no mercado;
- TypeScript melhora a organização;
- Vite simplifica o desenvolvimento;
- possui grande ecossistema.

Para estilização:

**Tailwind CSS**

Não criar um frontend excessivamente complexo.

Priorizar:

- clareza;
- acessibilidade;
- responsividade;
- leitura rápida.

## Coleta

Utilizar Python com:

- requests;
- httpx;
- feedparser quando necessário;
- bibliotecas específicas apenas quando realmente necessárias.

Priorizar APIs, JSON, RSS e feeds oficiais em vez de scraping.

## Agendamento

Inicialmente utilizar:

**APScheduler**

O sistema deverá possuir jobs para:

- coleta periódica;
- atualização de vulnerabilidades;
- processamento;
- envio de alertas.

Evitar adicionar Celery/Redis no MVP sem necessidade real.

## IA

A arquitetura deve ser independente do provedor.

Criar uma camada:

`AIProvider`

Ela deverá permitir futuramente conectar diferentes modelos.

A implementação inicial deve priorizar modelos locais/open source quando forem viáveis.

A IA não pode ser requisito para o funcionamento básico da plataforma.

Se a IA estiver indisponível:

- a coleta continua;
- os dados continuam disponíveis;
- a classificação básica continua;
- o usuário recebe a informação sem análise automática.

---

# 5. Fontes iniciais

Começar com poucas fontes de alta qualidade.

## Fonte 1 — CISA KEV

Usar o catálogo oficial de vulnerabilidades conhecidamente exploradas.

Objetivo:

identificar rapidamente vulnerabilidades que já possuem evidência de exploração.

## Fonte 2 — NVD

Utilizar para:

- CVE;
- CVSS;
- descrição;
- produtos afetados;
- referências;
- CPE quando disponível.

## Fonte 3 — CVE.org / CNA

Utilizar como referência adicional para informações oficiais de CVE.

## Fonte 4 — RSS/feeds oficiais

Adicionar inicialmente poucos fabricantes relevantes.

Exemplos:

- Microsoft
- Cisco
- Red Hat
- Ubuntu
- Google
- Apple

Não adicionar dezenas de fontes no início.

Primeiro construir uma arquitetura que permita adicionar novas fontes facilmente.

---

# 6. Arquitetura

Utilizar uma arquitetura simples e modular.

```text
                    ┌──────────────────────┐
                    │       Frontend       │
                    │ React + TypeScript   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │       FastAPI        │
                    │      REST API        │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        ┌───────────┐    ┌────────────┐   ┌────────────┐
        │ Collector │    │   Engine   │   │  Alerts    │
        │  Sources  │    │  Analysis  │   │   Email    │
        └─────┬─────┘    └──────┬─────┘   └──────┬─────┘
              │                 │                │
              └─────────────────┼────────────────┘
                                ▼
                       ┌─────────────────┐
                       │   PostgreSQL    │
                       └─────────────────┘
```

---

# 7. Estrutura do projeto

Criar inicialmente:

```text
cyberpulse/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── collectors/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── ai/
│   │   ├── alerts/
│   │   ├── database/
│   │   └── main.py
│   │
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── types/
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
│
├── docs/
│   ├── architecture.md
│   ├── sources.md
│   └── threat-model.md
│
├── scripts/
│
├── docker-compose.yml
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

Não criar arquivos desnecessários.

---

# 8. Modelo de dados

Criar entidades mínimas.

## Vulnerability

Campos sugeridos:

```text
id
cve_id
title
description
severity
cvss_score
cvss_vector
published_at
modified_at
exploit_available
known_exploited
vendor
product
affected_versions
fixed_versions
references
source
source_url
last_seen_at
created_at
updated_at
```

## Advisory

```text
id
title
vendor
description
published_at
updated_at
source_url
severity
related_cves
raw_content
```

## Analysis

```text
id
vulnerability_id
summary
business_impact
technical_impact
priority
recommended_actions
confidence
generated_at
model
```

## AlertSubscription

```text
id
email
severity_threshold
only_known_exploited
enabled
created_at
verified_at
```

Nunca armazenar senha de usuário em texto puro.

---

# 9. Pipeline de processamento

O pipeline deverá ser:

```text
COLETA
  ↓
VALIDAÇÃO
  ↓
NORMALIZAÇÃO
  ↓
DEDUPLICAÇÃO
  ↓
ENRIQUECIMENTO
  ↓
PRIORIZAÇÃO
  ↓
ANÁLISE
  ↓
ARMAZENAMENTO
  ↓
INTERFACE
  ↓
ALERTA
```

## Coleta

Cada fonte deve possuir um collector independente.

Exemplo:

```text
collectors/
├── cisa_kev.py
├── nvd.py
├── cve.py
├── microsoft.py
├── cisco.py
└── redhat.py
```

Todos devem implementar uma interface comum.

Exemplo conceitual:

```python
class Collector:
    def fetch(self):
        pass

    def normalize(self, data):
        pass
```

---

# 10. Deduplicação

A mesma vulnerabilidade pode aparecer em várias fontes.

O sistema deve utilizar:

1. CVE ID quando existir;
2. URL oficial;
3. hash de conteúdo quando necessário.

Exemplo:

```text
CVE-2026-12345
```

deve existir apenas uma vez no banco, mesmo que apareça em:

- NVD;
- CISA;
- Microsoft;
- notícia.

As fontes adicionais devem ser relacionadas à mesma vulnerabilidade.

---

# 11. Sistema de priorização

Não utilizar somente CVSS.

Criar um score interno de prioridade.

Exemplo:

```text
Prioridade =
CVSS
+ exploração ativa
+ disponibilidade de exploit
+ criticidade do produto
+ exposição
+ recência
```

A fórmula inicial deve ser simples e documentada.

Exemplo de categorias:

```text
CRÍTICA
ALTA
MÉDIA
BAIXA
INFORMATIVA
```

Uma vulnerabilidade presente na CISA KEV deve receber prioridade significativamente maior.

Não afirmar que uma vulnerabilidade é crítica somente porque o CVSS é alto.

---

# 12. Análise com IA

A IA deve funcionar como camada de interpretação.

Nunca utilizar a IA para inventar dados.

A IA deverá receber somente informações estruturadas e fontes verificáveis.

Prompt interno inicial:

```text
Você é um analista de segurança da informação.

Analise exclusivamente os dados fornecidos.

Não invente informações.

Se uma informação não estiver disponível, diga:
"Informação não disponível nas fontes consultadas."

Produza:

1. Resumo executivo
2. O que foi afetado
3. Qual o risco
4. Existe exploração ativa?
5. Impacto potencial para empresas
6. Ações recomendadas
7. Prioridade sugerida
8. Evidências utilizadas
9. Nível de confiança

Separe claramente:
- fatos;
- interpretação;
- recomendações.

Sempre preserve as referências originais.
```

A resposta deverá ser armazenada juntamente com:

- modelo utilizado;
- data;
- versão do prompt;
- fontes utilizadas.

---

# 13. Segurança da própria plataforma

A plataforma trata de segurança, portanto ela também deve ser segura.

Implementar:

- validação de entrada;
- rate limiting;
- headers de segurança;
- CORS configurado corretamente;
- proteção contra SQL injection;
- proteção contra XSS;
- secrets somente em variáveis de ambiente;
- logs sem dados sensíveis;
- sanitização de conteúdo externo;
- timeout para chamadas externas;
- tratamento de erros;
- dependências atualizadas;
- HTTPS em produção.

Não executar automaticamente código recebido das fontes.

Conteúdo externo deve ser tratado como não confiável.

---

# 14. Alertas por e-mail

Criar uma arquitetura de notificações.

Fluxo:

```text
Nova vulnerabilidade
        ↓
Verificação de prioridade
        ↓
Consulta às inscrições
        ↓
Gerar alerta
        ↓
Enviar e-mail
```

O MVP deve permitir cadastro de:

```text
email
nível mínimo de severidade
somente vulnerabilidades exploradas
```

Implementar confirmação de e-mail.

O sistema não deve enviar spam.

Adicionar:

- cooldown;
- deduplicação;
- registro de alertas enviados.

A camada de e-mail deve ser desacoplada.

Exemplo:

```python
class EmailProvider:
    def send(self, recipient, subject, body):
        pass
```

Isso permitirá trocar o provedor posteriormente.

---

# 15. Interface

A interface deve parecer um produto real de segurança, não um projeto acadêmico.

Criar:

## Dashboard

Exibir:

- vulnerabilidades novas;
- críticas;
- altas;
- exploradas ativamente;
- tendência dos últimos dias;
- principais fabricantes;
- principais produtos;
- últimos alertas.

## Vulnerabilidades

Tabela com:

```text
CVE
Severidade
Produto
Fabricante
CVSS
Exploração ativa
Publicação
Prioridade
```

Filtros:

- severidade;
- fabricante;
- produto;
- exploração;
- período.

## Página da vulnerabilidade

Exibir:

```text
CVE
Título
Resumo
Severidade
CVSS
Produtos afetados
Versões
Exploração ativa
Impacto
Mitigação
Referências
Linha do tempo
```

Separar visualmente:

**Dados oficiais**

de

**Análise da plataforma**

---

# 16. Página pública

O projeto deve permitir futuramente que qualquer pessoa consulte vulnerabilidades sem criar conta.

Apenas funcionalidades que realmente precisam de identificação devem exigir cadastro, como:

- alertas por e-mail;
- preferências;
- histórico pessoal.

Não exigir login para visualizar informações públicas.

---

# 17. Privacidade

Coletar o mínimo necessário.

Para alertas:

- e-mail;
- preferências;
- confirmação;
- data de cadastro.

Não vender dados.

Não utilizar dados pessoais para treinamento.

Adicionar uma política de privacidade simples.

Oferecer cancelamento de inscrição.

---

# 18. API

Criar endpoints simples.

Exemplo:

```text
GET /api/v1/vulnerabilities
GET /api/v1/vulnerabilities/{cve}
GET /api/v1/vulnerabilities/recent
GET /api/v1/vulnerabilities/critical
GET /api/v1/vulnerabilities/exploited
GET /api/v1/stats
POST /api/v1/subscriptions
POST /api/v1/subscriptions/verify
DELETE /api/v1/subscriptions/{token}
```

Documentar automaticamente com OpenAPI através do FastAPI.

---

# 19. Testes

Criar testes desde o começo.

Testar:

- collectors;
- normalização;
- deduplicação;
- classificação;
- API;
- banco;
- alertas;
- tratamento de erros.

Criar testes unitários para dados conhecidos.

Criar pelo menos um teste de integração do pipeline:

```text
Fonte simulada
→ collector
→ normalização
→ banco
→ API
```

---

# 20. Observabilidade

Criar logs estruturados.

Registrar:

- início da coleta;
- fonte;
- quantidade encontrada;
- quantidade nova;
- quantidade atualizada;
- erros;
- duração;
- alertas enviados.

Exemplo:

```text
[CISA] 35 itens encontrados
[CISA] 4 vulnerabilidades novas
[NVD] 128 itens processados
[ALERT] 3 notificações enviadas
```

Não registrar:

- senhas;
- tokens;
- chaves API;
- conteúdo privado de usuários.

---

# 21. Git e GitHub

Usar Git desde o primeiro dia.

Branches:

```text
main
develop
feature/*
fix/*
```

Commits claros.

Exemplos:

```text
feat: add CISA KEV collector
feat: add vulnerability normalization
fix: prevent duplicate CVEs
docs: add architecture documentation
test: add collector tests
```

Criar README profissional.

O README deve explicar:

- problema;
- solução;
- arquitetura;
- tecnologias;
- fontes;
- como executar;
- screenshots;
- roadmap;
- limitações;
- licença.

---

# 22. Licença

Usar uma licença open source permissiva, como:

**MIT License**

Verificar as licenças das dependências individualmente.

Não copiar conteúdo protegido de sites.

Armazenar somente os dados permitidos pelas APIs/licenças/fontes utilizadas.

Sempre manter links para as fontes originais.

---

# 23. Docker

Criar ambiente local reproduzível.

Serviços iniciais:

```text
frontend
backend
postgres
```

Não adicionar serviços adicionais sem necessidade.

O projeto deve iniciar com:

```bash
docker compose up
```

Documentar também uma execução sem Docker quando possível.

---

# 24. Variáveis de ambiente

Criar:

`.env.example`

Exemplo:

```env
DATABASE_URL=
NVD_API_KEY=
AI_PROVIDER=
AI_API_KEY=
EMAIL_PROVIDER=
EMAIL_API_KEY=
APP_BASE_URL=
```

Nunca colocar secrets no Git.

---

# 25. Roadmap

## Fase 1 — Fundação

- Git;
- estrutura;
- FastAPI;
- PostgreSQL;
- Docker;
- React;
- documentação.

## Fase 2 — Coleta

- CISA KEV;
- NVD;
- CVE;
- normalização;
- deduplicação.

## Fase 3 — Dashboard

- tabela;
- filtros;
- detalhes;
- estatísticas.

## Fase 4 — Priorização

- score;
- exploração;
- recência;
- classificação.

## Fase 5 — IA

- abstração do provedor;
- análise;
- resumo executivo;
- recomendações;
- controle de alucinação.

## Fase 6 — Alertas

- cadastro;
- confirmação;
- filtros;
- e-mail;
- unsubscribe.

## Fase 7 — Segurança

- threat model;
- testes;
- rate limiting;
- headers;
- validação;
- logs.

## Fase 8 — Publicação

- GitHub;
- documentação;
- deployment gratuito quando viável;
- domínio opcional;
- demonstração pública.

## Fase 9 — Evolução

Adicionar somente depois:

- mais fontes;
- ATT&CK;
- indicadores de comprometimento;
- tendências;
- organizações;
- watchlists;
- notificações;
- integrações;
- API pública.

---

# 26. Regras para o agente de desenvolvimento

Você deve agir como um desenvolvedor sênior orientando um estudante.

Não pule etapas.

Para cada etapa:

1. explique o objetivo;
2. explique por que a tecnologia foi escolhida;
3. mostre a estrutura dos arquivos;
4. forneça o código completo necessário;
5. explique onde colocar cada arquivo;
6. explique como executar;
7. explique como testar;
8. verifique possíveis erros;
9. só depois avance.

Não gerar o projeto inteiro de uma vez.

Construir incrementalmente.

Sempre perguntar ou verificar o resultado da etapa anterior antes de assumir que funcionou.

Quando houver uma decisão arquitetural importante:

- explique alternativas;
- escolha a opção mais simples;
- justifique.

Evitar overengineering.

O objetivo é que um estudante consiga entender o projeto inteiro.

---

# 27. Regra de fontes atuais

Como o sistema trabalha com segurança, informações podem mudar.

Sempre que precisar confirmar:

- API;
- endpoint;
- formato de feed;
- documentação;
- política de uso;
- licença;
- disponibilidade gratuita;

consultar a documentação oficial atual antes de implementar.

Não inventar endpoints.

Não inventar limites de API.

Não assumir que um serviço é gratuito sem verificar.

---

# 28. Regra de qualidade

Antes de considerar qualquer funcionalidade concluída, verificar:

```text
[ ] Funciona
[ ] Está documentada
[ ] Possui tratamento de erro
[ ] Possui teste
[ ] Não expõe secrets
[ ] Não inventa dados
[ ] Mantém a fonte original
[ ] É compreensível para um estudante
[ ] Não adiciona dependências desnecessárias
[ ] Não exige serviço pago
```

---

# 29. Primeira tarefa

NÃO implemente o projeto inteiro agora.

Comece somente pela **Fase 1 — Fundação**.

Primeiro:

1. apresentar a arquitetura inicial;
2. explicar cada tecnologia;
3. verificar as versões atuais recomendadas através da documentação oficial;
4. criar a estrutura inicial de diretórios;
5. criar o README inicial;
6. criar o backend FastAPI mínimo;
7. criar o frontend React + TypeScript + Vite mínimo;
8. criar o PostgreSQL;
9. criar o Docker Compose;
10. criar `.env.example`;
11. criar `.gitignore`;
12. criar o primeiro endpoint `/health`;
13. criar uma página inicial simples;
14. executar testes básicos;
15. documentar como executar localmente.

Não implementar ainda:

- IA;
- coleta de NVD;
- CISA;
- e-mail;
- autenticação;
- dashboard complexo.

Esses componentes virão depois.

---

# 30. Resultado esperado da primeira etapa

Ao terminar a Fase 1, o estudante deve conseguir executar:

```bash
docker compose up
```

e acessar:

```text
Frontend
http://localhost:5173

Backend
http://localhost:8000

Health check
http://localhost:8000/health

API Docs
http://localhost:8000/docs
```

O sistema deve responder corretamente.

---

# 31. Próxima etapa

Depois que a fundação estiver funcionando, parar.

Não avançar automaticamente.

Aguardar confirmação do estudante.

Quando confirmado, iniciar a Fase 2 começando pelo **CISA KEV**, pois é uma fonte extremamente importante para priorização de vulnerabilidades exploradas.

---

# 32. Filosofia do projeto

O projeto não deve ser apenas um agregador de notícias.

A proposta é criar uma ferramenta de:

**Coleta → Contextualização → Priorização → Mitigação → Comunicação**

O diferencial deve ser transformar informações técnicas complexas em decisões compreensíveis.

Exemplo:

Em vez de mostrar apenas:

> CVE-XXXX-XXXXX — CVSS 9.8

a plataforma deverá permitir que uma empresa entenda:

> **Prioridade alta:** esta vulnerabilidade afeta determinado produto, possui evidência de exploração ativa e pode permitir determinado impacto. Verifique se o produto está presente no ambiente, aplique a correção indicada pelo fabricante e, caso a atualização não seja possível, aplique as medidas de mitigação recomendadas.

Sempre mantendo a fonte original e deixando claro o que é fato e o que é análise.

---

# 33. Objetivo final

Ao final do projeto, o resultado deverá ser uma plataforma:

- gratuita;
- open source;
- pública;
- segura;
- documentada;
- tecnicamente relevante;
- útil para profissionais;
- acessível para empresas;
- baseada em fontes confiáveis;
- capaz de acompanhar vulnerabilidades recentes;
- capaz de priorizar riscos;
- capaz de explicar riscos em linguagem simples;
- capaz de recomendar ações de mitigação;
- capaz de enviar alertas por e-mail;
- preparada para crescer.

O projeto deve ser apresentado no LinkedIn como um projeto pessoal de **Cyber Threat Intelligence / Security Automation**, demonstrando conhecimento prático de:

- Python;
- APIs;
- FastAPI;
- React;
- TypeScript;
- PostgreSQL;
- Docker;
- Git;
- segurança de aplicações;
- coleta e normalização de dados;
- vulnerabilidades;
- CVE;
- CVSS;
- CISA KEV;
- automação;
- análise assistida por IA;
- observabilidade;
- engenharia de software.

**Comece agora pela Fase 1. Não pule etapas.**
