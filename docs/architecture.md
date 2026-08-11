# Arquitetura do CyberPulse

O CyberPulse segue uma arquitetura baseada em serviços para facilitar o desenvolvimento, a manutenção e futuras expansões.

## Componentes Principais

### 1. Frontend (Interface do Usuário)
* **Tecnologias:** React, TypeScript, Vite e Tailwind CSS.
* **Objetivo:** Fornecer uma interface visual simples e amigável para que o usuário possa consultar vulnerabilidades, aplicar filtros (ex: severidade, fornecedor) e ver relatórios e análises.

### 2. Backend (API e Processamento)
* **Tecnologias:** Python, FastAPI.
* **Objetivo:** Servir os dados ao Frontend através de uma API RESTful. No futuro, ele também englobará módulos para:
  * **Collectors:** Módulos autônomos que buscam dados nas fontes (CISA, NVD, etc.).
  * **Engine de Análise:** Classificação, deduplicação e pontuação de vulnerabilidades.
  * **Alertas:** Gerenciamento de inscrições de e-mail e disparos.

### 3. Banco de Dados
* **Tecnologias:** PostgreSQL.
* **Objetivo:** Armazenar os dados de vulnerabilidades, análises geradas, fontes configuradas e usuários inscritos para alertas.

## Diagrama da Arquitetura

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
