FROM node:20-slim

WORKDIR /app

# Copia os arquivos de dependência
COPY package.json package-lock.json* ./

# Instala todas as dependências do projeto
RUN npm install

# Copia o restante dos arquivos do frontend
COPY . .

# Expõe a porta que o Vite irá utilizar
EXPOSE 5173

# Comando para iniciar o servidor do Vite em modo host (permitindo acesso fora do container)
CMD ["npm", "run", "dev", "--", "--host"]
