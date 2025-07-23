# Utiliser Node.js avec Debian (permet d'installer Python)
FROM node:18

# Installer Python
RUN apt-get update && \
    apt-get install -y python3 python3-pip

# Créer le dossier de l'app
WORKDIR /app

# Copier les fichiers du projet
COPY . .

# Installer les dépendances Node.js
RUN npm install

# Lancer l'app
CMD ["node", "index.js"]
