# Stage unique basé sur l'image officielle Python
FROM python:3.11-slim

# Variables pour un comportement optimal
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Installer whois et utilitaires DNS
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      whois \
      dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code et exposer le port
COPY . .
EXPOSE 5000

# Démarrer Flask en production
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"] 