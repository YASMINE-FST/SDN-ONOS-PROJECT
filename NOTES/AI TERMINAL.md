✅ Toutes les dépendances installées avec succès !





FastAPI (IA)  ✅  port 8000  →  prédit les attaques

ONOS          ✅  port 8181  →  contrôle le réseau





\# Terminal 1 — vérifie que FastAPI tourne encore

curl http://localhost:8000/health



\# Terminal 2 — vérifie qu'ONOS tourne

curl -s -u onos:rocks http://localhost:8181/onos/v1/applications \\

&#x20; | python3 -m json.tool | grep "name" | head -5



yasmine@yasmine-virtual-machine:\~/Downloads/ONOS-IDS-main/ids\_service$ uvicorn main:app --host 0.0.0.0 --port 8000

INFO:     Started server process \[17895]





**ONOS :**

\# Active OpenFlow

curl -X POST -u onos:rocks \\

&#x20; "http://localhost:8181/onos/v1/applications/org.onosproject.openflow/active"



\# Active Reactive Forwarding

curl -X POST -u onos:rocks \\

&#x20; "http://localhost:8181/onos/v1/applications/org.onosproject.fwd/active"





**AI : REST API :**

Maintenant lance le serveur FastAPI :

cd \~/Downloads/ONOS-IDS-main/ids\_service

**uvicorn main:app --host 0.0.0.0 --port 8000**









Dans un 2ème terminal (Ctrl+Shift+` dans VS Code), teste que l'IA répond :  **http://localhost:8000/health**

**Le serveur FastAPI est en marche, les 14 classes d'attaques sont chargées, les 82 features sont prêtes. C'est exactement ce qu'on attendait !**



**Attaque :**

ARP Spoofing

STP Spoofing

MAC Flooding

DHCP Spoofing

IP Spoofing

DDoS

Routing Protocol Attacks

SYN Flooding

Port Scanning

SQL Injection

SSL/TLS Stripping

Session Hijacking





\# Test SYN FLOOD 🔴

curl -X POST http://localhost:8000/predict \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{"flow\_id":"test-syn-001","features":\[150,6,5000,0,250000,0,50,5,64,50,50,5,64,50,150,5,200,0,150,5,200,0,0,0,5000,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'



\# Test BENIGN 🟢

curl -X POST http://localhost:8000/predict \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{"flow\_id":"test-benign-001","features":\[30000,6,10,8,1500,1200,150,20,1500,100,150,20,1500,100,30000,5,35000,0,30000,5,35000,0,0,0,100,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'





\# Va à la racine du projet

cd \~/Downloads/ONOS-IDS-main



\# Réentraîne les modèles (ça prend 1-2 minutes)

**python3 train\_and\_visualize.py**

```



Tu devrais voir quelque chose comme :

```

Training Random Forest...

Training XGBoost...

F1 Score: 1.0000

Models saved to outputs/







\# Dans le terminal où FastAPI tourne : Ctrl+C pour arrêter



cd ids\_service

**uvicorn main:app --host 0.0.0.0 --port 8000**







Compile le plugin

crée plugin .oar fichier de applications de onos :

&#x20;**cd \~/Downloads/ONOS-IDS-main/ids-onos-app**

**mvn clean package -DskipTests**

**```**



Dans notre projet concrètement

Sans **plugin** → ONOS gère le réseau normalement, aucune détection d'attaques.

Avec notre plugin IDS → ONOS fait tout ça EN PLUS, automatiquement, sans qu'on ait besoin de modifier le code d'ONOS lui-même.

Le fichier .oar c'est le plugin emballé et prêt à installer — comme un .apk sur Android ou un .exe sur Windows. Ta binôme a compilé le code Java du dossier ids-onos-app/ pour produire ce fichier .oar, puis elle l'a uploadé dans ONOS via l'interface web.

Le résultat = la ligne verte ✅ "IDS AI App" qu'on voit dans son image !



Déploie le plugin IDS dans ONOS :

curl -X POST -u onos:rocks \\

&#x20; -H "Content-Type: application/octet-stream" \\

&#x20; --data-binary @\~/Downloads/ONOS-IDS-main/ids-onos-app-1.0.0.oar \\

&#x20; "http://localhost:8181/onos/v1/applications?activate=true"

```



\\\*\\\*Étape 4 — Vérifie dans l'interface web ONOS :\\\*\\\*



Ouvre Firefox sur Ubuntu et va sur :

```

http://localhost:8181/onos/ui

