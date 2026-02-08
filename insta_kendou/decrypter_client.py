import base64
import zlib
import re

print("=== DÉCRYPTAGE DE client.py ===")

# Lire le fichier client.py
with open('client.py', 'r') as f:
    content = f.read()

print("1. Fichier client.py lu")

# Vérifier si c'est crypté
if 'base64.b64decode' in content:
    print("2. Fichier est crypté")
    
    # Extraire le payload base64
    match = re.search(r"base64\.b64decode\(['\"]([^'\"]+)['\"]\)", content)
    if match:
        payload = match.group(1)
        print(f"3. Payload trouvé ({len(payload)} caractères)")
        
        try:
            # Décoder base64
            decoded = base64.b64decode(payload)
            print("4. Base64 décodé")
            
            # Décompresser zlib
            decompressed = zlib.decompress(decoded)
            print("5. Zlib décompressé")
            
            # Sauvegarder le code décrypté
            with open('client_decrypte.py', 'w', encoding='utf-8') as f:
                f.write(decompressed.decode('utf-8'))
            print("6. Code sauvegardé dans client_decrypte.py")
            
            # Afficher un extrait
            print("\n=== EXTRAIT DU CODE DÉCRYPTÉ ===")
            lines = decompressed.decode('utf-8').split('\n')
            for i, line in enumerate(lines[:20]):  # Premières 20 lignes
                print(f"{i+1}: {line}")
                
            # Chercher la vérification
            if "Vérification du statut utilisateur" in decompressed.decode('utf-8'):
                print("\n🚨 MESSAGE TROUVÉ DANS client.py !")
            else:
                print("\n🔍 Message non trouvé dans client.py")
                
        except Exception as e:
            print(f"❌ Erreur: {e}")
    else:
        print("❌ Impossible d'extraire le payload")
else:
    print("✅ client.py est déjà en clair")
    print(content[:500])  # Afficher les premiers 500 caractères
