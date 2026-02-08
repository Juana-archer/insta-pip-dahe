import os
import base64
import zlib
import re

print("🔓 DÉCRYPTAGE EN MASSE DE TOUS LES FICHIERS")
print("=" * 50)

def decrypter_fichier(chemin_entree, chemin_sortie):
    """Décrypter un fichier et le sauvegarder"""
    try:
        with open(chemin_entree, 'r', encoding='utf-8') as f:
            contenu = f.read()
        
        if 'base64.b64decode' in contenu:
            match = re.search(r"base64\.b64decode\(['\"]([^'\"]+)['\"]\)", contenu)
            if match:
                payload = match.group(1)
                decode = base64.b64decode(payload)
                decompresse = zlib.decompress(decode)
                
                with open(chemin_sortie, 'w', encoding='utf-8') as f:
                    f.write(decompresse.decode('utf-8'))
                return True
        else:
            # Fichier déjà clair, juste copier
            with open(chemin_sortie, 'w', encoding='utf-8') as f:
                f.write(contenu)
            return True
            
    except Exception as e:
        print(f"❌ Erreur avec {chemin_entree}: {e}")
        return False

# Créer un dossier pour les fichiers décryptés
dossier_decrypte = "fichiers_decryptes"
if not os.path.exists(dossier_decrypte):
    os.makedirs(dossier_decrypte)

# Décrypter tous les fichiers .py
fichiers_decryptes = 0
for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith('.py') and 'decrypte' not in file:
            chemin_entree = os.path.join(root, file)
            chemin_sortie = os.path.join(dossier_decrypte, f"{file}_decrypte.py")
            
            if decrypter_fichier(chemin_entree, chemin_sortie):
                print(f"✅ {chemin_entree} -> {chemin_sortie}")
                fichiers_decryptes += 1

print(f"\n🎉 {fichiers_decryptes} fichiers décryptés dans le dossier '{dossier_decrypte}'")

# Maintenant chercher la vérification dans tous les fichiers décryptés
print("\n🔍 RECHERCHE DE LA VÉRIFICATION BLOQUANTE...")
print("=" * 50)

messages_recherches = [
    "Vérification du statut utilisateur",
    "Accès Refusé",
    "propriétaire de l'ID",
    "appareil ne correspond pas"
]

trouve = False
for file in os.listdir(dossier_decrypte):
    if file.endswith('.py'):
        chemin = os.path.join(dossier_decrypte, file)
        
        with open(chemin, 'r', encoding='utf-8') as f:
            contenu = f.read()
        
        for message in messages_recherches:
            if message in contenu:
                print(f"🚨 TROUVÉ dans {file}:")
                print(f"   Message: '{message}'")
                
                # Afficher le contexte
                lignes = contenu.split('\\n')
                for i, ligne in enumerate(lignes):
                    if message in ligne:
                        print(f"\\n📄 Contexte (lignes {i-1} à {i+3}):")
                        for j in range(max(0, i-1), min(len(lignes), i+4)):
                            prefix = ">>> " if j == i else "    "
                            print(f"{prefix}{lignes[j]}")
                        break
                trouve = True
                break

if not trouve:
    print("❌ Aucune vérification trouvée dans les fichiers décryptés")
    print("💡 Le blocage vient peut-être d'une vérification dynamique ou serveur")
