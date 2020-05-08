import numpy
from PIL import Image
import encodings
import codecs
import random
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import math


# Définition des fonctions générales

# Fonction présente mais non utilisée dans le programme : permet de générer
# des images BMP aléatoire de taille 200x200
def generateBMP():
    print("[!] Génération de 10 images aléatoires (taille = 200x200) dans BMPLibrary/ ...")
    imgIndex = 1
    compteur = 1
    while compteur <= 10:
        imarray = numpy.random.rand(200,200,3) * 255
        im = Image.fromarray(imarray.astype('uint8')).convert('RGB')
        filename = "./BMPLibrary/%i.bmp" % (imgIndex)
        im.save(filename)         
        imgIndex += 1
        compteur += 1      
    print("[!] Les images ont été correctement créées ! ")
    
# Fonction permettant de traiter une image passer en entrée et d'en extraire des données
def image_to_imageData(imagePath):
    print("[!] Ouverture de l'image en cours...")
    image = Image.open(imagePath)
    print("[!] L'image a été ouverte correctement ! ")
    return image

# Fonction permettant de récupérer la partie des données de pixel de l'image et de les
# insérer dans un tableau les contenant
def imageData_to_tabPixels(image):
    print("[!] Récupération des données de l'image BMP sélectionnée")
    tabPixels = list(image.getdata())
    print("[!] Récupération des données de l'image BMP : Succés !")
    return tabPixels

# Fonction permettant de convertir un tableau de pixels sous la forme de valeurs décimales
# en un tableau de pixel sous la forme de valeurs binaires
def tabPixels_to_tabBinaries(tabPixels):
    print("[!] Création de la nouvelle table binaire...")
    i = 0
    tabBinaries = []
    while i < len(tabPixels):
        tuple = ()
        r = '{0:08b}'.format(tabPixels[i][0])
        g = '{0:08b}'.format(tabPixels[i][1])
        b = '{0:08b}'.format(tabPixels[i][2])
        tuple = (r,g,b)
        tabBinaries.append(tuple)
        i += 1
    print("[!] Création de la nouvelle table binaire : Succés !")
    return tabBinaries

# Fonction permettant de convertir un string en binaire : utilisée par exemple dans
# la conversion d'une entrée utilisateur chiffrée en données binaires à insérer dans les LSB
# de chaque pixel
def string_to_binary(data):
    userInput_bytes = bytes(data, "ascii")
    binInput = (''.join(["{0:08b}".format(x) for x in userInput_bytes]))
    print("[!] Conversion of ciphertext '%s' to binary : %s " % (data,binInput))
    tabBin = []
    for x in  binInput:
        tabBin.append(x)
    return tabBin

# Fonction permettant de convertir un binaire en string : utilisée par exemple dans
# la récupération de données binaire d'une image et les convertir en texte exploitable
# pour un attaquant
def binary_to_string(binaryString):
    binary_int = int(binaryString, 2)
    byte_number = binary_int.bit_length() + 7 // 8
    binary_array = binary_int.to_bytes(byte_number, "big")
    ascii_text = binary_array.decode()
    return ascii_text
    
# Fonction permettant, à partir d'un fichier, d'en extraire les données
def file_to_fileData(filePath):
    with codecs.open(filePath,"r",encoding="utf-8") as f:
        data = f.read()
    f.close()
    return data

# Fonction permettant de convertir un tableau de tuple en tableau listé génériquement : 
# utilisée lors de la décomposition des pixels d'une image (RGB) et l'insertion LSB
def tuple_to_list(tabBinaries):
    listBinaries = []
    for i in tabBinaries:
        list(i)
        for j in i:
            listBinaries.append(j)
    return listBinaries

# Fonction permettant de convertir un tableau listé génériquement en un tableau de tuple :
# utilisée lors de la reconstitution des pixels d'une image post insertion LSB
def list_to_tuple(listBinaries):
    tabBinaries = []
    for i in range (0,len(listBinaries)):
        if i % 3 == 0:
            r = listBinaries[i]
            v = listBinaries[i+1]
            b = listBinaries[i+2]
            tabBinaries.append((r,v,b))
    return tabBinaries
   
# Fonction permettant le chiffrement d'une entrée avec un mot de passe passé en paramètre
def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    cipher = str(base64.b64encode(iv + cipher.encrypt(raw))).split("'")
    print ("[!] Chiffrement du message avec l'algorithme AES 256 + hash en base64 : ", cipher[1])
    return cipher[1]

# Fonction permettant le déchiffrement d'une entrée avec un mot de passe passé en paramètre  
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    plain = str(unpad(cipher.decrypt(enc[16:]))).split("'")
    print ("[!] Message déchiffré : ", plain[1])
    return plain[1]


# Définition des fonctions de chiffrement

# Fonction permettant l'insertion d'un header : utilisée lors de l'insertion d'une chaine
# de caractère dans l'image. Le header est utilisé, par la suite, lors de la récupération de
# la chaîne lors de l'extraction des données d'une image
def importHeader(binInputUser):
    binaryMessage = []
    header = len(binInputUser)
    print ("Header = ", header)
    binHeader = list('{:016b}'.format(header))
    for i in binHeader:
        binaryMessage.append(i)
    for j in binInputUser:
        binaryMessage.append(j)
    print("[!] Insertion du header dans le message binaire : Succés ")
    return binaryMessage

# Fonction permettant de convertir un tableau de tuple binaire en un tableau de tuble
# décimal.
def binary_to_pixels(binaryTuple):
    pixels = []
    for i in range (0,len(binaryTuple)):
        data1 = int(binaryTuple[i][0],2)
        data2 = int(binaryTuple[i][1],2)
        data3 = int(binaryTuple[i][2],2)
        pixels.append((data1,data2,data3))
    return pixels

# Fonction permettant de pousser les données de pixels contenus dans un tableau de tuple
# dans une image: utilisée à la fin d'une insertion lorsque l'on souhaite reconstituer
# l'image
def pixels_to_image(pixels,infilename,outfilename):
    print ("[!] Création de la nouvelle image BMP avec les nouvelles données...")
    image = Image.open(infilename)
    image.putdata(pixels)
    image.save(outfilename)
    print ("[!] Création de la nouvelle image BMP avec les nouvelles données : Succés !")


# Fonction permettant l'insertion de données au sein d'une image.
# Cette fonction détaille le processus complet d'insertion de données avec une gestion
# fine d'erreur : si le message est trop long par rapport au support, alors une erreur
# est relevée (taux stéganographique trop haut)
def insertData(binaryMessage, tabBinaries, seedUser):
    print ("[!] Processus d'insertion des données en cours...")
    # Génération de la graine
    random.seed(seedUser)
    # Initialisation du tableau de départ qui permet une première génération de nombres
    # aléatoire
    init_table = []
    # On remplit le tableau sans tenir compte des redondances
    for i in range (0, 3 * len(binaryMessage)):
        init_table.append(random.randint(0,9999999) % (3 * len(tabBinaries)))
    # Initialisation d'un second tableau permettant de supprimer la redondance due à
    # la génération aléatoire précédente
    random_table = []
    for i in init_table:
        if i not in random_table:
            random_table.append(i)
    print ("[!] Vérification en cours...")
    # vérification de la possibilité d'intégration du message (vérification du taux stéga)
    if len(random_table) < len(binaryMessage):
        print("[/!\] Erreur : le message est trop long pour être inséré correctement dans l'image")
        return 0
    elif len(binaryMessage) >= (3* len(tabBinaries)):
        print("[/!\] Erreur : le message est trop long pour être inséré correctement dans l'image")
    print("[!] Longueur du message acceptable par rapport à la taille de l'image : début de l'insertion...")
    # Fin vérification #

    # On insère les données de façon random en parcourant d'un côté le tableau binaire de l'image
    # et le tableau de nombres aléatoires pour déterminer la position des LSB à modifier
    listBinaries = tuple_to_list(tabBinaries)
    for i in range (0,len(binaryMessage)):
        listBinaries[random_table[i]] = listBinaries[random_table[i]][:-1] + binaryMessage[i]
    finalTab = list_to_tuple(listBinaries)
    print ("[!] Les données ont été correctement insérées !")
    return finalTab

    
# Définition des fonctions de déchiffrement
def retrieveData(binaries_tuple, seedUser):
    print ("[!] Processus de récupération des données en cours...")
    #Génération de la seed suivant l'entrée utilisateur
    random.seed(seedUser)
    init_table = []
    for i in range (0,3*16):
        init_table.append(random.randint(0,9999999) % (3 * len(binaries_tuple)))
    random_table = []
    for i in init_table:
        if i not in random_table:
            random_table.append(i)
    ## On cherche le header
    listBinaries = tuple_to_list(binaries_tuple)
    header = ""
    for i in range (0,16):
        header = header + listBinaries[random_table[i]][-1]
    header = int(header, 2)

    ## On récupère le contenu du message caché
    for i in range (3*16,3*header):
        init_table.append(random.randint(0,9999999) % (3 * len(binaries_tuple)))
    print(init_table)
    for i in init_table:
        if i not in random_table:
            random_table.append(i)
    bincipherText = ""
    for i in range(16,16+header):
        bincipherText = bincipherText + listBinaries[random_table[i]][-1]
    cipherText = binary_to_string(bincipherText)
    print ("[!] Processus de récupération des données en cours : Succés !")
    print ("[!] Texte chiffré : ", cipherText)
    return cipherText

# Définition des fonctions de détections

def detection(tabPixels, width, height):
    #On initialise les variables globales de la fonction (j correspondant au canal de couleur)
    #On commence par le rouge
    #On définit un tableau qui contiendra les taux de change calculé par l'équation quadratique
    #pour chaque canal de couleur
    j = 0
    tab = []
    #Pour chaque canal de couleur RGB
    for j in range (0,3):
        X = 0
        Y = 0
        Z = 0
        i = 0
        #On incrémente X, Y, Z en fonction des probabilités
        for i in range (0,len(tabPixels)-1):
            if (tabPixels[i+1][j%3] % 2 == 0 and tabPixels[i][j%3] < tabPixels[i+1][j%3]) or (tabPixels[i+1][j%3] % 2 == 1 and tabPixels[i][j%3] > tabPixels[i+1][j%3]):
                X += 1
            elif (tabPixels[i+1][j%3] % 2 == 0 and tabPixels[i][j%3] > tabPixels[i+1][j%3]) or (tabPixels[i+1][j%3] % 2 == 1 and tabPixels[i][j%3] < tabPixels[i+1][j%3]):
                Y += 1
            elif (tabPixels[i][j%3] == tabPixels[i+1][j%3]):
                Z += 1
        #Erreur en cas de fail SPA
        if Z == 0:
            print("SPA failed because Z = 0")
            return 0

        #Définition des variables de l'équation quadratique
        a = 2 * Z
        b = 2 * (2 * X - width * (height -1))
        c = Y - X
        #Polynome du second degré
        D = math.pow(b,2) - (4 * a * c)
        if (D < 0):
            #Cela voudrait dire qu'on rentre dans le domaine des imaginaires, pas applicable
            # à la stéga, on retourne une erreur.
            return -1.0
        #Calcul des solutions de l'équation
        p1 = (-b + math.sqrt(D)) / (2 * a)
        p2 = (-b - math.sqrt(D)) / (2 * a)
        #On garde uniquement la valeur minimale des deux taux de changes calculé (les deux solutions
        #de l'équation)
        tab.append(min(p1,p2))
    print ("Tableau des taux de changes minimaux pour chaque canal (RGB) : ", tab)
    # Le tableau contient l'intégralité des taux de change pour chaque canal RGB, pour ne garder
    # qu'un seul taux de change qui sera utilisé pour être comparé au seuil, on calcule la moyenne
    # des sommes des taux de changes pour chaque canal :
    sum = 0
    for i in range(0, len(tab)):
        sum += tab[i]
    changerate = sum / len(tab)
    return changerate
# Fonction principale
if __name__ == '__main__':
    print("[Hello] TP Steganographie - Kevin MOREAU & Laurent GRAFF - ENSIBS Vannes - Specialite Cyberdefense")
    ans =''
    BLOCK_SIZE = 16
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    unpad = lambda s: s[:-ord(s[len(s) - 1:])] 
    while ans !='0':
        print ("""
        1. Fonction d'insertion aléatoire d'un message (Chiffrement AES & Clé Stéganographique)
        2. Fonction de déchiffrement d'un message (Déchiffrement AES & Clé Stéganographique)
        3. Fonction de detection (Determine si l'image donnée contient un contenu dissimulé)
        0. Quitter
        """
        )
        ans=input("Que voulez vous faire ? (saisir le chiffre) : ")
        
        if ans == "1":
            print("[!] Fonction d'insertion aléatoire (Chiffrement AES & Clé Stéganographique) : ")
            imagePath = input("[i] Entrer le nom de l'image à utiliser comme couverture (cover-image) : ")
            encryptedImage = input("[i] Donner un nom à image de sortie (stego-image) ")
            #Ouverture de l'image
            imageData = image_to_imageData(imagePath)
            #Récupération des données de l'image
            tabPixels = imageData_to_tabPixels(imageData)
            #Conversion des données des pixels en données binaires
            tabBinaries = tabPixels_to_tabBinaries(tabPixels)
            #Récupération du texte à cacher + seed
            inputUser = input("[i] Taper le message à cacher dans l'image : ")
            keyUser = input("[i] Taper la clé de chiffrement à utiliser : ")
            seedUser = input("[i] Taper la clé steganographique à utiliser : ")
            cipherInputUser = encrypt(inputUser, keyUser)
            plainTextUser = decrypt(cipherInputUser, keyUser)
            #Conversion de la chaîne de caractères en entrée en données binaires
            binInputUser = string_to_binary(cipherInputUser)
            #Ajout de l'header au message d'origine
            binaryMessage = importHeader(binInputUser)
            newTabBinaries = insertData(binaryMessage, tabBinaries, seedUser)
            newTabPixels = binary_to_pixels(newTabBinaries)
            finalDataImage = pixels_to_image(newTabPixels, imagePath, encryptedImage)
        elif ans == "2":
            print("[!] Fonction de déchiffrement : ")
            #RetrieveData
            encryptedImage = input("[i] Taper le nom de l'image à traiter : ")
            keyUser = input("[i] Saisir la clé de chiffrement utilisée lors de l'insertion : ")
            seedUser = input("[i] Saisir la clé stéganographique utilisée lors de l'insertion : ")
            retrievedImage = image_to_imageData(encryptedImage)
            retrievedTabPixels = imageData_to_tabPixels(retrievedImage)
            retrievedTabBinaries = tabPixels_to_tabBinaries(retrievedTabPixels)
            retrievedCipherText = retrieveData(retrievedTabBinaries, seedUser)
            retrievedPlainText = decrypt(retrievedCipherText, keyUser)
        elif ans == "3":
            print("[!] Fonction de détection : (image contient un contenu dissimulé ou non) ")
            #DetectData
            encryptedImage = input("[i] Taper le nom de l'image suspecte : ")
            image = Image.open(encryptedImage)
            width, height = image.size
            dataImage = image_to_imageData(encryptedImage)
            tabPixelImage = imageData_to_tabPixels(dataImage)
            changerate = detection(tabPixelImage, width, height)
            print("Taux de change final estimé de l'image suspectée : ", changerate)

            #Détermination du seuil de détection, si le taux de change est inférieur, alors l'image
            #suspectée est considérée comme propre et vue sans insertion
            threshold = 0.015
            print("Seuil de détection choisi :", threshold)

            if changerate <= threshold:
                print("Aucune donnée n'a été détectée dans l'image")
            elif changerate >= threshold:
                print("Détection réussie, des données ont été insérées dans l'image")

            
        elif ans == "0":
            print("[!] Goodbye my friend... ")

    
