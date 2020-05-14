# Tâches 

## Général
### Fonctions

- generateBMP ---> K Check

- image_to_imageData(imagePath) ---> K Check
    - input : image path
    - output : imageData     
    
- imageData_to_tabPixels(image) ---> K Check
    - input : imageData
    - output : list of tuple of decimals

- tabPixels_to_tabBinaries(tabPixels) ---> K Check
    - input : list of tuple of decimals
    - output : list of tuple of binaries

- string_to_binary(data) --> L Check
    - input : string
    - output : binary in array

- file_to_fileData(filePath) ---> L Check
    - input : file path
    - output : fileData

- encrypt(plaintext, key) ---> K + L Check
    - input : plaintext + key
    - output : string cypher
    
- decrypt(ciphertext, key) ---> K + L Check
    input : string + string
    output : string plaintext

- binary_to_string(binaryValue)
    input : string
    output : string

## Chiffrement
### Fonctions

- binary_to_pixels(binaryTuple) ---> L check
    - input : ("final")list of tuple of binaries
    - output : ("final")list of tuple of decimals

- importHeader ---> K Check
    - input : binary input user
    - output : binary_message (header + binary input user)

- insertData ---> K + L Check
    - input : binary_message + list of tuple of binaries + seed (if seed = "" then process by order)
    - output : ("final")list of tuple of binaries

- pixels_to_image() (save image .BMP) : ---> L Check
    - input : list of tuple of decimals + infilename (image to modify) + outfilename (image to save)
    
## Déchiffrement
### Fonctions

- retrieveData : ---> K + L
    - input : list of tuple of binaries + seed
    - output : data

## ROC
### Fonctions

- list_tvp_tfp(title):
    tfp, tvp = 0
    for seuilSPA in range (1 à -0.1):
        for picture in folder :
            - if (title > 50 AND detect == NO_LSB) OR (title <= 50  AND detect == LSB):
                TFP += 1
            - else:
                TVP +=1
        TFP = TFP / 100
        TVP = TVP / 100
        listTVP.append(TVP) (pour chaque valeur de seuil SPA)
        listTFP.append(TFP) (pour chaque valeur de seuil SPA)

    output : listTFP, listTVP

array = list(set(array))
    
    random.seed("maseed")
    i = random.randint(1000,39000)
    print ("i: ", i)

    21324
    3412
    7654
    7652
    3412



