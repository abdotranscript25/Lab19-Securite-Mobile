# Lab 19 - Snake : Résolution détaillée (PwnSec CTF 2024 Mobile Hard)

## 📱 Description

Ce laboratoire est un challenge **Hard** du PwnSec CTF 2024. L'application Android `Snake.apk` implémente plusieurs mécanismes de protection anti-reverse :

- **Détection de root** (Build.TAGS, fichiers `su`, `Runtime.exec`, etc.)
- **Détection d'émulateur** (propriétés système)
- **Détection de Frida** (dans la librairie native)

L'objectif est d'exploiter une vulnérabilité de désérialisation unsafe dans une vieille version de **SnakeYAML** (CVE-2022-1471) pour instancier une classe cachée `BigBoss` qui génère le flag.

**Niveau :** 🔴 Hard

---

## 🎯 Objectifs pédagogiques

| Objectif | Statut |
|----------|--------|
| Analyse statique avec Jadx | ✅ |
| Patching Smali avec apktool | ✅ |
| Désactivation des détections de root | ✅ |
| Modification du chemin du fichier YAML | ✅ |
| Création d'un payload YAML malveillant | ✅ |
| Exploitation via Intent SNAKE | ✅ |
| Récupération du flag dans logcat | ✅ |

---

## 🛠️ Technologies et outils utilisés

| Outil | Rôle |
|-------|------|
| **Jadx-GUI** | Décompilation Java / analyse du code |
| **apktool** | Décompilation/recompilation Smali |
| **uber-apk-signer** | Signature de l'APK patché |
| **ADB** | Installation et lancement sur émulateur |
| **SnakeYAML** | Bibliothèque vulnérable (CVE-2022-1471) |

---

## 🔍 Analyse statique avec Jadx

### Flux de l'application

```java
// MainActivity.onCreate() et MainActivity.C()
Intent intent = getIntent();
if (intent.hasExtra("SNAKE") && intent.getStringExtra("SNAKE").equals("BigBoss")) {
    File file = new File(Environment.getExternalStorageDirectory(), "snake/Skull_Face.yml");
    Yaml yaml = new Yaml();
    Object obj = yaml.load(new FileInputStream(file));
}
```



### Classe BigBoss (cible de l'exploit)

```java
public class BigBoss {
    static { System.loadLibrary("snake"); }

    public BigBoss(String str) {
        String result = stringFromJNI(str);
        if (str.equals("Snaaaaaaaaaaaaaake")) {
            Log.d("BigBoss: ", hexToAscii(result));
        }
    }

    public native String stringFromJNI(String str);
}
```

### Détections de root

```java
public static boolean isDeviceRooted(Context context) {
    return checkForDangerousBinaries() ||      // /system/bin/su
           checkForRootManagementApps(context) || // SuperSU
           checkForWritableSystem() ||          // /system writable
           checkForRootShell();                 // which su
}
```


<img width="1148" height="814" alt="Etape1_JADX" src="https://github.com/user-attachments/assets/a4f75666-1d66-4bc9-9b04-52a7abcdee7b" />


## 📦 Préparation de l'environnement

### Installation des outils

```bash
# Apktool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
sudo mv apktool_2.9.3.jar /usr/local/bin/apktool.jar
sudo mv apktool /usr/local/bin/apktool
sudo chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar

# Uber-apk-signer
wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar

# Jadx
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d jadx
```


## 🔧 Patching Smali (désactivation des détections)

### Étape 1 : Décompilation

```bash
apktool d snake.apk -o snake_original --no-res
```





### Étape 2 : Modification de MainActivity.smali

```bash
cd snake_original/smali/com/pwnsec/snake/
nano MainActivity.smali
```

**Méthode isDeviceRooted originale** :

```bash
.method public static isDeviceRooted(Landroid/content/Context;)Z
    .locals 1
    ... (plusieurs vérifications)
.end method
```

**Version patchée** :

```bash
.method public static isDeviceRooted(Landroid/content/Context;)Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

<img width="936" height="333" alt="Etape2_1" src="https://github.com/user-attachments/assets/a9312680-9993-4b82-aff3-f4523b8ca459" />



### Étape 3 : Modification du chemin du fichier YAML

**Le code original utilisait** :

```bash
invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
...
const-string v2, "snake"
...
const-string v2, "Skull_Face.yml"
```

**Remplacement par un chemin fixe** :

```bash
const-string v0, "/data/local/tmp/snake/Skull_Face.yml"
new-instance v1, Ljava/io/File;
invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
```


### Étape 4 : Recompilation et signature


```bash
apktool b snake_original -o snake_fixed.apk
java -jar uber-apk-signer-1.3.0.jar --apks snake_fixed.apk
adb install snake_fixed-aligned-debugSigned.apk
```

<img width="751" height="275" alt="Etape2_2" src="https://github.com/user-attachments/assets/1d30a971-34ce-4815-a567-596a0d0127d7" />
<img width="958" height="571" alt="Etape2_3" src="https://github.com/user-attachments/assets/844b070a-91fe-488a-a321-02b8e596758b" />
<img width="645" height="188" alt="Etape2_4" src="https://github.com/user-attachments/assets/ace9c07f-29f2-4430-9ffa-bccb97cbfb4a" />



## 📝 Création du payload YAML

### La vulnérabilité SnakeYAML (CVE-2022-1471)

SnakeYAML version **1.33** contient une vulnérabilité de désérialisation unsafe. Elle permet d'instancier n'importe quelle classe Java via un tag YAML.

**Payload utilisé :**

```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]

```
### Explication du payload

| Élément | Signification |
|---------|---------------|
| `!!com.pwnsec.snake.BigBoss` | Tag YAML qui demande l'instanciation de la classe `BigBoss` |
| `["Snaaaaaaaaaaaaaake"]` | Tableau contenant la chaîne exacte attendue par le constructeur |


### Installation sur l'appareil
```bash
# Créer le dossier
adb shell mkdir -p /data/local/tmp/snake

# Créer le fichier YAML
adb shell "echo '!!com.pwnsec.snake.BigBoss [\"Snaaaaaaaaaaaaaake\"]' > /data/local/tmp/snake/Skull_Face.yml"

# Vérifier
adb shell cat /data/local/tmp/snake/Skull_Face.yml

```

<img width="877" height="225" alt="Etape2_6" src="https://github.com/user-attachments/assets/e4d30cdb-aedd-416e-80d4-9871c1cc02de" />



## 🎯 Exploitation de la vulnérabilité

### Commande de lancement

```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

<img width="1502" height="744" alt="Etape2_5" src="https://github.com/user-attachments/assets/0eece044-4bbc-4ab3-b510-68ae4a308aae" />



### Ce qui se passe

| Étape | Description |
|-------|-------------|
| **1** | L'extra Intent `-e SNAKE BigBoss` satisfait la condition dans `MainActivity.C()` |
| **2** | L'application lit le fichier `/data/local/tmp/snake/Skull_Face.yml` |
| **3** | SnakeYAML parse le contenu et voit le tag `!!com.pwnsec.snake.BigBoss` |
| **4** | Instanciation automatique de la classe `BigBoss` avec le paramètre `"Snaaaaaaaaaaaaaake"` |
| **5** | Le constructeur `BigBoss(String str)` vérifie la chaîne et appelle la fonction native |
| **6** | La fonction native génère le flag et l'affiche dans `Log.d()` |


### Résultat dans les logs
```bash
adb logcat | grep -E "BigBoss:|PWNSEC"
```

### Flag obtenu :
```bash
PWNSEC{W3'r3_N0t_TO0l5_Of_The_g0v3rnm3n7_OR_4ny0n3_3ls3}
```

<img width="956" height="102" alt="flag" src="https://github.com/user-attachments/assets/0e5d9bce-d98a-4bcb-9fe7-23483ef79e0f" />



## 📊 Récapitulatif des étapes

| Étape | Action | Résultat |
|-------|--------|----------|
| **1** | Décompilation Jadx | Compréhension du flux |
| **2** | Patch Smali `isDeviceRooted` | Désactivation des détections root |
| **3** | Patch du chemin YAML | Fichier lu dans `/data/local/tmp` |
| **4** | Recompilation + signature | APK patché installable |
| **5** | Création du payload YAML | Tag `!!com.pwnsec.snake.BigBoss` |
| **6** | Lancement avec Intent | `-e SNAKE BigBoss` |
| **7** | Logcat | Flag récupéré |

---

## 👤 Auteur

| Information | Détail |
|-------------|--------|
| **Nom** | El Hachimi Abdelhamid |
| **Pseudonyme GitHub** | abdotranscript25 |
| **Laboratoire** | Lab 19 - Sécurité Mobile |

---

## 📅 Date de réalisation

**Avril 2026**

---












