# Ransom

Dificultad: ⭐️⭐️⭐️⭐️
Number: 1
Section: Linux, RedTeam

<p align="center">
  <img src="https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Ransom.png" alt="ImagenCustom"/>
</p>

# Foothold:

## Nmap

→ Lo primero que vamos a realizar es un escaneo mediante `NMAP` para poder identificar los distintos puertos y tecnologías que tenga abierta la máquina.

```bash
nmap -sCV -n -sS --min-rate 2000 -p- 10.10.11.153 -v -Pn

-n -> para que no aplique resolucion DNS
--min-rate 2000 -> no envie paquetes mas lentos de 2000/s 
-sS -> TCP SYN scan
-Pn -> Port scans only 

-> Ya que estamos en un CTF, queremos realizar un escaneo lo mas rapido posible
		para poder sacar informacion mas rapido. ( genera mucho ruido ).
```

```latex
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Gobuster

→Hemos descubierto que tiene un puerto 80 abierto, mientras que investigamos la APP web, ejecutamos `GOBUSTER` para ir ganando tiempo y ver si tiene algún directorio / archivo interesante del que poder sacar información.

```bash
gobuster dir -u http://10.10.11.153/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t150 2>/dev/null
```

```latex
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.153/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/24 04:52:24 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 6104]
/register             (Status: 500) [Size: 604276]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.153/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.153/js/] 
/fonts                (Status: 301) [Size: 312] [--> http://10.10.11.153/fonts/]
```

## Whatweb

→ Lanzamos `whatweb` para poder sacar alguna información extra { version, tecnología etc } y a partir de ella buscar algún posible exploit , en el caso que lo tenga.

```bash
whatweb 10.10.11.153
```

```latex
http://10.10.11.153 [302 Found] Apache[2.4.41], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], Laravel, Meta-Refresh-Redirect[http://10.10.11.153/login], RedirectLocation[http://10.10.11.153/login], Title[Redirecting to http://10.10.11.153/login]
```

```latex
http://10.10.11.153/login [200 OK] Apache[2.4.41], Bootstrap, Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.153], JQuery[1.9.1], Laravel, PasswordField[password], Script[text/javascript], Title[Admin - HTML5 Admin Template], X-UA-Compatible[IE=edge]
```

# User

→ Como hemos obtenido en el proceso de FUZZING, tenemos la web tiene un directorio web /login.

→ Es el único interesante del que, en un principio podremos sacar algo de información.

```latex
http://10.10.11.153/login
```

![web](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled.png)

→ Mediante la extension COOKIE EDITOR, sacamos dos TOKENS que pueden ser bastante interesantes para proceder a BYPASSEAR el login.

![cookieEditor](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%201.png)

→ Vamos a parar la petición mediante `BURPSUITE` .

→ Podemos ver en el GET que vuelven a aparcer los TOKENS que habiamos sacado mediante la extension.

GET

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%202.png)

→ Una practica muy común es cambiar el método para ver como se comportar la página ( si lo permite ) y poder sacar información diferente.

→ Como podemos ver en el cuerpo de la peticion, nos printea la contraseña que hemos introducido ( fallo grave ).

POST

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%203.png)

→ En la respuesta podemos ver que por debajo esta utilizando un JSON, por lo que vamos a probar a alterar la peticion, forzando a utilizar en el `Content-Type` el mismo formato. 

GET con PASSWORD

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%204.png)

JSON

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%205.png)

APPLICATION JSON]

→ Como podemos ver hemos conseguido alterar la respuesta escribiendo en el cuerpo del mensaje un JSON.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%206.png)

→ A traves de la extension `WAPPALYZER`obtenemos que la web esta hecha en LARAVEL, un framework hecho en PHP.

TYPE JUGGLING

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%207.png)

→ { explicada la vulnerabilidad al final del documento } ←

[PHP Type Juggling Vulnerabilities](https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09)

### LOGIN GOOD

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%208.png)

→ Vemos que tenemos un user.txt.

### USER FLAG

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%209.png)

### Zip

→ Nos descargamos el .zip

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2010.png)

→ Al estar encriptado el `.zip`, vamos a utilizar las herramientas `unzip / 7z` para poder sacar información de los archivos que contiene el archivo comprimido sin necesidad de acceder “directamente” a el.

### unzip

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2011.png)

### 7z

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2012.png)

→ Podemos ver que ha sido codeado a traves de `ZipCrypto Deflate`

## Bkcrack

→ Al buscar el método por el cual ha sido encodeado, nos encontramos muchos POSTs para poder sacar en texto plano el contenido.

[https://www.anter.dev/posts/plaintext-attack-zipcrypto/](https://www.anter.dev/posts/plaintext-attack-zipcrypto/)

→ Vamos a hacer uso de la herramienta `bkcrack`.

[https://github.com/kimci86/bkcrack](https://github.com/kimci86/bkcrack)

→ Esta herramienta nos va a permitir, a partir de un ZIP encriptado, indicar uno de los archivos que contenga y comparándolo con otro archivo del mismo tamaño pero sin cifrar y poder sacar los datos en texto plano.

→ Lo mas importante de esta parte es buscar un archivo que, este dentro del ZIP y este cifrado y luego el mismo archivo en texto plano para que haga la equivalencia y empezar el ataque.

→ Esto nos va a generar unas keys y un archivo zip nuevo, el cual va a ser una copia del archivo encriptado inicial pero con la contraseña que nosotros elijamos.

### help

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2013.png)

### bash_logout

→ El archivo que vamos a utilizar el bash_logout, ya que suele estar en todos los sistemas y tener el mismo contenido.

### error

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2014.png)

→ Os dejo un directorio por aqui por si no tenéis el FILE en vuestro equipo. { era mi caso por tener una máquina completamente nueva }

[home/.bash_logout at master · greenmoss/home](https://github.com/greenmoss/home/blob/master/.bash_logout)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2015.png)

```bash
-C -> archivo zip encriptado
-c -> file que contiene el texto encriptado { ya que se encuentra alocada dentro del zip }
-P -> arhivo zip sin encriptar, el cual creamos de forma local
-p -> file en texto plano, debe coincidir el contenido y el tamaño a la cifrada
				-> por eso es importante usar .bash_logout { suele ser standar en todos los sitemas }
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2016.png)

```bash
./bkcrack -C uploaded-file-3422.zip -c .bash_logout -P ransom.zip -p bash_logout
```

→ Nos ha generado 3 claves.

```bash
./bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U ransomDecrypt.zip password
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2017.png)

```bash
-k -> claves utilzidas en el original para la password ( 32 bits )
-U -> zip que vamos a generar con las claves anteriores, que va a ser una copia del archivo
				cifrado original seguido de "password" que es la contraseña que vamos a poner a nuestro
					gusto.
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2018.png)

→ Ahora ya podemos acceder al contenido del `.zip` y acceder a las claves ssh.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2019.png)

→ El único problema que tenemos es saber el usuario con el poder conectarnos con la clave privada.

→ En el archivo `authorized_keys` podemos  ver al final <usuario>@<ip>.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2020.png)

→ Muy importante dar los permisos necesarios a la clave privada para poder utilizarla y conector por ssh a la máquina y obtener la shell.

```bash
$chmod 600 id_rsa
$ssh -i id_rsa htb@10.10.11.153
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2021.png)

# ROOT

→ Lo primero que identificamos en esta maquina es que es vulnerable al `PwnKit` y antes de explotarla de esta manera, vamos a buscar otra forma de elevar privilegios.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2022.png)

→ Hacemos una busqueda de permisos de SGUID.

→ Nada relevante.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2023.png)

→ Me pase a la maquina el linpeas y realice un escaneo exhaustivo con la herramienta.

```bash
$./linpeas.sh -a > /dev/shm/linpeas.txt
$less -r /dev/shm/linpeas.txt
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2024.png)

→ Como podemos ver nos marca unos archivos de configuración del apache el cual esta corriendo en TCP 80.

→ Como es un archivo con permisos `root root` podemos suponer que la web que esta corriendo el apache mencionado es la “ `web root` ” que se encuentra en `/srv/prod` .

```bash
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /srv/prod/public

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
            <Directory /srv/prod/public>
               Options +FollowSymlinks
               AllowOverride All
               Require all granted
            </Directory>

</VirtualHost>
```

→ Buscamos de forma recursiva la palabra login.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2025.png)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2026.png)

→ Nos fijamos en la clase `AuthController`

→ Grep recursivo de la misma.

```bash
$grep -r "AuthController"
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2027.png)

→ Encontramos un archivo .php.

→ Cuando lo abrimos encontramos una contraseña con la cual podríamos utilizarla para autenticarnos como root ( reutilización de contraseñas ).

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2028.png)

→ Tenemos dos opciones:

- Conectarnos via SSH con el usuario root y la password anterior
- sudo root

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2029.png)

→ Ya somos root

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2030.png)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2031.png)

## Type Juggling

→ Una vez tenemos acceso al código fuente de la web podemos explicar de forma mas clara como hemos explotado la vulnerabilidad para bypassear el login.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/RansomImages/Untitled%2028.png)

→ Podemos ver que hace una simple comparación para validad la contraseña correcta.

```bash
-> Utiliza { == }
	-> Por lo que si 'password' != "UHC-March-Global-PW!" -> false
	-> Por lo que si 'password' == "UHC-March-Global-PW!" -> true
	-> El doble igual en PHP puede comparar tanto strings como ints
		-> (“7 hacker” == 7) -> true( coje el primer numero del string )
		// Si el String no contiene un numero \\
		-> (“hacker” == 0) -> true
			-> Si el string no contiene un numero lo convierte directamente a 0 
			-> Por lo que en nuestra aplicacion tenemos asignamos:
				-> La password que introducimos va a ser igual a 0
				-> "0" == 0 -> true
-> Forma de corregirla { === }:
	-> if ($request->get('password') === "UHC-March-Global-PW!")
```
