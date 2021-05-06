PA2 
By Mihir Chhiber 1004359 and Harshit Garg 1004422

### AP Specification
To solve the problem for replay effect and to have a secured connection and unique and for the server to check whether the client alive

### CP1 Specification
Using AP, we establish a safe connection and send filename and encrypted file using servers public key (RSA)

### CP2 Specification
Using AP, we establish a safe connection. First the client shares a unique session symmetric key encrypted using server public key. Later client sends filename and encrypted file using sessions symmetric key (AES)


### INSTRUCTIONS TO RUN
### 
#### For CP1
#
- Compile ServerCP1.java , ClientCP1.java and ProtocolClient.java.
- Run ServerCP1.java and ClientCP1.java. in seperate consoles.
- Remeber to run ServerCp1.java first as client wont detect any conection otherwise.
- If you want to change the server ip you can do that by changing the string in Clientcp1.java file or make it argumentative by adding args[1].
- While running ClientCP1, include the filenames in the arguements while running to trasnfer the files.
 EG: java ServerCP1.java
java ClientCP1.java  [filename1] [filename2]


#### For the CP2 
To run:
- Compile ServerCp2.java and ClientCp2.java. 
- run ServerCP2.java and ClientCP2.java on different terminals 
- In the clients terminal, you can have four commands followed by file names.
- upload <filename>  - uploads the given file onto the server (basically inside a folder called recv). If invalid file is provided, it asks you to reenter.
download <filename> - returns the file with given name from the server (from the recv folder). if a nonexistant file is give, it simply returns an empty file and creates a new file there.

This code loops therefore multiple files can be sent using multiple input statements. 
To exit, input exit and code will terminate.


###### The Private key and the certificates are provided in the certificates folder.
