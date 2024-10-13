//  gcc -g -o output_program openssl.c -lssl -lcrypto -I/usr/include -L/usr/lib/x86_64-linux-gnu
//  gdb ./output_program
//  valgrind -s --leak-check=full --track-origins=yes --show-reachable=yes ./output_program
//  ./output_program
// obsahuje treba nejake chybicky v preventive_size_buf(misto int je tu size_t), ale jinak vse funguje a ZADNE memory leaky + funkce delkaSouboru je nema zadny vyznam + muzu pouzivat handleErrors misto return -1 a to by melo byt vse

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// https://docs.openssl.org/master/man3/RAND_bytes/

// sizeof(pointer) nam ukaze velikost pointeru, ne velikost bloku pameti, kam ten pointer ukazuje!!
// \0 VYZADUJE dalsi pozici/misto => Byte
// V programování, offset je vzdálenost mezi referenčním bodem (např. začátkem paměti nebo datové struktury) 
// a cílovým bodem, který chcete přistupovat. Je to číselná hodnota, která udává, jak daleko je nějaká adresa nebo pozice od referenční adresy.

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *s_to_bin(const char *temp_buffer, int size_temp_buffer, size_t dynamicArraySize)
{
    // 65 = 64 char = 0-63
    /*zkouska*/
    // 0xc60xe30xf70x9c0x8a0x570x010xf40xb40x860x990x620x3d0x2b0x430xde\0 = 63 + 1
    // 0123456789                                                     63
    unsigned char *dynamic_pole = (unsigned char *)malloc(dynamicArraySize); // musi byt tam i \0!! vcetne, ted to funguje s opravdovou velikosti bufferu - OPRAVIT
    int iForDynamicArray = 0;
    for (int i = 2; i < size_temp_buffer || i == size_temp_buffer - 2; i += 4) // 2 6 10 14 18 22 26 30 34 38 42 46 50 54 58 62 66        64 - 1
    {
        // 5 9 13 17 23 27 31 35 39 43 47 51 55 59 63 67 71 < 64
        
        unsigned int tempHex; // 0-4,294,967,295
        sscanf(&temp_buffer[i], "%2x", &tempHex); // & protoze sscanf ocekava pointer na zacatek retezce; bylo by to 4s, ted jen 2x, protoze 0x se ignoruje
        // sscanf cte hexadecimalni hodnoty jako usnigned int takze se precte treba 3b, to se prevede do unsinged int a potom se to prevede fo unsigned char aby bylo vice bezpecnejsi ze se to vejde do unsinged char, kdyby tam třeba bylo 5 hexadecimalnich cisel tak se to potom da na cislo a to cislo na byte apod.
        dynamic_pole[iForDynamicArray] = (unsigned char)tempHex;
        iForDynamicArray++; 
    }
    printf("%d   %d\n", size_temp_buffer, dynamic_pole);

    for (int i = 0; i < dynamicArraySize; i++)
    {
        printf("0x%02x ", dynamic_pole[i]);
    }

    // printf("\n");
    // printf("ahooj");
    return dynamic_pole;
}
// KDYZ CTU VE SSCANF TREBA DVA ZNAKY Z POZICE 0, TAK SE PRECTOU ZNAKY NA POZICICH 0 A 1 A TEN INDEX SE POSUNE NA MISTO POSLEDNIHO PRECTENI = 1

void print_bytes(const unsigned char *data, size_t length) {

        for (size_t i = 0; i < length; i++) { 
            printf("0x%02x", data[i]); // Tiskne byte jako hexadecimální číslo s prefixem 0x
        }
        printf("\n"); // Nový řádek po vytisknutí všech bytů  
}

char *data_w_padding(const char *name_of_file)
{
    // pocet Bytu v souboru = pocet charakteru + \0
    // 20    Bytu           = 19    charakteru + \0
    // hokus_pokus.txt = 20 Bytu
    FILE *fileToTxtFile = fopen(name_of_file, "r");

    fseek(fileToTxtFile, 0, SEEK_SET);
    fseek(fileToTxtFile, 0, SEEK_END);
    size_t delkasouboru = ftell(fileToTxtFile); // 20 (Bytu)
    fseek(fileToTxtFile, 0, SEEK_SET);

    unsigned char data_from_file[delkasouboru]; // kdyz ma soubor 20 Bytu = 19 char + \0
    // datovy soubor v fread (sizeof(datovy typ)) + stejny datovy typ u pole = do takoveho typu se data prevedou

    size_t bytes_read = fread(data_from_file, sizeof(unsigned char), delkasouboru, fileToTxtFile); // fread cte size * count pocet znaku/...

    // for (int i = 0; i<delkasouboru; i++)
    // {
    //     printf("%02x", data_from_file[i]);
        
    // }
    // printf("\n\n");

    if (bytes_read != delkasouboru)
    {
        printf("chyba pri čtení souboru");
        handleErrors();
    }

    size_t needed_padding = 16 - (delkasouboru % 16); // 16 - (20 % 16) = 16 - (4) = 12

    unsigned char *data = (unsigned char *)malloc(delkasouboru);
    unsigned char *padding = (unsigned char *)malloc(needed_padding);
    unsigned char *data_w_padding = (unsigned char *)malloc(bytes_read + needed_padding); // bytes read bez ohledu na \0, aby to davalo 32 Bytu = 20 + 12

    // memset se pouziva spise treba na padding apod. kdyz nejaky memory blok chceme nastavit na nejakou hodnotu
    // memcpy se pouziva spise na kopirovani ruznych dat (spise dat ze souboru) do nejakeho memory bloku
    memset(padding, 0x00, needed_padding); // pamet ktera ma byt vyplnena, cim se to ma vyplnit (interne se to prevede na unsigned char a bude se pouzivat jenom zacatecnich 256 bitu), pocet Bytu na vyplneni
    // 0x00 stejne jako 0 v tomhle pripade

    //print_bytes(padding, needed_padding);

    memcpy(data_w_padding, data_from_file, delkasouboru);
    memcpy(data_w_padding + delkasouboru, padding, needed_padding); // pointer arythmetic => posuneme pointer data_w_padding o delkasouboru a nasledne budeme kopirovat data

    //print_bytes(data_w_padding, delkasouboru + needed_padding);

    free(data);
    free(padding);
    fclose(fileToTxtFile);
    return data_w_padding;

    // free(data);
    // free(padding);
}

size_t delkaSouboru(const char *nameOfFile)
{
    FILE *fPointer = fopen(nameOfFile, "r");

    fseek(fPointer, 0, SEEK_SET);
    fseek(fPointer, 0, SEEK_END);
    size_t delka = ftell(fPointer);
    fseek(fPointer, 0, SEEK_SET);

    //fclose(nameOfFile);
}


size_t preventive_buf_size(int delkasouboru)
{
    size_t result = delkasouboru + 16;
    return result;
}

char *data_wO_padding(const char *name_of_file)       // muze se pouzit i const char *name_of_file, konstantni pointer na charakter, takze muzeme predat jak char tak i string
{
    FILE *file_pointer; // inicializace file pointeeru ke kumunikaci se souborem

    file_pointer = fopen(name_of_file, "r"); // otevirani souboru v ctecim modu

    if (file_pointer == NULL) // file_pointer == NULL je stejne jako !file
    {
        printf("Stala se nejaka chyba!");
        return NULL;
    }

    fseek(file_pointer, 0, SEEK_END); // posunuti kurzoru na konec souboru
    size_t delka_souboru = ftell(file_pointer); // zjisteni delku souboru podle pozice
    fseek(file_pointer, 0, SEEK_SET); // posunuti kurzoru na zacatek souboru, abychom mohli cist data

    // jak pro s paddingem, tak i bez padding
    char *data = (char *)malloc(delka_souboru + 1); // NEJDULEZISTEJSI CAST TETO FUNKCE: tvoreni char pointeru, ktery bude ukazovat na pamet v ram, ktera byla
                                          // dynamicky alokovana, nevraci se pointer array, vraci se pointer na zacatek dat v RAM + 1 pro \0 aby byty premenily na C-style string
                                          // alokovani memory pro 2 pripady, s/bez paddingu
    
    if (data == NULL)
    {
        printf("chyba pri alokovani mista v RAM");
        fclose(file_pointer);
        return NULL;
    }
    if (fread(data, 1, delka_souboru, file_pointer) != delka_souboru) // fread precte cely soubor najednou (cte jakykoliv datovy typ: char, int, byty, float apod.) cte to jako pole bitu
                                                                             // fgets cte cele radky
                                                                             // *p kam se to nacte, velikost kazdeho elementu v Bytech, pocet elementu, ktere se mají precist, stream => odkud se to ma precist
    {
        free(data); // uvolneni dynamicky alokovane pameti
        fclose(file_pointer);
        return NULL;
    }

    if (delka_souboru % 16 == 0)
    {
        data[delka_souboru] = '\0'; // prevedeni bitu pole na C-string
        fclose(file_pointer);  // hotove data bez paddingu
        return data;
    }
    
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *cipher_decipher_key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        handleErrors();
    }

    if ((EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cipher_decipher_key, iv)) != 1)
    {
        handleErrors();
    }

    if ((EVP_EncryptUpdate(ctx,  ciphertext, &len, plaintext, plaintext_len)) != 1)
    {
        handleErrors();
    }
    ciphertext_len = len;

    if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1)
    {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len,unsigned char *cipher_decipher_key, unsigned char *iv, unsigned char *plaintext)

{
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        handleErrors();
    }

    if ((EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cipher_decipher_key, iv)) != 1) // 1 = spravny stav, 0 = spatny stav
    {
        handleErrors();
    }

    if ((EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) != 1)
    {
        handleErrors();
    }
    plaintext_len = len;

    if ((EVP_DecryptFinal(ctx, plaintext + len, &len)) != 1)
    {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int main()
{
    unsigned char encrypt_decrypt_key[32];               // pro volba == 1
    unsigned char IV_initialization_vector[16];          // pro volba == 1
    char str_encrypt_decrypt_key[129]; // 128 char + \0  // pro volba == 2
    char str_IV[65]; // 64 char + \0                     // pro volba == 2
    int volba;
    unsigned char *p_to_IV_initialization_vector = IV_initialization_vector;                     // pro volbu 2
    unsigned char *p_to_encrypt_decrypt_key = encrypt_decrypt_key;                               // pro volbu 2
    printf("-----------------------------------\n");
    printf("| 1 = jen sifrovani               |\n");
    printf("| 2 = jen desifrovani             |\n");
    printf("| 3 = ukazka sifrovani&desifrovani|\n");
    printf("|---------------------------------|\n");
    if (scanf("%d", &volba) != 1) // pokud je scanf uspesny, tak scanf vrati pocet uspesne prectenych prvku, v tomto pripadu 1
    {
        printf("\nspatna volba.\n");
        return -1;
    }

    FILE *file_pointer = fopen("hokus_pokus.txt", "r");
    
    fseek(file_pointer, 0, SEEK_END);
    size_t delka_souboru = ftell(file_pointer);
    fseek(file_pointer, 0, SEEK_SET);
    fclose(file_pointer);

    //printf("IV = OK\n");

    if(delka_souboru % 16 == 0)
    {
        if (RAND_bytes(encrypt_decrypt_key, sizeof(encrypt_decrypt_key)) == 0)
        {
            printf("stala se chyba pri generovani nahodnych Bytu pro encrypt key");
            return -1;
        }

        //printf("klic = OK\n");

        if (RAND_bytes(IV_initialization_vector, sizeof(IV_initialization_vector)) == 0)
        {
            printf("stala se chyba pri generovani nahodnych Bytu pro IV");
            return -1;
        }

        char *p_to_address = (unsigned char *)data_wO_padding("hokus_pokus.txt");
        
        unsigned char *p_to_ciphertext = (unsigned char *)malloc(preventive_buf_size(delka_souboru));
        unsigned char *p_to_decipheretext = (unsigned char *)malloc(delka_souboru + 1); // + 1 pro \0, protoze tam vkladam jakoby novy znak \0

        //printf("%d\n", delka_souboru + 2);
        //printf("pointery k cipher/decipher text = OK\n");
        if (p_to_ciphertext == NULL)
        {
            printf("\nchyba pri alokovani memory pro sifrovani\n");
            fflush(stdout);
            free(p_to_ciphertext);
            //free(p_to_decipheretext);
            return -1;
        }
        if (p_to_decipheretext == NULL)
        {
            printf("\nchyba pri alokovani memory pro desifrovani\n");
            fflush(stdout);
            free(p_to_ciphertext);
            //free(p_to_decipheretext);
            return -1;
        }

        int ciphertext_len, decipheredtext_len;
        if (volba == 1)
        {
            FILE *file_pointer_infoTXT = fopen("info.bin", "wb");
            ciphertext_len = encrypt(p_to_address, delka_souboru, encrypt_decrypt_key, IV_initialization_vector, p_to_ciphertext);
            fwrite(p_to_ciphertext, sizeof(unsigned char), ciphertext_len, file_pointer_infoTXT);
            printf("\nvase sifra: \n");
            if (ciphertext_len < 0)
            {
                printf("nejspise se stala chyba pri sifrovani souboru");
                return -1;
            }
            
            //BIO_dump_fp(stdout, (const char *)p_to_ciphertext, ciphertext_len);
            //printing_ciphertext(p_to_ciphertext, ciphertext_len);
            print_bytes(p_to_ciphertext, ciphertext_len);
            printf("\nulozte si tyto udaje pro desifrovani souboru nekdy v budoucnu: \nIV\nencryption&decription key\nciphertextlen");
            printf("\n\nIV:\n");
            print_bytes(IV_initialization_vector, sizeof(IV_initialization_vector));
            //printing_IV_initialization_vector(IV_initialization_vector);
            //BIO_dump_fp(stdout, (const char *)p_to_IV_initialization_vector, 16); // 128 = delka IV

            //printing_IV_initialization_vector(IV_initialization_vector);
            printf("\nencryption&decryption key: \n");
            print_bytes(encrypt_decrypt_key, sizeof(encrypt_decrypt_key));
            //print_bytes()
            //printing_encrypt_decrypt_key(encrypt_decrypt_key);

            //print_bytes(encrypt_decrypt_key, sizeof(encrypt_decrypt_key)); // 32 bajtů pro AES-256
            
            printf("\nciphertextlen: \n");
            printf("%d", ciphertext_len);

            printf("\n");
            //BIO_dump_fp(stdout, (const char *)p_to_encrypt_decrypt_key, 32);      // 256 = delka encryption_decrypt_key

            //printing_encrypt_decrypt_key(encrypt_decrypt_key);

            //printf("printing ciphertext = OK\n");
            fclose(file_pointer_infoTXT);
            //fclose(file_pointer);
        }
        else if (volba == 2)
        {
            

            // unsigned char used_IV_initialization_vector[16];    // pro 32 hexadecimalnich cisel (16 dvojic - Bytes)
            // +1 pro \0      0-63
            // +1 pro \0    0-127
            //char ch;

            //unsigned char *final_ciphertext = malloc(preventive_buf_size(delka_souboru));
            int new_ciphertext_len;
            FILE *file_pointer_to_ciphertext = fopen("info.bin", "rb"); // rb musí být fread;
            fseek(file_pointer_to_ciphertext, 0, SEEK_SET);
            fseek(file_pointer_to_ciphertext, 0, SEEK_END);
            
            size_t infoTXT_delka_souboru = ftell(file_pointer_to_ciphertext);
            fseek(file_pointer_to_ciphertext, 0, SEEK_SET); // aby se veci mohli precist!!

            if (file_pointer_to_ciphertext == NULL)
            {
                printf("chyba");
                return -1;
            }
            printf("\nvas IV?\n");
            scanf("%s", str_IV);

            size_t sixteen = 16;
            unsigned char *dynamic_iv = s_to_bin(str_IV, 65, sixteen); // pointer na první prvek ve statickem poli definovanem v te funcki
            
            printf("\n\nvas encryption&decryption key?\n");

            size_t thirtyTwo = 32;
            scanf("%s", str_encrypt_decrypt_key);
            unsigned char *dynamic_key = s_to_bin(str_encrypt_decrypt_key, 129, thirtyTwo);
            printf("\nvas ciphertextlen?\n");
            scanf("%d", &new_ciphertext_len);
            printf("\n");

            //printf("\n%d\n", new_ciphertext_len);

            //char *ciphertext_temp_buffer = (char *)malloc(new_ciphertext_len * 4 + 1); // new_ciphertext_len jsou Byty (32) => 64 hexadecimalnich dvojic => 128 char + \0
            unsigned char *p_to_new_ciphertext = malloc(infoTXT_delka_souboru); // protoze je size_ciphertext_len v Bytech, tak ma polovicni velikost 2 hexadecimalni cisla == 1 Byte
            unsigned char *p_to_new_decipheredtext = malloc(infoTXT_delka_souboru + 1);

            if (p_to_new_decipheredtext == NULL)
            {
                printf("chyba, spatne alokovane");
                return -1;
            }

            if (p_to_new_ciphertext == NULL)
            {
                printf("chyba, spatne alokovane");
                return -1;
            }
            //printf("porad to funguje?");

            // 64 charakteru = 32 hexadecimalnich dvojic = 16 Bytu
            //printf("\njde se cist");
            size_t bytes_read = fread(p_to_new_ciphertext, sizeof(unsigned char), infoTXT_delka_souboru, file_pointer_to_ciphertext); // cteni ciphertext ze souboru jako string
            //printf("%zu\n", bytes_read);

            // printf("Ciphertext in hexadecimal:\n");
            // for (size_t i = 0; i < bytes_read; i++) {
            //     printf("%02x ", p_to_new_ciphertext[i]);
            // }
            // printf("\n");

            //ciphertext_len = encrypt(p_to_address, delka_souboru, encrypt_decrypt_key, IV_initialization_vector, p_to_ciphertext);
            decipheredtext_len = decrypt(p_to_new_ciphertext, new_ciphertext_len, dynamic_key, dynamic_iv, p_to_new_decipheredtext);
            //printf("%d\n", decipheredtext_len);
            //decrypt()

            

            if (p_to_new_decipheredtext < 0)
            {
                printf("nejspise se stala chyba pri desifrovani souboru");
                return -1;
            }

            p_to_new_decipheredtext[decipheredtext_len] = '\0';

            printf("vas decryptovany text:\n");
            printf("%s", p_to_new_decipheredtext); // p_todecipheretext ukazuje na zacatek stringu, proto tam musim dat jen ten ukazatel, ktery ukazuje na ZACATEK stringu, kdyby to byl jen charakter tak bych pravdepodobne musel zmenit format specifier a dat tam tu hvezdicku

            free(dynamic_iv);
            free(dynamic_key);
            free(p_to_new_ciphertext);
            free(p_to_new_decipheredtext);
            fclose(file_pointer_to_ciphertext);
        }
        else if (volba == 3)
        {
            printf("vas IV:\n");
            size_t sixteen = 16;
            print_bytes(IV_initialization_vector, 16);

            printf("\nvas decryption&encryption key:\n");
            size_t thiryTwo = 32;
            print_bytes(encrypt_decrypt_key, thiryTwo);

            ciphertext_len = encrypt(p_to_address, delka_souboru, encrypt_decrypt_key, IV_initialization_vector, p_to_ciphertext);
            //printf("encrypce = OK\n");
            if (ciphertext_len < 0)
            {
                printf("nejspise se stala chyba pri sifrovani souboru");
                return -1;
            }
            
            printf("\nvase sifra:\n");
            print_bytes(p_to_ciphertext, ciphertext_len);

            printf("\nvas ciphertextlen:\n");
            printf("%d", ciphertext_len);
            //BIO_dump_fp(stdout, (const char *)p_to_ciphertext, ciphertext_len);

            //printf("printing ciphertext = OK\n");

            decipheredtext_len = decrypt(p_to_ciphertext, ciphertext_len, encrypt_decrypt_key, IV_initialization_vector, p_to_decipheretext);

            printf("\nvas decipheredtextlen:\n");
            printf("%d", decipheredtext_len);

            //printf("deciphering = OK\n");

            if (decipheredtext_len < 0)
            {
                printf("nejspise se stala chyba pri desifrovani souboru");
                return -1;
            }

            //printf("pridavani null charakteru = OK\n");

            p_to_decipheretext[decipheredtext_len] = '\0';

            //printf("pridano null charakteru = OK\n");
            printf("\n\nvas desifrovany text:");
            printf("\n%s", p_to_decipheretext); // p_todecipheretext ukazuje na zacatek stringu, proto tam musim dat jen ten ukazatel, ktery ukazuje na ZACATEK stringu, kdyby to byl jen charakter tak bych pravdepodobne musel zmenit format specifier a dat tam tu hvezdicku

            //printf("vyprintovani deciphered textu = OK\n");
            // free(p_to_decipheretext);
        }

        // printf("uvolni se to?\n");
        // fflush(stdout);
        free(p_to_address);
        // printf("1.\n");
        // fflush(stdout);
        free(p_to_ciphertext);
        // printf("2.\n");
        // fflush(stdout);
        free(p_to_decipheretext);
        // printf("3.\n");
        // fflush(stdout);
    }
    else
    {
        if (volba == 1)
        {
            FILE *fPointerToInfoBin = fopen("info.bin", "wb");

            if (fPointerToInfoBin == NULL)
            {
                printf("chyba u otevirani souboru info.bin");
                handleErrors();
            }

            if (RAND_bytes(encrypt_decrypt_key, 32) != 1)
            {
                printf("nastala chyba pri generovani Bytu pro encryption_decryption_key");
                handleErrors();
            }

            if ((RAND_bytes(IV_initialization_vector, 16)) != 1)
            {
                printf("nastala chyba pri generovani Bytu pro IV.");
                handleErrors();
            }

            unsigned char *pToText = (unsigned char *)data_w_padding("hokus_pokus.txt");
            // for (size_t i = 0; i <48; i++)
            // {
            //     printf("%02x", pToText[i]);
            // }
            // printf("\n\n");

            
            
            size_t paddingNeeded = 16 - (delka_souboru % 16);
            size_t delkaWPadding = delka_souboru + paddingNeeded;
            int paddingDelka;
            paddingDelka = delkaWPadding;

            // print_bytes(pToText, delkaWPadding);
            // printf("\n\n");
            
            unsigned char *pToCipherText = malloc(preventive_buf_size(paddingDelka));

            int ciphertext_len = encrypt(pToText, delka_souboru, encrypt_decrypt_key, IV_initialization_vector, pToCipherText);
            // encrypt()

            fwrite(pToCipherText, sizeof(unsigned char), ciphertext_len, fPointerToInfoBin); // sizeof(pointer) NEFUNGUJE!!!


            //BIO_dump_fp(stdout, (const char *)pToCipherText, ciphertext_len);
            
            printf("\nvase sifra: \n");
            if (ciphertext_len < 0)
            {
                printf("nejspise se stala chyba pri sifrovani souboru");
                return -1;
            }
            print_bytes(pToCipherText, delkaWPadding);
            
            printf("\nulozte si tyto udaje pro desifrovani souboru nekdy v budoucnu: \nIV\nencryption&decription key\nciphertextlen");
            printf("\n\nIV:\n");
            print_bytes(IV_initialization_vector, sizeof(IV_initialization_vector));

            printf("\nencryption&decryption key: \n");
            print_bytes(encrypt_decrypt_key, sizeof(encrypt_decrypt_key));

            printf("\nciphertextlen: \n");
            printf("%d", ciphertext_len);

            
            // char ahoj[] = "0x750xbe0x6d0xd80x8c0xbd0x5f0x8c0x900xd40xc50xca0xb80x410x570xc80xa70xf00x4b0xe2";
            // printf("%d", strlen(ahoj));

            // free(pToCipherText);
            // free(pToCipherText);

            free(pToText);
            free(pToCipherText);
            fclose(fPointerToInfoBin);

            // for (int i = 0; i < 16; i++)
            // {
            //     printf("%02x ", IV[i]);
            // }
            // printf("\n");

        }
        else if (volba == 2)
        {
            // 16 Bytu = 32 hexadecimalnich dvojic = 64 charakteru + \0
            // 32 Bytu = 64 hexadecimalnich dvojic = 128 charakteru + \0
            int cipheredtext_len;

            printf("vas IV?\n");
            scanf("%s", str_IV);

            printf("vas Encryption&Decryption Key?\n");
            scanf("%s", str_encrypt_decrypt_key);

            printf("vas ciphertextlen?\n");
            scanf("%d", &cipheredtext_len); // protoze tam nedavame pointer, tak tam musime dat adresu te promenne
            //printf("porad xd\n");
            FILE *fPointerToCIpherTxt = fopen("info.bin", "rb");
            fseek(fPointerToCIpherTxt, 0, SEEK_SET);
            fseek(fPointerToCIpherTxt, 0, SEEK_END);
            size_t delkaSouboruCipherText = ftell(fPointerToCIpherTxt);
            fseek(fPointerToCIpherTxt, 0, SEEK_SET);

            size_t sixteen = 16;
            printf("\n");
            unsigned char *dynamicArrayIV = s_to_bin(str_IV, 65, 16);
            //printf("IV");
            printf("\n");

            size_t thirtyTwo = 32;
            printf("\n");
            unsigned char *dynamicArrayEncDecKey = s_to_bin(str_encrypt_decrypt_key, 129, 32);
            //printf("Key");

            printf("\n");

            //printf("1. alokovani\n");
            unsigned char *pToCipherTxt = (unsigned char *)malloc(delkaSouboruCipherText);
            //printf("alokovano\n");
            //printf("2. alokovani\n");
            unsigned char *pToDecipheredTxt = (unsigned char *)malloc(delkaSouboruCipherText + 1);
            //printf("alokovano\n");
            
            size_t bytes_read;
            if ((bytes_read = fread(pToCipherTxt, sizeof(unsigned char), delkaSouboruCipherText, fPointerToCIpherTxt)) != delkaSouboruCipherText)
            {
                printf("\nchyba u cteni prvku  binarniho souboru\n");
                return -1;
                //handleErrors();
            }

            size_t paddingNeeded = 16 - (delkaSouboruCipherText % 16);
            size_t celkovaVelikost = delkaSouboruCipherText + paddingNeeded;


            int decipheredtext_len;

            decipheredtext_len = decrypt(pToCipherTxt, cipheredtext_len, dynamicArrayEncDecKey, dynamicArrayIV, pToDecipheredTxt);
            //printf("\ndecryptovano\n");
            // print_bytes(dataNoPadding, delkaSouboruCipherText);

            // data: 686f6b7573706f6b757378646b6f6c42797475786a666864666c6975677668646c6976756a746f69670a000000000000
            pToDecipheredTxt[decipheredtext_len] = '\0';
            // data: 686f6b7573706f6b757378646b6f6c42797475786a666864666c6975677668646c6976756a746f69670a\0000000000000
            //                                                                                           xx
            
            printf("\nvas decryptovany text:");
            printf("\n%s", pToDecipheredTxt);

            fclose(fPointerToCIpherTxt);
            free(pToDecipheredTxt);
            free(pToCipherTxt);
            free(dynamicArrayIV);
            free(dynamicArrayEncDecKey);
        }
        else if (volba == 3)
        {
            unsigned char IV[16];
            unsigned char encDecKey[32];

            FILE *fPointerToCipherText = fopen("info.bin", "rb");

            fseek(fPointerToCipherText, 0, SEEK_SET);
            fseek(fPointerToCipherText, 0, SEEK_END);
            size_t delkaCipherTextu = ftell(fPointerToCipherText);
            fseek(fPointerToCipherText, 0, SEEK_SET);

            if (RAND_bytes(IV, 16) != 1)
            {
                printf("vyskytla se chyba pri generovani nahodnych Bytu pro IV");
                handleErrors();
            }

            if (RAND_bytes(encDecKey, 32) != 1)
            {
                printf("vyskytla se chyba pri generovani nahodnych Bytu pro encryption&decryption key");
                handleErrors();
            }
            int delkaSouboruHokusPokusTXT = delka_souboru;
            size_t howmuchADD = 16 - (delka_souboru % 16);

            unsigned char *plaintext = (unsigned char *)data_w_padding("hokus_pokus.txt");
            unsigned char *ciphertext = (unsigned char *)malloc(delkaCipherTextu + howmuchADD);
            unsigned char *decipheredtext = (unsigned char *)malloc(delkaCipherTextu+1);

            int decipheredtext_len, ciphertext_len;

            size_t thirtyTwo = 32;
            printf("vas encryption&decryption key:\n");
            print_bytes(encDecKey, thirtyTwo);

            size_t sixteen = 16;
            printf("\nvas IV:\n");
            print_bytes(IV, sixteen);

            

            printf("\nvase sifra:\n");
            ciphertext_len = encrypt(plaintext, delkaSouboruHokusPokusTXT, encDecKey, IV, ciphertext);
            size_t lenCiphertext = ciphertext_len;
            print_bytes(ciphertext, lenCiphertext);

            printf("\nvas ciphertext len:\n");
            printf("%d", ciphertext_len);

            size_t lenDecipheredtext = decipheredtext_len;
            decipheredtext_len = decrypt(ciphertext, ciphertext_len, encDecKey, IV, decipheredtext);

            printf("\nvas decipheredtext len:\n");
            printf("%d", decipheredtext_len);

            decipheredtext[decipheredtext_len] = '\0';
            
            printf("\n\nvas desifrovany text:");
            printf("\n%s", decipheredtext);


            //IO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

            fclose(fPointerToCipherText);
            free(plaintext);
            free(ciphertext);
            free(decipheredtext);
        }
        /*
        !!!
        takže sizeof vrací jenom velikosti tich datových typů a podobně, ale nevrací velikost pointeru/proměnných apod.?

        Ano, přesně tak. sizeof v jazyce C a C++ vrací velikost typu nebo objektu v bajtech. To zahrnuje datové typy, struktury, pole a další, 
        ale nevrací přímo velikost obsahu proměnné nebo velikost paměti alokované pro pointer.
        !!!
        */  
        // unsigned char *p_to_ciphertext = malloc(preventive_buf_size(delka_souboru)); // nejake Byty tam nebudou potreba, max 15, min 1
    }
    return 0;
}
