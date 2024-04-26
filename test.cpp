#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <iostream>

// int main(int argc, char* args[])
// {
//     if(argc < 2) 
//     {
//         std::cout << "Where is argument nigga\n";
//         return 1;
//     }
//     std::cout << "Args i ok nigga\n";

//     int me, him;
//     std::string ip = "192.168.1.103";
//     if(std::string(args[1]) == "1" )
//     {
//         me = 51001;
//         him = 51002;
//     }
//     else
//     {
//         me = 51002;
//         him = 51001;
//     }

//     int sockfd; /* Дескриптор сокета */
//     socklen_t clilen, n; /* Переменные для различных длин 
//         и количества символов */
//     char line[1000] = "lololololo nigga"; /* Массив для принятой и 
//         отсылаемой строки */
//     sockaddr_in servaddr, cliaddr; /* Структуры 
//         для адресов сервера и клиента */
//     /* Заполняем структуру для адреса сервера: семейство
//     протоколов TCP/IP, сетевой интерфейс – любой, номер порта 
//     51000. Поскольку в структуре содержится дополнительное не
//     нужное нам поле, которое должно быть нулевым, перед 
//     заполнением обнуляем ее всю */
//     bzero(&servaddr, sizeof(servaddr));
//     servaddr.sin_family = AF_INET;
//     servaddr.sin_port = htons(me);
//     servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
//     /* Создаем UDP сокет */
//     if((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
//                             std::cout << "Error nigga\n";

//         perror(NULL); /* Печатаем сообщение об ошибке */
//         exit(1);
//     }
//     /* Настраиваем адрес сокета */
//     if(bind(sockfd, (sockaddr *) &servaddr, 
//     sizeof(servaddr)) < 0){
//                             std::cout << "Error nigga\n";

//         perror(NULL);
//         close(sockfd);
//         exit(1);
//     }

//     bzero(&cliaddr, sizeof(cliaddr));
//     cliaddr.sin_family = AF_INET;
//     cliaddr.sin_port = htons(him);

//     cliaddr.sin_addr.s_addr = inet_addr(ip.c_str());

//         /* Основной цикл обслуживания*/
//         /* В переменную clilen заносим максимальную длину
//         для ожидаемого адреса клиента */
//         clilen = sizeof(cliaddr);
//         /* Ожидаем прихода запроса от клиента и читаем его. 
//         Максимальная допустимая длина датаграммы – 999 
//         символов, адрес отправителя помещаем в структуру 
//         cliaddr, его реальная длина будет занесена в 
//         переменную clilen */

//         if (std::string(args[1]) == "1")
//         {
//             if(sendto(sockfd, line, strlen(line), 0,(struct sockaddr *) &cliaddr, clilen) < 0)
//             {
//                                     std::cout << "Error nigga\n";

//                 perror(NULL);
//                 close(sockfd);
//                 exit(1);
//             }
//         }
//         else
//         {
//             if((n = recvfrom(sockfd, line, 999, 0,(struct sockaddr *) &cliaddr, &clilen)) < 0)
//             {
//                 std::cout << "Error nigga\n";
//                 perror(NULL);
//                 close(sockfd);
//                 exit(1);
//             }
//         /* Печатаем принятый текст на экране */
//             printf("%s\n", line);
//         }
        
//         /* Принятый текст отправляем обратно по адресу 
//         отправителя */
//          /* Уходим ожидать новую датаграмму*/


//     close(sockfd);
//     // close(sockReceive);
//     std::cout << "End of program nigga\n";

//     return 0;
// }

int main()
{
    unsigned int l = 255 + 256;
    std::cout << ((l << 24) >> 24) << "\n";
    // std::cout << sizeof(unsigned int);
}